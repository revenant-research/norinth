"""sdk delivery durability and tenant inference"""

from __future__ import annotations

import http.server
import pathlib
import sys
import threading

SDK_DIR = pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"
sys.path.insert(0, str(SDK_DIR))

from norinth_logger.config import NorinthConfig  # noqa: E402
from norinth_logger.privacy import infer_governance_context  # noqa: E402
from norinth_logger.transport import EventTransport  # noqa: E402

# app tenant vs platform routing tenant


def test_app_tenant_is_not_stamped_as_platform_tenant():
    ctx = infer_governance_context(({"tenant_id": "customer-acme", "user_id": "u1"},), {})
    # routing key must be absent so the server stamps it from the key
    assert "tenant_id" not in ctx
    # app's tenant survives under a non-colliding key
    assert ctx["subject_tenant"] == "customer-acme"
    assert ctx["user_id"] == "u1"


def test_alternate_app_tenant_field_names_map_to_subject_tenant():
    for field in ("org_id", "organization_id", "account_id", "customer_id"):
        ctx = infer_governance_context(({field: "cust-1"},), {})
        assert ctx.get("subject_tenant") == "cust-1"
        assert "tenant_id" not in ctx


# spool durability


def _spooling_transport(tmp_path, endpoint="http://127.0.0.1:9"):
    config = NorinthConfig(
        api_key="test",
        endpoint=endpoint,
        async_transport=False,
        timeout_seconds=0.2,
        max_send_retries=1,
        retry_backoff_seconds=0,
        spool_dir=str(tmp_path / "spool"),
    )
    return EventTransport(config)


def test_transient_failure_is_spooled_not_dropped(tmp_path):
    transport = _spooling_transport(tmp_path)
    transport.send_batch([{"type": "model.call", "trace_id": "t1"}])
    assert transport.stats.spooled == 1
    assert transport.stats.dropped == 0
    spooled = list((tmp_path / "spool").glob("*.json"))
    assert len(spooled) == 1


class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    received: list[bytes] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _RecordingHandler.received.append(self.rfile.read(length))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):  # silence
        pass


def test_spool_drains_on_next_flush(tmp_path):
    _RecordingHandler.received = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _RecordingHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        # spool against a dead endpoint
        transport = _spooling_transport(tmp_path)
        transport.send_batch([{"type": "model.call", "trace_id": "spooled"}])
        assert transport.stats.spooled == 1

        # now point a working transport (same spool dir) and flush
        port = server.server_address[1]
        transport.config = NorinthConfig(
            api_key="test",
            endpoint=f"http://127.0.0.1:{port}",
            async_transport=False,
            spool_dir=str(tmp_path / "spool"),
            max_send_retries=0,
            retry_backoff_seconds=0,
        )
        transport.flush()
    finally:
        server.shutdown()

    assert len(_RecordingHandler.received) == 1
    assert b"spooled" in _RecordingHandler.received[0]
    assert list((tmp_path / "spool").glob("*.json")) == []


class _RejectingHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(400)
        self.end_headers()
        self.wfile.write(b"bad request")

    def log_message(self, *args):
        pass


def test_permanent_4xx_is_dropped_not_spooled(tmp_path):
    server = http.server.HTTPServer(("127.0.0.1", 0), _RejectingHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        config = NorinthConfig(
            api_key="test",
            endpoint=f"http://127.0.0.1:{port}",
            async_transport=False,
            spool_dir=str(tmp_path / "spool"),
            max_send_retries=3,
            retry_backoff_seconds=0,
        )
        transport = EventTransport(config)
        transport.send_batch([{"type": "model.call"}])
    finally:
        server.shutdown()

    # a 400 will never succeed on retry, so it is dropped without retrying or
    # filling the spool with poison
    assert transport.stats.dropped == 1
    assert transport.stats.spooled == 0
    assert transport.stats.retried == 0
    assert not list((tmp_path / "spool").glob("*.json"))
