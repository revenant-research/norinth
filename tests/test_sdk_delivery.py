"""sdk delivery durability and tenant inference"""

from __future__ import annotations

import http.server
import os
import pathlib
import stat
import sys
import threading
import time
from urllib.error import HTTPError

SDK_DIR = pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"
sys.path.insert(0, str(SDK_DIR))

from norinth_logger.config import NorinthConfig  # noqa: E402
from norinth_logger.privacy import infer_governance_context  # noqa: E402
from norinth_logger.spool import resolve_spool_dir  # noqa: E402
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


# the durability decision is loud at startup


def _quiet_config(**overrides):
    values = dict(api_key="test", endpoint="http://127.0.0.1:9", async_transport=False)
    values.update(overrides)
    return NorinthConfig(**values)


def test_transport_without_spool_warns_once_at_startup(caplog):
    with caplog.at_level("WARNING", logger="norinth_logger"):
        EventTransport(_quiet_config(spool_dir="off"))
    warnings = [r for r in caplog.records if "durable delivery is off" in r.getMessage()]
    assert len(warnings) == 1
    # the line has to say why and how to change it, not just that it is off
    assert "NORINTH_SPOOL_DIR=off" in warnings[0].getMessage()
    assert "NORINTH_DURABLE" in warnings[0].getMessage()


def test_transport_with_spool_does_not_warn(tmp_path, caplog):
    with caplog.at_level("WARNING", logger="norinth_logger"):
        EventTransport(_quiet_config(spool_dir=str(tmp_path / "spool")))
    assert not [r for r in caplog.records if "durable delivery is off" in r.getMessage()]


def test_sdk_health_reports_durability_posture(tmp_path):
    from norinth_logger.client import NorinthClient

    class _Capture(EventTransport):
        def __init__(self, config, spool_dir):
            super().__init__(config, spool_dir=spool_dir)
            self.events = []

        def enqueue(self, event):
            self.events.append(event)

    def build(**overrides):
        client = NorinthClient.__new__(NorinthClient)
        client.config = _quiet_config(**overrides)
        client.transport = _Capture(client.config, resolve_spool_dir(client.config))
        client.emit_sdk_health("initialized")
        return client.transport.events[-1]["attributes"]

    off = build(spool_dir="off")
    assert off["durable"] is False
    assert off["spool_configured"] is False
    assert off["spooled"] == 0

    default = build()
    assert default["spool_configured"] is True

    durable = build(durable=True, spool_dir=str(tmp_path / "spool"))
    assert durable["durable"] is True
    assert durable["spool_configured"] is True


# the spool is on by default


def test_default_spool_is_a_private_per_service_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    path = resolve_spool_dir(_quiet_config(service="svc-a"))
    assert path and path.startswith(str(tmp_path / "state"))
    assert os.path.isdir(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o700
    # another service, or another key, never shares the directory
    assert resolve_spool_dir(_quiet_config(service="svc-b")) != path
    assert resolve_spool_dir(_quiet_config(service="svc-a", api_key="other")) != path
    # same identity resolves to the same place across restarts
    assert resolve_spool_dir(_quiet_config(service="svc-a")) == path
    # the key is hashed, never written into the path
    assert "test" not in os.path.basename(path)


def test_default_spool_falls_back_when_state_dir_is_unwritable(tmp_path, monkeypatch):
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory")
    monkeypatch.setenv("XDG_STATE_HOME", str(blocked))
    monkeypatch.setattr("norinth_logger.spool.tempfile.gettempdir", lambda: str(tmp_path / "tmp"))
    monkeypatch.setattr("norinth_logger.spool.os.path.expanduser", lambda p: "~")
    path = resolve_spool_dir(_quiet_config())
    assert path and path.startswith(str(tmp_path / "tmp"))


def test_no_writable_location_means_no_spool_and_a_warning(monkeypatch, caplog):
    monkeypatch.setattr("norinth_logger.spool.default_spool_candidates", lambda config: [])
    assert resolve_spool_dir(_quiet_config()) is None
    with caplog.at_level("WARNING", logger="norinth_logger"):
        EventTransport(_quiet_config())
    assert any("no writable spool directory" in r.getMessage() for r in caplog.records)


def test_raw_content_is_never_spooled_to_a_default_location(tmp_path):
    assert resolve_spool_dir(_quiet_config(capture_content=True)) is None
    explicit = str(tmp_path / "chosen")
    assert resolve_spool_dir(_quiet_config(capture_content=True, spool_dir=explicit)) == explicit


def test_spool_off_is_explicit():
    assert resolve_spool_dir(_quiet_config(spool_dir="off")) is None
    assert resolve_spool_dir(_quiet_config(spool_dir="OFF")) is None


def test_default_spool_catches_a_failed_batch(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    transport = EventTransport(_quiet_config(timeout_seconds=0.2, max_send_retries=0, retry_backoff_seconds=0))
    transport.send_batch([{"type": "model.call", "trace_id": "t1"}])
    assert transport.stats.spooled == 1
    assert transport.stats.dropped == 0
    assert len(list(pathlib.Path(transport.spool_dir).glob("*.json"))) == 1


# draining is safe across workers that share a spool


def test_drain_claims_a_batch_before_sending_and_releases_it_on_failure(tmp_path):
    spool = tmp_path / "spool"
    transport = _spooling_transport(tmp_path)
    transport.send_batch([{"type": "model.call", "trace_id": "t1"}])
    (batch,) = list(spool.glob("*.json"))

    seen = []

    def failing_post(payload):
        seen.append(sorted(p.name for p in spool.iterdir()))
        raise OSError("still down")

    transport._post_once = failing_post
    transport.flush()
    # while the send was in flight the file carried the claim suffix
    assert seen == [[batch.name + ".sending"]]
    # and it is back in the queue afterwards
    assert sorted(p.name for p in spool.iterdir()) == [batch.name]


def test_drain_skips_a_batch_another_worker_claimed(tmp_path):
    spool = tmp_path / "spool"
    transport = _spooling_transport(tmp_path)
    transport.send_batch([{"type": "model.call", "trace_id": "t1"}])
    (batch,) = list(spool.glob("*.json"))
    batch.rename(batch.with_name(batch.name + ".sending"))

    transport._post_once = lambda payload: (_ for _ in ()).throw(AssertionError("must not send a claimed batch"))
    transport.flush()
    assert sorted(p.name for p in spool.iterdir()) == [batch.name + ".sending"]


def test_stale_claim_from_a_dead_worker_is_reclaimed(tmp_path):
    spool = tmp_path / "spool"
    transport = _spooling_transport(tmp_path)
    transport.send_batch([{"type": "model.call", "trace_id": "t1"}])
    (batch,) = list(spool.glob("*.json"))
    claimed = batch.with_name(batch.name + ".sending")
    batch.rename(claimed)
    old = time.time() - 3600
    os.utime(claimed, (old, old))

    sent = []
    transport._post_once = lambda payload: sent.append(payload)
    transport.flush()
    assert len(sent) == 1
    assert list(spool.iterdir()) == []


def test_permanently_rejected_spooled_batch_is_dropped_not_stuck(tmp_path):
    spool = tmp_path / "spool"
    transport = _spooling_transport(tmp_path)
    transport.send_batch([{"type": "model.call", "trace_id": "poison"}])
    transport.send_batch([{"type": "model.call", "trace_id": "good"}])
    assert len(list(spool.glob("*.json"))) == 2

    sent = []

    def post(payload):
        if b"poison" in payload:
            raise HTTPError("http://x", 400, "bad", None, None)
        sent.append(payload)

    transport._post_once = post
    transport.flush()
    assert transport.stats.dropped == 1
    assert len(sent) == 1
    assert list(spool.iterdir()) == []
