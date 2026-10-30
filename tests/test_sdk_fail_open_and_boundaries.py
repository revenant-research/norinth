"""the sdk's two guarantees, checked where they used to fail

observe-only and fail-open: nothing the sdk does on the host's call path may
raise into the host, however odd the arguments or responses. content boundary:
caller content never leaves the process in the clear unless capture is on, and
the ingestion key never goes anywhere but the configured endpoint
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from norinth_logger.client import NorinthClient
from norinth_logger.config import NorinthConfig

# a port nothing listens on: a refused connection fails at once, no backoff
UNREACHABLE = "http://127.0.0.1:9"


def _client(**overrides) -> tuple[NorinthClient, list[dict]]:
    settings = {
        "api_key": "k-test", "endpoint": UNREACHABLE, "async_transport": False, "max_send_retries": 0,
        "timeout_seconds": 0.5, "spool_dir": "off", **overrides,
    }
    config = NorinthConfig(**settings)
    client = NorinthClient(config)
    events: list[dict] = []
    client.transport.send_batch = lambda batch, **kwargs: events.extend(batch)  # type: ignore[method-assign]
    return client, events


class _Unhashable:
    """an argument that refuses inspection, like a lazy orm object"""

    def model_dump(self):
        raise RuntimeError("not loaded")


class _Unprintable:
    """a value that cannot even be rendered as text"""

    def __str__(self):
        raise RuntimeError("not loaded")

    __repr__ = __str__


class _ArrayLike:
    """truth is ambiguous, like a numpy array or a pandas frame"""

    def __bool__(self):
        raise ValueError("The truth value of an array is ambiguous")

    def __len__(self):
        return 3


# --- fail-open on the host's call path ------------------------------------------


def test_trace_runs_the_host_function_when_an_argument_refuses_inspection():
    client, events = _client()

    @client.trace
    def host(record):
        return "ran"

    assert host(_Unhashable()) == "ran"
    (trace,) = [e for e in events if e["type"] == "trace.completed"]
    assert trace["status"] == "success"


def test_trace_raises_sdk_errors_only_when_fail_open_is_off():
    client, _ = _client(fail_open=False)

    @client.trace
    def host(record):
        return "ran"

    with pytest.raises(RuntimeError, match="not loaded"):
        host(_Unhashable())


def test_wrapped_client_returns_the_response_when_an_input_has_no_truth_value():
    from norinth_logger.wrappers import wrap_client

    class _Embeddings:
        def create(self, **kwargs):
            return {"data": [0.1, 0.2], "model": "text-embedding-3-small"}

    class _Provider:
        def __init__(self):
            self.embeddings = _Embeddings()

    client, events = _client()
    wrapped = wrap_client(_Provider(), client)
    response = wrapped.embeddings.create(input=_ArrayLike(), model="text-embedding-3-small")
    assert response["data"] == [0.1, 0.2]
    (call,) = [e for e in events if e["type"] == "model.call"]
    assert call["attributes"]["operation"].endswith("embeddings.create")


def test_patched_provider_method_never_raises_from_its_finally_block():
    from norinth_logger.autoinstrument import _PATCHED, patch_provider_method

    class _Owner:
        def create(self, **kwargs):
            return _ArrayLike()  # a response whose attributes misbehave

    client, events = _client()
    _PATCHED.discard("test.owner.create")
    patch_provider_method(
        patch_key="test.owner.create", owner=_Owner, method_name="create", provider="test",
        operation="create", prompt_getter=lambda args, kwargs: _ArrayLike(), client=client,
    )
    assert isinstance(_Owner().create(model="m"), _ArrayLike)


def test_an_emitter_given_an_unsummarizable_value_does_not_raise():
    client, events = _client()
    client.model_call(provider="p", model="m", operation="chat", prompt=_Unprintable(), response=None)
    assert [e["type"] for e in events if e["type"] == "model.call"] == []  # the event is lost, the host is not
    # with fail_open off the same call surfaces the error
    strict, _ = _client(fail_open=False)
    with pytest.raises(RuntimeError, match="not loaded"):
        strict.model_call(provider="p", model="m", operation="chat", prompt=_Unprintable(), response=None)


# --- async trace ------------------------------------------------------------------


def test_trace_awaits_an_async_function_inside_the_span():
    client, events = _client()
    order: list[str] = []

    @client.trace
    async def host():
        await asyncio.sleep(0.02)
        order.append("body")
        client.model_call(provider="p", model="m", operation="chat", prompt="hi", response="yo")
        return "done"

    assert asyncio.run(host()) == "done"
    (trace,) = [e for e in events if e["type"] == "trace.completed"]
    (call,) = [e for e in events if e["type"] == "model.call"]
    assert trace["status"] == "success"
    assert trace["duration_ms"] >= 15
    assert call["trace_id"] == trace["trace_id"]  # the nested call joined the span


def test_trace_records_an_async_failure_as_an_error():
    client, events = _client()

    @client.trace
    async def host():
        raise KeyError("boom")

    with pytest.raises(KeyError):
        asyncio.run(host())
    (trace,) = [e for e in events if e["type"] == "trace.completed"]
    assert trace["status"] == "error"
    assert trace["attributes"]["error"]["type"] == "KeyError"


# --- content boundary ---------------------------------------------------------------


def test_fastapi_middleware_sends_inferred_context_through_the_content_boundary():
    pytest.importorskip("starlette")
    from norinth_logger.autoinstrument import NorinthFastAPIMiddleware
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    async def handler(request):
        return JSONResponse({"ok": True})

    client, events = _client()
    app = Starlette(routes=[Route("/claims", handler, methods=["POST"])])
    app.add_middleware(NorinthFastAPIMiddleware, client=client, system="api")
    body = {"user_id": "jane.doe@hospital.org", "use_case": "SSN 123-45-6789 flagged", "customer_id": "MRN-00012345"}
    assert TestClient(app).post("/claims", json=body).status_code == 200

    (trace,) = [e for e in events if e["type"] == "trace.completed"]
    wire = json.dumps(trace)
    assert "jane.doe@hospital.org" not in wire
    assert "123-45-6789" not in wire
    assert trace["attributes"]["metadata"]["workflow_name"] == "claims"


def test_health_event_does_not_carry_endpoint_credentials():
    client, events = _client(endpoint="http://user:secret@127.0.0.1:9")
    client.emit_sdk_health("checked")
    (health,) = [e for e in events if e["type"] == "sdk.health"]
    assert "secret" not in json.dumps(health)
    assert health["attributes"]["endpoint"] == "http://127.0.0.1:9"


def test_a_client_on_the_default_api_key_warns_that_fingerprints_are_guessable(caplog):
    with caplog.at_level(logging.WARNING, logger="norinth_logger"):
        _client(api_key="dev")
    assert any("reversed by guessing" in record.message for record in caplog.records)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="norinth_logger"):
        _client(api_key="dev", signing_secret="pinned-secret")
    assert not any("reversed by guessing" in record.message for record in caplog.records)


# --- transport ------------------------------------------------------------------------


class _Collector(BaseHTTPRequestHandler):
    seen: list[dict] = []

    def do_POST(self):
        self.seen.append({"path": self.path, "auth": self.headers.get("Authorization")})
        self.send_response(200)
        self.end_headers()

    do_GET = do_POST

    def log_message(self, *args):
        pass


def _serve(handler) -> tuple[HTTPServer, str]:
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


def test_transport_does_not_follow_a_redirect_with_the_key_attached():
    from norinth_logger.transport import EventTransport

    _Collector.seen = []
    collector, collector_url = _serve(_Collector)

    class _Redirector(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", f"{collector_url}/v1/events/batch")
            self.end_headers()

        def log_message(self, *args):
            pass

    redirector, redirector_url = _serve(_Redirector)
    try:
        transport = EventTransport(NorinthConfig(
            api_key="nrk_SECRET", endpoint=redirector_url, async_transport=False, max_send_retries=0, spool_dir="off",
        ))
        transport.send_batch([{"type": "sdk.health"}])
        assert _Collector.seen == []  # nothing, with or without the key, reached the redirect target
        assert transport.stats.sent == 0 and transport.stats.dropped == 1
    finally:
        redirector.shutdown()
        collector.shutdown()


def test_cli_does_not_follow_a_redirect_with_the_key_attached():
    from norinth_logger.cli import _http

    _Collector.seen = []
    collector, collector_url = _serve(_Collector)

    class _Redirector(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"{collector_url}/v1/gates/check")
            self.end_headers()

        def log_message(self, *args):
            pass

    redirector, redirector_url = _serve(_Redirector)
    try:
        status, _ = _http("GET", f"{redirector_url}/v1/gates/check", key="nrk_SECRET")
        assert status == 302
        assert _Collector.seen == []
    finally:
        redirector.shutdown()
        collector.shutdown()


def test_shutdown_makes_one_attempt_per_batch_and_does_not_sleep_through_retries():
    from norinth_logger.transport import EventTransport

    transport = EventTransport(NorinthConfig(
        api_key="k", endpoint=UNREACHABLE, async_transport=True, max_send_retries=3,
        retry_backoff_seconds=0.5, flush_interval_seconds=60, timeout_seconds=0.5, spool_dir="off",
    ))
    transport.enqueue({"type": "sdk.health"})
    started = time.monotonic()
    transport.shutdown()
    assert time.monotonic() - started < 1.0  # the configured schedule would be 3.5 s of sleeping
    assert transport.stats.failed_sends == 1 and transport.stats.retried == 0
    assert transport.stats.dropped == 1


# --- auto-instrumentation streaming ---------------------------------------------------


def test_patched_provider_method_records_a_stream_without_hashing_it():
    from norinth_logger.autoinstrument import _PATCHED, patch_provider_method

    class _Stream:
        def __iter__(self):
            return iter([])

    class _Owner:
        def create(self, **kwargs):
            return _Stream()

    client, events = _client()
    _PATCHED.discard("test.stream.create")
    patch_provider_method(
        patch_key="test.stream.create", owner=_Owner, method_name="create", provider="test",
        operation="chat.completions.create", prompt_getter=lambda args, kwargs: kwargs.get("messages"), client=client,
    )
    _Owner().create(model="m", messages=[], stream=True)
    (call,) = [e for e in events if e["type"] == "model.call"]
    assert call["attributes"]["response"].get("is_none") is True  # the stream object was never hashed
    assert call["attributes"]["usage"] == {}
    assert call["attributes"]["metadata"]["streaming"] == "True"


# --- cli --------------------------------------------------------------------------------


def test_gate_check_tolerates_an_approved_response_without_a_gate_id(monkeypatch, capsys):
    import argparse

    from norinth_logger import cli

    monkeypatch.setenv("NORINTH_ENDPOINT", "http://norinth.test")
    monkeypatch.setenv("NORINTH_API_KEY", "k")
    monkeypatch.setattr(cli, "_http", lambda *a, **k: (200, {"approved": True, "decided_by": "gov@acme.test"}))
    args = argparse.Namespace(deployment="dep", version="v1", wait=0, poll=1, current=False, endpoint=None, api_key=None, project=None, environment=None, service=None)
    assert cli.cmd_gate_check(args) == 0
    assert "approved by gov@acme.test" in capsys.readouterr().out


def test_an_api_key_on_argv_is_called_out(monkeypatch, capsys):
    import argparse

    from norinth_logger import cli

    cli._settings(argparse.Namespace(endpoint=None, api_key="nrk_x", project=None, environment=None, service=None))
    assert "visible to other processes" in capsys.readouterr().err
