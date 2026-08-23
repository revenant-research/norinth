"""The FastAPI middleware does not livelock the host on a streaming response
(critical C8), and it records the response status instead of always 'success'.
Driven through Starlette's real ASGI machinery.
"""

from __future__ import annotations

import asyncio
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"))


class _RecordingClient:
    def __init__(self) -> None:
        self.events: list = []

        class _Cfg:
            service = "svc"
            environment = "test"
            project = "p"
            capture_content = False
            signing_secret = None

        self.config = _Cfg()

    def record(self, event) -> None:
        self.events.append(event)


def _app_with_middleware():
    pytest.importorskip("starlette")
    from norinth_logger.autoinstrument import NorinthFastAPIMiddleware
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse, StreamingResponse
    from starlette.routing import Route

    async def stream(request):
        async def gen():
            for i in range(3):
                yield f"chunk-{i}\n".encode()

        return StreamingResponse(gen(), media_type="text/plain")

    async def boom(request):
        return JSONResponse({"detail": "nope"}, status_code=500)

    async def ok(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/stream", stream), Route("/boom", boom), Route("/ok", ok)])
    client = _RecordingClient()
    app.add_middleware(NorinthFastAPIMiddleware, client=client, system="fastapi")
    return app, client


def test_streaming_response_completes_and_does_not_block(anyio_backend="asyncio"):
    from httpx import ASGITransport, AsyncClient

    async def run():
        app, client = _app_with_middleware()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://t") as http:
            # A streaming response must complete, not hang.
            resp = await asyncio.wait_for(http.get("/stream"), timeout=5)
            assert resp.status_code == 200
            assert resp.text == "chunk-0\nchunk-1\nchunk-2\n"
            # A concurrent request is served (no CPU-spinning livelock holding the loop).
            a, b = await asyncio.wait_for(asyncio.gather(http.get("/stream"), http.get("/ok")), timeout=5)
            assert a.status_code == 200 and b.json() == {"ok": True}
            # 5xx is recorded as an error with the status, not as success.
            r = await asyncio.wait_for(http.get("/boom"), timeout=5)
            assert r.status_code == 500
        statuses = [(e.name, e.status, e.attributes.get("http_status")) for e in client.events if e.type == "trace.completed"]
        assert statuses, "no trace recorded"
        boom = [s for s in statuses if s[2] == 500]
        assert boom and boom[0][1] == "error"
        ok = [s for s in statuses if s[2] == 200]
        assert ok and all(s[1] == "success" for s in ok)

    asyncio.run(run())
