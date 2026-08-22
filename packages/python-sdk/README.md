# Norinth Logger SDK

**Open client (Apache-2.0)** for the Norinth AI governance system.

This package is the part of Norinth that runs inside *your* infrastructure. It
captures AI telemetry, redacts and hashes content by default, optionally signs
the payload, and transmits it over the documented Norinth wire protocol. It
contains no dashboard, no database, and no governance logic — it is a thin,
auditable client. The server that receives this telemetry (the Norinth
Platform) is a separate, commercially licensed component.

Because this SDK runs next to your prompts and responses, it is open by design:
you can read exactly what is captured, how it is redacted, and what leaves your
network.

## Install

```bash
pip install norinth-logger
```

## Quick start

```python
import norinth_logger as norinth

norinth.init(
    api_key="your-key",
    endpoint="https://platform.your-host.example",
    project="my-project",
    environment="production",
    service="my-service",
)

# Auto-instrument supported provider clients (OpenAI, Anthropic).
norinth.autoinstrument()

# Optional: capture FastAPI request context as workflow traces.
# norinth.instrument_fastapi(app, system="my-service")
```

From that point, supported provider calls emit `model.call` events
automatically. Higher-level governance events (`prompt`, `deployment`,
`incident`, `guardrail`, `eval_result`, `agent_run`, `retrieval`, `tool_call`)
can be emitted explicitly through the SDK API.

## CLI: static AI inventory scanner

```bash
norinth path/to/your/codebase
```

Scans a codebase for AI provider/model usage and writes a CycloneDX-style
`ai-manifest.json`. Runs entirely locally; no server required.

## Safety defaults

- **Observe-only by default.** The SDK records structured metadata and hashes
  of inputs and outputs, not raw content.
- **Fail-open.** If the platform is unreachable or transport fails, your code
  keeps running; events are dropped rather than raised.
- **Content capture is opt-in.** Set `NORINTH_CAPTURE_CONTENT=true` only in a
  controlled environment where raw prompt/response capture is intended.
- **Optional payload signing.** Set a signing secret to attach an
  `X-Norinth-Signature` (HMAC-SHA256) header so a receiver can verify the
  payload was not tampered with in transit.

## The wire protocol

Everything this SDK sends is the documented Norinth event format, POSTed to
`/v1/events/batch` on whatever endpoint you configure. The format is the public
contract between this open client and any receiver. See
[`PROTOCOL.md`](./PROTOCOL.md) for the full specification.

## License

Apache License 2.0. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
