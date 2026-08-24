# Norinth Logger SDK

**Open client (Apache-2.0)** for the Norinth AI governance system.

This package is the part of Norinth that runs inside *your* infrastructure. It
captures AI telemetry, hashes inputs and outputs by default (and redacts common
secrets and identifiers from any content you opt into capturing), optionally
signs the payload, and transmits it over the documented Norinth wire protocol. It
contains no dashboard, no database, and no governance logic — it is a thin,
auditable client. The server that receives this telemetry (the Norinth
Platform, also Apache-2.0) is a separate program that shares only the wire protocol.

Because this SDK runs next to your prompts and responses, it is open by design:
you can read exactly what is captured, how content is hashed and redacted, and
what leaves your network.

## Install

```bash
pip install norinth-logger
```

## Quick start

`api_key` is an **ingestion key** you create inside your own Norinth instance
(setup wizard, or Identity & Integrations → ingestion keys); it authenticates the
SDK to your platform and scopes events to your tenant. `endpoint` is your
instance's URL. There is no external service or account.

```python
import norinth_logger as norinth

norinth.init(
    api_key="your-ingestion-key",   # from your Norinth instance (prefixed nrk_)
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

## Command line: `norinth`

```bash
norinth init                    # asks for endpoint + key, writes NORINTH_* to .env (mode 600), detects AI clients
norinth doctor                  # reachability, key validity, sends a test event — says exactly what is wrong if not
norinth gate check --deployment dep-1 --version v12 [--wait 600]   # CI: exit 0 only if the release gate is approved
norinth attest keygen           # Ed25519 key pair for signing eval results
norinth attest sign --key-id nak_… < eval.json > signed.json
norinth scan [DIR]              # static inventory of AI providers/models in a codebase
```

`gate check` exit codes: `0` approved, `1` pending or rejected (blockers printed), `2` no gate for that deployment/version, `3` configuration or auth error. Put it after your deploy step:

```yaml
- run: pip install norinth-logger
- run: norinth gate check --deployment "$DEPLOYMENT_ID" --version "$GIT_SHA" --wait 900
  env: { NORINTH_ENDPOINT: https://norinth.internal, NORINTH_API_KEY: ${{ secrets.NORINTH_API_KEY }} }
```

## CLI: static AI inventory scanner

```bash
norinth path/to/your/codebase
```

Scans a codebase for AI provider/model usage and writes a CycloneDX-style
`ai-manifest.json`. Runs entirely locally; no server required.

## Signed eval evidence (CI attestation)

A passing eval is only trustworthy as release evidence if it came from your
CI pipeline rather than from anyone holding an ingestion key. The SDK can sign
`eval.result` events with an Ed25519 key whose public half is registered on the
platform (Identity & Integrations → Evidence attestation). Once a key is
registered, the platform verifies every signed result at ingestion and release
gates only count **attested** passing evals.

```bash
pip install "norinth-logger[attest]"
python -m norinth_logger.attest keygen   # private key → CI secret store; public key → platform
```

```python
import os
from norinth_logger.attest import sign_eval_result

event = {
    "type": "eval.result", "schema_version": "2026-01",
    "trace_id": run_id, "span_id": f"{run_id}-safety", "timestamp": now_iso(),
    "service": "claims-ci", "environment": "prod", "project": "claims",
    "status": "success",
    "attributes": {
        "eval_id": "safety-suite", "passed": True, "score": 0.97,
        "prompt_version": "p12", "artifact_ref": "sha256:...",
        "metadata": {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "triage"},
    },
}
sign_eval_result(event, private_key_pem=os.environ["NORINTH_ATTEST_KEY"], key_id=os.environ["NORINTH_ATTEST_KEY_ID"])
client.record(event)   # attributes.attestation = {key_id, signature}
```

What is signed: tenant, application, workflow, eval id, pass/fail, score,
prompt version, artifact, trace id, span id and timestamp — so a signature
cannot be replayed onto another organization, application, run, or flipped
from fail to pass. A present-but-invalid attestation rejects the batch and is
written to the organization's audit log. Clients cannot set `attested`
themselves; the platform strips it and sets it only after verification.

## Safety defaults

- **Observe-only by default.** The SDK records structured metadata and hashes
  of inputs and outputs, not raw content. The hash is SHA-256; set
  `NORINTH_SIGNING_SECRET` to make it a keyed HMAC so short prompts and codes
  cannot be recovered by a dictionary attack on the digest.
- **Fail-open with durability.** If the platform is unreachable or transport
  fails, your code keeps running. Transient failures are retried with backoff;
  set `NORINTH_SPOOL_DIR` to persist un-delivered batches to disk and redeliver
  them on recovery instead of dropping evidence.
- **Content capture is opt-in.** Set `NORINTH_CAPTURE_CONTENT=true` only in a
  controlled environment where raw prompt/response capture is intended. Even
  then, only JSON-native content is captured (never a repr of a client or config
  object), and emails, national ID numbers, card numbers and API-key-shaped
  tokens are masked before the content leaves the process.
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
