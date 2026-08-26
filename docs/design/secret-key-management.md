# RFC: Secret key management and rotation

**Status:** Accepted. Phases 1–2 (the encryption keyring and the audit-HMAC
keyring) are implemented; phases 4–5 (the rewrap tool and the optional KMS mode)
remain. The decisions are recorded at the end.

## Problem

A single environment variable, `NORINTH_SECRET_KEY`, is used for two unrelated
cryptographic jobs:

- **Secret encryption at rest** — `services/secrets.py` base64-decodes it to a
  32-byte AES-256-GCM key. It encrypts SSO OIDC client secrets (AAD =
  `tenant_id`), webhook signing secrets (AAD = `webhook:<tenant>:<id>`), and,
  when `NORINTH_ENCRYPT_RAW_EVENTS=1`, raw SDK events (AAD = `sdk_event`). Stored
  form: `enc:v1:<b64 nonce>:<b64 ciphertext+tag>`.
- **Audit-chain anchoring** — `storage/audit.py` uses the same variable's raw
  UTF-8 bytes as the HMAC-SHA256 key for each row's `row_hmac`, so a DB-write
  attacker can't forge a valid chain without the key.

Two consequences:

1. **There is no rotation path.** The `v1` in `enc:v1:` is a *format* tag, not a
   key id. Changing `NORINTH_SECRET_KEY` makes every stored ciphertext
   undecryptable (no rewrap) *and* makes every historical `row_hmac` fail
   verification — `verify_audit_chain` would report tamper across the whole
   history even though nothing was tampered.
2. **The two roles are coupled.** You cannot rotate the encryption key without
   also breaking audit verification, and vice versa. They have different rotation
   cadences and different blast radii, so they should be independent.

Enterprise/medical buyers routinely require key rotation (often annually, and
on-demand after suspected exposure), so this will come up in vetting.

## Goals

- Rotate the **encryption** key without downtime and without losing access to
  previously encrypted data.
- Rotate the **audit HMAC** key without invalidating verification of rows
  written under the previous key.
- Decouple the two keys.
- Keep the current zero-dependency default (a local key from the environment)
  working, while allowing an external KMS for those who want it.
- Preserve the existing fail-closed behavior (no key ⇒ no plaintext storage
  unless `NORINTH_ALLOW_PLAINTEXT_SECRETS=1`).

## Non-goals

- Per-tenant encryption keys (the AAD already binds ciphertext to its tenant;
  per-tenant keys are a larger, separate initiative).
- Rotating the *data* itself (webhook/SSO secrets) — that is the operator's or
  tenant's action; this RFC is about the key that wraps them.
- Hardware HSM integration beyond what a KMS provider already offers.

## Design

### 1. A keyring instead of a single key

Introduce a small keyring abstraction with **one primary key for new writes** and
**any number of retired keys kept only for decryption/verification**. Each key
has a short, stable **key id**.

Configuration (local-key mode, the default):

```
NORINTH_SECRET_KEYS = '{"2026a": "<b64 32 bytes>", "2025a": "<b64 32 bytes>"}'
NORINTH_SECRET_PRIMARY = "2026a"
```

- `NORINTH_SECRET_PRIMARY` names the key used to encrypt new values.
- Every id in `NORINTH_SECRET_KEYS` can decrypt.
- Backwards compatibility: if only the legacy `NORINTH_SECRET_KEY` is set, treat
  it as a keyring with a single key whose id is `legacy`, primary = `legacy`.
  Existing deployments keep working with no config change.

### 2. Encryption format carries the key id

Change the stored format from `enc:v1:<nonce>:<ct>` to:

```
enc:v2:<key_id>:<b64 nonce>:<b64 ciphertext+tag>
```

- `encrypt()` writes `v2` with `NORINTH_SECRET_PRIMARY`.
- `decrypt()` reads the key id from the value, looks it up in the keyring, and
  decrypts. `enc:v1:` values continue to decrypt under the `legacy` key
  (unprefixed legacy plaintext still passes through unchanged, as today).
- AAD handling is unchanged, so tenant binding is preserved.

### 3. Separate the audit HMAC key from the encryption key

Give the audit chain its own keyring, independent of the encryption keyring:

```
NORINTH_AUDIT_HMAC_KEYS = '{"2026a": "<secret>", "2025a": "<secret>"}'
NORINTH_AUDIT_HMAC_PRIMARY = "2026a"
```

Add a `hmac_key_id` column alongside the existing `row_hmac` (mirroring how
`hash_version` was added for the versioned hash). On write, stamp the primary
key id. On `verify_audit_chain`, verify each row's `row_hmac` under the key named
by its `hmac_key_id` (falling back to the `legacy` key for rows written before
this change). Rotating the primary key then leaves all historical rows verifiable
under their original key, and new rows anchor to the new key.

Backwards compatibility: if only `NORINTH_SECRET_KEY` is set, it becomes the
`legacy` audit key, primary = `legacy` — identical behavior to today.

### 4. Optional external KMS (envelope encryption)

Behind the same keyring interface, allow a provider mode:

```
NORINTH_KMS_PROVIDER = "aws" | "gcp" | "vault" | "none"   # default none
```

In provider mode, data keys are wrapped by the KMS: `encrypt()` requests (or
caches) a data key, uses it for AES-GCM, and stores the KMS-wrapped data key
alongside the ciphertext. Rotation becomes a KMS concern; the on-disk format
records the wrapping key id. This is strictly opt-in and does not change the
default local-key path. (KMS calls are network I/O — must be gated by the same
`net_guard` egress rules and must fail closed.)

### 5. A rewrap tool for retiring a key

Add an offline/admin operation that walks every encrypted column
(`sso_configurations.client_secret`, webhook secrets, optionally `sdk_events`)
and re-encrypts any value not already under the primary key. After a rewrap
completes and the audit chain has aged past retention for old rows (or a full
re-anchor is run), a retired key can be dropped from the keyring. This makes
rotation *finishable*, not just additive.

## Migration / rollout (phased, each phase shippable)

1. **Keyring + format v2, legacy-compatible.** Add the keyring, write `v2` with
   a `legacy` primary derived from `NORINTH_SECRET_KEY`. No operator action
   required; behavior identical. Ships the read/write path for key ids.
2. **Audit `hmac_key_id`.** Migration adds the column; writers stamp it; verify
   uses it with a `legacy` fallback. No operator action required.
3. **Multi-key config.** Document `NORINTH_SECRET_KEYS` / `_PRIMARY` and the
   audit equivalents. An operator can now add a new primary and keep the old key
   for decryption/verification — this is the first point at which real rotation
   is possible.
4. **Rewrap tool.** Ship the admin rewrap so a retired encryption key can
   eventually be removed.
5. **KMS provider (optional).** Land last, behind `NORINTH_KMS_PROVIDER`.

Phases 1–3 deliver rotation with only local keys; 4–5 are follow-ups.

## Decisions (made)

1. **Local keyring is the default; KMS is opt-in.** The self-hosted OSS default
   must work with zero external dependencies. KMS (phase 5) is a later opt-in for
   deployments that want it, behind the same keyring interface.
2. **Config is JSON env vars** (`NORINTH_SECRET_KEYS` + `NORINTH_SECRET_PRIMARY`,
   and the audit equivalents) — same shape as today's single variable, and mounts
   cleanly from a k8s secret. No new key directory or keys table.
3. **No audit re-anchoring.** Old rows stay verifiable under their original key
   via `hmac_key_id`; new rows use the new key. A tamper-evident log should be
   additive, never rewritten — recomputing historical HMACs is exactly what an
   auditor does not want to see.
4. **Rewrap covers the config secrets only** (SSO client secret, webhook secret).
   `sdk_events` are left to age out under retention rather than rewrapping a
   potentially large table.

## Implementation status

- **Phase 1 (encryption keyring)** — done. `services/secrets.py` resolves a
  keyring, writes `enc:v2:<key_id>:…`, and decrypts `enc:v1` by trying each key.
- **Phase 2 (audit HMAC keyring)** — done. `storage/audit.py` has an independent
  audit keyring; migration 17 adds `hmac_key_id`; each row verifies under its own
  key.
- **Phase 3 (multi-key config)** — usable now: set `NORINTH_SECRET_KEYS` /
  `NORINTH_SECRET_PRIMARY` (and the audit equivalents) to rotate.
- **Phase 4 (rewrap tool)** — not yet built.
- **Phase 5 (KMS provider)** — not yet built.

## Notes on effort

Phases 1–2 are contained (a keyring module, a format bump with back-compat, one
migration, and touching the three call sites). Phase 3 is mostly documentation
plus config plumbing. Phase 4 (rewrap) and phase 5 (KMS) are the larger pieces
and can be scheduled independently once 1–3 land.
