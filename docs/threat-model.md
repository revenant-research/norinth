# Norinth threat model and data flow

Written for the security reviewer who has to approve running Norinth inside a
regulated network. It describes what the system is, what data moves where,
who the adversaries are, and which controls exist in code (with pointers) —
not aspirations.

## 1. System summary

One stateless web service (FastAPI + compiled React dashboard) and one
PostgreSQL database, run entirely inside your environment. There is no
hosted component, no vendor account, no telemetry to Revenant Research, no
outbound calls except to identity providers you configure (OIDC discovery /
JWKS, SAML) and Google Fonts for the dashboard's typeface.

```
 your applications ──SDK / OTel──▶  /v1/events/batch  ─┐
 your CI pipeline  ──signed evals─▶ /v1/otel/traces     │   Norinth
 your people       ──browser/SSO──▶ /  /api/*            ├──▶ (stateless) ──▶ PostgreSQL (yours)
 your IdP          ──SCIM────────▶ /scim/v2/*           │
 your auditor      ◀──audit packet── /api/compliance/* ─┘
```

## 2. Data inventory

| Data | Where it comes from | Sensitivity | Stored |
|---|---|---|---|
| Telemetry metadata: model, provider, latency, token counts, status, tool names, guardrail decisions, eval results, agent steps | SDK / OTel | Low. Operational. | `sdk_events`, derived entity tables |
| Prompt / completion **text** | SDK | **High** (may contain PHI/PII) | **Not sent by default.** The SDK sends a keyed HMAC fingerprint (`privacy.py`); raw text only if `NORINTH_CAPTURE_CONTENT=1` is set on the application side. |
| Exception messages | SDK | Medium (often contain PII) | Hashed + length by default (`summarize_error`). |
| Governance records: systems, owners, findings, decisions with rationale, exceptions, incidents | People via the dashboard | Medium (business-confidential) | PostgreSQL |
| Identity: users, emails, password hashes (salted PBKDF2-HMAC via `services/auth.py`), role assignments | Admins / SCIM / SSO | Medium | PostgreSQL |
| IdP secrets (OIDC client secret) | Org admins | High | AES-256-GCM with tenant-bound AAD (`services/secrets.py`), key from `NORINTH_SECRET_KEY` |
| Credentials issued by Norinth: ingestion keys, SCIM tokens, session tokens | Platform | High | Only SHA-256 hashes are stored; plaintext shown once |
| Attestation public keys | Org admins | Low | PostgreSQL |
| Audit log | Platform | Medium, integrity-critical | Hash-chained rows (`storage/audit.py`), `GET /api/admin/audit-logs/verify` |

## 3. Trust boundaries and principals

- **Platform administrator** (super admin): creates organizations and their first administrator; reads the platform audit trail; cannot read any organization's governance data (`require_super_admin` vs tenant scoping in `services/authorization.py`).
- **Organization administrator**: manages people, roles, identity, keys for one organization. Cannot hold a decision role (`would_violate_role_separation`), cannot approve work, cannot change their own roles.
- **Decision roles** (`governance_admin`, `risk_owner`, `control_owner`, `governance_reviewer`): act on work routed to them; cannot decide work they originated (`enforce_segregation_of_duties`).
- **Applications**: hold an ingestion key; can only write telemetry, and only into the organization the key belongs to (`_bind_events_to_tenant`). Cannot read anything.
- **CI**: holds an Ed25519 private key; its signatures make eval results *attested* (`services/attestation.py`). Cannot approve a gate.
- **Identity provider**: asserts who a user is (OIDC/SAML) and whether they still exist (SCIM). Cannot grant administration roles (JIT provisioning caps at non-admin roles).

## 4. Adversaries and what stops them

| Threat | Control |
|---|---|
| Forged evidence: anyone with network access posts `passed: true` | Per-tenant hashed ingestion keys; tenant derived from key, never from payload; once an attestation key exists, unsigned evals do not satisfy gates; signatures bind tenant/app/workflow/trace/span (no replay). |
| Self-approval / one person approving their own AI | Admin vs decision role exclusivity; maker–checker on reviews and gates; gates never auto-approve; generic decisions route cannot transition gates or incidents. |
| Cross-tenant read or write | Fail-closed scope checks; NULL tenant never matches; ingestion keys, SCIM tokens, attestation keys, SSO configs all tenant-bound. |
| Session theft / CSRF | HttpOnly, SameSite=Lax, Secure (outside dev) cookies; hashed session tokens; all sessions revoked on password change; Origin check on every mutating `/api/*` request. |
| Credential stuffing / spraying | Per-account and per-IP throttling with lockout (`storage/login_attempts.py`); `X-Forwarded-For` honoured only with `NORINTH_TRUST_PROXY=1`. |
| SSO attacks (token substitution, replay, signature wrapping) | OIDC: PKCE S256, nonce, single-use state, RS256 via the issuer's JWKS, `aud`/`iss`/`exp` checks. SAML: signature verified only against the configured certificate, signed subtree only, InResponseTo single-use, audience/recipient/time checks, hardened XML parser. |
| Stolen database dump | IdP secrets encrypted with a key that is not in the database; credential hashes only; audit chain detects row tampering. |
| Audit log tampering by a DBA | Hash chain over every row; verification endpoint; export in the audit packet. Residual: a DBA who rewrites the whole chain from genesis — mitigate by exporting packets regularly and storing them outside the database. |
| Malicious or compromised SDK | Apache-2.0, zero dependencies, ~2k lines; fail-open so it can never block the host app; content off by default. |
| Supply chain of the platform image | Built in GitHub Actions from the public repo, multi-arch, cosign keyless signature, SPDX SBOM attestation, build provenance attestation, Trivy CRITICAL gate. Verify with `cosign verify`. |
| Public contact form abuse | Validation, 10 submissions per source address per day, no email is sent. |

## 5. Residual risks and operator responsibilities

- Norinth does not encrypt PostgreSQL at rest; use your database's encryption.
- `NORINTH_SECRET_KEY` and the super-admin password are only as safe as your secret store.
- Dashboard, API and SCIM should be reachable only from your network; ingestion endpoints only from where applications run.
- The SDK runs inside your applications; review what your applications put in `metadata` (it is stored as-is).
- Notifications (email/webhooks) are not yet implemented; invites are one-time passwords delivered out of band.
- Rate limiting on ingestion is by key validity only; put the ingestion endpoints behind your normal API gateway limits.

## 6. Verification you can run

- Full test suite on SQLite and PostgreSQL: `make test`, `make test-postgres`.
- Tenant isolation, separation of duties, gate integrity, attestation, SSO/SAML/SCIM attack cases: `tests/test_tenant_isolation.py`, `test_separation_of_duties.py`, `test_deployment_gate_integrity.py`, `test_evidence_attestation.py`, `test_sso_oidc.py`, `test_saml_sso.py`, `test_scim.py`.
- Audit chain: `GET /api/admin/audit-logs/verify`.
- Image signature and SBOM: `cosign verify` / `cosign verify-attestation --type spdxjson`.
