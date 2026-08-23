import { useEffect, useState } from "react";

import { getJson, postJson, putJson, deleteJson } from "../api";
import { confirm } from "./confirm";
import { toast } from "./toast";
import { Badge, EmptyState, RecordList, Section } from "./ui";
import { useResource } from "./useResource";
import { WebhookSettings } from "./webhooks";

// identity & integrations: org-admin setup for sso (oidc), scim provisioning
// tokens and sdk ingestion keys. secrets are shown once in a dismissable reveal
// with copy-to-clipboard; never persisted in the ui, never re-fetchable

// --- one-time secret reveal -----------------------------------------------------

export function SecretReveal({ label, value, onDismiss }: { label: string; value: string; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    setCopied(false);
  }, [value]);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      toast.success("Copied to clipboard.");
    } catch {
      toast.error("Clipboard unavailable — select and copy the value manually.");
    }
  }
  return (
    <div className="secret-reveal" role="status" aria-live="polite" data-testid="secret-reveal">
      <p>
        <strong>{label}</strong> — shown once. Store it now; it cannot be retrieved again.
      </p>
      <code className="secret-value">{value}</code>
      <div className="secret-actions">
        <button type="button" onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </button>
        <button type="button" className="secondary" onClick={onDismiss}>
          I've stored it
        </button>
      </div>
    </div>
  );
}

// --- sso --------------------------------------------------------------------------

type SsoConfig = {
  issuer: string;
  client_id: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  default_role: string;
  allowed_email_domain: string | null;
  enabled: number | boolean;
  updated_at?: string;
} | null;

const JIT_ROLES = ["governance_reviewer", "control_owner", "risk_owner", "governance_admin"];

export function SsoSettings({ tenantId }: { tenantId: string }) {
  const { value, error, reload } = useResource(() => getJson<{ sso: SsoConfig }>("/api/org/sso"));
  const [form, setForm] = useState({ issuer: "", client_id: "", client_secret: "", default_role: "governance_reviewer", allowed_email_domain: "" });
  const [saving, setSaving] = useState(false);
  const config = value?.sso;
  const enabled = !!(config && config.enabled);

  useEffect(() => {
    if (config) {
      setForm((current) => ({
        ...current,
        issuer: config.issuer,
        client_id: config.client_id,
        default_role: config.default_role,
        allowed_email_domain: config.allowed_email_domain || "",
      }));
    }
  }, [config]);

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    try {
      await putJson("/api/org/sso", { ...form, allowed_email_domain: form.allowed_email_domain || null });
      toast.success("SSO configured. OpenID discovery succeeded.");
      setForm((current) => ({ ...current, client_secret: "" }));
      reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "SSO configuration failed.");
    } finally {
      setSaving(false);
    }
  }

  async function disable() {
    const ok = await confirm({
      title: "Disable SSO?",
      body: "Users provisioned through SSO have no password and will be unable to sign in until SSO is re-enabled.",
      confirmLabel: "Disable SSO",
      tone: "danger",
    });
    if (!ok) return;
    try {
      await deleteJson("/api/org/sso");
      toast.success("SSO disabled.");
      reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not disable SSO.");
    }
  }

  const loginUrl = `${window.location.origin}/api/auth/sso/${encodeURIComponent(tenantId)}/start`;
  const redirectUri = `${window.location.origin}/api/auth/sso/callback`;

  return (
    <Section title="Single sign-on (OpenID Connect)" description="Connect Okta, Microsoft Entra ID, Auth0, or any OpenID Connect provider. New users are provisioned just-in-time with the default role below — never an administration role.">
      {error ? <p className="feedback error" role="alert">{error}</p> : null}
      <div className="status-row">
        <Badge value={enabled ? "enabled" : "not configured"} />
        {enabled && config ? <span>Issuer {config.issuer}</span> : null}
      </div>
      <form className="admin-form" onSubmit={save} aria-label="Configure SSO">
        <label className="wide">
          Issuer URL
          <input value={form.issuer} onChange={(e) => setForm({ ...form, issuer: e.target.value })} required placeholder="https://your-tenant.okta.com" />
        </label>
        <label>
          Client ID
          <input value={form.client_id} onChange={(e) => setForm({ ...form, client_id: e.target.value })} required />
        </label>
        <label>
          Client secret
          <input type="password" value={form.client_secret} onChange={(e) => setForm({ ...form, client_secret: e.target.value })} required autoComplete="off" placeholder={enabled ? "Enter to rotate" : ""} />
        </label>
        <label>
          Default role for new users
          <select value={form.default_role} onChange={(e) => setForm({ ...form, default_role: e.target.value })}>
            {JIT_ROLES.map((role) => (
              <option key={role} value={role}>
                {role}
              </option>
            ))}
          </select>
        </label>
        <label>
          Restrict to email domain (optional)
          <input value={form.allowed_email_domain} onChange={(e) => setForm({ ...form, allowed_email_domain: e.target.value })} placeholder="company.com" />
        </label>
        <div className="wide form-actions">
          <button type="submit" disabled={saving}>
            {saving ? "Verifying with provider…" : enabled ? "Update SSO" : "Enable SSO"}
          </button>
          {enabled ? (
            <button type="button" className="secondary danger" onClick={disable}>
              Disable SSO
            </button>
          ) : null}
        </div>
      </form>
      <dl className="kv">
        <dt>Redirect URI to register with your provider</dt>
        <dd>
          <code>{redirectUri}</code>
        </dd>
        <dt>Sign-in link for your users</dt>
        <dd>
          <code>{loginUrl}</code>
        </dd>
      </dl>
    </Section>
  );
}

// --- saml -------------------------------------------------------------------------

type SamlPayload = {
  saml: { idp_entity_id: string; idp_sso_url: string; idp_certificate: string; default_role: string; allowed_email_domain: string | null; enabled: number | boolean } | null;
  sp_entity_id: string;
  acs_url: string;
  login_url: string;
};

export function SamlSettings() {
  const { value, error, reload } = useResource(() => getJson<SamlPayload>("/api/org/saml"));
  const [form, setForm] = useState({ idp_entity_id: "", idp_sso_url: "", idp_certificate: "", default_role: "governance_reviewer", allowed_email_domain: "" });
  const [saving, setSaving] = useState(false);
  const config = value?.saml;
  const enabled = !!(config && config.enabled);

  useEffect(() => {
    if (config) {
      setForm((current) => ({
        ...current,
        idp_entity_id: config.idp_entity_id,
        idp_sso_url: config.idp_sso_url,
        idp_certificate: config.idp_certificate,
        default_role: config.default_role,
        allowed_email_domain: config.allowed_email_domain || "",
      }));
    }
  }, [config]);

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    try {
      await putJson("/api/org/saml", { ...form, allowed_email_domain: form.allowed_email_domain || null });
      toast.success("SAML configured.");
      reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "SAML configuration failed.");
    } finally {
      setSaving(false);
    }
  }

  async function disable() {
    const ok = await confirm({ title: "Disable SAML SSO?", body: "Users who sign in through this identity provider will be unable to sign in until it is re-enabled.", confirmLabel: "Disable SAML", tone: "danger" });
    if (!ok) return;
    try {
      await deleteJson("/api/org/saml");
      toast.success("SAML disabled.");
      reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not disable SAML.");
    }
  }

  return (
    <Section title="Single sign-on (SAML 2.0)" description="For SAML-only identity providers (ADFS, Okta or Entra SAML apps). Import the SP metadata below into your provider, then paste its entity ID, SSO URL, and signing certificate here.">
      {error ? <p className="feedback error" role="alert">{error}</p> : null}
      <div className="status-row">
        <Badge value={enabled ? "enabled" : "not configured"} />
        {enabled && config ? <span>IdP {config.idp_entity_id}</span> : null}
      </div>
      <form className="admin-form" onSubmit={save} aria-label="Configure SAML">
        <label>
          IdP entity ID
          <input value={form.idp_entity_id} onChange={(e) => setForm({ ...form, idp_entity_id: e.target.value })} required placeholder="https://idp.company.com/saml" />
        </label>
        <label>
          IdP SSO URL
          <input value={form.idp_sso_url} onChange={(e) => setForm({ ...form, idp_sso_url: e.target.value })} required placeholder="https://idp.company.com/sso" />
        </label>
        <label className="wide">
          IdP signing certificate (PEM)
          <textarea value={form.idp_certificate} onChange={(e) => setForm({ ...form, idp_certificate: e.target.value })} required rows={6} placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"} spellCheck={false} />
        </label>
        <label>
          Default role for new users
          <select value={form.default_role} onChange={(e) => setForm({ ...form, default_role: e.target.value })}>
            {JIT_ROLES.map((role) => (
              <option key={role} value={role}>
                {role}
              </option>
            ))}
          </select>
        </label>
        <label>
          Restrict to email domain (optional)
          <input value={form.allowed_email_domain} onChange={(e) => setForm({ ...form, allowed_email_domain: e.target.value })} placeholder="company.com" />
        </label>
        <div className="wide form-actions">
          <button type="submit" disabled={saving}>
            {saving ? "Saving…" : enabled ? "Update SAML" : "Enable SAML"}
          </button>
          {enabled ? (
            <button type="button" className="secondary danger" onClick={disable}>
              Disable SAML
            </button>
          ) : null}
        </div>
      </form>
      {value ? (
        <dl className="kv">
          <dt>SP entity ID / metadata URL</dt>
          <dd>
            <code>{value.sp_entity_id}</code>
          </dd>
          <dt>Assertion Consumer Service (ACS) URL</dt>
          <dd>
            <code>{value.acs_url}</code>
          </dd>
          <dt>Sign-in link for your users</dt>
          <dd>
            <code>{value.login_url}</code>
          </dd>
        </dl>
      ) : null}
    </Section>
  );
}

// --- generic token list (scim tokens / ingestion keys) --------------------------

type TokenRecord = { status: string; name: string; created_at: string; last_used_at?: string | null } & Record<string, any>;

function TokenManager({
  title,
  description,
  listPath,
  listKey,
  createPath,
  createKey,
  idField,
  secretLabel,
  hint,
}: {
  title: string;
  description: string;
  listPath: string;
  listKey: string;
  createPath: string;
  createKey: string;
  idField: string;
  secretLabel: string;
  hint?: React.ReactNode;
}) {
  const { value, error, reload } = useResource(() => getJson<Record<string, any>>(listPath));
  const [name, setName] = useState("");
  const [secret, setSecret] = useState<string | null>(null);
  const rows: TokenRecord[] = value?.[listKey] || [];

  async function create(event: React.FormEvent) {
    event.preventDefault();
    try {
      const result = await postJson<{ token: string }>(createPath, { name });
      setSecret(result.token);
      setName("");
      reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not create.");
    }
  }

  async function revoke(row: TokenRecord) {
    const ok = await confirm({
      title: `Revoke "${row.name}"?`,
      body: "Anything using this credential will be rejected immediately. This cannot be undone.",
      confirmLabel: "Revoke",
      tone: "danger",
    });
    if (!ok) return;
    try {
      await postJson(`${createPath}/${encodeURIComponent(row[idField])}/revoke`, {});
      toast.success("Revoked.");
      reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Revoke failed.");
    }
  }

  return (
    <Section title={title} description={description}>
      {error ? <p className="feedback error" role="alert">{error}</p> : null}
      {hint}
      {secret ? <SecretReveal label={secretLabel} value={secret} onDismiss={() => setSecret(null)} /> : null}
      <form className="admin-form inline" onSubmit={create} aria-label={`Create ${secretLabel}`}>
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} required placeholder="e.g. production, okta" />
        </label>
        <button type="submit">Create</button>
      </form>
      {rows.length === 0 ? (
        <EmptyState>None yet.</EmptyState>
      ) : (
        <RecordList empty="">
          {rows.map((row) => (
            <article className="record-card" key={row[idField]} data-testid="token-row">
              <div className="record-main">
                <span className="record-title">{row.name}</span>
                <Badge value={row.status} />
                <code>{row[idField]}…</code>
              </div>
              <p>
                Created {row.created_at}
                {row.last_used_at ? ` · last used ${row.last_used_at}` : " · never used"}
                {row.created_by ? ` · by ${row.created_by}` : ""}
              </p>
              {row.status === "active" ? (
                <button type="button" className="secondary" onClick={() => revoke(row)}>
                  Revoke
                </button>
              ) : null}
            </article>
          ))}
        </RecordList>
      )}
    </Section>
  );
}

export function ScimSettings() {
  const scimUrl = `${window.location.origin}/scim/v2`;
  return (
    <TokenManager
      title="User provisioning (SCIM 2.0)"
      description="Let your identity provider create, update, and deactivate users automatically. Deactivated users lose access immediately."
      listPath="/api/org/scim-tokens"
      listKey="scim_tokens"
      createPath="/api/org/scim-tokens"
      createKey="scim_token"
      idField="token_id"
      secretLabel="SCIM bearer token"
      hint={
        <dl className="kv">
          <dt>SCIM base URL for your provider</dt>
          <dd>
            <code>{scimUrl}</code>
          </dd>
        </dl>
      }
    />
  );
}

export function IngestionKeySettings() {
  return (
    <TokenManager
      title="SDK ingestion keys"
      description="Keys your applications use to send telemetry. Each key is bound to this organization — telemetry can never be attributed to another tenant."
      listPath="/api/ingestion-keys"
      listKey="ingestion_keys"
      createPath="/api/ingestion-keys"
      createKey="ingestion_key"
      idField="key_id"
      secretLabel="Ingestion key"
      hint={
        <p className="hint">
          Set <code>NORINTH_API_KEY</code> in the application environment. OpenTelemetry pipelines send to <code>/v1/otel/traces</code> with the same key.
        </p>
      }
    />
  );
}

// --- evidence attestation keys -----------------------------------------------------

type AttestationKey = {
  key_id: string;
  name: string;
  status: string;
  fingerprint: string;
  created_at: string;
  created_by?: string | null;
  last_used_at?: string | null;
  revoked_at?: string | null;
};

// registers the ed25519 public keys ci uses to sign eval results. registering
// the first key opts the org in: gates then only count attested passing evals,
// so a self-reported `passed: true` can't satisfy a gate
export function AttestationKeySettings() {
  const { value, error, reload } = useResource(() =>
    getJson<{ attestation_keys: AttestationKey[]; attestation_required: boolean }>("/api/attestation-keys"),
  );
  const [name, setName] = useState("");
  const [pem, setPem] = useState("");
  const rows = value?.attestation_keys || [];
  const required = Boolean(value?.attestation_required);

  async function register(event: React.FormEvent) {
    event.preventDefault();
    try {
      await postJson("/api/attestation-keys", { name, public_key_pem: pem });
      toast.success("Attestation key registered. Only attested evals now satisfy release gates.");
      setName("");
      setPem("");
      reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not register key.");
    }
  }

  async function revoke(row: AttestationKey) {
    const ok = await confirm({
      title: `Revoke "${row.name}"?`,
      body: "Eval results signed with this key will be rejected at ingestion from now on. Evidence already verified keeps its attested status.",
      confirmLabel: "Revoke",
      tone: "danger",
    });
    if (!ok) return;
    try {
      await postJson(`/api/attestation-keys/${encodeURIComponent(row.key_id)}/revoke`, {});
      toast.success("Key revoked.");
      reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Revoke failed.");
    }
  }

  return (
    <Section
      title="Evidence attestation"
      description="Public keys your CI pipeline uses to sign eval results. Signed evals are verified at ingestion and marked attested; release gates then require attested evidence instead of a self-reported pass."
    >
      {error ? <p className="feedback error" role="alert">{error}</p> : null}
      <p className="hint" role="status">
        {required
          ? "Attestation is enforced: release gates in this organization only count attested passing evals."
          : "No key registered yet: any passing eval currently satisfies a release gate. Register a key to require signed evidence."}
      </p>
      <p className="hint">
        Generate a key pair with <code>python -m norinth_logger.attest keygen</code>, keep the private key in your CI secret store, and sign results with{" "}
        <code>norinth_logger.attest.sign_eval_result(...)</code> before sending them. Ed25519 only.
      </p>
      <form className="admin-form" onSubmit={register} aria-label="Register attestation key">
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} required placeholder="e.g. GitHub Actions – claims-api" />
        </label>
        <label>
          Public key (PEM)
          <textarea
            value={pem}
            onChange={(e) => setPem(e.target.value)}
            required
            rows={4}
            spellCheck={false}
            placeholder={"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}
          />
        </label>
        <button type="submit">Register key</button>
      </form>
      {rows.length === 0 ? (
        <EmptyState>No attestation keys registered.</EmptyState>
      ) : (
        <RecordList empty="" label="keys">
          {rows.map((row) => (
            <article className="record-card" key={row.key_id} data-testid="attestation-key-row">
              <div className="record-main">
                <span className="record-title">{row.name}</span>
                <Badge value={row.status} />
                <code>{row.key_id}</code>
              </div>
              <p>
                <code>{row.fingerprint}</code>
              </p>
              <p>
                Registered {row.created_at}
                {row.created_by ? ` by ${row.created_by}` : ""}
                {row.last_used_at ? ` · last verified ${row.last_used_at}` : " · no evidence verified yet"}
                {row.revoked_at ? ` · revoked ${row.revoked_at}` : ""}
              </p>
              {row.status === "active" ? (
                <button type="button" className="secondary" onClick={() => revoke(row)}>
                  Revoke
                </button>
              ) : null}
            </article>
          ))}
        </RecordList>
      )}
    </Section>
  );
}

export function IdentityView({ tenantId }: { tenantId: string }) {
  return (
    <>
      <SsoSettings tenantId={tenantId} />
      <SamlSettings />
      <ScimSettings />
      <IngestionKeySettings />
      <AttestationKeySettings />
      <WebhookSettings />
    </>
  );
}
