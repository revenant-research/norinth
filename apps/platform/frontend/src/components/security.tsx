// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { useEffect, useState } from "react";
import { MfaStatus, mfaDisable, mfaEnable, mfaSetup, mfaStatus } from "../api";

// account security dialog: totp enrollment and disable. the secret and the
// recovery codes are shown exactly once; only hashes ever reach storage
export function SecurityDialog({ onClose }: { onClose: () => void }) {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // enrollment state
  const [pending, setPending] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [enrollCode, setEnrollCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  // disable state
  const [disabling, setDisabling] = useState(false);
  const [password, setPassword] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);

  async function refresh() {
    try {
      setStatus(await mfaStatus());
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not load security settings.");
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Action failed.");
    } finally {
      setBusy(false);
    }
  }

  const beginEnrollment = () =>
    run(async () => {
      setPending(await mfaSetup());
    });

  const confirmEnrollment = () =>
    run(async () => {
      const result = await mfaEnable(enrollCode);
      setRecoveryCodes(result.recovery_codes);
      setPending(null);
      setEnrollCode("");
      await refresh();
    });

  const confirmDisable = () =>
    run(async () => {
      await mfaDisable(password, disableCode, useRecovery);
      setDisabling(false);
      setPassword("");
      setDisableCode("");
      await refresh();
    });

  return (
    <div className="confirm-overlay" role="presentation" onClick={onClose}>
      <div
        className="confirm-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="Account security"
        onClick={(event) => event.stopPropagation()}
      >
        <h2 className="confirm-title">Account security</h2>
        {!status ? <p className="confirm-body">Loading…</p> : null}

        {status && recoveryCodes ? (
          <div>
            <p className="confirm-body">
              <strong>Save these recovery codes now.</strong> Each works once, and they are shown only this
              once. They are the only way back into this account if the authenticator is lost.
            </p>
            <pre className="mfa-recovery-codes">{recoveryCodes.join("\n")}</pre>
            <div className="confirm-actions">
              <button onClick={() => setRecoveryCodes(null)}>I saved them</button>
            </div>
          </div>
        ) : null}

        {status && !recoveryCodes && pending ? (
          <div>
            <p className="confirm-body">
              Add this secret to an authenticator app (scan or manual entry), then confirm with a code.
            </p>
            <p className="confirm-body">
              Secret: <code>{pending.secret}</code>
            </p>
            <p className="confirm-body mfa-uri">
              <code>{pending.otpauth_uri}</code>
            </p>
            <label>
              Code from the app
              <input
                value={enrollCode}
                inputMode="numeric"
                autoComplete="one-time-code"
                onChange={(event) => setEnrollCode(event.target.value)}
              />
            </label>
            {error ? <div className="auth-error" role="alert">{error}</div> : null}
            <div className="confirm-actions">
              <button className="secondary" disabled={busy} onClick={() => setPending(null)}>
                Cancel
              </button>
              <button disabled={busy || enrollCode.length < 6} onClick={confirmEnrollment}>
                Turn on MFA
              </button>
            </div>
          </div>
        ) : null}

        {status && !recoveryCodes && !pending && disabling ? (
          <div>
            <p className="confirm-body">Turning off the second factor requires both factors.</p>
            <label>
              Password
              <input type="password" value={password} autoComplete="current-password" onChange={(event) => setPassword(event.target.value)} />
            </label>
            <label>
              {useRecovery ? "Recovery code" : "Code from the app"}
              <input value={disableCode} autoComplete="one-time-code" onChange={(event) => setDisableCode(event.target.value)} />
            </label>
            <button type="button" className="link-button" onClick={() => setUseRecovery((value) => !value)}>
              {useRecovery ? "Use the authenticator instead" : "Use a recovery code instead"}
            </button>
            {error ? <div className="auth-error" role="alert">{error}</div> : null}
            <div className="confirm-actions">
              <button className="secondary" disabled={busy} onClick={() => setDisabling(false)}>
                Cancel
              </button>
              <button className="danger" disabled={busy || !password || !disableCode} onClick={confirmDisable}>
                Turn off MFA
              </button>
            </div>
          </div>
        ) : null}

        {status && !recoveryCodes && !pending && !disabling ? (
          <div>
            {status.enabled ? (
              <p className="confirm-body">
                Multi-factor authentication is <strong>on</strong> (since {status.enabled_at?.slice(0, 10)}).{" "}
                {status.recovery_codes_remaining} recovery code(s) remaining.
              </p>
            ) : (
              <p className="confirm-body">
                Multi-factor authentication is <strong>off</strong>. With MFA on, a password alone — including a
                password reset by an operator — cannot open this account.
              </p>
            )}
            {error ? <div className="auth-error" role="alert">{error}</div> : null}
            <div className="confirm-actions">
              <button className="secondary" onClick={onClose}>Close</button>
              {status.enabled ? (
                <button className="danger" disabled={busy} onClick={() => setDisabling(true)}>
                  Turn off MFA
                </button>
              ) : (
                <button disabled={busy} onClick={beginEnrollment}>
                  Turn on MFA
                </button>
              )}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
