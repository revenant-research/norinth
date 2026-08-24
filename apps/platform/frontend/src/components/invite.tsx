import { useEffect, useState } from "react";

import { type User, getJson, postJson } from "../api";
import { Button, Callout, Card, Container, Eyebrow, Heading, Lede, Stack, Text, TextField } from "../design";
import styles from "./setup.module.css";

/** invite acceptance: invitee sets their own password and is signed in */
export function InviteScreen({ token, onAccepted }: { token: string; onAccepted: (user: User) => void }) {
  const [preview, setPreview] = useState<{ email: string; display_name: string | null; organization: string } | null>(null);
  const [error, setError] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getJson<{ email: string; display_name: string | null; organization: string }>(`/api/auth/invite/${encodeURIComponent(token)}`)
      .then(setPreview)
      .catch((caught) => setError(caught instanceof Error ? caught.message : "This invite link is not valid."));
  }, [token]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (password.length < 12) return setError("Use at least 12 characters.");
    if (password !== confirmPw) return setError("Passwords do not match.");
    setBusy(true);
    setError("");
    try {
      const result = await postJson<{ user: User }>("/api/auth/accept-invite", { token, password });
      onAccepted(result.user);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not accept the invite.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={styles.page}>
      <Container>
        <div className={styles.frame}>
          <Stack gap={2}>
            <Eyebrow>Norinth · Invitation</Eyebrow>
            <Heading level={1} size="2xl">{preview ? `Join ${preview.organization}` : "Invitation"}</Heading>
          </Stack>
          <Card padding="lg" tone="lead">
            {error && !preview ? (
              <Callout tone="danger">{error} Ask your administrator for a new invite link.</Callout>
            ) : (
              <form onSubmit={submit} aria-label="Accept invitation">
                <Stack gap={4}>
                  <Lede>
                    {preview ? <>You were invited as <strong>{preview.email}</strong>{preview.display_name ? ` (${preview.display_name})` : ""}. Choose a password to finish.</> : "Checking your invitation…"}
                  </Lede>
                  {error ? <Callout tone="danger">{error}</Callout> : null}
                  <TextField label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={12} autoComplete="new-password" hint="At least 12 characters." />
                  <TextField label="Confirm password" type="password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} required autoComplete="new-password" />
                  <div><Button type="submit" size="lg" disabled={busy || !preview}>Set password and sign in</Button></div>
                  <Text size="sm">Your organization may also sign you in through its identity provider; this password is for direct sign-in.</Text>
                </Stack>
              </form>
            )}
          </Card>
        </div>
      </Container>
    </div>
  );
}
