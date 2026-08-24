import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../api";
import * as confirmModule from "./confirm";
import { AttestationKeySettings, IngestionKeySettings, SecretReveal, SsoSettings } from "./identity";

describe("SecretReveal", () => {
  it("shows the secret once and copies it", async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    const onDismiss = vi.fn();
    render(<SecretReveal label="Ingestion key" value="nrk_secret123" onDismiss={onDismiss} />);
    expect(screen.getByText("nrk_secret123")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Copy" }));
    expect(writeText).toHaveBeenCalledWith("nrk_secret123");
    await user.click(screen.getByRole("button", { name: "I've stored it" }));
    expect(onDismiss).toHaveBeenCalled();
  });
});

describe("SsoSettings", () => {
  beforeEach(() => {
    vi.spyOn(api, "getJson").mockResolvedValue({ sso: null } as any);
  });

  it("submits the provider configuration and shows the redirect URI", async () => {
    const user = userEvent.setup();
    const put = vi.spyOn(api, "putJson").mockResolvedValue({ sso: {} } as any);
    render(<SsoSettings tenantId="acme" />);
    await waitFor(() => expect(screen.getByText("not configured")).toBeInTheDocument());

    await user.type(screen.getByLabelText("Issuer URL"), "https://idp.example.test");
    await user.type(screen.getByLabelText("Client ID"), "client-1");
    await user.type(screen.getByLabelText("Client secret"), "s3cret");
    await user.type(screen.getByLabelText(/Restrict to email domain/), "acme.test");
    await user.click(screen.getByRole("button", { name: "Enable SSO" }));

    await waitFor(() => expect(put).toHaveBeenCalled());
    const [path, body] = put.mock.calls[0];
    expect(path).toBe("/api/org/sso");
    expect(body).toMatchObject({ issuer: "https://idp.example.test", client_id: "client-1", client_secret: "s3cret", allowed_email_domain: "acme.test" });
    // redirect uri the admin registers with the idp is displayed
    expect(screen.getByText(/\/api\/auth\/sso\/callback/)).toBeInTheDocument();
    expect(screen.getByText(/\/api\/auth\/sso\/acme\/start/)).toBeInTheDocument();
  });
});

describe("IngestionKeySettings", () => {
  it("creates a key, reveals it once, and can revoke", async () => {
    const user = userEvent.setup();
    let keys: any[] = [];
    vi.spyOn(api, "getJson").mockImplementation(async () => ({ ingestion_keys: keys }) as any);
    const post = vi.spyOn(api, "postJson").mockImplementation(async (path: string) => {
      if (path === "/api/ingestion-keys") {
        keys = [{ key_id: "nrk_abcd1234", name: "prod", status: "active", created_at: "2026-08-23" }];
        return { token: "nrk_abcd1234FULLSECRET", ingestion_key: keys[0] } as any;
      }
      if (path.endsWith("/revoke")) {
        keys = [{ ...keys[0], status: "revoked" }];
        return {} as any;
      }
      throw new Error(path);
    });
    vi.spyOn(confirmModule, "confirm").mockResolvedValue(true);

    render(<IngestionKeySettings />);
    await waitFor(() => expect(screen.getByText("None yet.")).toBeInTheDocument());

    await user.type(screen.getByLabelText("Name"), "prod");
    await user.click(screen.getByRole("button", { name: "Create" }));

    // full secret revealed once; the list shows only the id prefix
    await waitFor(() => expect(screen.getByTestId("secret-reveal")).toBeInTheDocument());
    expect(screen.getByText("nrk_abcd1234FULLSECRET")).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByTestId("token-row")).toHaveLength(1));

    await user.click(screen.getByRole("button", { name: "I've stored it" }));
    expect(screen.queryByText("nrk_abcd1234FULLSECRET")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/ingestion-keys/nrk_abcd1234/revoke", {}));
    await waitFor(() => expect(screen.getByText("revoked")).toBeInTheDocument());
  });
});

describe("SamlSettings", () => {
  it("submits the IdP configuration and shows SP metadata + ACS URL", async () => {
    const { SamlSettings } = await import("./identity");
    const user = userEvent.setup();
    vi.spyOn(api, "getJson").mockResolvedValue({
      saml: null,
      sp_entity_id: "http://localhost/api/auth/saml/metadata",
      acs_url: "http://localhost/api/auth/saml/acs",
      login_url: "http://localhost/api/auth/saml/acme/start",
    } as any);
    const put = vi.spyOn(api, "putJson").mockResolvedValue({ saml: {} } as any);
    render(<SamlSettings />);
    await waitFor(() => expect(screen.getByText(/\/api\/auth\/saml\/acs/)).toBeInTheDocument());

    await user.type(screen.getByLabelText("IdP entity ID"), "https://idp.example.test/saml");
    await user.type(screen.getByLabelText("IdP SSO URL"), "https://idp.example.test/sso");
    await user.type(screen.getByLabelText(/IdP signing certificate/), "-----BEGIN CERTIFICATE-----abc-----END CERTIFICATE-----");
    await user.click(screen.getByRole("button", { name: "Enable SAML" }));

    await waitFor(() => expect(put).toHaveBeenCalled());
    const [path, body] = put.mock.calls[0];
    expect(path).toBe("/api/org/saml");
    expect(body).toMatchObject({ idp_entity_id: "https://idp.example.test/saml", idp_sso_url: "https://idp.example.test/sso" });
    expect((body as any).idp_certificate).toContain("BEGIN CERTIFICATE");
  });
});

describe("AttestationKeySettings", () => {
  it("explains enforcement state, registers a public key, and can revoke it", async () => {
    const user = userEvent.setup();
    let keys: any[] = [];
    vi.spyOn(api, "getJson").mockImplementation(
      async () => ({ attestation_keys: keys, attestation_required: keys.some((k) => k.status === "active") }) as any,
    );
    const post = vi.spyOn(api, "postJson").mockImplementation(async (path: string, body: any) => {
      if (path === "/api/attestation-keys") {
        expect(body.public_key_pem).toContain("BEGIN PUBLIC KEY");
        keys = [
          {
            key_id: "nak_abc123",
            name: body.name,
            status: "active",
            fingerprint: "sha256:deadbeef",
            created_at: "2026-08-23",
            last_used_at: null,
          },
        ];
        return { attestation_key: keys[0] } as any;
      }
      if (path.endsWith("/revoke")) {
        keys = [{ ...keys[0], status: "revoked", revoked_at: "2026-08-24" }];
        return {} as any;
      }
      throw new Error(path);
    });
    vi.spyOn(confirmModule, "confirm").mockResolvedValue(true);

    render(<AttestationKeySettings />);
    await waitFor(() => expect(screen.getByText("No attestation keys registered.")).toBeInTheDocument());
    expect(screen.getByRole("status")).toHaveTextContent("No key registered yet");

    await user.type(screen.getByLabelText("Name"), "GitHub Actions");
    await user.type(screen.getByLabelText("Public key (PEM)"), "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----");
    await user.click(screen.getByRole("button", { name: "Register key" }));

    await waitFor(() => expect(screen.getAllByTestId("attestation-key-row")).toHaveLength(1));
    expect(screen.getByText("sha256:deadbeef")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Attestation is enforced");

    await user.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/attestation-keys/nak_abc123/revoke", {}));
    await waitFor(() => expect(screen.getByText("revoked")).toBeInTheDocument());
    expect(screen.getByRole("status")).toHaveTextContent("No key registered yet");
  });
});
