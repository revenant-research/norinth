import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as api from "../api";
import { SetupWizard } from "./setup";

const superAdmin = { user_ref: "admin@norinth.local", display_name: "Admin", email: "admin@norinth.local", tenant_id: null, platform_role: "super_admin", must_change_password: false, permissions: [], is_super_admin: true };
const orgAdmin = { ...superAdmin, user_ref: "dana@example.org", email: "dana@example.org", tenant_id: "example-health", platform_role: null, is_super_admin: false, permissions: ["user.manage"] };

afterEach(() => vi.restoreAllMocks());

describe("SetupWizard", () => {
  it("walks from organization creation to the first event and hands off to Getting started", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const post = vi.spyOn(api, "postJson").mockImplementation(async (path: string) => {
      if (path === "/api/setup/organization") return { organization: { tenant_id: "example-health" }, org_admin_email: "dana@example.org" } as any;
      if (path === "/api/ingestion-keys") return { token: "nrk_FULLSECRET", ingestion_key: { key_id: "nrk_abc" } } as any;
      throw new Error(path);
    });
    vi.spyOn(api, "logout").mockResolvedValue();
    vi.spyOn(api, "login").mockResolvedValue({ user: orgAdmin } as any);
    let eventsSeen = false;
    vi.spyOn(api, "getJson").mockImplementation(async (path: string) => {
      if (path === "/api/onboarding") return { steps: [{ id: "send_events", done: eventsSeen }] } as any;
      if (path === "/api/applications") return { applications: [{ application_name: "Claims Copilot" }] } as any;
      throw new Error(path);
    });
    const onFinished = vi.fn();

    render(<SetupWizard initialUser={superAdmin as any} onFinished={onFinished} />);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Create your organization");

    await user.type(screen.getByLabelText("Organization name"), "Example Health");
    await user.type(screen.getByLabelText("Your name"), "Dana");
    await user.type(screen.getByLabelText("Your work email"), "dana@example.org");
    await user.type(screen.getByLabelText("Your password"), "a-long-password-123");
    await user.click(screen.getByRole("button", { name: "Create organization" }));

    await waitFor(() => expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Create an ingestion key"));
    expect(post).toHaveBeenCalledWith("/api/setup/organization", expect.objectContaining({ name: "Example Health", admin_email: "dana@example.org" }));
    expect(api.login).toHaveBeenCalledWith("dana@example.org", "a-long-password-123");

    await user.click(screen.getByRole("button", { name: "Create ingestion key" }));
    await waitFor(() => expect(screen.getByText("nrk_FULLSECRET")).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: "I've stored it" }));

    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Instrument one application");
    expect(screen.getByRole("status")).toHaveTextContent("Waiting for the first event");

    // first event arrives; the poll notices and advances
    eventsSeen = true;
    await vi.advanceTimersByTimeAsync(3500);
    await waitFor(() => expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("You are set up"));
    expect(screen.getByText("Claims Copilot")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Open Getting started" }));
    expect(onFinished).toHaveBeenCalledWith(orgAdmin);
    vi.useRealTimers();
  });

  it("starts at sign-in when nobody is signed in and rejects a non-administrator account", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "login").mockResolvedValue({ user: orgAdmin } as any);
    render(<SetupWizard initialUser={null} onFinished={vi.fn()} />);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Sign in as the platform administrator");
    await user.type(screen.getByLabelText("Administrator email"), "dana@example.org");
    await user.type(screen.getByLabelText("Password"), "whatever-long-enough");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("platform administrator account"));
  });
});
