import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as api from "../api";
import { WebhookSettings } from "./webhooks";

afterEach(() => vi.restoreAllMocks());

describe("WebhookSettings", () => {
  it("explains email state, adds a signed webhook (secret shown once) and lists deliveries", async () => {
    const user = userEvent.setup();
    let hooks: any[] = [];
    vi.spyOn(api, "getJson").mockImplementation(async (path: string) => {
      if (path === "/api/org/webhooks") return { webhooks: hooks, events: ["gate.approved", "gate.rejected", "incident.opened", "test"], smtp_configured: false } as any;
      if (path === "/api/org/notifications") return { notifications: [{ id: 1, channel: "email", event_type: "user.invited", target: "rev@acme.test", subject: "Invite", status: "skipped_no_smtp", attempts: 0, last_error: null, created_at: "2026-08-23", sent_at: null }], smtp_configured: false } as any;
      throw new Error(path);
    });
    vi.spyOn(api, "postJson").mockImplementation(async (path: string, body: any) => {
      if (path === "/api/org/webhooks") {
        expect(body.events).toContain("gate.approved");
        hooks = [{ webhook_id: "whk_1", name: body.name, url: body.url, events: body.events, format: body.format, status: "active", created_at: "2026-08-23" }];
        return { webhook: hooks[0], secret: "whs_SECRET_ONCE" } as any;
      }
      throw new Error(path);
    });

    render(<WebhookSettings />);
    await waitFor(() => expect(screen.getByText("Email is not configured.")).toBeInTheDocument());
    expect(screen.getByText("skipped_no_smtp")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Name"), "Splunk");
    await user.type(screen.getByLabelText("URL"), "https://siem.example/hook");
    await user.click(screen.getByRole("button", { name: "Add webhook" }));
    await waitFor(() => expect(screen.getByText("whs_SECRET_ONCE")).toBeInTheDocument());
    await waitFor(() => expect(screen.getAllByTestId("webhook-row")).toHaveLength(1));
    await user.click(screen.getByRole("button", { name: "I've stored it" }));
    expect(screen.queryByText("whs_SECRET_ONCE")).not.toBeInTheDocument();
  });
});
