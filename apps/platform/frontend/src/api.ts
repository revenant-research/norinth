export type Scope = {
  tenantId: string;
  project: string;
  environment: string;
};

export type User = {
  user_ref: string;
  display_name: string;
  email: string | null;
  tenant_id: string | null;
  platform_role: string | null;
  must_change_password: boolean;
  // org policy: this account must enroll a second factor before the
  // workspace opens (sso/scim accounts are exempt server-side)
  mfa_enrollment_required?: boolean;
  permissions: string[];
  is_super_admin: boolean;
};

export type DashboardData = {
  summary: Record<string, any>;
  applications: Array<Record<string, any>>;
  workflows: Array<Record<string, any>>;
  models: Array<Record<string, any>>;
  agents: Array<Record<string, any>>;
  retrievals: Array<Record<string, any>>;
  tools: Array<Record<string, any>>;
  guardrails: Array<Record<string, any>>;
  evals: Array<Record<string, any>>;
  risks: Array<Record<string, any>>;
  controls: Array<Record<string, any>>;
  reviewTasks: Array<Record<string, any>>;
  promptTemplates: Array<Record<string, any>>;
  deployments: Array<Record<string, any>>;
  deploymentGates: Array<Record<string, any>>;
  incidents: Array<Record<string, any>>;
  owners: Array<Record<string, any>>;
  decisions: Array<Record<string, any>>;
  exceptions: Array<Record<string, any>>;
  traces: Array<Record<string, any>>;
  modelCalls: Array<Record<string, any>>;
  intake: Array<Record<string, any>>;
  /** server-side totals per list (from `page.total`) so metrics count the whole
   *  tenant, not just the first page in memory */
  totals: Partial<Record<ListKey, number>>;
  /** endpoints that failed on the last load; the rest of the dashboard still
   *  renders so one failing endpoint doesn't blank every view */
  partialErrors: Array<{ key: string; message: string }>;
};

export type ListKey = Exclude<keyof DashboardData, "summary" | "totals" | "partialErrors">;

export type PageMeta = { offset: number; limit: number; total: number; has_more: boolean };

export function totalOf(data: Pick<DashboardData, "totals">, key: ListKey, fallback: unknown[]): number {
  const total = data.totals?.[key];
  return typeof total === "number" ? total : fallback.length;
}

export type DetailKind = "application" | "workflow" | "review" | "gate" | "incident" | "trace";

const detailEndpoints: Record<DetailKind, string> = {
  application: "/api/applications",
  workflow: "/api/workflows",
  review: "/api/reviews",
  gate: "/api/deployment-gates",
  incident: "/api/incidents",
  trace: "/api/traces",
};

const endpoints = {
  summary: "/api/summary",
  applications: "/api/applications",
  workflows: "/api/workflows",
  models: "/api/models",
  agents: "/api/agents",
  retrievals: "/api/retrievals",
  tools: "/api/tools",
  guardrails: "/api/guardrails",
  evals: "/api/evals",
  risks: "/api/risk-register",
  controls: "/api/control-evidence",
  reviewTasks: "/api/review-tasks",
  promptTemplates: "/api/prompt-templates",
  deployments: "/api/deployments",
  deploymentGates: "/api/deployment-gates",
  incidents: "/api/incidents",
  owners: "/api/owner-assignments",
  decisions: "/api/decisions",
  exceptions: "/api/exceptions",
  traces: "/api/traces",
  modelCalls: "/api/model-calls",
  intake: "/api/intake",
} as const;

const responseKeys: Record<keyof typeof endpoints, string> = {
  summary: "",
  applications: "applications",
  workflows: "workflows",
  models: "models",
  agents: "agents",
  retrievals: "retrievals",
  tools: "tools",
  guardrails: "guardrails",
  evals: "evals",
  risks: "risks",
  controls: "controls",
  reviewTasks: "review_tasks",
  promptTemplates: "prompt_templates",
  deployments: "deployments",
  deploymentGates: "deployment_gates",
  incidents: "incidents",
  owners: "owners",
  decisions: "decisions",
  exceptions: "exceptions",
  traces: "traces",
  modelCalls: "model_calls",
  intake: "intake",
};

function scopedUrl(path: string, scope: Scope): string {
  const params = new URLSearchParams();
  if (scope.tenantId) params.set("tenant_id", scope.tenantId);
  if (scope.project) params.set("project", scope.project);
  if (scope.environment) params.set("environment", scope.environment);
  const query = params.toString();
  if (!query) return path;
  return `${path}${path.includes("?") ? "&" : "?"}${query}`;
}

const jsonHeaders: HeadersInit = { "Content-Type": "application/json" };

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function parseError(response: Response): Promise<ApiError> {
  let detail = `Request failed: ${response.status}`;
  try {
    const body = await response.json();
    if (body && typeof body.detail === "string") {
      detail = body.detail;
    } else if (body && Array.isArray(body.detail)) {
      // fastapi validation errors arrive as a list of {msg, loc} objects
      const messages = body.detail
        .map((item: { msg?: string }) => item?.msg)
        .filter((msg: unknown): msg is string => typeof msg === "string");
      if (messages.length) detail = messages.join(". ");
    }
  } catch {
    const text = await response.text().catch(() => "");
    if (text) detail = text;
  }
  return new ApiError(response.status, detail);
}

export async function getJson<T>(path: string, scope?: Scope): Promise<T> {
  const url = scope ? scopedUrl(path, scope) : path;
  const response = await fetch(url, { headers: jsonHeaders, credentials: "include" });
  if (!response.ok) throw await parseError(response);
  return response.json() as Promise<T>;
}

export async function postJson<T>(path: string, payload: unknown): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: jsonHeaders,
    credentials: "include",
    body: JSON.stringify(payload ?? {}),
  });
  if (!response.ok) throw await parseError(response);
  return response.json() as Promise<T>;
}

export async function putJson<T>(path: string, payload: unknown): Promise<T> {
  const response = await fetch(path, {
    method: "PUT",
    headers: jsonHeaders,
    credentials: "include",
    body: JSON.stringify(payload ?? {}),
  });
  if (!response.ok) throw await parseError(response);
  return response.json() as Promise<T>;
}

export async function deleteJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { method: "DELETE", headers: jsonHeaders, credentials: "include" });
  if (!response.ok) throw await parseError(response);
  return response.json() as Promise<T>;
}

export async function fetchMe(): Promise<User> {
  const data = await getJson<{ user: User }>("/api/auth/me");
  return data.user;
}

// an mfa-enrolled account gets a short-lived challenge instead of a session;
// the code step redeems it
export type LoginResult = { user: User; mfa_required?: undefined } | { mfa_required: true; challenge: string };

export async function login(email: string, password: string): Promise<LoginResult> {
  return await postJson<LoginResult>("/api/auth/login", { email, password });
}

export async function mfaVerify(challenge: string, code: string, useRecovery: boolean): Promise<User> {
  const payload = useRecovery ? { challenge, recovery_code: code } : { challenge, code };
  const data = await postJson<{ user: User }>("/api/auth/mfa/verify", payload);
  return data.user;
}

export type MfaStatus = { enabled: boolean; enabled_at: string | null; recovery_codes_remaining: number };

export async function mfaStatus(): Promise<MfaStatus> {
  return await getJson<MfaStatus>("/api/auth/mfa");
}

export async function mfaSetup(): Promise<{ secret: string; otpauth_uri: string }> {
  return await postJson<{ secret: string; otpauth_uri: string }>("/api/auth/mfa/setup", {});
}

export async function mfaEnable(code: string): Promise<{ recovery_codes: string[] }> {
  return await postJson<{ recovery_codes: string[] }>("/api/auth/mfa/enable", { code });
}

export async function mfaDisable(password: string, code: string, useRecovery: boolean): Promise<void> {
  const payload = useRecovery ? { password, recovery_code: code } : { password, code };
  await postJson("/api/auth/mfa/disable", payload);
}

export async function logout(): Promise<void> {
  await postJson("/api/auth/logout", {});
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  await postJson("/api/auth/change-password", { current_password: currentPassword, new_password: newPassword });
}

export async function loadDetail(kind: DetailKind, id: string, scope: Scope): Promise<Record<string, any>> {
  return getJson<Record<string, any>>(`${detailEndpoints[kind]}/${encodeURIComponent(id)}`, scope);
}

export async function loadGraphNeighborhood(nodeId: string, scope: Scope): Promise<Record<string, any>> {
  const params = new URLSearchParams({ node_id: nodeId });
  return getJson<Record<string, any>>(`/api/resource-graph/neighborhood?${params.toString()}`, scope);
}

export async function loadDashboardData(scope: Scope): Promise<DashboardData> {
  const totals: DashboardData["totals"] = {};
  const partialErrors: DashboardData["partialErrors"] = [];
  const settled = await Promise.allSettled(
    Object.entries(endpoints).map(async ([key, endpoint]) => {
      const raw = await getJson<Record<string, any>>(endpoint, scope);
      const responseKey = responseKeys[key as keyof typeof endpoints];
      const page = raw?.page as PageMeta | undefined;
      if (page && typeof page.total === "number") totals[key as ListKey] = page.total;
      return [key, responseKey ? raw[responseKey] ?? [] : raw] as const;
    }),
  );
  const keys = Object.keys(endpoints) as Array<keyof typeof endpoints>;
  const entries: Array<readonly [string, unknown]> = settled.map((result, index) => {
    const key = keys[index];
    if (result.status === "fulfilled") return result.value;
    const reason = result.reason;
    // session loss isn't partial: rethrow so the shell can sign out
    if (reason instanceof ApiError && reason.status === 401) throw reason;
    partialErrors.push({ key, message: reason instanceof Error ? reason.message : String(reason) });
    return [key, responseKeys[key] ? [] : {}] as const;
  });
  return { ...(Object.fromEntries(entries) as Omit<DashboardData, "totals" | "partialErrors">), totals, partialErrors };
}
