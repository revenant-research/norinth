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
};

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
      // FastAPI validation errors arrive as a list of {msg, loc} objects.
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

export async function fetchMe(): Promise<User> {
  const data = await getJson<{ user: User }>("/api/auth/me");
  return data.user;
}

export async function login(email: string, password: string): Promise<User> {
  const data = await postJson<{ user: User }>("/api/auth/login", { email, password });
  return data.user;
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
  const pairs = await Promise.all(
    Object.entries(endpoints).map(async ([key, endpoint]) => {
      const raw = await getJson<Record<string, any>>(endpoint, scope);
      const responseKey = responseKeys[key as keyof typeof endpoints];
      return [key, responseKey ? raw[responseKey] : raw] as const;
    }),
  );
  return Object.fromEntries(pairs) as DashboardData;
}
