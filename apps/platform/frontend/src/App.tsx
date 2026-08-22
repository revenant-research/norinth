import { useEffect, useMemo, useState } from "react";

import {
  ApiError,
  type DashboardData,
  type DetailKind,
  type Scope,
  type User,
  changePassword,
  fetchMe,
  loadDashboardData,
  loadDetail,
  loadGraphNeighborhood,
  login,
  logout,
  postJson,
} from "./api";
import {
  AdminConsole,
  AuditLog,
  IntakeView,
  MyQueue,
  OrgOverview,
  PlatformOverview,
  PlatformUsers,
  RbacMatrixEditor,
  TeamConsole,
} from "./components/admin";
import { Badge, Chip, EmptyState, MetricCard, RecordList, Section, SkeletonCards, SkeletonMetrics, formatList } from "./components/ui";
import { ToastHost, toast } from "./components/toast";
import { ConfirmHost, confirm } from "./components/confirm";

type RouteDef = { id: string; label: string; description: string; permission?: string };

const baseRoutes: RouteDef[] = [
  { id: "overview", label: "Overview", description: "Posture, accountability staffing, and segregation of duties.", permission: "user.manage" },
  { id: "portfolio", label: "My Work", description: "Reviews, release gates, and incidents that need attention." },
  { id: "myqueue", label: "My Queue", description: "Review tasks routed directly to you for sign-off." },
  { id: "intake", label: "Intake", description: "Register new AI use cases and review their risk tier.", permission: "intake.submit" },
  { id: "inventory", label: "Inventory", description: "Applications, workflows, providers, prompts, and releases in your organization." },
  { id: "reviews", label: "Review Work", description: "Open review tasks, owner follow-up, decisions, and active exceptions." },
  { id: "risk", label: "Risk", description: "Open findings, accepted exceptions, and records that need a risk owner." },
  { id: "controls", label: "Controls", description: "Control checks, missing records, and trace links for auditors and control owners." },
  { id: "deployments", label: "Deployments", description: "Release records, approval gates, blockers, and reviewer decisions." },
  { id: "monitoring", label: "Monitoring", description: "Request traces, model calls, tool use, guardrails, and evaluation records." },
  { id: "incidents", label: "Incidents", description: "Open incidents, linked records, owners, and closure decisions." },
  { id: "team", label: "People & Access", description: "Create users, set their status, reset passwords, and assign governance roles in your organization.", permission: "user.manage" },
  { id: "audit", label: "Audit Log", description: "Immutable record of administrative, identity, and decision actions." },
];

type Mutate = (path: string, payload: unknown, success: string) => Promise<void>;

function currentHash(): string[] {
  // An empty array lets each surface choose its own role-appropriate landing
  // route rather than forcing everyone onto the same default.
  return (window.location.hash || "").slice(1).split("/").filter(Boolean);
}

function visibleRoutes(user: User): RouteDef[] {
  return baseRoutes.filter((route) => {
    if (route.id === "audit") return user.permissions.includes("user.manage");
    if (route.permission) return user.permissions.includes(route.permission);
    return true;
  });
}

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [bootstrapped, setBootstrapped] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchMe()
      .then((value) => {
        if (!cancelled) setUser(value);
      })
      .catch(() => {
        if (!cancelled) setUser(null);
      })
      .finally(() => {
        if (!cancelled) setBootstrapped(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function content() {
    if (!bootstrapped) return <div className="boot">Loading workspace</div>;
    if (!user) return <PublicEntry onAuthenticated={setUser} />;
    if (user.must_change_password) return <ChangePasswordScreen user={user} onChanged={setUser} />;
    if (user.is_super_admin) return <PlatformConsole user={user} onSignOut={() => setUser(null)} />;
    return <Workspace user={user} onSignOut={() => setUser(null)} />;
  }

  return (
    <>
      {content()}
      <ToastHost />
      <ConfirmHost />
    </>
  );
}

// The platform plane. A super admin provisions organizations and their first
// administrator, reviews the platform-wide audit trail, and never touches any
// tenant's governance data.
const PLATFORM_ROUTES: RouteDef[] = [
  { id: "overview", label: "Overview", description: "Platform health: tenants, accounts, telemetry volume, and recent activity across every organization." },
  { id: "organizations", label: "Organizations", description: "Provision tenants and their first administrator, and suspend or reactivate them." },
  { id: "platform-users", label: "Accounts", description: "Every account on the platform. Suspend access or issue one-time passwords." },
  { id: "rbac", label: "Roles", description: "The platform-global role and permission matrix that governs what each role can do in every tenant." },
  { id: "audit", label: "Audit Log", description: "Append-only record of provisioning, identity, and governance actions across every tenant." },
];

function PlatformConsole({ user, onSignOut }: { user: User; onSignOut: () => void }) {
  const [route, setRoute] = useState<string[]>(currentHash);

  useEffect(() => {
    const onHashChange = () => setRoute(currentHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const active = PLATFORM_ROUTES.some((item) => item.id === route[0]) ? route[0] : "overview";
  const routeMeta = PLATFORM_ROUTES.find((item) => item.id === active) || PLATFORM_ROUTES[0];

  async function signOut() {
    await logout().catch(() => undefined);
    onSignOut();
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">Norinth</div>
        <p>Platform administration.</p>
        <nav>
          {PLATFORM_ROUTES.map((item) => (
            <a className={active === item.id ? "active" : ""} href={`#${item.id}`} key={item.id}>
              {item.label}
            </a>
          ))}
        </nav>
      </aside>
      <main className="main">
        <header className="topbar">
          <div>
            <h1>{routeMeta.label}</h1>
            <p>{routeMeta.description}</p>
          </div>
          <div className="session-summary">
            <div className="actor-summary">
              <strong>{user.display_name}</strong>
              <span>Platform super admin</span>
            </div>
            <button className="secondary" onClick={signOut}>Sign out</button>
          </div>
        </header>
        <div className="page">
          {active === "overview" ? <PlatformOverview /> : null}
          {active === "organizations" ? <AdminConsole /> : null}
          {active === "platform-users" ? <PlatformUsers /> : null}
          {active === "rbac" ? <RbacMatrixEditor /> : null}
          {active === "audit" ? <AuditLog superAdmin /> : null}
        </div>
      </main>
    </div>
  );
}

type EntryMode = "landing" | "client" | "admin";

function PublicEntry({ onAuthenticated }: { onAuthenticated: (user: User) => void }) {
  const [mode, setMode] = useState<EntryMode>("landing");

  if (mode === "client") {
    return (
      <LoginScreen
        title="Client sign in"
        subtitle="Sign in with the email your organization administrator gave you. Your role and access are set automatically once you are in."
        onAuthenticated={onAuthenticated}
        onBack={() => setMode("landing")}
      />
    );
  }
  if (mode === "admin") {
    return (
      <LoginScreen
        title="Platform administrator"
        subtitle="Sign in to provision organizations, create administrators, and oversee every tenant on the platform."
        onAuthenticated={onAuthenticated}
        onBack={() => setMode("landing")}
      />
    );
  }
  return <LandingPage onClientSignIn={() => setMode("client")} onAdminSignIn={() => setMode("admin")} />;
}

const LANDING_FEATURES: Array<{ title: string; body: string }> = [
  {
    title: "Register and tier every use case",
    body: "Intake captures the purpose, data sensitivity, and level of autonomy for each AI system, then assigns a risk tier the moment it is submitted.",
  },
  {
    title: "Route reviews to accountable owners",
    body: "Every review lands with the right role, carries a due date and escalation clock, and produces a signed decision record that stands up in an audit.",
  },
  {
    title: "Prove control coverage with live evidence",
    body: "Controls map to NIST AI RMF, ISO 42001, and SOC 2, and each assessment links straight back to the runtime telemetry that backs it.",
  },
  {
    title: "Keep duties separate and the trail clean",
    body: "Approvals keep the submitter and the reviewer apart, and the audit log records who changed identities, roles, and decisions across the platform.",
  },
];

function LandingPage({ onClientSignIn, onAdminSignIn }: { onClientSignIn: () => void; onAdminSignIn: () => void }) {
  return (
    <div className="landing">
      <header className="landing-nav">
        <div className="brand">Norinth</div>
        <button onClick={onClientSignIn}>Client sign in</button>
      </header>

      <section className="landing-hero">
        <span className="eyebrow">AI governance platform</span>
        <h1>Govern every AI system your company runs.</h1>
        <p>
          Norinth gives risk, compliance, security, and engineering teams one place to register AI use cases, route
          reviews to the people who own them, and prove control coverage with evidence pulled straight from production.
        </p>
        <div className="landing-actions">
          <button onClick={onClientSignIn}>Client sign in</button>
          <a className="landing-link" href="#features">See what runs inside</a>
        </div>
      </section>

      <section className="landing-features" id="features">
        {LANDING_FEATURES.map((feature) => (
          <article className="landing-feature" key={feature.title}>
            <h2>{feature.title}</h2>
            <p>{feature.body}</p>
          </article>
        ))}
      </section>

      <section className="landing-band">
        <h2>One workflow from intake to retirement.</h2>
        <p>
          Submit a use case, tier its risk, route it for review, gate the release, and recertify it on a schedule. Risk
          owners, control owners, reviewers, and release managers each see the work that belongs to them and nothing else.
        </p>
      </section>

      <footer className="landing-footer">
        <div>
          <div className="brand">Norinth</div>
          <p>AI governance for teams that answer to regulators, customers, and their own boards.</p>
        </div>
        <div className="landing-footer-links">
          <button className="secondary" onClick={onClientSignIn}>Client sign in</button>
          <button className="link-button" onClick={onAdminSignIn}>Platform administrator access</button>
        </div>
      </footer>
    </div>
  );
}

function LoginScreen({
  title,
  subtitle,
  onAuthenticated,
  onBack,
}: {
  title: string;
  subtitle: string;
  onAuthenticated: (user: User) => void;
  onBack?: () => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      onAuthenticated(await login(email, password));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Sign in failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-screen">
      <form className="auth-card" onSubmit={submit}>
        <div className="brand">Norinth</div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
        <label>
          Email
          <input type="email" value={email} autoComplete="username" onChange={(event) => setEmail(event.target.value)} required />
        </label>
        <label>
          Password
          <input type="password" value={password} autoComplete="current-password" onChange={(event) => setPassword(event.target.value)} required />
        </label>
        {error ? <div className="auth-error">{error}</div> : null}
        <button type="submit" disabled={busy}>{busy ? "Signing in" : "Sign in"}</button>
        {onBack ? (
          <button type="button" className="link-button" onClick={onBack}>Back to home</button>
        ) : null}
      </form>
    </div>
  );
}

function ChangePasswordScreen({ user, onChanged }: { user: User; onChanged: (user: User) => void }) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (newPassword.length < 8) {
      setError("New password must be at least 8 characters.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await changePassword(currentPassword, newPassword);
      onChanged({ ...user, must_change_password: false });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not change password.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-screen">
      <form className="auth-card" onSubmit={submit}>
        <div className="brand">Norinth</div>
        <h1>Set a new password</h1>
        <p>Your account requires a password change before continuing.</p>
        <label>
          Current password
          <input type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} required />
        </label>
        <label>
          New password
          <input type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required />
          <span className="field-hint">At least 8 characters.</span>
        </label>
        {error ? <div className="auth-error">{error}</div> : null}
        <button type="submit" disabled={busy}>{busy ? "Saving" : "Update password"}</button>
      </form>
    </div>
  );
}

function Workspace({ user, onSignOut }: { user: User; onSignOut: () => void }) {
  const [route, setRoute] = useState<string[]>(currentHash);
  const [data, setData] = useState<DashboardData | null>(null);
  const [message, setMessage] = useState<string>("");
  const [isLoading, setIsLoading] = useState(false);

  const routes = useMemo(() => visibleRoutes(user), [user]);
  // Org admins land on the organization overview; everyone else lands on their
  // daily work queue.
  const defaultRoute = user.permissions.includes("user.manage") ? "overview" : "portfolio";
  const active = route[0] || defaultRoute;
  const routeMeta = routes.find((item) => item.id === active) || baseRoutes.find((item) => item.id === active) || baseRoutes[0];

  // Tenant actors are pinned server-side to their own organization; the scope
  // here is informational and never widens access.
  const scope: Scope = useMemo(
    () => ({ tenantId: user.tenant_id || "", project: "", environment: "" }),
    [user],
  );

  useEffect(() => {
    const onHashChange = () => setRoute(currentHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  async function refresh() {
    setIsLoading(true);
    setMessage("");
    try {
      setData(await loadDashboardData(scope));
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        await logout().catch(() => undefined);
        onSignOut();
        return;
      }
      setMessage(error instanceof Error ? error.message : "Unable to load records.");
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, [scope]);

  async function mutate(path: string, payload: unknown, success: string) {
    try {
      await postJson(path, payload);
      toast.success(success);
      await refresh();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Action failed.");
    }
  }

  async function signOut() {
    await logout().catch(() => undefined);
    onSignOut();
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">Norinth</div>
        <p>Governance workspace for your organization.</p>
        <nav>
          {routes.map((item) => (
            <a className={active === item.id ? "active" : ""} href={`#${item.id}`} key={item.id}>
              {item.label}
            </a>
          ))}
        </nav>
      </aside>
      <main className="main">
        <header className="topbar">
          <div>
            <h1>{routeMeta.label}</h1>
            <p>{routeMeta.description}</p>
          </div>
          <div className="session-summary">
            <div className="actor-summary">
              <strong>{user.display_name}</strong>
              <span>{roleLabel(user)} / {user.tenant_id || "No organization"}</span>
            </div>
            <button className="secondary" onClick={refresh}>Refresh</button>
            <button className="secondary" onClick={signOut}>Sign out</button>
          </div>
        </header>
        <div className="page">
          {isAdminRoute(active) ? <AdminRoutes active={active} scope={scope} /> : null}
          {!isAdminRoute(active) && isLoading && !data ? <WorkspaceSkeleton /> : null}
          {!isAdminRoute(active) && !isLoading && !data && message ? <EmptyState>{message}</EmptyState> : null}
          {data && !isAdminRoute(active) ? <View route={route} data={data} scope={scope} user={user} mutate={mutate} /> : null}
        </div>
      </main>
    </div>
  );
}

function WorkspaceSkeleton() {
  return (
    <>
      <SkeletonMetrics count={4} />
      <div className="lane-grid" style={{ marginTop: 14 }}>
        <SkeletonCards count={2} />
        <SkeletonCards count={2} />
        <SkeletonCards count={2} />
      </div>
    </>
  );
}

function roleLabel(user: User): string {
  if (user.is_super_admin) return "Platform super admin";
  if (user.permissions.includes("user.manage")) return "Organization administrator";
  if (user.permissions.includes("gate.decide")) return "Governance administrator";
  if (user.permissions.includes("risk.accept")) return "Risk owner";
  if (user.permissions.includes("review.decide")) return "Reviewer";
  if (user.permissions.includes("network.read")) return "Enterprise subscriber";
  return "Member";
}

const ADMIN_ROUTES = new Set(["overview", "intake", "team", "audit"]);

function isAdminRoute(active: string): boolean {
  return ADMIN_ROUTES.has(active);
}

function AdminRoutes({ active, scope }: { active: string; scope: Scope }) {
  switch (active) {
    case "overview":
      return <OrgOverview />;
    case "intake":
      return <IntakeView scope={scope} />;
    case "team":
      return <TeamConsole />;
    case "audit":
      return <AuditLog />;
    default:
      return null;
  }
}

function View({ route, data, scope, user, mutate }: { route: string[]; data: DashboardData; scope: Scope; user: User; mutate: Mutate }) {
  if (route[0] === "application" && route[1]) return <DetailRoute kind="application" id={route[1]} scope={scope} mutate={mutate} />;
  if (route[0] === "workflow" && route[1]) return <DetailRoute kind="workflow" id={route[1]} scope={scope} mutate={mutate} />;
  if (route[0] === "review" && route[1]) return <DetailRoute kind="review" id={route[1]} scope={scope} mutate={mutate} />;
  if (route[0] === "gate" && route[1]) return <DetailRoute kind="gate" id={route[1]} scope={scope} mutate={mutate} />;
  if (route[0] === "incident" && route[1]) return <DetailRoute kind="incident" id={route[1]} scope={scope} mutate={mutate} />;
  if (route[0] === "trace" && route[1]) return <DetailRoute kind="trace" id={route[1]} scope={scope} mutate={mutate} />;
  switch (route[0]) {
    case "myqueue":
      return <MyQueue rows={data.reviewTasks.filter((task) => task.assigned_to === user.user_ref)} />;
    case "inventory":
      return <Inventory data={data} />;
    case "reviews":
      return <Reviews data={data} mutate={mutate} />;
    case "risk":
      return <Risk data={data} mutate={mutate} />;
    case "controls":
      return <Controls data={data} />;
    case "deployments":
      return <Deployments data={data} mutate={mutate} />;
    case "monitoring":
      return <Monitoring data={data} />;
    case "incidents":
      return <Incidents data={data} mutate={mutate} />;
    case "portfolio":
    default:
      return <Portfolio data={data} mutate={mutate} />;
  }
}

function DetailRoute({ kind, id, scope, mutate }: { kind: DetailKind; id: string; scope: Scope; mutate: Mutate }) {
  const [detail, setDetail] = useState<Record<string, any> | null>(null);
  const [graph, setGraph] = useState<Record<string, any> | null>(null);
  const [message, setMessage] = useState("");
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setIsLoading(true);
      setMessage("");
      try {
        const nextDetail = await loadDetail(kind, id, scope);
        if (cancelled) return;
        setDetail(nextDetail);
        const nodeId = resourceGraphNodeId(kind, nextDetail);
        if (!nodeId) {
          setGraph(null);
          return;
        }
        try {
          const nextGraph = await loadGraphNeighborhood(nodeId, scope);
          if (!cancelled) setGraph(nextGraph);
        } catch {
          if (!cancelled) setGraph(null);
        }
      } catch (error) {
        if (!cancelled) {
          setDetail(null);
          setGraph(null);
          setMessage(error instanceof Error ? error.message : "Unable to load detail.");
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [kind, id, scope]);

  if (isLoading) return <EmptyState>Loading the selected record.</EmptyState>;
  if (!detail) return <EmptyState>{message || "The requested object was not found in the current scope."}</EmptyState>;

  switch (kind) {
    case "application":
      return <ApplicationDetail detail={detail} graph={graph} mutate={mutate} />;
    case "workflow":
      return <WorkflowDetail detail={detail} graph={graph} mutate={mutate} />;
    case "review":
      return <ReviewDetail detail={detail} mutate={mutate} />;
    case "gate":
      return <GateDetail detail={detail} mutate={mutate} />;
    case "incident":
      return <IncidentDetail detail={detail} mutate={mutate} />;
    case "trace":
      return <TraceDetail detail={detail} />;
    default: {
      const exhaustive: never = kind;
      return <EmptyState>Unsupported detail route: {exhaustive}</EmptyState>;
    }
  }
}

function resourceGraphNodeId(kind: DetailKind, detail: Record<string, any>): string | null {
  if (kind === "application") return detail.application?.application_name ? `application:${detail.application.application_name}` : null;
  if (kind === "workflow") return detail.workflow?.workflow_name ? `workflow:${detail.workflow.workflow_name}` : null;
  return null;
}

function Portfolio({ data, mutate }: { data: DashboardData; mutate: (path: string, payload: unknown, success: string) => Promise<void> }) {
  const openReviews = data.reviewTasks.filter((task) => task.status === "open");
  const pendingGates = data.deploymentGates.filter((gate) => gate.gate_status === "pending_review");
  const openIncidents = data.incidents.filter((incident) => incident.status !== "closed");
  return (
    <>
      <div className="metric-grid">
        <MetricCard label="Applications" value={data.summary.applications} />
        <MetricCard label="Model calls" value={data.summary.model_calls} />
        <MetricCard label="Open reviews" value={data.summary.open_reviews} note={`${data.summary.overdue_reviews} overdue`} />
        <MetricCard label="Open incidents" value={data.summary.open_incidents} note={`${data.summary.critical_incidents} critical or high`} />
      </div>
      <div className="lane-grid">
        <WorkLane title="Reviews" count={openReviews.length}>
          <ReviewCards rows={openReviews.slice(0, 5)} />
        </WorkLane>
        <WorkLane title="Release Gates" count={pendingGates.length}>
          <GateCards rows={pendingGates.slice(0, 5)} />
        </WorkLane>
        <WorkLane title="Incidents" count={openIncidents.length}>
          <IncidentCards rows={openIncidents.slice(0, 5)} />
        </WorkLane>
      </div>
      <Section title="Applications" description="Open an application to review owners, workflows, risks, controls, releases, incidents, and decisions.">
        <ApplicationCards rows={data.applications} />
      </Section>
    </>
  );
}

function WorkLane({ title, count, children }: { title: string; count: number; children: React.ReactNode }) {
  return (
    <section className="lane">
      <div className="lane-title">
        <h2>{title}</h2>
        <Badge value={count} />
      </div>
      {children}
    </section>
  );
}

function Inventory({ data }: { data: DashboardData }) {
  const [query, setQuery] = useState("");
  const search = query.trim().toLowerCase();
  const matches = (row: Record<string, any>, keys: string[]) => !search || keys.some((key) => String(row[key] || "").toLowerCase().includes(search));
  return (
    <>
      <div className="toolbar">
        <input className="search" placeholder="Search applications, workflows, models, prompts, deployments" value={query} onChange={(event) => setQuery(event.target.value)} />
      </div>
      <Section title="Applications" description="Business applications in the selected tenant.">
        <ApplicationCards rows={data.applications.filter((row) => matches(row, ["application_name", "tenant_id", "environment"]))} />
      </Section>
      <Section title="Workflows" description="Business processes inside those applications.">
        <WorkflowCards rows={data.workflows.filter((row) => matches(row, ["workflow_name"]))} />
      </Section>
      <div className="two-column">
        <Section title="Models And Providers">
          <ModelCards rows={data.models.filter((row) => matches(row, ["provider", "model"]))} />
        </Section>
        <Section title="Prompt Releases">
          <PromptCards rows={data.promptTemplates.filter((row) => matches(row, ["prompt_id", "application_name", "workflow_name"]))} />
        </Section>
      </div>
      <Section title="Deployments">
        <DeploymentCards rows={data.deployments.filter((row) => matches(row, ["deployment_id", "application_name", "workflow_name", "current_version"]))} />
      </Section>
    </>
  );
}

function Reviews({ data, mutate }: { data: DashboardData; mutate: Mutate }) {
  return (
    <>
      <div className="metric-grid">
        <MetricCard label="Open Tasks" value={data.reviewTasks.filter((task) => task.status === "open").length} />
        <MetricCard label="Unassigned Owners" value={data.owners.filter((owner) => owner.status === "unassigned").length} />
        <MetricCard label="Active Exceptions" value={data.exceptions.filter((item) => item.status === "active").length} />
        <MetricCard label="Decisions" value={data.decisions.length} />
      </div>
      <Section title="All Open Review Tasks" description="Risk, control, release, and change reviews waiting for a reviewer decision.">
        <ReviewCards rows={data.reviewTasks} />
      </Section>
      <Section title="Owner Follow-Up" description="Records that need a named business, technical, risk, control, or incident owner.">
        <OwnerCards rows={data.owners} />
      </Section>
      <Section title="Decision Log" description="Recorded reviewer decisions and rationale.">
        <DecisionCards rows={data.decisions} />
      </Section>
      <Section title="Active Exceptions" description="Accepted risks that still need an owner, compensating control, and expiration date.">
        <ExceptionCards rows={data.exceptions.filter((item) => item.status === "active")} />
      </Section>
    </>
  );
}

function Risk({ data, mutate }: { data: DashboardData; mutate: (path: string, payload: unknown, success: string) => Promise<void> }) {
  return (
    <>
      <div className="metric-grid">
        <MetricCard label="Findings" value={data.risks.length} />
        <MetricCard label="Open Findings" value={data.risks.filter((risk) => risk.status !== "closed").length} />
        <MetricCard label="Active Exceptions" value={data.exceptions.filter((item) => item.status === "active").length} />
        <MetricCard label="Linked Incidents" value={data.incidents.length} />
      </div>
      <Section title="Risk Findings">
        <RiskCards rows={data.risks} />
      </Section>
    </>
  );
}

function Controls({ data }: { data: DashboardData }) {
  return (
    <>
      <div className="metric-grid">
        <MetricCard label="Assessments" value={data.controls.length} />
        <MetricCard label="Passing" value={data.controls.filter((control) => control.status === "passing").length} />
        <MetricCard label="Missing" value={data.controls.filter((control) => control.status === "missing").length} />
        <MetricCard label="Trace Links" value={new Set(data.controls.flatMap((control) => control.evidence_trace_ids || [])).size} />
      </div>
      <Section title="Control Checks" description="Passing and missing control records for the selected tenant.">
        <ControlCards rows={data.controls} />
      </Section>
    </>
  );
}

function Deployments({ data, mutate }: { data: DashboardData; mutate: (path: string, payload: unknown, success: string) => Promise<void> }) {
  return (
    <>
      <Section title="Deployment Registry">
        <DeploymentCards rows={data.deployments} />
      </Section>
      <Section title="Approval Gates" description="Release decisions waiting on a reviewer. Open a gate before approving or rejecting.">
        <GateCards rows={data.deploymentGates} />
      </Section>
    </>
  );
}

function Monitoring({ data }: { data: DashboardData }) {
  return (
    <>
      <div className="metric-grid">
        <MetricCard label="Traces" value={data.traces.length} />
        <MetricCard label="Model Calls" value={data.modelCalls.length} />
        <MetricCard label="Agent Runs" value={data.agents.length} />
        <MetricCard label="Guardrails" value={data.guardrails.length} />
      </div>
      <Section title="Trace Index">
        <TraceCards rows={data.traces} />
      </Section>
      <div className="two-column">
        <Section title="Agent Runs">
          <AgentCards rows={data.agents} />
        </Section>
        <Section title="Guardrails And Evals">
          <GuardrailEvalCards guardrails={data.guardrails} evals={data.evals} />
        </Section>
      </div>
    </>
  );
}

function Incidents({ data, mutate }: { data: DashboardData; mutate: (path: string, payload: unknown, success: string) => Promise<void> }) {
  return (
    <Section title="Incident Response" description="Open incidents and their closure actions. Review linked records before closing.">
      <IncidentCards rows={data.incidents} />
    </Section>
  );
}

function ApplicationDetail({ detail, graph, mutate }: { detail: Record<string, any>; graph: Record<string, any> | null; mutate: Mutate }) {
  const application = detail.application;
  return (
    <ObjectWorkspace title={application.application_name} subtitle={`${application.tenant_id || "Unscoped"} / ${application.environment || "unknown environment"}`}>
      <div className="detail-rail">
        <MetricCard label="Calls" value={application.model_calls} />
        <MetricCard label="Errors" value={application.errors} />
        <MetricCard label="Risks" value={(detail.risks || []).length} />
        <MetricCard label="Open Reviews" value={(detail.review_tasks || []).filter((task: Record<string, any>) => task.status === "open").length} />
      </div>
      <div className="detail-stack">
        <Section title="Overview">
          <div className="chip-row">
            {(application.providers || []).map((provider: string) => <Chip key={provider}>{provider}</Chip>)}
            {(application.models || []).map((model: string) => <Chip key={model}>{model}</Chip>)}
          </div>
        </Section>
        <Section title="Workflow Relationships">
          <WorkflowCards rows={detail.workflows || []} />
        </Section>
        <Section title="Risk And Controls">
          <div className="two-column">
            <RiskCards rows={detail.risks || []} />
            <ControlCards rows={detail.controls || []} />
          </div>
        </Section>
        <Section title="Governance Work">
          <ReviewCards rows={detail.review_tasks || []} />
        </Section>
        <Section title="Release Records">
          <div className="two-column">
            <DeploymentCards rows={detail.deployments || []} />
            <PromptCards rows={detail.prompt_templates || []} />
          </div>
        </Section>
        <Section title="Incidents And Decisions">
          <div className="two-column">
            <IncidentCards rows={detail.incidents || []} />
            <DecisionCards rows={detail.decisions || []} />
          </div>
        </Section>
        <GraphNeighborhood graph={graph} />
      </div>
    </ObjectWorkspace>
  );
}

function WorkflowDetail({ detail, graph, mutate }: { detail: Record<string, any>; graph: Record<string, any> | null; mutate: Mutate }) {
  const workflow = detail.workflow;
  return (
    <ObjectWorkspace title={workflow.workflow_name} subtitle={formatList(workflow.applications) || "No application links"}>
      <div className="detail-rail">
        <MetricCard label="Calls" value={workflow.model_calls} />
        <MetricCard label="Errors" value={workflow.errors} />
        <MetricCard label="Agents" value={(detail.agents || []).length} />
        <MetricCard label="Evals" value={(detail.evals || []).length} />
      </div>
      <div className="detail-stack">
        <Section title="Request Records">
          <div className="two-column">
            <AgentCards rows={detail.agents || []} />
            <GuardrailEvalCards guardrails={detail.guardrails || []} evals={detail.evals || []} />
          </div>
        </Section>
        <Section title="Trace Activity">
          <TraceCards rows={detail.traces || []} />
        </Section>
        <Section title="Risks, Controls, Reviews">
          <RiskCards rows={detail.risks || []} />
          <ControlCards rows={detail.controls || []} />
          <ReviewCards rows={detail.review_tasks || []} />
        </Section>
        <Section title="Release And Incident Links">
          <div className="two-column">
            <GateCards rows={detail.deployment_gates || []} />
            <IncidentCards rows={detail.incidents || []} />
          </div>
        </Section>
        <GraphNeighborhood graph={graph} />
      </div>
    </ObjectWorkspace>
  );
}

function ReviewDetail({ detail, mutate }: { detail: Record<string, any>; mutate: Mutate }) {
  const task = detail.review_task;
  return (
    <ObjectWorkspace title={task.title} subtitle={`${task.application_name} / ${task.assigned_role || "unrouted"} / ${task.assigned_to || "no assignee"}`}>
      <div className="detail-rail">
        <MetricCard label="Status" value={task.status} />
        <MetricCard label="Priority" value={task.priority || "n/a"} />
        <MetricCard label="Escalation" value={task.escalation_status || "unassigned"} />
        <MetricCard label="Decisions" value={(detail.decisions || []).length} />
      </div>
      <div className="detail-stack">
        <Section title="Review Context" description="This page uses the review detail API, including the triggering change and prior decisions.">
          <ReviewCards rows={[task]} />
          <ReviewDecisionPanel task={task} mutate={mutate} />
        </Section>
        <Section title="Detected Change">
          {detail.change_event ? <ChangeCard change={detail.change_event} /> : <EmptyState>No change event is linked to this review task.</EmptyState>}
        </Section>
        <Section title="Ownership And Decisions">
          <div className="two-column">
            <OwnerCards rows={detail.owners || []} />
            <DecisionCards rows={detail.decisions || []} />
          </div>
          <OwnerAssignmentPanels rows={detail.owners || []} mutate={mutate} />
        </Section>
        <Section title="Active Exceptions">
          <ExceptionCards rows={detail.exceptions || []} />
        </Section>
      </div>
    </ObjectWorkspace>
  );
}

function GateDetail({ detail, mutate }: { detail: Record<string, any>; mutate: Mutate }) {
  const gate = detail.deployment_gate;
  return (
    <ObjectWorkspace title={`${gate.application_name} release gate`} subtitle={`${gate.workflow_name} / ${gate.gate_status}`}>
      <div className="detail-rail">
        <MetricCard label="Risks" value={gate.risk_count} />
        <MetricCard label="Missing Controls" value={gate.missing_control_count} />
        <MetricCard label="Material Changes" value={gate.material_change_count} />
        <MetricCard label="Passing Evals" value={gate.passing_eval_count} />
      </div>
      <div className="detail-stack">
        <Section title="Gate Decision" description="Approve or reject only after reviewing blockers, prompt record, evaluation result, and prior decisions.">
          <GateCards rows={[gate]} />
          <GateDecisionPanel gate={gate} mutate={mutate} />
        </Section>
        <Section title="Deployment Version">
          <div className="two-column">
            <DeploymentCards rows={detail.deployment ? [detail.deployment] : []} />
            <DeploymentCards rows={detail.deployment_version ? [detail.deployment_version] : []} />
          </div>
        </Section>
        <Section title="Prompt And Eval Readiness">
          <div className="evidence-grid">
            <MiniStat label="Prompt Record" value={gate.prompt_evidence_status} />
            <MiniStat label="Prompt Version" value={detail.prompt_version?.version || gate.prompt_version_id || "missing"} />
            <MiniStat label="Passing Evals" value={gate.passing_eval_count} />
          </div>
        </Section>
        <Section title="Blocking Records">
          <div className="two-column">
            <RiskCards rows={detail.risks || []} />
            <ControlCards rows={detail.controls || []} />
          </div>
          <RiskExceptionPanels rows={detail.risks || []} mutate={mutate} />
        </Section>
        <Section title="Review History">
          <div className="two-column">
            <ReviewCards rows={detail.review_tasks || []} />
            <DecisionCards rows={detail.decisions || []} />
          </div>
        </Section>
      </div>
    </ObjectWorkspace>
  );
}

function IncidentDetail({ detail, mutate }: { detail: Record<string, any>; mutate: Mutate }) {
  const incident = detail.incident;
  return (
    <ObjectWorkspace title={incident.title} subtitle={`${incident.application_name} / ${incident.workflow_name} / ${incident.severity}`}>
      <div className="detail-rail">
        <MetricCard label="Status" value={incident.status} />
        <MetricCard label="Severity" value={incident.severity} />
        <MetricCard label="Risks" value={incident.risk_count} />
        <MetricCard label="Missing Controls" value={incident.missing_control_count} />
      </div>
      <div className="detail-stack">
        <Section title="Incident Closure" description="Close only when the linked request records, controls, risks, and decisions support the rationale.">
          <IncidentCards rows={[incident]} />
          <IncidentClosurePanel incident={incident} mutate={mutate} />
        </Section>
        <Section title="Request Records">
          {detail.trace ? <TraceSummary trace={detail.trace} /> : <EmptyState>No trace detail is linked to this incident.</EmptyState>}
        </Section>
        <Section title="Linked Records">
          <div className="two-column">
            <RiskCards rows={detail.risks || []} />
            <ControlCards rows={detail.controls || []} />
          </div>
          <RiskExceptionPanels rows={detail.risks || []} mutate={mutate} />
        </Section>
        <Section title="Ownership And Decisions">
          <div className="two-column">
            <OwnerCards rows={detail.owners || []} />
            <DecisionCards rows={detail.decisions || []} />
          </div>
          <OwnerAssignmentPanels rows={detail.owners || []} mutate={mutate} />
        </Section>
        <Section title="Deployment Context">
          <div className="two-column">
            <DeploymentCards rows={detail.deployment ? [detail.deployment] : []} />
            <GateCards rows={detail.deployment_gate ? [detail.deployment_gate] : []} />
          </div>
        </Section>
      </div>
    </ObjectWorkspace>
  );
}

function TraceDetail({ detail }: { detail: Record<string, any> }) {
  const events = detail.events || [];
  return (
    <ObjectWorkspace title={`Trace ${detail.trace_id}`} subtitle={`${detail.application_name || "unknown application"} / ${detail.workflow_name || "unknown workflow"}`}>
      <div className="detail-rail">
        <MetricCard label="Events" value={detail.event_count} />
        <MetricCard label="Status" value={detail.status} />
        <MetricCard label="Started" value={shortDate(detail.started_at)} />
        <MetricCard label="Ended" value={shortDate(detail.ended_at)} />
      </div>
      <div className="detail-stack">
        <Section title="Execution Timeline">
          <EventCards rows={events} />
        </Section>
      </div>
    </ObjectWorkspace>
  );
}

function GraphNeighborhood({ graph }: { graph: Record<string, any> | null }) {
  if (!graph || !Array.isArray(graph.nodes) || !graph.nodes.length) return null;
  return (
      <Section title="Related Records" description="Applications, workflows, providers, models, traces, and checks directly linked to this record.">
      <div className="relationship-list">
        {graph.edges.map((edge: Record<string, any>) => (
          <div className="relationship-row" key={`${edge.source}-${edge.relationship}-${edge.target}`}>
            <span>{edge.source}</span>
            <Badge value={edge.relationship} />
            <span>{edge.target}</span>
          </div>
        ))}
      </div>
    </Section>
  );
}

function ChangeCard({ change }: { change: Record<string, any> }) {
  return (
    <article className="record-card">
      <div className="record-main">
        <span className="record-title">{change.subject_type}: {change.subject_name}</span>
        <Badge value={`${change.severity} / ${change.status}`} />
      </div>
      <p>{change.rationale}</p>
      <p>Changed fields: {formatList(change.changed_fields) || "none recorded"}</p>
      <EvidenceTraceLinks traceIds={change.evidence_trace_ids || []} />
    </article>
  );
}

function TraceSummary({ trace }: { trace: Record<string, any> }) {
  return (
    <article className="record-card">
      <div className="record-main">
        <a className="record-title" href={`#trace/${trace.trace_id}`}>{trace.trace_id}</a>
        <Badge value={trace.status} />
      </div>
      <p>{trace.event_count} events from {shortDate(trace.started_at)} to {shortDate(trace.ended_at)}</p>
    </article>
  );
}

function ExceptionCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No active exceptions are linked to this object.">
      {rows.map((exception) => (
        <article className="record-card" key={exception.exception_id}>
          <div className="record-main">
            <span className="record-title">{exception.target_type}: {exception.target_id}</span>
            <Badge value={exception.status} />
          </div>
          <p>{exception.reason}</p>
          <p>Compensating control: {exception.compensating_control}. Expires: {exception.expires_at}</p>
        </article>
      ))}
    </RecordList>
  );
}

function EvidenceTraceLinks({ traceIds }: { traceIds: unknown }) {
  const ids = Array.isArray(traceIds) ? traceIds : [];
  if (!ids.length) return null;
  return (
    <div className="chip-row">
      {ids.map((traceId) => (
        <a className="chip" href={`#trace/${traceId}`} key={String(traceId)}>{String(traceId)}</a>
      ))}
    </div>
  );
}

function shortDate(value: unknown): string {
  if (!value) return "n/a";
  const parsed = new Date(String(value));
  if (Number.isNaN(parsed.getTime())) return String(value);
  return parsed.toLocaleString();
}

function ObjectWorkspace({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <>
      <div className="object-heading">
        <div>
          <button className="back-link" onClick={() => window.history.back()}>← Back</button>
          <h2>{title}</h2>
          <p>{subtitle}</p>
        </div>
      </div>
      <div className="detail-layout">{children}</div>
    </>
  );
}

function ApplicationCards({ rows }: { rows: Array<Record<string, any>> }) {
  if (!rows.length) return <EmptyState>No applications found for this tenant.</EmptyState>;
  return (
    <div className="object-grid">
      {rows.map((application) => (
        <a className="object-card" href={`#application/${application.entity_id}`} key={application.entity_id}>
          <div>
            <div className="object-title">{application.application_name}</div>
            <div className="object-subtitle">{application.tenant_id || "Unscoped"} / {application.environment || "unknown environment"}</div>
          </div>
          <div className="chip-row">
            {(application.providers || []).map((provider: string) => <Chip key={provider}>{provider}</Chip>)}
            {(application.models || []).slice(0, 2).map((model: string) => <Chip key={model}>{model}</Chip>)}
          </div>
          <div className="object-stats">
            <MiniStat label="Calls" value={application.model_calls} />
            <MiniStat label="Errors" value={application.errors} />
            <MiniStat label="Tokens" value={Number(application.input_tokens || 0) + Number(application.output_tokens || 0)} />
          </div>
        </a>
      ))}
    </div>
  );
}

function WorkflowCards({ rows }: { rows: Array<Record<string, any>> }) {
  if (!rows.length) return <EmptyState>No workflows found for this tenant.</EmptyState>;
  return (
    <div className="object-grid">
      {rows.map((workflow) => (
        <a className="object-card" href={`#workflow/${workflow.entity_id}`} key={workflow.entity_id}>
          <div>
            <div className="object-title">{workflow.workflow_name}</div>
            <div className="object-subtitle">{formatList(workflow.applications) || "No application links"}</div>
          </div>
          <div className="chip-row">{(workflow.providers || []).map((provider: string) => <Chip key={provider}>{provider}</Chip>)}</div>
          <div className="object-stats">
            <MiniStat label="Calls" value={workflow.model_calls} />
            <MiniStat label="Errors" value={workflow.errors} />
            <MiniStat label="Models" value={(workflow.models || []).length} />
          </div>
        </a>
      ))}
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: unknown }) {
  return (
    <div className="mini-stat">
      <strong>{String(value ?? 0)}</strong>
      <span>{label}</span>
    </div>
  );
}

function ReviewCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No review tasks are open.">
      {rows.map((task) => <ReviewCard key={task.task_id} task={task} />)}
    </RecordList>
  );
}

function ReviewCard({ task }: { task: Record<string, any> }) {
  return (
    <article className="record-card">
      <div className="record-main">
        <a href={`#review/${task.task_id}`} className="record-title">{task.title}</a>
        <Badge value={task.status} />
      </div>
      <p>{task.application_name} / {task.assigned_role || "Unrouted"} / {task.assigned_to || "No assignee"}</p>
      <div className="evidence-grid">
        <MiniStat label="Priority" value={task.priority || "n/a"} />
        <MiniStat label="Due" value={task.due_at ? shortDate(task.due_at) : "not routed"} />
        <MiniStat label="Escalation" value={task.escalation_status || "unassigned"} />
      </div>
    </article>
  );
}

function GateCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No deployment approval gates have been generated.">
      {rows.map((gate) => <GateCard key={gate.gate_id} gate={gate} />)}
    </RecordList>
  );
}

function GateCard({ gate }: { gate: Record<string, any> }) {
  return (
    <article className="record-card">
      <div className="record-main">
        <a href={`#gate/${gate.gate_id}`} className="record-title">{gate.application_name} release gate</a>
        <Badge value={gate.gate_status} />
      </div>
      <p>{gate.required_reason}</p>
      <div className="evidence-grid">
        <MiniStat label="Risks" value={gate.risk_count} />
        <MiniStat label="Missing Controls" value={gate.missing_control_count} />
        <MiniStat label="Material Changes" value={gate.material_change_count} />
        <MiniStat label="Prompt" value={gate.prompt_evidence_status || "unknown"} />
        <MiniStat label="Passing Evals" value={gate.passing_eval_count} />
        <MiniStat label="Submitted" value={shortDate(gate.submitted_at)} />
      </div>
    </article>
  );
}

function IncidentCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No incidents have been reported.">
      {rows.map((incident) => <IncidentCard key={incident.incident_id} incident={incident} />)}
    </RecordList>
  );
}

function IncidentCard({ incident }: { incident: Record<string, any> }) {
  return (
    <article className="record-card">
      <div className="record-main">
        <a href={`#incident/${incident.incident_id}`} className="record-title">{incident.title}</a>
        <Badge value={incident.status} />
      </div>
      <p>{incident.application_name} / {incident.workflow_name} / severity {incident.severity}</p>
    </article>
  );
}

function RiskCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No risk findings found for this tenant.">
      {rows.map((risk) => <RiskCard key={risk.finding_id || risk.rule_id} risk={risk} />)}
    </RecordList>
  );
}

function RiskCard({ risk }: { risk: Record<string, any> }) {
  return (
    <article className="record-card">
      <div className="record-main">
        <span className="record-title">{risk.risk}</span>
        <Badge value={`${risk.severity} / ${risk.status}`} />
      </div>
      <p>{risk.application_name}. Basis: {risk.evidence_summary || risk.evidence || "No supporting detail."}</p>
      <EvidenceTraceLinks traceIds={risk.evidence_trace_ids || []} />
    </article>
  );
}

function OwnerCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No ownership records have been created.">
      {rows.map((owner) => <OwnerCard key={owner.owner_assignment_id} owner={owner} />)}
    </RecordList>
  );
}

function OwnerCard({ owner }: { owner: Record<string, any> }) {
  return (
    <article className="record-card">
      <div className="record-main">
        <span className="record-title">{owner.subject_type}: {owner.subject_name}</span>
        <Badge value={owner.status} />
      </div>
      <p>{owner.application_name} / {owner.owner_role}</p>
    </article>
  );
}

function OwnerAssignmentPanels({ rows, mutate }: { rows: Array<Record<string, any>>; mutate: Mutate }) {
  if (!rows.length) return null;
  return (
    <div className="workflow-panel">
      <div>
        <h3>Ownership Routing</h3>
      </div>
      <div className="workflow-list">
        {rows.map((owner) => <OwnerAssignmentPanel key={owner.owner_assignment_id} owner={owner} mutate={mutate} />)}
      </div>
    </div>
  );
}

function OwnerAssignmentPanel({ owner, mutate }: { owner: Record<string, any>; mutate: Mutate }) {
  const [ownerRef, setOwnerRef] = useState(owner.owner_ref || "");
  const [reason, setReason] = useState("");
  const assignmentPacket = [
    `Subject: ${owner.subject_type} ${owner.subject_name || owner.subject_ref || ""}`.trim(),
    `Role: ${owner.owner_role || "unassigned role"}`,
    `Assignment reason: ${reason || "not provided"}`,
  ].join("\n");

  return (
    <div className="workflow-row">
      <div>
        <strong>{owner.subject_type}: {owner.subject_name}</strong>
        <span>{owner.application_name} / {owner.owner_role} / {owner.status}</span>
      </div>
      <div className="inline-form owner-action">
        <input placeholder="owner@company.com" value={ownerRef} onChange={(event) => setOwnerRef(event.target.value)} />
        <input placeholder="Why this owner is accountable" value={reason} onChange={(event) => setReason(event.target.value)} />
        <button onClick={() => mutate(`/api/owner-assignments/${owner.owner_assignment_id}/assign`, { owner_ref: ownerRef, rationale: assignmentPacket }, "Owner assigned.")}>Assign owner</button>
      </div>
    </div>
  );
}

function RiskExceptionPanels({ rows, mutate }: { rows: Array<Record<string, any>>; mutate: Mutate }) {
  const actionable = rows.filter((risk) => risk.finding_id);
  if (!actionable.length) return null;
  return (
    <div className="workflow-panel">
      <div>
        <h3>Risk Treatment</h3>
      </div>
      <div className="workflow-list">
        {actionable.map((risk) => <RiskExceptionPanel key={risk.finding_id} risk={risk} mutate={mutate} />)}
      </div>
    </div>
  );
}

function RiskExceptionPanel({ risk, mutate }: { risk: Record<string, any>; mutate: Mutate }) {
  const [reason, setReason] = useState("");
  const [compensatingControl, setCompensatingControl] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const exceptionPacket = [
    `Risk: ${risk.risk || risk.finding_id}`,
    `Evidence basis: ${risk.evidence_summary || risk.evidence || "not provided"}`,
    `Exception reason: ${reason || "not provided"}`,
    `Compensating control: ${compensatingControl || "not provided"}`,
    `Expiry: ${expiresAt || "not provided"}`,
  ].join("\n");

  return (
    <div className="workflow-row">
      <div>
        <strong>{risk.risk}</strong>
        <span>{risk.application_name} / {risk.severity} / {risk.status}</span>
      </div>
      <div className="inline-form risk-action">
        <input placeholder="Business reason for exception" value={reason} onChange={(event) => setReason(event.target.value)} />
        <input placeholder="Compensating control or owner" value={compensatingControl} onChange={(event) => setCompensatingControl(event.target.value)} />
        <input placeholder="YYYY-MM-DD expiry" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
        <button className="secondary" onClick={() => mutate("/api/exceptions", { target_type: "risk_finding", target_id: risk.finding_id, reason: exceptionPacket, compensating_control: compensatingControl, expires_at: expiresAt }, "Exception created.")}>Create exception</button>
      </div>
    </div>
  );
}

function ReviewDecisionPanel({ task, mutate }: { task: Record<string, any>; mutate: Mutate }) {
  const [decision, setDecision] = useState("approve");
  const [evidenceReviewed, setEvidenceReviewed] = useState(false);
  const [policyChecked, setPolicyChecked] = useState(false);
  const [ownerConfirmed, setOwnerConfirmed] = useState(false);
  const [rationale, setRationale] = useState("");
  const decisionPacket = [
    `Evidence reviewed: ${evidenceReviewed ? "yes" : "no"}`,
    `Policy basis checked: ${policyChecked ? "yes" : "no"}`,
    `Owner accountability confirmed: ${ownerConfirmed ? "yes" : "no"}`,
    `Reviewer rationale: ${rationale || "not provided"}`,
  ].join("\n");

  return (
    <div className="workflow-panel">
      <div>
        <h3>Reviewer Decision Packet</h3>
      </div>
      <div className="workflow-grid">
        <label className="check-row">
          <input type="checkbox" checked={evidenceReviewed} onChange={(event) => setEvidenceReviewed(event.target.checked)} />
          Evidence supports the requested decision
        </label>
        <label className="check-row">
          <input type="checkbox" checked={policyChecked} onChange={(event) => setPolicyChecked(event.target.checked)} />
          Control or standard requirement has been checked
        </label>
        <label className="check-row">
          <input type="checkbox" checked={ownerConfirmed} onChange={(event) => setOwnerConfirmed(event.target.checked)} />
          Business or technical owner remains accountable
        </label>
      </div>
      <div className="inline-form workflow-action">
        <select value={decision} onChange={(event) => setDecision(event.target.value)}>
          <option value="approve">Approve</option>
          <option value="reject">Reject</option>
          <option value="request_changes">Request changes</option>
          <option value="mitigate">Require mitigation</option>
        </select>
        <textarea placeholder="Rationale, required changes, or residual risk accepted by the reviewer" value={rationale} onChange={(event) => setRationale(event.target.value)} />
        <button onClick={() => mutate("/api/decisions", { target_type: "review_task", target_id: task.task_id, decision, rationale: decisionPacket }, "Review decision recorded.")}>Record decision</button>
      </div>
    </div>
  );
}

function GateDecisionPanel({ gate, mutate }: { gate: Record<string, any>; mutate: Mutate }) {
  const [changeImpact, setChangeImpact] = useState(false);
  const [controlEvidence, setControlEvidence] = useState(false);
  const [residualRisk, setResidualRisk] = useState(false);
  const [rationale, setRationale] = useState("");
  const decisionPacket = [
    `Change impact reviewed: ${changeImpact ? "yes" : "no"}`,
    `Control evidence reviewed: ${controlEvidence ? "yes" : "no"}`,
    `Residual risk disposition reviewed: ${residualRisk ? "yes" : "no"}`,
    `Release decision rationale: ${rationale || "not provided"}`,
  ].join("\n");

  return (
    <div className="workflow-panel">
      <div>
        <h3>Release Readiness Review</h3>
      </div>
      <div className="workflow-grid">
        <label className="check-row">
          <input type="checkbox" checked={changeImpact} onChange={(event) => setChangeImpact(event.target.checked)} />
          Material changes and deployment scope have been reviewed
        </label>
        <label className="check-row">
          <input type="checkbox" checked={controlEvidence} onChange={(event) => setControlEvidence(event.target.checked)} />
          Missing or stale controls have an owner and remediation path
        </label>
        <label className="check-row">
          <input type="checkbox" checked={residualRisk} onChange={(event) => setResidualRisk(event.target.checked)} />
          Residual risk is accepted, remediated, or explicitly blocked
        </label>
      </div>
      <div className="inline-form workflow-action">
        <textarea placeholder="Decision rationale, production condition, or blocker that prevents release" value={rationale} onChange={(event) => setRationale(event.target.value)} />
        <button
          onClick={async () => {
            const ok = await confirm({
              title: "Approve this release?",
              body: `${gate.application_name} will be cleared to ship under ${gate.workflow_name}. Your rationale is recorded against the gate.`,
              confirmLabel: "Approve release",
            });
            if (ok) mutate(`/api/deployment-gates/${gate.gate_id}/approve`, { rationale: decisionPacket }, "Gate approved.");
          }}
        >
          Approve release
        </button>
        <button
          className="secondary"
          onClick={async () => {
            const ok = await confirm({
              title: "Reject this release?",
              body: `${gate.application_name} will be blocked from shipping under ${gate.workflow_name}. Your rationale is recorded against the gate.`,
              confirmLabel: "Reject release",
              tone: "danger",
            });
            if (ok) mutate(`/api/deployment-gates/${gate.gate_id}/reject`, { rationale: decisionPacket }, "Gate rejected.");
          }}
        >
          Reject release
        </button>
      </div>
    </div>
  );
}

function IncidentClosurePanel({ incident, mutate }: { incident: Record<string, any>; mutate: Mutate }) {
  const [rootCause, setRootCause] = useState("");
  const [customerImpact, setCustomerImpact] = useState("");
  const [remediation, setRemediation] = useState("");
  const [recurrencePrevention, setRecurrencePrevention] = useState("");
  const rationale = [
    `Root cause: ${rootCause || "not documented"}`,
    `Impact: ${customerImpact || "not documented"}`,
    `Remediation completed: ${remediation || "not documented"}`,
    `Recurrence prevention: ${recurrencePrevention || "not documented"}`,
  ].join("\n");

  if (incident.status === "closed") {
    return <EmptyState>This incident is already closed.</EmptyState>;
  }

  return (
    <div className="workflow-panel">
      <div>
        <h3>Incident Closure Record</h3>
      </div>
      <div className="workflow-grid">
        <textarea placeholder="Root cause" value={rootCause} onChange={(event) => setRootCause(event.target.value)} />
        <textarea placeholder="Customer or business impact" value={customerImpact} onChange={(event) => setCustomerImpact(event.target.value)} />
        <textarea placeholder="Remediation completed" value={remediation} onChange={(event) => setRemediation(event.target.value)} />
        <textarea placeholder="Recurrence prevention or follow-up owner" value={recurrencePrevention} onChange={(event) => setRecurrencePrevention(event.target.value)} />
      </div>
      <div className="inline-form workflow-action">
        <button
          onClick={async () => {
            const ok = await confirm({
              title: "Close this incident?",
              body: "Closing records your rationale and marks the incident resolved. Reopen requires filing a new incident.",
              confirmLabel: "Close incident",
            });
            if (ok) mutate(`/api/incidents/${incident.incident_id}/close`, { rationale }, "Incident closed.");
          }}
        >
          Close incident
        </button>
      </div>
    </div>
  );
}

function ControlCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No control assessments generated yet.">
      {rows.map((control) => (
        <article className="record-card" key={`${control.application_name}-${control.control_id}`}>
          <div className="record-main">
            <span className="record-title">{control.control_name || control.control_id || control.control}</span>
            <Badge value={control.status} />
          </div>
          <p>{control.application_name}. Required record types: {formatList(control.evidence_event_types) || "none"}</p>
          <p>Required fields: {formatList(control.required_fields) || "none"}. Frameworks: {formatList(control.framework_refs) || "none"}</p>
          <p>{control.rationale}</p>
          <EvidenceTraceLinks traceIds={control.evidence_trace_ids || []} />
        </article>
      ))}
    </RecordList>
  );
}

function ModelCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No model calls have been observed.">
      {rows.map((model) => (
        <article className="record-card" key={`${model.provider}-${model.model}`}>
          <div className="record-main">
            <span className="record-title">{model.provider} / {model.model}</span>
            <Badge value={`${model.model_calls} calls`} />
          </div>
          <p>Applications: {formatList(model.applications) || "none"}. Tokens: {model.input_tokens} in / {model.output_tokens} out.</p>
        </article>
      ))}
    </RecordList>
  );
}

function PromptCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No prompt release records found.">
      {rows.map((prompt) => (
        <article className="record-card" key={prompt.prompt_id}>
          <div className="record-main">
            <span className="record-title">{prompt.prompt_id}</span>
            <Badge value={prompt.current_status || prompt.status} />
          </div>
          <p>{prompt.application_name} / {prompt.workflow_name} / version {prompt.current_version || prompt.version || "unknown"}</p>
        </article>
      ))}
    </RecordList>
  );
}

function DeploymentCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No deployment records found.">
      {rows.map((deployment) => (
        <article className="record-card" key={deployment.deployment_id || `${deployment.application_name}-${deployment.current_version}`}>
          <div className="record-main">
            <span className="record-title">{deployment.application_name}</span>
            <Badge value={deployment.current_status || deployment.status} />
          </div>
          <p>{deployment.workflow_name} / {deployment.current_version || deployment.version || "unknown version"} / {deployment.provider || "unknown provider"}</p>
        </article>
      ))}
    </RecordList>
  );
}

function AgentCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No agent run records found.">
      {rows.map((agent) => (
        <article className="record-card" key={`${agent.trace_id}-${agent.agent_name}`}>
          <div className="record-main">
            <span className="record-title">{agent.agent_name}</span>
            <a className="chip" href={`#trace/${agent.trace_id}`}>Trace</a>
          </div>
          <p>{agent.application_name} / {agent.workflow_name}. Steps: {agent.step_count}. Outcome: {agent.outcome}</p>
        </article>
      ))}
    </RecordList>
  );
}

function GuardrailEvalCards({ guardrails, evals }: { guardrails: Array<Record<string, any>>; evals: Array<Record<string, any>> }) {
  const rows = [
    ...guardrails.map((row) => ({ id: `${row.trace_id}-${row.guardrail_name}`, type: "Guardrail", name: row.guardrail_name, result: row.decision, score: row.score, trace_id: row.trace_id })),
    ...evals.map((row) => ({ id: `${row.trace_id}-${row.eval_name}`, type: "Eval", name: row.eval_name, result: row.passed ? "passed" : "failed", score: row.score, trace_id: row.trace_id })),
  ];
  return (
    <RecordList empty="No guardrail or evaluation records found.">
      {rows.map((row) => (
        <article className="record-card" key={row.id}>
          <div className="record-main">
            <span className="record-title">{row.type}: {row.name}</span>
            <Badge value={row.result} />
          </div>
          <p>Score: {row.score ?? "n/a"} / <a href={`#trace/${row.trace_id}`}>trace</a></p>
        </article>
      ))}
    </RecordList>
  );
}

function TraceCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No request traces found.">
      {rows.map((trace) => (
        <article className="record-card" key={trace.trace_id}>
          <div className="record-main">
            <a className="record-title" href={`#trace/${trace.trace_id}`}>{trace.trace_id}</a>
            <Badge value={trace.status || "observed"} />
          </div>
          <p>{trace.event_count} events</p>
        </article>
      ))}
    </RecordList>
  );
}

function EventCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No events were found for this trace.">
      {rows.map((event, index) => (
        <article className="record-card" key={`${event.trace_id}-${event.type}-${index}`}>
          <div className="record-main">
            <span className="record-title">{event.type || event.name}</span>
            <Badge value={event.status || event.decision || "observed"} />
          </div>
          <p>{event.application_name || event.system || event.service || "Unknown system"} / {event.workflow_name || event.name || "unknown workflow"}</p>
        </article>
      ))}
    </RecordList>
  );
}

function DecisionCards({ rows }: { rows: Array<Record<string, any>> }) {
  return (
    <RecordList empty="No decisions have been recorded.">
      {rows.map((decision) => (
        <article className="record-card" key={`${decision.target_id}-${decision.created_at}`}>
          <div className="record-main">
            <span className="record-title">{decision.decision}</span>
            <Badge value={decision.target_type} />
          </div>
          <p>{decision.rationale} / {decision.actor_ref}</p>
        </article>
      ))}
    </RecordList>
  );
}

