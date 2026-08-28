import { useEffect, useMemo, useState } from "react";

import {
  ApiError,
  type DashboardData,
  type DetailKind,
  type Scope,
  type User,
  changePassword,
  fetchMe,
  getJson,
  loadDashboardData,
  totalOf,
  loadDetail,
  loadGraphNeighborhood,
  login,
  logout,
  mfaVerify,
  postJson,
} from "./api";
import { SecurityDialog } from "./components/security";
import { LandingPage } from "./components/landing";
import { SetupWizard } from "./components/setup";
import { InviteScreen } from "./components/invite";
import { Home } from "./components/home";
import { SystemHubHeader } from "./components/systemHub";
import { GettingStarted } from "./components/guide";
import { DocsView } from "./components/docs";
import { Sidebar, SkipLink, useRouteAnnouncement } from "./components/shell";
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
import { AgentsView } from "./components/agents";
import { ComplianceView } from "./components/compliance";
import { IdentityView } from "./components/identity";
import { Badge, Chip, EmptyState, MetricCard, RecordList, Section, SkeletonCards, SkeletonMetrics, formatList } from "./components/ui";
import { ToastHost, toast } from "./components/toast";
import { ConfirmHost, confirm } from "./components/confirm";

type RouteDef = { id: string; label: string; description: string; permission?: string; group?: string };

// detail routes need their own heading and title so screen readers and the
// tab strip name the right page
const DETAIL_ROUTE_META: Record<string, RouteDef> = {
  application: { id: "application", label: "AI system", description: "Stage, owners, what is blocking it, and every piece of evidence and work linked to it." },
  workflow: { id: "workflow", label: "Workflow", description: "Workflow record, models, and linked governance work." },
  review: { id: "review", label: "Review Task", description: "Evidence packet and reviewer decision for one review task." },
  gate: { id: "gate", label: "Release Gate", description: "Release readiness evidence and approval decision." },
  incident: { id: "incident", label: "Incident", description: "Incident evidence, linked risks, and closure record." },
  trace: { id: "trace", label: "Trace", description: "Request trace and the events captured for it." },
};

// grouped by task not data type; route ids stay stable so existing links keep working
const baseRoutes: RouteDef[] = [
  { id: "home", label: "Home", description: "What needs you, and where your organization stands.", group: "" },
  { id: "inventory", label: "AI systems", description: "Every AI system seen in production, including the ones nobody registered. Open one to see its owners, risks, controls, releases and incidents.", group: "Systems" },
  { id: "intake", label: "Register a system", description: "Register an AI use case before it ships. It gets a risk tier and a review task the moment you submit.", permission: "intake.submit", group: "Systems" },
  { id: "agents", label: "Agents", description: "Register the agents you sanction with an autonomy level and tool allow-list. Unregistered agents and off-policy tool use become findings.", group: "Systems" },
  { id: "myqueue", label: "My queue", description: "Review tasks assigned to you. Decide them here with a rationale; the decision is recorded in the audit trail.", group: "Work" },
  { id: "reviews", label: "Reviews & owners", description: "Decide open reviews, name accountable owners, and manage accepted risks. Submitters can never decide their own work.", group: "Work" },
  { id: "deployments", label: "Release gates", description: "Nothing ships without a gate. Gates are approved by a named reviewer with a linked prompt version and signed eval evidence, never automatically.", group: "Work" },
  { id: "risk", label: "Risk findings", description: "Findings raised by the platform and by people. Accept a risk only with an owner, a compensating control and an expiry.", group: "Work" },
  { id: "incidents", label: "Incidents", description: "Incidents reported by guardrails, evals or people. Close one only with a root cause, impact and remediation on record.", group: "Work" },
  { id: "compliance", label: "Compliance", description: "Which requirements of NIST AI RMF, ISO 42001, the EU AI Act and OWASP you can evidence today, and the packet to hand an auditor.", group: "Evidence" },
  { id: "controls", label: "Controls", description: "Each control assessed from what actually ran: passing with linked evidence, or missing with the gap named.", group: "Evidence" },
  { id: "monitoring", label: "Telemetry", description: "The raw evidence: traces, model calls, tool use, guardrail decisions and eval results as the SDK reported them.", group: "Evidence" },
  { id: "audit", label: "Audit log", description: "Who did what, when. Hash-chained and verifiable; it is the trail your auditor will read.", group: "Evidence" },
  { id: "overview", label: "Organization posture", description: "How much of your AI estate is governed, who is accountable for it, and what is waiting on a decision.", permission: "user.manage", group: "Setup" },
  { id: "team", label: "People & access", description: "Invite people and give them a role. Administrators and decision-makers are kept separate by design.", permission: "user.manage", group: "Setup" },
  { id: "identity", label: "Identity & integrations", description: "Connect your identity provider, issue SDK ingestion keys, register the CI key that signs release evidence, and route notifications.", permission: "user.manage", group: "Setup" },
  { id: "guide", label: "Getting started", description: "Set up your organization step by step. Each step is checked against your real state.", permission: "user.manage", group: "Setup" },
  { id: "docs", label: "Docs", description: "Roles, terms and integrations, explained in plain language.", group: "Setup" },
  // kept for old links, not shown in nav
  { id: "portfolio", label: "My work", description: "Everything waiting on you: reviews to decide, releases to approve, incidents to close.", group: "hidden" },
];

type Mutate = (path: string, payload: unknown, success: string) => Promise<void>;

function currentHash(): string[] {
  // empty array lets each view pick its own role-appropriate landing route
  return (window.location.hash || "").slice(1).split("/").filter(Boolean);
}

function visibleRoutes(user: User): RouteDef[] {
  return baseRoutes.filter((route) => {
    if (route.group === "hidden") return false;
    if (route.id === "audit") return user.permissions.includes("user.manage");
    if (route.permission) return user.permissions.includes(route.permission);
    return true;
  });
}

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [bootstrapped, setBootstrapped] = useState(false);
  const [needsSetup, setNeedsSetup] = useState(false);

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      fetchMe().catch(() => null),
      getJson<{ needs_setup: boolean }>("/api/setup/state").catch(() => ({ needs_setup: false })),
    ])
      .then(([me, setup]) => {
        if (cancelled) return;
        setUser(me);
        setNeedsSetup(Boolean(setup.needs_setup));
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
    // invite links work regardless of sign-in state: #invite/<token>
    const hash = currentHash();
    if (hash[0] === "invite" && hash[1]) {
      return (
        <InviteScreen
          token={hash[1]}
          onAccepted={(invited) => {
            window.location.hash = "#portfolio";
            setUser(invited);
          }}
        />
      );
    }
    // fresh install with no orgs yet: show setup instead of the landing page
    if (needsSetup && (!user || user.is_super_admin)) {
      return (
        <SetupWizard
          initialUser={user}
          onFinished={(orgUser) => {
            setNeedsSetup(false);
            setUser(orgUser);
            window.location.hash = "#guide";
          }}
        />
      );
    }
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

// platform plane: super admin provisions orgs and their first admin, never
// touches tenant governance data
const PLATFORM_ROUTES: RouteDef[] = [
  { id: "overview", label: "Overview", description: "Organizations on the platform, accounts, telemetry volume and recent activity." },
  { id: "organizations", label: "Organizations", description: "Create an organization and its first administrator; suspend or reactivate it." },
  { id: "platform-users", label: "Accounts", description: "Every account on the platform. Suspend access or issue a one-time password." },
  { id: "rbac", label: "Roles", description: "What each role is allowed to do, in every organization." },
  { id: "audit", label: "Audit Log", description: "Who did what, when, across every organization. Hash-chained and verifiable." },
];

function PlatformConsole({ user, onSignOut }: { user: User; onSignOut: () => void }) {
  const [route, setRoute] = useState<string[]>(currentHash);
  const [showSecurity, setShowSecurity] = useState(false);

  useEffect(() => {
    const onHashChange = () => setRoute(currentHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const active = PLATFORM_ROUTES.some((item) => item.id === route[0]) ? route[0] : "overview";
  const routeMeta = PLATFORM_ROUTES.find((item) => item.id === active) || PLATFORM_ROUTES[0];
  const headingRef = useRouteAnnouncement(routeMeta.label);

  async function signOut() {
    await logout().catch(() => undefined);
    onSignOut();
  }

  return (
    <div className="shell">
      <SkipLink />
      <Sidebar tagline="Platform administration." routes={PLATFORM_ROUTES} active={active} />
      <main className="main" id="main-content">
        <header className="topbar">
          <div>
            <h1 ref={headingRef} tabIndex={-1}>{routeMeta.label}</h1>
            <p>{routeMeta.description}</p>
          </div>
          <div className="session-summary">
            <div className="actor-summary">
              <strong>{user.display_name}</strong>
              <span>Platform super admin</span>
            </div>
            <button className="secondary" onClick={() => setShowSecurity(true)}>Security</button>
            <button className="secondary" onClick={signOut}>Sign out</button>
          </div>
        </header>
        {showSecurity ? <SecurityDialog onClose={() => setShowSecurity(false)} /> : null}
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

type EntryMode = "landing" | "signin";

function PublicEntry({ onAuthenticated }: { onAuthenticated: (user: User) => void }) {
  const [mode, setMode] = useState<EntryMode>("landing");

  if (mode === "signin") {
    // one sign-in for the whole instance; the account decides what it can see
    return (
      <LoginScreen
        title="Sign in"
        subtitle="Use the email and password from your invitation, or your organization's single sign-on."
        onAuthenticated={onAuthenticated}
        onBack={() => setMode("landing")}
      />
    );
  }
  return <LandingPage onClientSignIn={() => setMode("signin")} />;
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
  // set once the password is accepted on an mfa-enrolled account
  const [challenge, setChallenge] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await login(email, password);
      if (result.mfa_required) {
        setChallenge(result.challenge);
      } else {
        onAuthenticated(result.user);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Sign in failed.");
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(event: React.FormEvent) {
    event.preventDefault();
    if (!challenge) return;
    setBusy(true);
    setError("");
    try {
      onAuthenticated(await mfaVerify(challenge, code, useRecovery));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Verification failed.");
      // an expired or burned challenge means starting over with the password
      if (caught instanceof ApiError && caught.status === 401 && /challenge/i.test(caught.message)) {
        setChallenge(null);
        setCode("");
      }
    } finally {
      setBusy(false);
    }
  }

  if (challenge) {
    return (
      <div className="auth-screen">
        <form className="auth-card" onSubmit={submitCode}>
          <div className="brand">Norinth</div>
          <h1>Two-factor check</h1>
          <p>{useRecovery ? "Enter one of your saved recovery codes." : "Enter the code from your authenticator app."}</p>
          <label>
            {useRecovery ? "Recovery code" : "Authentication code"}
            <input
              value={code}
              inputMode={useRecovery ? "text" : "numeric"}
              autoComplete="one-time-code"
              autoFocus
              onChange={(event) => setCode(event.target.value)}
              required
            />
          </label>
          {error ? <div className="auth-error" role="alert">{error}</div> : null}
          <button type="submit" disabled={busy || !code}>{busy ? "Checking" : "Verify"}</button>
          <button type="button" className="link-button" onClick={() => setUseRecovery((value) => !value)}>
            {useRecovery ? "Use the authenticator instead" : "Use a recovery code instead"}
          </button>
          <button type="button" className="link-button" onClick={() => { setChallenge(null); setCode(""); setError(""); }}>
            Back to sign in
          </button>
        </form>
      </div>
    );
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
        {error ? <div className="auth-error" role="alert">{error}</div> : null}
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
    if (newPassword.length < 12) {
      setError("New password must be at least 12 characters.");
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
          <input type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required minLength={12} />
          <span className="field-hint">At least 12 characters.</span>
        </label>
        {error ? <div className="auth-error" role="alert">{error}</div> : null}
        <button type="submit" disabled={busy}>{busy ? "Saving" : "Update password"}</button>
      </form>
    </div>
  );
}

function Workspace({ user, onSignOut }: { user: User; onSignOut: () => void }) {
  const [route, setRoute] = useState<string[]>(currentHash);
  const [showSecurity, setShowSecurity] = useState(false);
  const [data, setData] = useState<DashboardData | null>(null);
  const [message, setMessage] = useState<string>("");
  const [isLoading, setIsLoading] = useState(false);

  const routes = useMemo(() => visibleRoutes(user), [user]);
  // default landing route per role
  const active = route[0] || "home";
  const [setupComplete, setSetupComplete] = useState<boolean | null>(null);
  useEffect(() => {
    if (!user.permissions.includes("user.manage")) return;
    getJson<{ complete: boolean }>("/api/onboarding")
      .then((state) => setSetupComplete(Boolean(state.complete)))
      .catch(() => setSetupComplete(null));
  }, [user]);
  const routeMeta =
    routes.find((item) => item.id === active) ||
    baseRoutes.find((item) => item.id === active) ||
    DETAIL_ROUTE_META[active] ||
    baseRoutes[0];
  const headingRef = useRouteAnnouncement(routeMeta.label);

  // tenant actors are pinned to their org server-side; this scope is informational
  // and never widens access
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
      <SkipLink />
      <Sidebar tagline="Governance workspace for your organization." routes={routes} active={active} />
      <main className="main" id="main-content" aria-busy={isLoading}>
        <header className="topbar">
          <div>
            <h1 ref={headingRef} tabIndex={-1}>{routeMeta.label}</h1>
            <p>{routeMeta.description}</p>
          </div>
          <div className="session-summary">
            <div className="actor-summary">
              <strong>{user.display_name}</strong>
              <span>{roleLabel(user)} / {user.tenant_id || "No organization"}</span>
            </div>
            <button className="secondary" onClick={refresh}>Refresh</button>
            <button className="secondary" onClick={() => setShowSecurity(true)}>Security</button>
            <button className="secondary" onClick={signOut}>Sign out</button>
          </div>
        </header>
        {showSecurity ? <SecurityDialog onClose={() => setShowSecurity(false)} /> : null}
        <div className="page">
          {isAdminRoute(active) ? <AdminRoutes active={active} scope={scope} user={user} /> : null}
          {!isAdminRoute(active) && isLoading && !data ? <WorkspaceSkeleton /> : null}
          {!isAdminRoute(active) && !isLoading && !data && message ? <EmptyState>{message}</EmptyState> : null}
          {data && !isAdminRoute(active) && data.partialErrors.length ? (
            <div className="partial-load" role="alert">
              <strong>Some records could not be loaded.</strong>
              <span>
                {data.partialErrors.map((item) => `${item.key}: ${item.message}`).join(" · ")}
              </span>
              <button type="button" className="linklike" onClick={refresh}>Retry</button>
            </div>
          ) : null}
          {data && !isAdminRoute(active) ? <View route={route} data={data} scope={scope} user={user} mutate={mutate} setupComplete={setupComplete} /> : null}
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
  return "Member";
}

const ADMIN_ROUTES = new Set(["overview", "intake", "team", "audit", "agents", "identity", "compliance", "guide", "docs"]);

function isAdminRoute(active: string): boolean {
  return ADMIN_ROUTES.has(active);
}

function AdminRoutes({ active, scope, user }: { active: string; scope: Scope; user: User }) {
  switch (active) {
    case "overview":
      return <OrgOverview />;
    case "intake":
      return <IntakeView scope={scope} />;
    case "agents":
      return (
        <AgentsView
          scope={scope}
          canRegister={user.permissions.includes("config.write")}
          canRetire={user.permissions.includes("lifecycle.manage")}
        />
      );
    case "team":
      return <TeamConsole />;
    case "identity":
      return <IdentityView tenantId={user.tenant_id || ""} />;
    case "compliance":
      return <ComplianceView scope={scope} tenantId={user.tenant_id || ""} />;
    case "audit":
      return <AuditLog />;
    case "guide":
      return <GettingStarted />;
    case "docs":
      return <DocsView />;
    default:
      return null;
  }
}

function View({ route, data, scope, user, mutate, setupComplete }: { route: string[]; data: DashboardData; scope: Scope; user: User; mutate: Mutate; setupComplete: boolean | null }) {
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
      return <Portfolio data={data} mutate={mutate} />;
    case "home":
    default:
      return <Home user={user} data={data} setupComplete={setupComplete} />;
  }
}

export function DetailRoute({ kind, id, scope, mutate }: { kind: DetailKind; id: string; scope: Scope; mutate: Mutate }) {
  // tag the loaded record with its route: the component re-renders on hash change
  // before the load effect runs, so without the tag a stale payload of the wrong
  // kind gets handed to the detail view
  const [loaded, setLoaded] = useState<{ kind: DetailKind; id: string; detail: Record<string, any> | null }>({ kind, id, detail: null });
  const [graph, setGraph] = useState<Record<string, any> | null>(null);
  const [message, setMessage] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  // a decision recorded from within a detail view (approve a gate, decide a
  // review, close an incident) changes this record, but the load effect is keyed
  // on kind/id/scope, none of which change. bump a token after each mutation so
  // the detail re-fetches and the view reflects the action instead of going stale
  const [reloadToken, setReloadToken] = useState(0);
  const detailMutate: Mutate = async (path, payload, success) => {
    await mutate(path, payload, success);
    setReloadToken((n) => n + 1);
  };
  const isCurrent = loaded.kind === kind && loaded.id === id;
  const detail = isCurrent ? loaded.detail : null;
  const setDetail = (value: Record<string, any> | null) => setLoaded({ kind, id, detail: value });

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
  }, [kind, id, scope, reloadToken]);

  if (isLoading || !isCurrent) return <div role="status" aria-live="polite"><EmptyState>Loading the selected record.</EmptyState></div>;
  if (!detail) return <EmptyState>{message || "The requested object was not found in the current scope."}</EmptyState>;

  switch (kind) {
    case "application":
      return <ApplicationDetail detail={detail} graph={graph} mutate={detailMutate} />;
    case "workflow":
      return <WorkflowDetail detail={detail} graph={graph} mutate={detailMutate} />;
    case "review":
      return <ReviewDetail detail={detail} mutate={detailMutate} />;
    case "gate":
      return <GateDetail detail={detail} mutate={detailMutate} />;
    case "incident":
      return <IncidentDetail detail={detail} mutate={detailMutate} />;
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
      <Section title="AI systems" description="Open a system to see who owns it, what it runs, what is wrong with it, and what is blocking its next release.">
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
        <input className="search" placeholder="Search applications, workflows, models, prompts, deployments" aria-label="Search inventory" value={query} onChange={(event) => setQuery(event.target.value)} />
      </div>
      <Section title="AI systems" description="Everything that has called a model from your organization, registered or not.">
        <ApplicationCards rows={data.applications.filter((row) => matches(row, ["application_name", "tenant_id", "environment"]))} />
      </Section>
      <Section title="Workflows" description="The business processes inside those systems, each with its own models, prompts and controls.">
        <WorkflowCards rows={data.workflows.filter((row) => matches(row, ["workflow_name"]))} />
      </Section>
      <div className="two-column">
        <Section title="Models and providers" description="What your systems actually call, with volume and error rates. Unapproved vendors show up here first.">
          <ModelCards rows={data.models.filter((row) => matches(row, ["provider", "model"]))} />
        </Section>
        <Section title="Prompt versions" description="Every prompt version seen in production. A release gate needs one linked to it.">
          <PromptCards rows={data.promptTemplates.filter((row) => matches(row, ["prompt_id", "application_name", "workflow_name"]))} />
        </Section>
      </div>
      <Section title="Deployments" description="Deployment versions reported by your pipeline. Each one gets a release gate.">
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
        <MetricCard label="Decisions" value={totalOf(data, "decisions", data.decisions)} />
      </div>
      <Section title="Open reviews" description="Intake, risk, control and change reviews waiting for a decision. Overdue items escalate to the role owner.">
        <ReviewCards rows={data.reviewTasks} total={totalOf(data, "reviewTasks", data.reviewTasks)} />
      </Section>
      <Section title="Needs an owner" description="Systems, risks and controls with nobody accountable yet. Name a person; they are notified and it is recorded.">
        <OwnerCards rows={data.owners} total={totalOf(data, "owners", data.owners)} />
      </Section>
      <Section title="Decisions" description="Every decision with who made it and why. This is what an auditor reads first.">
        <DecisionCards rows={data.decisions} total={totalOf(data, "decisions", data.decisions)} />
      </Section>
      <Section title="Accepted risks" description="Risks someone chose to live with. Each needs an owner, a compensating control and an expiry date, and comes back for re-review when it expires.">
        <ExceptionCards rows={data.exceptions.filter((item) => item.status === "active")} />
      </Section>
    </>
  );
}

function Risk({ data, mutate }: { data: DashboardData; mutate: (path: string, payload: unknown, success: string) => Promise<void> }) {
  return (
    <>
      <div className="metric-grid">
        <MetricCard label="Findings" value={totalOf(data, "risks", data.risks)} />
        <MetricCard label="Open Findings" value={data.risks.filter((risk) => risk.status !== "closed").length} />
        <MetricCard label="Active Exceptions" value={data.exceptions.filter((item) => item.status === "active").length} />
        <MetricCard label="Linked Incidents" value={totalOf(data, "incidents", data.incidents)} />
      </div>
      <Section title="Findings" description="Raised by platform rules (missing guardrails, failed evals, unregistered agents) or by people. Decide each one: mitigate, accept with an exception, or close.">
        <RiskCards rows={data.risks} total={totalOf(data, "risks", data.risks)} />
      </Section>
    </>
  );
}

function Controls({ data }: { data: DashboardData }) {
  return (
    <>
      <div className="metric-grid">
        <MetricCard label="Assessments" value={totalOf(data, "controls", data.controls)} />
        <MetricCard label="Passing" value={data.controls.filter((control) => control.status === "passing").length} />
        <MetricCard label="Missing" value={data.controls.filter((control) => control.status === "missing").length} />
        <MetricCard label="Trace Links" value={new Set(data.controls.flatMap((control) => control.evidence_trace_ids || [])).size} />
      </div>
      <Section title="Controls" description="Each control is passing with linked evidence or missing with the gap named. Control owners can waive with a rationale.">
        <ControlCards rows={data.controls} total={totalOf(data, "controls", data.controls)} />
      </Section>
    </>
  );
}

function Deployments({ data, mutate }: { data: DashboardData; mutate: (path: string, payload: unknown, success: string) => Promise<void> }) {
  return (
    <>
      <Section title="Deployments" description="Versions reported by your pipeline and their current status.">
        <DeploymentCards rows={data.deployments} />
      </Section>
      <Section title="Release gates" description="Open a gate to see what is blocking it. Approval needs a linked prompt version, passing eval evidence and a reviewer who did not submit the change.">
        <GateCards rows={data.deploymentGates} total={totalOf(data, "deploymentGates", data.deploymentGates)} />
      </Section>
    </>
  );
}

function Monitoring({ data }: { data: DashboardData }) {
  return (
    <>
      <div className="metric-grid">
        <MetricCard label="Traces" value={totalOf(data, "traces", data.traces)} />
        <MetricCard label="Model Calls" value={totalOf(data, "modelCalls", data.modelCalls)} />
        <MetricCard label="Agent Runs" value={totalOf(data, "agents", data.agents)} />
        <MetricCard label="Guardrails" value={totalOf(data, "guardrails", data.guardrails)} />
      </div>
      <Section title="Traces" description="One row per request. Open a trace to see every model call, tool use and guardrail decision inside it.">
        <TraceCards rows={data.traces} total={totalOf(data, "traces", data.traces)} />
      </Section>
      <div className="two-column">
        <Section title="Agent runs" description="Runs reported by the SDK or OpenTelemetry, with steps and tools used.">
          <AgentCards rows={data.agents} total={totalOf(data, "agents", data.agents)} />
        </Section>
        <Section title="Guardrails and evals" description="Guardrail decisions and evaluation results. Evals signed by your CI key are marked attested.">
          <GuardrailEvalCards guardrails={data.guardrails} evals={data.evals} />
        </Section>
      </div>
    </>
  );
}

function Incidents({ data, mutate }: { data: DashboardData; mutate: (path: string, payload: unknown, success: string) => Promise<void> }) {
  return (
    <Section title="Incidents" description="Open an incident to see the request that caused it, linked risks and controls, then close it with a root cause on record.">
      <IncidentCards rows={data.incidents} total={totalOf(data, "incidents", data.incidents)} />
    </Section>
  );
}

function ApplicationDetail({ detail, graph, mutate }: { detail: Record<string, any>; graph: Record<string, any> | null; mutate: Mutate }) {
  const application = detail.application;
  if (!application) return <EmptyState>The requested record is no longer available.</EmptyState>;
  return (
    <ObjectWorkspace title={application.application_name} subtitle={`${application.tenant_id || "Unscoped"} / ${application.environment || "unknown environment"}`}>
      <div className="detail-stack">
        <SystemHubHeader detail={detail} />
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
  if (!workflow) return <EmptyState>The requested record is no longer available.</EmptyState>;
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
  if (!task) return <EmptyState>The requested record is no longer available.</EmptyState>;
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
  if (!gate) return <EmptyState>The requested record is no longer available.</EmptyState>;
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
  if (!incident) return <EmptyState>The requested record is no longer available.</EmptyState>;
  return (
    <ObjectWorkspace title={incident.title} subtitle={`${incident.application_name} / ${incident.workflow_name} / ${incident.severity}`}>
      <div className="detail-rail">
        <MetricCard label="Status" value={incident.status} />
        <MetricCard label="Severity" value={incident.severity} />
        <MetricCard label="Risks" value={incident.risk_count} />
        <MetricCard label="Missing Controls" value={incident.missing_control_count} />
      </div>
      <div className="detail-stack">
        {incident.description ? (
          <Section title="What Was Reported" description="The account given when the incident was raised.">
            <p>{incident.description}</p>
          </Section>
        ) : null}
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

function ReviewCards({ rows, total }: { rows: Array<Record<string, any>>; total?: number }) {
  return (
    <RecordList total={total} empty="No review tasks are open.">
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

function GateCards({ rows, total }: { rows: Array<Record<string, any>>; total?: number }) {
  return (
    <RecordList total={total} empty="No deployment approval gates have been generated.">
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

function IncidentCards({ rows, total }: { rows: Array<Record<string, any>>; total?: number }) {
  return (
    <RecordList total={total} empty="No incidents have been reported.">
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

function RiskCards({ rows, total }: { rows: Array<Record<string, any>>; total?: number }) {
  return (
    <RecordList total={total} empty="No risk findings found for this tenant.">
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

function OwnerCards({ rows, total }: { rows: Array<Record<string, any>>; total?: number }) {
  return (
    <RecordList total={total} empty="No ownership records have been created.">
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
        <input placeholder="Email of the accountable owner" aria-label="Owner email" value={ownerRef} onChange={(event) => setOwnerRef(event.target.value)} />
        <input placeholder="Why this owner is accountable" aria-label="Assignment rationale" value={reason} onChange={(event) => setReason(event.target.value)} />
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
        <input placeholder="Business reason for exception" aria-label="Business reason for exception" value={reason} onChange={(event) => setReason(event.target.value)} />
        <input placeholder="Compensating control or owner" aria-label="Compensating control or owner" value={compensatingControl} onChange={(event) => setCompensatingControl(event.target.value)} />
        <input placeholder="YYYY-MM-DD expiry" aria-label="Exception expiry date (YYYY-MM-DD)" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
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
        <select aria-label="Decision" value={decision} onChange={(event) => setDecision(event.target.value)}>
          <option value="approve">Approve</option>
          <option value="reject">Reject</option>
          <option value="request_changes">Request changes</option>
          <option value="mitigate">Require mitigation</option>
        </select>
        <textarea placeholder="Rationale, required changes, or residual risk accepted by the reviewer" aria-label="Reviewer rationale" value={rationale} onChange={(event) => setRationale(event.target.value)} />
        <button
          disabled={rationale.trim().length < 12}
          title={rationale.trim().length < 12 ? "Enter a rationale before recording the decision" : undefined}
          onClick={() => mutate("/api/decisions", { target_type: "review_task", target_id: task.task_id, decision, rationale: decisionPacket }, "Review decision recorded.")}
        >
          Record decision
        </button>
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
        <textarea placeholder="Decision rationale, production condition, or blocker that prevents release" aria-label="Release decision rationale" value={rationale} onChange={(event) => setRationale(event.target.value)} />
        <button
          disabled={rationale.trim().length < 12}
          title={rationale.trim().length < 12 ? "Enter a rationale before recording the decision" : undefined}
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
          disabled={rationale.trim().length < 12}
          title={rationale.trim().length < 12 ? "Enter a rationale before recording the decision" : undefined}
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
        <textarea placeholder="Root cause" aria-label="Root cause" value={rootCause} onChange={(event) => setRootCause(event.target.value)} />
        <textarea placeholder="Customer or business impact" aria-label="Customer or business impact" value={customerImpact} onChange={(event) => setCustomerImpact(event.target.value)} />
        <textarea placeholder="Remediation completed" aria-label="Remediation completed" value={remediation} onChange={(event) => setRemediation(event.target.value)} />
        <textarea placeholder="Recurrence prevention or follow-up owner" aria-label="Recurrence prevention or follow-up owner" value={recurrencePrevention} onChange={(event) => setRecurrencePrevention(event.target.value)} />
      </div>
      <div className="inline-form workflow-action">
        <button
          disabled={rootCause.trim().length < 12}
          title={rootCause.trim().length < 12 ? "Document the root cause before closing" : undefined}
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

function ControlCards({ rows, total }: { rows: Array<Record<string, any>>; total?: number }) {
  return (
    <RecordList total={total} empty="No control assessments generated yet.">
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

function AgentCards({ rows, total }: { rows: Array<Record<string, any>>; total?: number }) {
  return (
    <RecordList total={total} empty="No agent run records found.">
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

type EvidenceRow = {
  id: string;
  type: "Guardrail" | "Eval";
  name: string;
  result: string;
  score?: number | null;
  trace_id: string;
  attested?: boolean;
  attestedKeyId?: string;
};

function GuardrailEvalCards({ guardrails, evals }: { guardrails: Array<Record<string, any>>; evals: Array<Record<string, any>> }) {
  const rows: EvidenceRow[] = [
    ...guardrails.map((row) => ({ id: `${row.trace_id}-${row.guardrail_name}`, type: "Guardrail" as const, name: row.guardrail_name, result: row.decision, score: row.score, trace_id: row.trace_id })),
    ...evals.map((row) => ({
      id: `${row.trace_id}-${row.eval_name}`,
      type: "Eval" as const,
      name: row.eval_name,
      result: row.passed ? "passed" : "failed",
      score: row.score,
      trace_id: row.trace_id,
      attested: typeof row.attested === "boolean" ? row.attested : undefined,
      attestedKeyId: typeof row.attested_key_id === "string" ? row.attested_key_id : undefined,
    })),
  ];
  return (
    <RecordList empty="No guardrail or evaluation records found.">
      {rows.map((row) => (
        <article className="record-card" key={row.id}>
          <div className="record-main">
            <span className="record-title">{row.type}: {row.name}</span>
            <span className="badge-row">
              <Badge value={row.result} />
              {row.attested !== undefined ? <Badge value={row.attested ? "attested" : "unattested"} /> : null}
            </span>
          </div>
          <p>
            Score: {row.score ?? "n/a"} / <a href={`#trace/${row.trace_id}`}>trace</a>
            {row.attestedKeyId ? <> · signed by <code>{row.attestedKeyId}</code></> : null}
          </p>
        </article>
      ))}
    </RecordList>
  );
}

function TraceCards({ rows, total }: { rows: Array<Record<string, any>>; total?: number }) {
  return (
    <RecordList total={total} empty="No request traces found.">
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

function DecisionCards({ rows, total }: { rows: Array<Record<string, any>>; total?: number }) {
  return (
    <RecordList total={total} empty="No decisions have been recorded.">
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

