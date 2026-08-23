import { useCallback, useEffect, useRef, useState } from "react";

import { type PageMeta, type Scope, getJson, postJson } from "../api";
import { Button, Callout, Code } from "../design";
import { useResource } from "./useResource";
import { Badge, EmptyState, MetricCard, RecordList, Section, SkeletonCards, SkeletonMetrics } from "./ui";
import { toast } from "./toast";
import { confirm } from "./confirm";

const DATA_SENSITIVITY = ["public", "internal", "confidential", "restricted"];
const AUTONOMY = ["assistive", "supervised", "autonomous"];

/**
 * Deep-link handoff from the org overview into People & Access.
 *
 * A staffing or segregation-of-duties flag is only useful if the admin can act
 * on it. Rather than thread router state through both consoles, the overview
 * stashes the intent here and switches the route hash; the team console picks
 * it up on mount, pre-selects the relevant role, and scrolls to the assign
 * form. The value is consumed once so a later manual visit starts clean.
 */
let pendingRoleToStaff: string | null = null;

function staffRoleInTeamConsole(role: string): void {
  pendingRoleToStaff = role;
  window.location.hash = "team";
}

function consumePendingRole(): string | null {
  const role = pendingRoleToStaff;
  pendingRoleToStaff = null;
  return role;
}


function Feedback({ message }: { message: string }) {
  if (!message) return null;
  return <div className="message">{message}</div>;
}

function formatTimestamp(value: unknown): string {
  if (!value) return "no activity";
  const parsed = new Date(String(value));
  if (Number.isNaN(parsed.getTime())) return String(value);
  return parsed.toLocaleString();
}

// --- Intake ------------------------------------------------------------------

export function IntakeView({ scope }: { scope: Scope }) {
  const { value, error, reload } = useResource(() => getJson<{ intake: Array<Record<string, any>> }>("/api/intake", scope));
  const [form, setForm] = useState({
    application_name: "",
    use_case: "",
    description: "",
    intended_purpose: "",
    data_sensitivity: "internal",
    autonomy_level: "assistive",
    affects_individuals: false,
  });

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    try {
      await postJson("/api/intake", form);
      toast.success("Use case registered and routed for review.");
      setForm({ ...form, application_name: "", use_case: "", description: "", intended_purpose: "" });
      reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Submission failed.");
    }
  }

  const rows = value?.intake || [];
  return (
    <>
      <Feedback message={error} />
      <Section title="Register an AI use case" description="The risk tier is derived from data sensitivity, autonomy, and whether the system affects individuals.">
        <form className="admin-form" onSubmit={submit}>
          <label>
            Application
            <input value={form.application_name} onChange={(event) => setForm({ ...form, application_name: event.target.value })} required />
          </label>
          <label>
            Use case
            <input value={form.use_case} onChange={(event) => setForm({ ...form, use_case: event.target.value })} required />
          </label>
          <label className="wide">
            Description
            <textarea value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} required />
          </label>
          <label className="wide">
            Intended purpose
            <textarea value={form.intended_purpose} onChange={(event) => setForm({ ...form, intended_purpose: event.target.value })} required />
          </label>
          <label>
            Data sensitivity
            <select value={form.data_sensitivity} onChange={(event) => setForm({ ...form, data_sensitivity: event.target.value })}>
              {DATA_SENSITIVITY.map((level) => <option key={level} value={level}>{level}</option>)}
            </select>
          </label>
          <label>
            Autonomy
            <select value={form.autonomy_level} onChange={(event) => setForm({ ...form, autonomy_level: event.target.value })}>
              {AUTONOMY.map((level) => <option key={level} value={level}>{level}</option>)}
            </select>
          </label>
          <label className="check-row">
            <input type="checkbox" checked={form.affects_individuals} onChange={(event) => setForm({ ...form, affects_individuals: event.target.checked })} />
            Makes or influences decisions about individuals
          </label>
          <button type="submit">Submit for review</button>
        </form>
      </Section>
      <Section title="Registered use cases" description="Each submission opens an intake review task in the reviewer queue.">
        <RecordList empty="No AI use cases have been registered yet.">
          {rows.map((record) => (
            <article className="record-card" key={record.intake_id}>
              <div className="record-main">
                <span className="record-title">{record.application_name}: {record.use_case}</span>
                <Badge value={`tier ${record.risk_tier}`} />
              </div>
              <p>{record.intended_purpose}</p>
              <p>Status: {record.status} / sensitivity {record.data_sensitivity} / autonomy {record.autonomy_level}</p>
            </article>
          ))}
        </RecordList>
      </Section>
    </>
  );
}

// --- My Queue ----------------------------------------------------------------

export function MyQueue({ rows }: { rows: Array<Record<string, any>> }) {
  const open = rows.filter((task) => task.status === "open");
  return (
    <>
      <div className="metric-grid">
        <MetricCard label="Assigned To Me" value={rows.length} />
        <MetricCard label="Open" value={open.length} />
        <MetricCard label="Overdue" value={rows.filter((task) => task.escalation_status === "overdue" || task.escalation_status === "escalated").length} />
      </div>
      <Section title="Tasks routed to me" description="Review tasks where you are the named assignee. Open a task to record your decision.">
        {rows.length ? (
          <div className="record-list">
            {rows.map((task) => (
              <article className="record-card" key={task.task_id}>
                <div className="record-main">
                  <a className="record-title" href={`#review/${task.task_id}`}>{task.title}</a>
                  <Badge value={task.status} />
                </div>
                <p>{task.application_name} / {task.assigned_role || "unrouted"} / due {task.due_at || "not routed"}</p>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState>
            Nothing is waiting on you. Tasks appear here once a reviewer role is assigned to you and a use case enters review, so an empty queue means you are caught up.
          </EmptyState>
        )}
      </Section>
    </>
  );
}

// --- Platform overview (super admin) -----------------------------------------

type PlatformOverviewData = {
  tenants: { total: number; active: number; suspended: number };
  accounts: { total: number; super_admins: number; org_admins: number; pending_password_reset: number };
  ingestion: { events_total: number };
  recent_activity: Array<Record<string, any>>;
};

export function PlatformOverview() {
  const { value, error } = useResource(() => getJson<PlatformOverviewData>("/api/admin/overview"));
  if (error) return <Feedback message={error} />;
  if (!value) {
    return (
      <>
        <SkeletonMetrics count={4} />
        <Section title="Recent platform activity" description="Loading the most recent actions across every tenant.">
          <SkeletonCards count={4} />
        </Section>
      </>
    );
  }
  return (
    <>
      <div className="metric-grid">
        <MetricCard label="Tenants" value={value.tenants.total} note={`${value.tenants.active} active / ${value.tenants.suspended} suspended`} />
        <MetricCard label="Accounts" value={value.accounts.total} note={`${value.accounts.org_admins} org admins`} />
        <MetricCard label="Pending password reset" value={value.accounts.pending_password_reset} note="Accounts that must change password" />
        <MetricCard label="Telemetry events" value={value.ingestion.events_total} note="Total ingested across all tenants" />
      </div>
      <Section title="Recent platform activity" description="The most recent provisioning, identity, and governance actions across every tenant.">
        <RecordList empty="No activity recorded yet.">
          {value.recent_activity.map((entry) => (
            <article className="record-card" key={entry.id}>
              <div className="record-main">
                <span className="record-title">{entry.action}</span>
                <Badge value={entry.tenant_id || "platform"} />
              </div>
              <p>{entry.actor_ref} / {entry.target_type || "n/a"} {entry.target_id || ""}</p>
              <p>{formatTimestamp(entry.created_at)}</p>
            </article>
          ))}
        </RecordList>
      </Section>
    </>
  );
}

// --- Organizations (super admin) ---------------------------------------------

export function AdminConsole() {
  const orgs = useResource(() => getJson<{ organizations: Array<Record<string, any>> }>("/api/admin/organizations"));
  const [form, setForm] = useState({ tenant_id: "", name: "", admin_email: "", admin_display_name: "" });
  const [tempPassword, setTempPassword] = useState<{ user: string; password: string } | null>(null);

  async function provision(event: React.FormEvent) {
    event.preventDefault();
    setTempPassword(null);
    try {
      const result = await postJson<{ temporary_password: string | null }>("/api/admin/organizations", form);
      toast.success(`Organization '${form.name}' provisioned with administrator ${form.admin_email}.`);
      if (result.temporary_password) {
        setTempPassword({ user: form.admin_email, password: result.temporary_password });
      }
      setForm({ tenant_id: "", name: "", admin_email: "", admin_display_name: "" });
      orgs.reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Provisioning failed.");
    }
  }

  async function setStatus(tenantId: string, name: string, status: string) {
    if (status === "suspended") {
      const ok = await confirm({
        title: `Suspend ${name}?`,
        body: "Every account in this organization will be blocked from signing in until you reactivate it. In-flight governance work is preserved but cannot be acted on.",
        confirmLabel: "Suspend organization",
        tone: "danger",
      });
      if (!ok) return;
    }
    try {
      await postJson(`/api/admin/organizations/${encodeURIComponent(tenantId)}/status`, { status });
      toast.success(`Organization ${status === "active" ? "reactivated" : "suspended"}.`);
      orgs.reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Status change failed.");
    }
  }

  const rows = orgs.value?.organizations || [];
  return (
    <>
      <Feedback message={orgs.error} />
      {tempPassword ? (
        <div className="message">
          One-time password for {tempPassword.user}: <strong>{tempPassword.password}</strong>. Deliver it securely. The administrator must change it at first sign in. This is shown once.
        </div>
      ) : null}
      <Section title="Provision an organization" description="Creates the tenant and its first org administrator. A one-time password is generated for you to relay; the administrator must change it at first sign in.">
        <form className="admin-form" onSubmit={provision}>
          <label>
            Tenant id
            <input value={form.tenant_id} onChange={(event) => setForm({ ...form, tenant_id: event.target.value })} required />
          </label>
          <label>
            Organization name
            <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} required />
          </label>
          <label>
            Admin email
            <input type="email" value={form.admin_email} onChange={(event) => setForm({ ...form, admin_email: event.target.value })} required />
          </label>
          <label>
            Admin name
            <input value={form.admin_display_name} onChange={(event) => setForm({ ...form, admin_display_name: event.target.value })} required />
          </label>
          <button type="submit">Provision organization</button>
        </form>
      </Section>
      <Section title="Organizations" description="All tenants on the platform, with usage drawn from live telemetry and account records.">
        <RecordList empty="No organizations have been provisioned.">
          {rows.map((org) => (
            <article className="record-card" key={org.tenant_id}>
              <div className="record-main">
                <span className="record-title">{org.name}</span>
                <Badge value={org.status} />
              </div>
              <p>Tenant id: {org.tenant_id} / created by {org.created_by}</p>
              <div className="evidence-grid">
                <MetricCard label="Accounts" value={org.user_count ?? 0} />
                <MetricCard label="Applications" value={org.app_count ?? 0} />
                <MetricCard label="Last activity" value={formatTimestamp(org.last_activity)} />
              </div>
              <div className="inline-form">
                {org.status === "active" ? (
                  <button className="secondary" onClick={() => setStatus(org.tenant_id, org.name, "suspended")}>Suspend</button>
                ) : (
                  <button className="secondary" onClick={() => setStatus(org.tenant_id, org.name, "active")}>Activate</button>
                )}
              </div>
            </article>
          ))}
        </RecordList>
      </Section>
    </>
  );
}

// --- Accounts (super admin) --------------------------------------------------

export function PlatformUsers() {
  const { value, error, reload } = useResource(() => getJson<{ users: Array<Record<string, any>> }>("/api/admin/users"));
  const [tempPassword, setTempPassword] = useState<{ user: string; password: string } | null>(null);

  async function setStatus(userRef: string, name: string, status: string) {
    setTempPassword(null);
    if (status === "suspended") {
      const ok = await confirm({
        title: `Suspend ${name}?`,
        body: "This account will be signed out and blocked from signing in until reactivated.",
        confirmLabel: "Suspend account",
        tone: "danger",
      });
      if (!ok) return;
    }
    try {
      await postJson(`/api/admin/users/${encodeURIComponent(userRef)}/status`, { status });
      toast.success(`Account ${name} ${status === "active" ? "reactivated" : "suspended"}.`);
      reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Status change failed.");
    }
  }

  async function resetPassword(userRef: string, name: string) {
    setTempPassword(null);
    const ok = await confirm({
      title: `Reset password for ${name}?`,
      body: "The current password stops working immediately. A one-time password is issued that the user must change at next sign in.",
      confirmLabel: "Reset password",
    });
    if (!ok) return;
    try {
      const result = await postJson<{ temporary_password: string }>(`/api/admin/users/${encodeURIComponent(userRef)}/reset-password`, {});
      setTempPassword({ user: userRef, password: result.temporary_password });
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Reset failed.");
    }
  }

  const rows = value?.users || [];
  return (
    <>
      <Feedback message={error} />
      {tempPassword ? (
        <div className="message">
          Temporary password for {tempPassword.user}: <strong>{tempPassword.password}</strong>. Deliver it securely. The user must change it at next sign in.
        </div>
      ) : null}
      <Section title="Accounts" description="Every account on the platform. Suspend an account to block sign in, or issue a one-time password the user must change.">
        <RecordList empty="No users exist yet.">
          {rows.map((user) => (
            <article className="record-card" key={user.user_ref}>
              <div className="record-main">
                <span className="record-title">{user.display_name}</span>
                <Badge value={user.status} />
              </div>
              <p>{user.email} / {user.platform_role || user.tenant_id || "unassigned"}{user.must_change_password ? " / password reset pending" : ""}</p>
              {(user.roles || []).length ? <p>Roles: {(user.roles as string[]).join(", ")}</p> : null}
              <div className="inline-form">
                {user.status === "active" ? (
                  <button className="secondary" onClick={() => setStatus(user.user_ref, user.display_name, "suspended")}>Suspend</button>
                ) : (
                  <button className="secondary" onClick={() => setStatus(user.user_ref, user.display_name, "active")}>Reactivate</button>
                )}
                <button className="secondary" onClick={() => resetPassword(user.user_ref, user.display_name)}>Reset password</button>
              </div>
            </article>
          ))}
        </RecordList>
      </Section>
    </>
  );
}

// --- RBAC matrix editor (super admin) ----------------------------------------

export function RbacMatrixEditor() {
  const { value, error, reload } = useResource(() =>
    getJson<{
      roles: string[];
      permissions: Array<Record<string, any>>;
      role_permissions: Array<Record<string, any>>;
    }>("/api/admin/role-permissions"),
  );
  async function toggle(role: string, permission: string, granted: boolean) {
    try {
      await postJson("/api/admin/role-permissions", { role, permission, granted });
      toast.success(`${granted ? "Granted" : "Revoked"} ${permission} for ${role}.`);
      reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not update the matrix.");
    }
  }

  if (error) return <Feedback message={error} />;
  if (!value) {
    return (
      <Section title="Role and permission matrix" description="Loading the platform-global role and permission matrix.">
        <SkeletonCards count={5} />
      </Section>
    );
  }
  const held = new Set(value.role_permissions.map((row) => `${row.role}:${row.permission}`));
  // Pin the column count to the number of roles so the grid never collapses.
  const gridStyle = { gridTemplateColumns: `1.6fr repeat(${value.roles.length}, minmax(96px, 1fr))` };
  return (
    <>
      <Section title="Role and permission matrix" description="The platform-global definition of what each role can do. Changes apply to every tenant and are recorded in the audit log.">
        <div className="matrix">
          <div className="matrix-row matrix-head" style={gridStyle}>
            <span>Permission</span>
            {value.roles.map((role) => <span key={role}>{role}</span>)}
          </div>
          {value.permissions.map((permission) => (
            <div className="matrix-row" key={permission.permission} style={gridStyle}>
              <span title={permission.description}>{permission.permission}</span>
              {value.roles.map((role) => {
                const granted = held.has(`${role}:${permission.permission}`);
                return (
                  <span key={role}>
                    <button
                      className={granted ? "matrix-toggle on" : "matrix-toggle"}
                      onClick={() => toggle(role, permission.permission, !granted)}
                      aria-label={`${granted ? "Revoke" : "Grant"} ${permission.permission} for ${role}`}
                      aria-pressed={granted}
                      title={granted ? "Granted. Click to revoke." : "Denied. Click to grant."}
                    >
                      {granted ? "✓" : ""}
                    </button>
                  </span>
                );
              })}
            </div>
          ))}
        </div>
      </Section>
    </>
  );
}

// --- Organization overview (org admin) ---------------------------------------

type OrgOverviewData = {
  tenant_id: string;
  posture: Record<string, any>;
  staffing: Array<{ role: string; assignee_count: number; staffed: boolean }>;
  unstaffed_roles: string[];
  sod_conflicts: string[];
};

export function OrgOverview() {
  const { value, error } = useResource(() => getJson<OrgOverviewData>("/api/org/overview"));
  if (error) return <Feedback message={error} />;
  if (!value) {
    return (
      <>
        <SkeletonMetrics count={4} />
        <Section title="Accountability staffing" description="Loading required governance role coverage.">
          <SkeletonCards count={4} />
        </Section>
      </>
    );
  }
  const posture = value.posture;
  return (
    <>
      <div className="metric-grid">
        <MetricCard label="Applications" value={posture.applications} note={`${posture.model_calls} model calls observed`} />
        <MetricCard label="Open reviews" value={posture.open_reviews} note={`${posture.overdue_reviews} overdue`} />
        <MetricCard label="Open incidents" value={posture.open_incidents} note={`${posture.critical_incidents} critical or high`} />
        <MetricCard label="Unassigned owners" value={posture.unassigned_owners} note="Records without a named owner" />
      </div>
      <Section title="Accountability staffing" description="Every required governance role must have at least one active assignee. Unstaffed roles mean work cannot be routed to an accountable person.">
        <RecordList empty="No required roles configured.">
          {value.staffing.map((item) => (
            <article className="record-card" key={item.role}>
              <div className="record-main">
                <span className="record-title">{item.role}</span>
                <Badge value={item.staffed ? "staffed" : "unstaffed"} />
              </div>
              <p>{item.assignee_count} active assignee{item.assignee_count === 1 ? "" : "s"}</p>
              {item.staffed ? null : (
                <div className="flag-action">
                  <button onClick={() => staffRoleInTeamConsole(item.role)}>Assign someone to {item.role}</button>
                </div>
              )}
            </article>
          ))}
        </RecordList>
      </Section>
      <Section title="Segregation of duties" description="The same person owning and reviewing risk collapses the maker-checker boundary. Resolve any overlap by assigning distinct people.">
        {value.sod_conflicts.length ? (
          <RecordList empty="">
            {value.sod_conflicts.map((userRef) => (
              <article className="record-card" key={userRef}>
                <div className="record-main">
                  <span className="record-title">{userRef}</span>
                  <Badge value="conflict" />
                </div>
                <p>Holds both risk owner and reviewer roles. Revoke one to restore the maker-checker boundary.</p>
                <div className="flag-action">
                  <button onClick={() => { window.location.hash = "team"; }}>Resolve in People &amp; Access</button>
                </div>
              </article>
            ))}
          </RecordList>
        ) : (
          <div className="empty-state">No segregation of duties conflicts. Risk owners and reviewers are distinct people.</div>
        )}
      </Section>
    </>
  );
}

// --- Team (org admin) --------------------------------------------------------

export function TeamConsole() {
  const users = useResource(() => getJson<{ users: Array<Record<string, any>> }>("/api/org/users"));
  const roles = useResource(() =>
    getJson<{
      role_assignments: Array<Record<string, any>>;
      assignable_roles: string[];
      permissions: Array<Record<string, any>>;
      role_permissions: Array<Record<string, any>>;
    }>("/api/org/role-assignments"),
  );
  const [tempPassword, setTempPassword] = useState<{ user: string; password: string } | null>(null);
  const [invite, setInvite] = useState<{ user: string; url: string; emailed: boolean } | null>(null);
  const [userForm, setUserForm] = useState({ email: "", display_name: "" });
  const [assignForm, setAssignForm] = useState({ user_ref: "", role: "" });
  const assignRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const role = consumePendingRole();
    if (!role) return;
    setAssignForm((prev) => ({ ...prev, role }));
    requestAnimationFrame(() => assignRef.current?.scrollIntoView({ behavior: "smooth", block: "center" }));
  }, []);

  async function createUser(event: React.FormEvent) {
    event.preventDefault();
    setTempPassword(null);
    try {
      const result = await postJson<{ temporary_password: string | null; invite_url?: string; invite_emailed?: boolean }>("/api/org/users", userForm);
      toast.success(result.invite_emailed ? `Invitation emailed to ${userForm.email}.` : `User ${userForm.email} created.`);
      if (result.invite_url) {
        setInvite({ user: userForm.email, url: result.invite_url, emailed: Boolean(result.invite_emailed) });
      }
      if (result.temporary_password && !result.invite_emailed) {
        setTempPassword({ user: userForm.email, password: result.temporary_password });
      }
      setUserForm({ email: "", display_name: "" });
      users.reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not create user.");
    }
  }

  async function assignRole(event: React.FormEvent) {
    event.preventDefault();
    try {
      await postJson("/api/org/role-assignments", { ...assignForm, status: "active" });
      toast.success("Role assigned.");
      roles.reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not assign role.");
    }
  }

  async function revoke(user_ref: string, role: string) {
    const ok = await confirm({
      title: `Revoke ${role}?`,
      body: `${user_ref} will lose this role and any work routed to it immediately. You can reassign it later.`,
      confirmLabel: "Revoke role",
      tone: "danger",
    });
    if (!ok) return;
    try {
      await postJson("/api/org/role-assignments", { user_ref, role, status: "revoked" });
      toast.success(`Revoked ${role} from ${user_ref}.`);
      roles.reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not revoke role.");
    }
  }

  async function setUserStatus(userRef: string, name: string, status: string) {
    setTempPassword(null);
    if (status !== "active") {
      const ok = await confirm({
        title: `Deactivate ${name}?`,
        body: "This person will be signed out and blocked from signing in until reactivated. Their role assignments are kept.",
        confirmLabel: "Deactivate user",
        tone: "danger",
      });
      if (!ok) return;
    }
    try {
      await postJson(`/api/org/users/${encodeURIComponent(userRef)}/status`, { status });
      toast.success(`User ${name} ${status === "active" ? "reactivated" : "deactivated"}.`);
      users.reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not change user status.");
    }
  }

  async function resetUserPassword(userRef: string, name: string) {
    setTempPassword(null);
    const ok = await confirm({
      title: `Reset password for ${name}?`,
      body: "The current password stops working immediately. A one-time password is issued that the user must change at next sign in.",
      confirmLabel: "Reset password",
    });
    if (!ok) return;
    try {
      const result = await postJson<{ temporary_password: string }>(`/api/org/users/${encodeURIComponent(userRef)}/reset-password`, {});
      setTempPassword({ user: userRef, password: result.temporary_password });
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not reset password.");
    }
  }

  const assignableRoles = roles.value?.assignable_roles || [];
  const userRows = users.value?.users || [];
  const assignments = (roles.value?.role_assignments || []).filter((row) => row.status === "active");

  return (
    <>
      <Feedback message={users.error || roles.error} />
      {invite ? (
        <Callout tone={invite.emailed ? "success" : "info"} title={invite.emailed ? `Invitation emailed to ${invite.user}.` : `Invite link for ${invite.user}`}
          action={<Button variant="secondary" size="sm" onClick={() => navigator.clipboard?.writeText(invite.url)}>Copy link</Button>}>
          {invite.emailed ? "They set their own password through the link; it expires in 7 days." : "Email is not configured on this platform, so send this link yourself. They set their own password through it; it expires in 7 days."}
          <div><Code>{invite.url}</Code></div>
        </Callout>
      ) : null}
      {tempPassword ? (
        <div className="message">
          Fallback one-time password for {tempPassword.user}: <strong>{tempPassword.password}</strong> (if the invite link cannot be used). The user must change it at next sign in.
        </div>
      ) : null}
      <div className="two-column">
        <Section title="Invite a person" description="They receive an invite link (emailed when SMTP is configured) and set their own password. Give them a role next; administrators cannot hold decision roles.">
          <form className="admin-form" onSubmit={createUser}>
            <label>
              Email
              <input type="email" value={userForm.email} onChange={(event) => setUserForm({ ...userForm, email: event.target.value })} required />
            </label>
            <label>
              Display name
              <input value={userForm.display_name} onChange={(event) => setUserForm({ ...userForm, display_name: event.target.value })} required />
            </label>
            <button type="submit">Create user</button>
          </form>
        </Section>
        <div ref={assignRef}>
        <Section title="Assign a role" description="Grant a governance role to a user in your organization.">
          <form className="admin-form" onSubmit={assignRole}>
            <label>
              User
              <select value={assignForm.user_ref} onChange={(event) => setAssignForm({ ...assignForm, user_ref: event.target.value })} required>
                <option value="">Select a user</option>
                {userRows.map((user) => <option key={user.user_ref} value={user.user_ref}>{user.display_name}</option>)}
              </select>
            </label>
            <label>
              Role
              <select value={assignForm.role} onChange={(event) => setAssignForm({ ...assignForm, role: event.target.value })} required>
                <option value="">Select a role</option>
                {assignableRoles.map((role) => <option key={role} value={role}>{role}</option>)}
              </select>
            </label>
            <button type="submit">Assign role</button>
          </form>
        </Section>
        </div>
      </div>
      <Section title="Users" description="Members of your organization. Deactivate an account to block sign in, or issue a one-time password the user must change.">
        <RecordList empty="No users yet. Add your team with the Create a user form above, then assign each person a governance role.">
          {userRows.map((user) => (
            <article className="record-card" key={user.user_ref}>
              <div className="record-main">
                <span className="record-title">{user.display_name}</span>
                <Badge value={user.status} />
              </div>
              <p>{user.email}{user.must_change_password ? " / password reset pending" : ""}</p>
              {(user.roles || []).length ? <p>Roles: {(user.roles as string[]).join(", ")}</p> : null}
              <div className="inline-form">
                {user.status === "active" ? (
                  <button className="secondary" onClick={() => setUserStatus(user.user_ref, user.display_name, "suspended")}>Deactivate</button>
                ) : (
                  <button className="secondary" onClick={() => setUserStatus(user.user_ref, user.display_name, "active")}>Reactivate</button>
                )}
                <button className="secondary" onClick={() => resetUserPassword(user.user_ref, user.display_name)}>Reset password</button>
              </div>
            </article>
          ))}
        </RecordList>
      </Section>
      <Section title="Active role assignments" description="Who holds which role in your organization.">
        <RecordList empty="No roles assigned yet. Use Assign a role above so governance work can route to an accountable person.">
          {assignments.map((assignment) => (
            <article className="record-card" key={assignment.role_assignment_id}>
              <div className="record-main">
                <span className="record-title">{assignment.user_ref}</span>
                <Badge value={assignment.role} />
              </div>
              <div className="inline-form">
                <button className="secondary" onClick={() => revoke(assignment.user_ref, assignment.role)}>Revoke</button>
              </div>
            </article>
          ))}
        </RecordList>
      </Section>
      <RolePermissionMatrix permissions={roles.value?.permissions || []} rolePermissions={roles.value?.role_permissions || []} roles={assignableRoles} />
    </>
  );
}

function RolePermissionMatrix({
  permissions,
  rolePermissions,
  roles,
}: {
  permissions: Array<Record<string, any>>;
  rolePermissions: Array<Record<string, any>>;
  roles: string[];
}) {
  if (!permissions.length) return null;
  const held = new Set(rolePermissions.map((row) => `${row.role}:${row.permission}`));
  const gridStyle = { gridTemplateColumns: `1.6fr repeat(${roles.length}, minmax(96px, 1fr))` };
  return (
    <Section title="Role and permission reference" description="Permissions granted to each role. The platform administrator manages this matrix.">
      <div className="matrix">
        <div className="matrix-row matrix-head" style={gridStyle}>
          <span>Permission</span>
          {roles.map((role) => <span key={role}>{role}</span>)}
        </div>
        {permissions.map((permission) => (
          <div className="matrix-row" key={permission.permission} style={gridStyle}>
            <span title={permission.description}>{permission.permission}</span>
            {roles.map((role) => (
              <span key={role} className="matrix-mark">{held.has(`${role}:${permission.permission}`) ? "✓" : ""}</span>
            ))}
          </div>
        ))}
      </div>
    </Section>
  );
}

// --- Audit log ---------------------------------------------------------------

const AUDIT_PAGE_SIZE = 50;

export function AuditLog({ superAdmin = false }: { superAdmin?: boolean }) {
  const [filters, setFilters] = useState({ tenant_id: "", actor_ref: "", action: "" });
  const [applied, setApplied] = useState({ tenant_id: "", actor_ref: "", action: "" });
  const [offset, setOffset] = useState(0);

  const query = useCallback(() => {
    const params = new URLSearchParams();
    if (superAdmin && applied.tenant_id) params.set("tenant_id", applied.tenant_id);
    if (applied.actor_ref) params.set("actor_ref", applied.actor_ref);
    if (applied.action) params.set("action", applied.action);
    params.set("offset", String(offset));
    params.set("limit", String(AUDIT_PAGE_SIZE));
    return getJson<{ audit_logs: Array<Record<string, any>>; page: PageMeta }>(`/api/audit-logs?${params.toString()}`);
  }, [applied, offset, superAdmin]);

  const { value, error, reload } = useResource(query);
  const rows = value?.audit_logs || [];
  const page = value?.page;
  const total = page?.total ?? rows.length;
  const pageNumber = Math.floor(offset / AUDIT_PAGE_SIZE) + 1;
  const pageCount = Math.max(1, Math.ceil(total / AUDIT_PAGE_SIZE));

  function submit(event: React.FormEvent) {
    event.preventDefault();
    setOffset(0);
    setApplied({ ...filters });
  }

  useEffect(() => {
    reload();
  }, [applied, offset, reload]);

  return (
    <>
      <Feedback message={error} />
      <Section title="Audit log" description="Append-only record of identity, administrative, and governance decision actions.">
        <form className="admin-form" onSubmit={submit}>
          {superAdmin ? (
            <label>
              Tenant
              <input value={filters.tenant_id} placeholder="All tenants" onChange={(event) => setFilters({ ...filters, tenant_id: event.target.value })} />
            </label>
          ) : null}
          <label>
            Actor
            <input value={filters.actor_ref} placeholder="Any actor" onChange={(event) => setFilters({ ...filters, actor_ref: event.target.value })} />
          </label>
          <label>
            Action
            <input value={filters.action} placeholder="e.g. role.assign" onChange={(event) => setFilters({ ...filters, action: event.target.value })} />
          </label>
          <button type="submit">Apply filters</button>
        </form>
        <RecordList empty="No audit entries match the current filters." pageSize={AUDIT_PAGE_SIZE} label="entries">
          {rows.map((entry) => (
            <article className="record-card" key={entry.id}>
              <div className="record-main">
                <span className="record-title">{entry.action}</span>
                <Badge value={entry.tenant_id || "platform"} />
              </div>
              <p>{entry.actor_ref} / {entry.target_type || "n/a"} {entry.target_id || ""}</p>
              <p>{formatTimestamp(entry.created_at)}</p>
            </article>
          ))}
        </RecordList>
        {total > AUDIT_PAGE_SIZE ? (
          <nav className="pager" aria-label="Audit log pages">
            <button type="button" className="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - AUDIT_PAGE_SIZE))}>
              Newer
            </button>
            <span className="muted" role="status" aria-live="polite">
              Page {pageNumber} of {pageCount} · {total} entries
            </span>
            <button type="button" className="secondary" disabled={!page?.has_more} onClick={() => setOffset(offset + AUDIT_PAGE_SIZE)}>
              Older
            </button>
          </nav>
        ) : null}
      </Section>
    </>
  );
}
