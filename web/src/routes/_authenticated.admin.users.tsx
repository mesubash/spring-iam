import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { assignmentsApi, identitiesApi, rolesApi, scopesApi } from "@/api/resources";
import type { Assignment, IdentityAdmin } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { Can } from "@/components/iam/Can";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { Tag } from "@/components/iam/badges";
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
import { useAuthz } from "@/context/AuthzContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { formatDate } from "@/lib/format";
import { Copy } from "lucide-react";

export const Route = createFileRoute("/_authenticated/admin/users")({
  component: () => (
    <PermissionGuardedPage permission="platform.identity.read">
      <UsersPage />
    </PermissionGuardedPage>
  ),
});

function statusTone(status: IdentityAdmin["accountStatus"]): "success" | "warning" | "destructive" | "neutral" {
  switch (status) {
    case "ACTIVE":
      return "success";
    case "LOCKED":
      return "warning";
    case "SUSPENDED":
      return "warning";
    case "DEACTIVATED":
      return "destructive";
  }
}

function copyToClipboard(label: string, value: string) {
  navigator.clipboard
    .writeText(value)
    .then(() => toast.success(`${label} copied`))
    .catch(() => toast.error("Could not copy to clipboard"));
}

function UsersPage() {
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [status, setStatus] = useState("");
  const [creating, setCreating] = useState(false);
  const [selected, setSelected] = useState<IdentityAdmin | null>(null);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(query.trim()), 250);
    return () => clearTimeout(t);
  }, [query]);

  const q = useQuery({
    queryKey: ["identities", debounced, status],
    queryFn: () =>
      identitiesApi.list({
        query: debounced || undefined,
        status: status || undefined,
        limit: 100,
      }),
  });

  const columns: Column<IdentityAdmin>[] = [
    { key: "email", header: "Email", render: (u) => <span className="text-[13px]">{u.email}</span> },
    {
      key: "status",
      header: "Status",
      width: "110px",
      render: (u) => <Tag tone={statusTone(u.accountStatus)}>{u.accountStatus}</Tag>,
    },
    {
      key: "verified",
      header: "Verified",
      width: "90px",
      render: (u) =>
        u.emailVerified ? <Tag tone="success">Yes</Tag> : <Tag tone="warning">No</Tag>,
    },
    {
      key: "lastLogin",
      header: "Last login",
      width: "170px",
      render: (u) =>
        u.lastLoginAt ? formatDate(u.lastLoginAt) : <span className="text-[var(--muted-foreground)]">Never</span>,
    },
    { key: "created", header: "Created", width: "170px", render: (u) => formatDate(u.createdAt) },
  ];

  return (
    <div>
      <PageHeader
        title="Users"
        description="Accounts known to this IAM instance. Manage roles, credentials and status per user."
        actions={
          <Can permission="platform.identity.create">
            <Button onClick={() => setCreating(true)}>New user</Button>
          </Can>
        }
      />
      <div className="mb-3 flex gap-2">
        <Input
          placeholder="Search by email…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="max-w-xs"
        />
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="h-9 rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
        >
          <option value="">All statuses</option>
          <option>ACTIVE</option>
          <option>LOCKED</option>
          <option>SUSPENDED</option>
          <option>DEACTIVATED</option>
        </select>
      </div>
      <DataTable
        columns={columns}
        rows={q.data}
        loading={q.isLoading}
        empty={debounced || status ? "No users match the filter." : "No users."}
        rowKey={(u) => u.id}
        onRowClick={setSelected}
      />
      {creating ? <CreateUserDialog open onOpenChange={setCreating} /> : null}
      {selected ? (
        <UserDetailDialog
          open
          onOpenChange={(v) => !v && setSelected(null)}
          user={selected}
        />
      ) : null}
    </div>
  );
}

/* ------------------------------ Create user ----------------------------- */

function CreateUserDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const qc = useQueryClient();
  const { can } = useAuthz();
  const canAssign = can("platform.assignment.create");
  const rolesQ = useQuery({ queryKey: ["roles"], queryFn: () => rolesApi.list(), enabled: canAssign });
  const scopesQ = useQuery({ queryKey: ["scopes"], queryFn: () => scopesApi.list(), enabled: canAssign });

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [emailVerified, setEmailVerified] = useState(true);
  const [roleId, setRoleId] = useState("");
  const [scopeId, setScopeId] = useState("");
  const [tempPassword, setTempPassword] = useState<string | null>(null);
  const [createdEmail, setCreatedEmail] = useState("");

  const scopes = useMemo(
    () => [...(scopesQ.data ?? [])].sort((a, b) => a.path.localeCompare(b.path)),
    [scopesQ.data],
  );

  const create = useMutation({
    mutationFn: async () => {
      const created = await identitiesApi.create({
        email: email.trim(),
        password: password || undefined,
        emailVerified,
      });
      if (roleId && scopeId) {
        await assignmentsApi.create({
          subjectId: created.identity.id,
          subjectType: "USER",
          roleId,
          scopeId,
        });
      }
      return created;
    },
    onSuccess: (created) => {
      qc.invalidateQueries({ queryKey: ["identities"] });
      qc.invalidateQueries({ queryKey: ["assignments"] });
      if (created.temporaryPassword) {
        setCreatedEmail(created.identity.email);
        setTempPassword(created.temporaryPassword);
        toast.success("User created — copy the temporary password now");
      } else {
        toast.success("User created");
        onOpenChange(false);
      }
    },
    onError: (e: Error) => toast.error(e.message),
  });

  if (tempPassword) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Temporary password</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-[var(--muted-foreground)]">
            Share this with <span className="font-medium text-[var(--foreground)]">{createdEmail}</span>{" "}
            over a secure channel. It is shown only once.
          </p>
          <div className="flex items-center gap-2 rounded border border-[var(--border)] bg-[var(--background)] px-3 py-2">
            <code className="flex-1 break-all font-mono text-sm">{tempPassword}</code>
            <button
              type="button"
              onClick={() => copyToClipboard("Password", tempPassword)}
              aria-label="Copy password"
              className="rounded p-1 text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
            >
              <Copy className="h-4 w-4" />
            </button>
          </div>
          <DialogFooter>
            <Button onClick={() => onOpenChange(false)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>New user</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="u-email">Email</Label>
            <Input
              id="u-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="u-pass">Password</Label>
            <Input
              id="u-pass"
              type="text"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Leave blank to generate a temporary password"
              autoComplete="off"
            />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={emailVerified}
              onChange={(e) => setEmailVerified(e.target.checked)}
            />
            Mark email as verified (skip the verification loop)
          </label>
          <Can permission="platform.assignment.create">
            <div className="space-y-3 rounded border border-[var(--border)] p-3">
              <p className="text-xs font-medium text-[var(--muted-foreground)]">
                Initial role (optional)
              </p>
              <div className="space-y-1.5">
                <Label htmlFor="u-role">Role</Label>
                <select
                  id="u-role"
                  value={roleId}
                  onChange={(e) => setRoleId(e.target.value)}
                  className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
                >
                  <option value="">No role</option>
                  {(rolesQ.data ?? []).map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.displayName || r.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="u-scope">Scope</Label>
                <select
                  id="u-scope"
                  value={scopeId}
                  onChange={(e) => setScopeId(e.target.value)}
                  className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
                >
                  <option value="">Select a scope…</option>
                  {scopes.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.path}
                    </option>
                  ))}
                </select>
              </div>
              {roleId && !scopeId ? (
                <p className="text-xs text-[var(--warning)]">Pick a scope for the initial role.</p>
              ) : null}
            </div>
          </Can>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            Cancel
          </Button>
          <Button
            onClick={() => create.mutate()}
            disabled={create.isPending || !email.trim() || (!!roleId && !scopeId)}
          >
            {create.isPending ? "Creating…" : "Create user"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ------------------------------ User detail ----------------------------- */

function UserDetailDialog({
  open,
  onOpenChange,
  user,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  user: IdentityAdmin;
}) {
  const qc = useQueryClient();
  const { can } = useAuthz();

  // Keep the header fresh after status changes.
  const userQ = useQuery({
    queryKey: ["identity", user.id],
    queryFn: () => identitiesApi.get(user.id),
    initialData: user,
  });
  const u = userQ.data ?? user;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {u.email}
            <Tag tone={statusTone(u.accountStatus)}>{u.accountStatus}</Tag>
          </DialogTitle>
        </DialogHeader>

        <div className="flex items-center gap-2 text-xs text-[var(--muted-foreground)]">
          <span className="font-mono">{u.id}</span>
          <button
            type="button"
            onClick={() => copyToClipboard("Subject ID", u.id)}
            aria-label="Copy subject id"
            className="rounded p-0.5 hover:text-[var(--foreground)]"
          >
            <Copy className="h-3 w-3" />
          </button>
          <span>·</span>
          <span>{u.emailVerified ? "Verified" : "Unverified"}</span>
          <span>·</span>
          <span>Last login {u.lastLoginAt ? formatDate(u.lastLoginAt) : "never"}</span>
        </div>

        <div className="max-h-[60vh] space-y-5 overflow-y-auto pr-1">
          {can("platform.assignment.read") ? <UserRolesSection subjectId={u.id} /> : null}
          {can("platform.identity.update") ? (
            <>
              <AdminPasswordSection user={u} />
              <StatusSection
                user={u}
                onChanged={() => {
                  qc.invalidateQueries({ queryKey: ["identities"] });
                  qc.invalidateQueries({ queryKey: ["identity", u.id] });
                }}
              />
            </>
          ) : null}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ------------------------- Roles / assignments -------------------------- */

function UserRolesSection({ subjectId }: { subjectId: string }) {
  const qc = useQueryClient();
  const { can } = useAuthz();
  const assignmentsQ = useQuery({
    queryKey: ["assignments", subjectId],
    queryFn: () => assignmentsApi.list({ subjectId }),
  });
  const rolesQ = useQuery({ queryKey: ["roles"], queryFn: () => rolesApi.list() });
  const scopesQ = useQuery({ queryKey: ["scopes"], queryFn: () => scopesApi.list() });

  const roleName = useMemo(() => {
    const m = new Map<string, string>();
    for (const r of rolesQ.data ?? []) m.set(r.id, r.displayName || r.name);
    return m;
  }, [rolesQ.data]);
  const scopePath = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of scopesQ.data ?? []) m.set(s.id, s.path);
    return m;
  }, [scopesQ.data]);
  const scopes = useMemo(
    () => [...(scopesQ.data ?? [])].sort((a, b) => a.path.localeCompare(b.path)),
    [scopesQ.data],
  );

  const [roleId, setRoleId] = useState("");
  const [scopeId, setScopeId] = useState("");
  const [revoking, setRevoking] = useState<Assignment | null>(null);
  const [reason, setReason] = useState("");

  const active = (assignmentsQ.data ?? []).filter((a) => a.active && !a.revokedAt);

  const grant = useMutation({
    mutationFn: () =>
      assignmentsApi.create({ subjectId, subjectType: "USER", roleId, scopeId }),
    onSuccess: () => {
      toast.success("Role granted");
      qc.invalidateQueries({ queryKey: ["assignments"] });
      setRoleId("");
      setScopeId("");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const revoke = useMutation({
    mutationFn: () => assignmentsApi.revoke(revoking!.id, reason.trim()),
    onSuccess: () => {
      toast.success("Role revoked");
      qc.invalidateQueries({ queryKey: ["assignments"] });
      setRevoking(null);
      setReason("");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <section className="rounded border border-[var(--border)] p-3">
      <h3 className="text-sm font-semibold">Roles</h3>
      {assignmentsQ.isLoading ? (
        <p className="mt-2 text-xs text-[var(--muted-foreground)]">Loading…</p>
      ) : active.length === 0 ? (
        <p className="mt-2 text-xs text-[var(--muted-foreground)]">No active role assignments.</p>
      ) : (
        <ul className="mt-2 divide-y divide-[var(--border)]">
          {active.map((a) => (
            <li key={a.id} className="flex items-center justify-between gap-2 py-1.5">
              <div className="min-w-0">
                <span className="text-sm">{roleName.get(a.roleId) ?? a.roleId}</span>
                <span className="ml-2 font-mono text-xs text-[var(--muted-foreground)]">
                  {scopePath.get(a.scopeId) ?? a.scopeId}
                </span>
                {a.origin && a.origin !== "STANDARD" ? (
                  <Tag tone="neutral">{a.origin}</Tag>
                ) : null}
              </div>
              {can("platform.assignment.revoke") ? (
                <Button
                  variant="ghost"
                  size="sm"
                  style={{ color: "var(--destructive)" }}
                  onClick={() => setRevoking(a)}
                >
                  Revoke
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      )}

      {can("platform.assignment.create") ? (
        <div className="mt-3 flex flex-wrap items-end gap-2 border-t border-[var(--border)] pt-3">
          <div className="min-w-40 flex-1 space-y-1">
            <Label className="text-xs">Role</Label>
            <select
              value={roleId}
              onChange={(e) => setRoleId(e.target.value)}
              className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
            >
              <option value="">Select…</option>
              {(rolesQ.data ?? []).map((r) => (
                <option key={r.id} value={r.id}>
                  {r.displayName || r.name}
                </option>
              ))}
            </select>
          </div>
          <div className="min-w-40 flex-1 space-y-1">
            <Label className="text-xs">Scope</Label>
            <select
              value={scopeId}
              onChange={(e) => setScopeId(e.target.value)}
              className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
            >
              <option value="">Select…</option>
              {scopes.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.path}
                </option>
              ))}
            </select>
          </div>
          <Button
            onClick={() => grant.mutate()}
            disabled={grant.isPending || !roleId || !scopeId}
          >
            {grant.isPending ? "Granting…" : "Grant role"}
          </Button>
        </div>
      ) : null}

      <ConfirmDialog
        open={!!revoking}
        onOpenChange={(v) => {
          if (!v) {
            setRevoking(null);
            setReason("");
          }
        }}
        title="Revoke role"
        description="The user immediately loses this role. A reason is required for the audit trail."
        target={revoking ? roleName.get(revoking.roleId) ?? revoking.roleId : undefined}
        confirmLabel="Revoke"
        destructive
        pending={revoke.isPending}
        onConfirm={() => {
          if (!reason.trim()) {
            toast.error("A reason is required.");
            return;
          }
          revoke.mutate();
        }}
      >
        <div className="mt-2 space-y-1.5">
          <Label htmlFor="user-revoke-reason">Reason</Label>
          <Input
            id="user-revoke-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Why is this being revoked?"
            required
          />
        </div>
      </ConfirmDialog>
    </section>
  );
}

/* ----------------------------- Password reset --------------------------- */

function AdminPasswordSection({ user }: { user: IdentityAdmin }) {
  const [password, setPassword] = useState("");
  const [revokeSessions, setRevokeSessions] = useState(true);
  const [tempPassword, setTempPassword] = useState<string | null>(null);

  const reset = useMutation({
    mutationFn: () =>
      identitiesApi.setPassword(user.id, {
        newPassword: password || undefined,
        revokeSessions,
      }),
    onSuccess: (res) => {
      setPassword("");
      if (res.temporaryPassword) {
        setTempPassword(res.temporaryPassword);
        toast.success("Password reset — copy the temporary password now");
      } else {
        setTempPassword(null);
        toast.success(
          res.sessionsRevoked ? "Password set; all sessions revoked" : "Password set",
        );
      }
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <section className="rounded border border-[var(--border)] p-3">
      <h3 className="text-sm font-semibold">Reset password</h3>
      <p className="mt-0.5 text-xs text-[var(--muted-foreground)]">
        Leave blank to generate a temporary password (shown once).
      </p>
      <div className="mt-2 flex flex-wrap items-end gap-2">
        <div className="min-w-56 flex-1 space-y-1">
          <Label htmlFor="adm-pass" className="text-xs">
            New password
          </Label>
          <Input
            id="adm-pass"
            type="text"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Blank = generate"
            autoComplete="off"
          />
        </div>
        <Button variant="outline" onClick={() => reset.mutate()} disabled={reset.isPending}>
          {reset.isPending ? "Resetting…" : "Reset password"}
        </Button>
      </div>
      <label className="mt-2 flex items-center gap-2 text-xs text-[var(--muted-foreground)]">
        <input
          type="checkbox"
          checked={revokeSessions}
          onChange={(e) => setRevokeSessions(e.target.checked)}
        />
        Sign the user out of all devices
      </label>
      {tempPassword ? (
        <div className="mt-2 flex items-center gap-2 rounded border border-[var(--border)] bg-[var(--background)] px-3 py-2">
          <code className="flex-1 break-all font-mono text-sm">{tempPassword}</code>
          <button
            type="button"
            onClick={() => copyToClipboard("Password", tempPassword)}
            aria-label="Copy password"
            className="rounded p-1 text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
          >
            <Copy className="h-4 w-4" />
          </button>
        </div>
      ) : null}
    </section>
  );
}

/* ------------------------------ Status change --------------------------- */

function StatusSection({
  user,
  onChanged,
}: {
  user: IdentityAdmin;
  onChanged: () => void;
}) {
  const [status, setStatus] = useState<string>("");
  const [reason, setReason] = useState("");
  const [confirming, setConfirming] = useState(false);

  const targets = (["ACTIVE", "SUSPENDED", "DEACTIVATED"] as const).filter(
    (s) => s !== user.accountStatus,
  );

  const change = useMutation({
    mutationFn: () => identitiesApi.setStatus(user.id, status, reason.trim() || undefined),
    onSuccess: (updated) => {
      toast.success(`Account is now ${updated.accountStatus}`);
      setConfirming(false);
      setStatus("");
      setReason("");
      onChanged();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const destructive = status !== "ACTIVE";

  return (
    <section className="rounded border border-[var(--border)] p-3">
      <h3 className="text-sm font-semibold">Account status</h3>
      <p className="mt-0.5 text-xs text-[var(--muted-foreground)]">
        Suspending or deactivating revokes every session immediately. LOCKED is set automatically by
        failed-login protection.
      </p>
      <div className="mt-2 flex flex-wrap items-end gap-2">
        <div className="min-w-40 space-y-1">
          <Label className="text-xs">New status</Label>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
          >
            <option value="">Select…</option>
            {targets.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </div>
        <div className="min-w-56 flex-1 space-y-1">
          <Label className="text-xs">Reason (optional)</Label>
          <Input value={reason} onChange={(e) => setReason(e.target.value)} />
        </div>
        <Button
          variant="outline"
          style={destructive && status ? { color: "var(--destructive)" } : undefined}
          onClick={() => setConfirming(true)}
          disabled={!status || change.isPending}
        >
          Change status
        </Button>
      </div>
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title="Change account status"
        description={
          destructive
            ? "The user is signed out everywhere and cannot log in until reactivated."
            : "The account is restored and the user can sign in again."
        }
        target={`${user.email} → ${status}`}
        confirmLabel="Change status"
        destructive={destructive}
        pending={change.isPending}
        onConfirm={() => change.mutate()}
      />
    </section>
  );
}
