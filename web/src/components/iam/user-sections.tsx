import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { assignmentsApi, identitiesApi, rolesApi, scopesApi } from "@/api/resources";
import type { Assignment, IdentityAdmin } from "@/api/types";
import { Tag } from "@/components/iam/badges";
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
import { useAuthz } from "@/context/AuthzContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Copy } from "lucide-react";

// Sections of the user detail page, kept out of the route file so the users
// list can share statusTone/copyToClipboard without pulling the page in.

export function statusTone(
  status: IdentityAdmin["accountStatus"],
): "success" | "warning" | "destructive" | "neutral" {
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

export function copyToClipboard(label: string, value: string) {
  navigator.clipboard
    .writeText(value)
    .then(() => toast.success(`${label} copied`))
    .catch(() => toast.error("Could not copy to clipboard"));
}

/* ------------------------- Roles / assignments -------------------------- */

export function UserRolesSection({ subjectId }: { subjectId: string }) {
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

  // Prefill with the user's current role and scope so the form reflects what
  // they hold; the button arms only for a combination not already assigned.
  useEffect(() => {
    if (!roleId && !scopeId && active.length > 0) {
      setRoleId(active[0].roleId);
      setScopeId(active[0].scopeId);
    }
  }, [roleId, scopeId, active]);

  const alreadyAssigned = active.some((a) => a.roleId === roleId && a.scopeId === scopeId);

  const grant = useMutation({
    mutationFn: () => assignmentsApi.create({ subjectId, subjectType: "USER", roleId, scopeId }),
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
                {a.origin && a.origin !== "STANDARD" ? <Tag tone="neutral">{a.origin}</Tag> : null}
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
          <p className="w-full text-xs font-medium text-[var(--muted-foreground)]">
            Grant another role
          </p>
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
            variant={roleId && scopeId && !alreadyAssigned ? "default" : "outline"}
            onClick={() => grant.mutate()}
            disabled={grant.isPending || !roleId || !scopeId || alreadyAssigned}
          >
            {grant.isPending ? "Granting…" : "Grant role"}
          </Button>
          {alreadyAssigned ? (
            <p className="w-full text-xs text-[var(--muted-foreground)]">
              This role is already assigned at this scope. Change either to grant something new.
            </p>
          ) : null}
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
        target={revoking ? (roleName.get(revoking.roleId) ?? revoking.roleId) : undefined}
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

export function AdminPasswordSection({ user }: { user: IdentityAdmin }) {
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
        toast.success(res.sessionsRevoked ? "Password set; all sessions revoked" : "Password set");
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

/* ------------------------------- MFA reset ------------------------------ */

export function MfaResetSection({ user }: { user: IdentityAdmin }) {
  const qc = useQueryClient();
  const [confirming, setConfirming] = useState(false);

  const reset = useMutation({
    mutationFn: () => identitiesApi.resetMfa(user.id),
    onSuccess: () => {
      toast.success("MFA reset. The user sets it up again at next sign-in if required.");
      setConfirming(false);
      qc.invalidateQueries({ queryKey: ["identities"] });
      qc.invalidateQueries({ queryKey: ["identity", user.id] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <section className="rounded border border-[var(--border)] p-3">
      <h3 className="text-sm font-semibold">Two-factor authentication</h3>
      <p className="mt-0.5 text-xs text-[var(--muted-foreground)]">
        MFA is enabled. Reset it when the user has lost their authenticator and recovery codes.
      </p>
      <Button
        variant="outline"
        className="mt-2"
        style={{ color: "var(--destructive)" }}
        onClick={() => setConfirming(true)}
      >
        Reset MFA
      </Button>
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title="Reset this user's MFA"
        description="Removes their authenticator and recovery codes. If MFA is required for their role, they must set it up again at next sign-in. This is audited."
        target={user.email}
        confirmLabel="Reset MFA"
        destructive
        pending={reset.isPending}
        onConfirm={() => reset.mutate()}
      />
    </section>
  );
}

/* ------------------------------ Status change --------------------------- */

export function StatusSection({ user, onChanged }: { user: IdentityAdmin; onChanged: () => void }) {
  // Prefilled with the current status; the button arms only on a change.
  const [status, setStatus] = useState<string>(user.accountStatus);
  const [reason, setReason] = useState("");
  const [confirming, setConfirming] = useState(false);

  const change = useMutation({
    mutationFn: () => identitiesApi.setStatus(user.id, status, reason.trim() || undefined),
    onSuccess: (updated) => {
      toast.success(`Account is now ${updated.accountStatus}`);
      setConfirming(false);
      setStatus(updated.accountStatus);
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
          <Label htmlFor="user-status" className="text-xs">
            Status
          </Label>
          <select
            id="user-status"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
          >
            {user.accountStatus === "LOCKED" ? (
              <option value="LOCKED">LOCKED (current)</option>
            ) : null}
            {(["ACTIVE", "SUSPENDED", "DEACTIVATED"] as const).map((s) => (
              <option key={s} value={s}>
                {s === user.accountStatus ? `${s} (current)` : s}
              </option>
            ))}
          </select>
        </div>
        <div className="min-w-56 flex-1 space-y-1">
          <Label className="text-xs">Reason (optional)</Label>
          <Input value={reason} onChange={(e) => setReason(e.target.value)} />
        </div>
        <Button
          variant="outline"
          style={
            destructive && status !== user.accountStatus
              ? { color: "var(--destructive)" }
              : undefined
          }
          onClick={() => setConfirming(true)}
          disabled={status === user.accountStatus || change.isPending}
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
