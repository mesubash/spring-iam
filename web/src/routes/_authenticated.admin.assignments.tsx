import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { assignmentsApi, breakGlassApi, rolesApi, scopesApi } from "@/api/resources";
import type { Assignment } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { Can } from "@/components/iam/Can";
import { SubjectPicker } from "@/components/iam/SubjectPicker";
import { useAuthz } from "@/context/AuthzContext";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { Tag } from "@/components/iam/badges";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { formatDate, isExpiring } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/admin/assignments")({
  component: () => (
    <PermissionGuardedPage permission="platform.assignment.read">
      <AssignmentsPage />
    </PermissionGuardedPage>
  ),
});

function statusOf(a: Assignment): { label: string; tone: "success" | "destructive" | "warning" } {
  if (a.revokedAt) return { label: "Revoked", tone: "destructive" };
  if (a.expiresAt && new Date(a.expiresAt).getTime() < Date.now())
    return { label: "Expired", tone: "warning" };
  if (!a.active) return { label: "Inactive", tone: "warning" };
  return { label: "Active", tone: "success" };
}

function AssignmentsPage() {
  const [subjectFilter, setSubjectFilter] = useState("");
  const subjectId = subjectFilter.trim();
  const q = useQuery({
    queryKey: ["assignments", subjectId || "all"],
    queryFn: () => assignmentsApi.list(subjectId ? { subjectId } : undefined),
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

  const { features } = useAuthz();
  const [createOpen, setCreateOpen] = useState(false);
  const [breakGlassOpen, setBreakGlassOpen] = useState(false);
  const [revoking, setRevoking] = useState<Assignment | null>(null);
  const [reason, setReason] = useState("");
  const qc = useQueryClient();

  const revoke = useMutation({
    mutationFn: () => assignmentsApi.revoke(revoking!.id, reason.trim()),
    onSuccess: () => {
      toast.success("Assignment revoked");
      qc.invalidateQueries({ queryKey: ["assignments"] });
      setRevoking(null);
      setReason("");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<Assignment>[] = [
    {
      key: "subject",
      header: "Subject",
      render: (a) => (
        <span className="font-mono text-xs" title={a.subjectType}>
          {a.subjectId}
        </span>
      ),
    },
    {
      key: "role",
      header: "Role",
      render: (a) => roleName.get(a.roleId) ?? <span className="font-mono text-xs">{a.roleId}</span>,
    },
    {
      key: "scope",
      header: "Scope",
      render: (a) => (
        <span className="font-mono text-xs">
          {scopePath.get(a.scopeId) ?? a.scopeId}
        </span>
      ),
    },
    {
      key: "origin",
      header: "Origin",
      width: "110px",
      render: (a) => <Tag tone="neutral">{a.origin ?? "STANDARD"}</Tag>,
    },
    {
      key: "expires",
      header: "Expires",
      width: "160px",
      render: (a) =>
        a.expiresAt ? (
          isExpiring(a.expiresAt) ? (
            <Tag tone="warning">{formatDate(a.expiresAt)}</Tag>
          ) : (
            <span>{formatDate(a.expiresAt)}</span>
          )
        ) : (
          <span className="text-[var(--muted-foreground)]">—</span>
        ),
    },
    {
      key: "status",
      header: "Status",
      width: "100px",
      render: (a) => {
        const s = statusOf(a);
        return <Tag tone={s.tone}>{s.label}</Tag>;
      },
    },
    {
      key: "actions",
      header: "",
      width: "90px",
      render: (a) =>
        a.active && !a.revokedAt ? (
          <Can permission="platform.assignment.revoke">
            <Button
              variant="ghost"
              size="sm"
              style={{ color: "var(--destructive)" }}
              onClick={() => setRevoking(a)}
            >
              Revoke
            </Button>
          </Can>
        ) : null,
    },
  ];

  return (
    <div>
      <PageHeader
        title="Assignments"
        description="Role grants of subjects at scopes."
        actions={
          <Can permission="platform.assignment.create">
            <div className="flex gap-2">
              {features?.["break-glass"] ? (
                <Button variant="outline" onClick={() => setBreakGlassOpen(true)}>
                  Break-glass
                </Button>
              ) : null}
              <Button onClick={() => setCreateOpen(true)}>Grant assignment</Button>
            </div>
          </Can>
        }
      />
      <div className="mb-3 max-w-sm">
        <SubjectPicker
          value={subjectFilter}
          onChange={setSubjectFilter}
          placeholder="Filter by user…"
        />
      </div>
      <DataTable
        columns={columns}
        rows={q.data}
        loading={q.isLoading}
        empty={subjectId ? "No assignments for this subject." : "No assignments."}
        rowKey={(a) => a.id}
      />
      {createOpen ? <GrantDialog open onOpenChange={setCreateOpen} /> : null}
      {breakGlassOpen ? <BreakGlassDialog open onOpenChange={setBreakGlassOpen} /> : null}
      <ConfirmDialog
        open={!!revoking}
        onOpenChange={(v) => {
          if (!v) {
            setRevoking(null);
            setReason("");
          }
        }}
        title="Revoke assignment"
        description="The subject immediately loses this role. A reason is required for the audit trail."
        target={
          revoking
            ? `${roleName.get(revoking.roleId) ?? revoking.roleId} → ${revoking.subjectId}`
            : undefined
        }
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
          <Label htmlFor="revoke-reason">Reason</Label>
          <Input
            id="revoke-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Why is this being revoked?"
            required
          />
        </div>
      </ConfirmDialog>
    </div>
  );
}

function GrantDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const rolesQ = useQuery({ queryKey: ["roles"], queryFn: () => rolesApi.list() });
  const scopesQ = useQuery({ queryKey: ["scopes"], queryFn: () => scopesApi.list() });
  const [subjectId, setSubjectId] = useState("");
  const [subjectType, setSubjectType] = useState("USER");
  const [roleId, setRoleId] = useState("");
  const [scopeId, setScopeId] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [conditions, setConditions] = useState("");

  const conditionsInvalid = useMemo(() => {
    if (!conditions.trim()) return false;
    try {
      JSON.parse(conditions);
      return false;
    } catch {
      return true;
    }
  }, [conditions]);

  const canSubmit = !!subjectId.trim() && !!roleId && !!scopeId && !conditionsInvalid;

  const m = useMutation({
    mutationFn: () =>
      assignmentsApi.create({
        subjectId: subjectId.trim(),
        subjectType,
        roleId,
        scopeId,
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : undefined,
        conditions: conditions.trim()
          ? (JSON.parse(conditions) as Record<string, unknown>)
          : undefined,
      }),
    onSuccess: () => {
      toast.success("Assignment granted");
      qc.invalidateQueries({ queryKey: ["assignments"] });
      onOpenChange(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const scopes = useMemo(
    () => [...(scopesQ.data ?? [])].sort((a, b) => a.path.localeCompare(b.path)),
    [scopesQ.data],
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Grant assignment</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="a-sub">Subject</Label>
            <SubjectPicker id="a-sub" value={subjectId} onChange={setSubjectId} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="a-st">Subject type</Label>
            <select
              id="a-st"
              value={subjectType}
              onChange={(e) => setSubjectType(e.target.value)}
              className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
            >
              <option value="USER">USER</option>
              <option value="SERVICE">SERVICE</option>
              <option value="GROUP">GROUP</option>
            </select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="a-role">Role</Label>
            <select
              id="a-role"
              value={roleId}
              onChange={(e) => setRoleId(e.target.value)}
              className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
            >
              <option value="">Select a role…</option>
              {(rolesQ.data ?? []).map((r) => (
                <option key={r.id} value={r.id}>
                  {r.displayName || r.name}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="a-scope">Scope</Label>
            <select
              id="a-scope"
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
          <div className="space-y-1.5">
            <Label htmlFor="a-exp">Expires at (optional)</Label>
            <Input
              id="a-exp"
              type="datetime-local"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="a-cond">Conditions JSON (optional)</Label>
            <textarea
              id="a-cond"
              value={conditions}
              onChange={(e) => setConditions(e.target.value)}
              rows={3}
              placeholder='{"ipRange": "10.0.0.0/8"}'
              className="w-full rounded border border-[var(--border)] bg-[var(--card)] p-2 font-mono text-xs"
            />
            {conditionsInvalid ? (
              <p className="text-xs text-[var(--destructive)]">Conditions must be valid JSON.</p>
            ) : null}
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={m.isPending}>
            Cancel
          </Button>
          <Button onClick={() => m.mutate()} disabled={m.isPending || !canSubmit}>
            {m.isPending ? "Granting..." : "Grant"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function BreakGlassDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const qc = useQueryClient();
  const rolesQ = useQuery({ queryKey: ["roles"], queryFn: () => rolesApi.list() });
  const scopesQ = useQuery({ queryKey: ["scopes"], queryFn: () => scopesApi.list() });
  const [subjectId, setSubjectId] = useState("");
  const [roleId, setRoleId] = useState("");
  const [scopeId, setScopeId] = useState("");
  const [durationMinutes, setDurationMinutes] = useState("60");
  const [reason, setReason] = useState("");
  const [referenceId, setReferenceId] = useState("");

  const scopes = useMemo(
    () => [...(scopesQ.data ?? [])].sort((a, b) => a.path.localeCompare(b.path)),
    [scopesQ.data],
  );

  const canSubmit =
    !!subjectId.trim() && !!roleId && !!scopeId && !!reason.trim() && Number(durationMinutes) > 0;

  const m = useMutation({
    mutationFn: () =>
      breakGlassApi.grant({
        subjectId: subjectId.trim(),
        roleId,
        scopeId,
        durationMinutes: Number(durationMinutes),
        reason: reason.trim(),
        referenceId: referenceId.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Break-glass access granted");
      qc.invalidateQueries({ queryKey: ["assignments"] });
      onOpenChange(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Break-glass access</DialogTitle>
        </DialogHeader>
        <div className="mb-1 rounded border border-[var(--warning)] bg-[var(--warning-subtle)] px-3 py-2 text-xs text-[var(--warning)]">
          Emergency, time-boxed elevation. The grant is fully audited and expires automatically.
          Use only for genuine incidents.
        </div>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="bg-sub">Subject</Label>
            <SubjectPicker id="bg-sub" value={subjectId} onChange={setSubjectId} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="bg-role">Role</Label>
            <select
              id="bg-role"
              value={roleId}
              onChange={(e) => setRoleId(e.target.value)}
              className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
            >
              <option value="">Select a role…</option>
              {(rolesQ.data ?? []).map((r) => (
                <option key={r.id} value={r.id}>
                  {r.displayName || r.name}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="bg-scope">Scope</Label>
            <select
              id="bg-scope"
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
          <div className="space-y-1.5">
            <Label htmlFor="bg-dur">Duration (minutes)</Label>
            <Input
              id="bg-dur"
              type="number"
              min={1}
              value={durationMinutes}
              onChange={(e) => setDurationMinutes(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="bg-reason">Reason (required)</Label>
            <Input
              id="bg-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Incident reference or justification"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="bg-ref">Reference ID (optional)</Label>
            <Input
              id="bg-ref"
              value={referenceId}
              onChange={(e) => setReferenceId(e.target.value)}
              placeholder="e.g. INC-1234"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={m.isPending}>
            Cancel
          </Button>
          <Button onClick={() => m.mutate()} disabled={m.isPending || !canSubmit}>
            {m.isPending ? "Granting…" : "Grant break-glass"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
