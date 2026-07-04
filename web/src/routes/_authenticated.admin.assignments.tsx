import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { assignmentsApi, rolesApi } from "@/api/resources";
import type { Assignment } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { Can } from "@/components/iam/Can";
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
  head: () => ({ meta: [{ title: "Assignments — IAM Console" }] }),
  component: () => (
    <PermissionGuardedPage permission="platform.assignment.read">
      <AssignmentsPage />
    </PermissionGuardedPage>
  ),
});

function AssignmentsPage() {
  const [subjectId, setSubjectId] = useState("");
  const q = useQuery({
    queryKey: ["assignments", subjectId || null],
    queryFn: () => assignmentsApi.list(subjectId ? { subjectId } : undefined),
  });
  const [createOpen, setCreateOpen] = useState(false);
  const [revoking, setRevoking] = useState<Assignment | null>(null);
  const [reason, setReason] = useState("");
  const qc = useQueryClient();

  const revoke = useMutation({
    mutationFn: () => assignmentsApi.revoke(revoking!.id, reason),
    onSuccess: () => {
      toast.success("Assignment revoked");
      qc.invalidateQueries({ queryKey: ["assignments"] });
      setRevoking(null);
      setReason("");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<Assignment>[] = [
    { key: "subject", header: "Subject", render: (a) => <span className="font-mono text-xs">{a.subjectId}</span> },
    { key: "role", header: "Role", render: (a) => a.roleName ?? <span className="font-mono text-xs">{a.roleId}</span> },
    {
      key: "scope",
      header: "Scope",
      render: (a) => (a.scopePath ? <span className="font-mono text-xs">{a.scopePath}</span> : <Tag>Global</Tag>),
    },
    {
      key: "expires",
      header: "Expires",
      render: (a) =>
        a.expiresAt ? (
          <span className={isExpiring(a.expiresAt) ? "text-[var(--warning)]" : undefined}>
            {formatDate(a.expiresAt)}
          </span>
        ) : (
          "—"
        ),
    },
    { key: "origin", header: "Origin", width: "110px", render: (a) => <Tag>{a.origin ?? "direct"}</Tag> },
    {
      key: "actions",
      header: "",
      width: "100px",
      render: (a) => (
        <Can permission="platform.assignment.revoke">
          <Button variant="ghost" size="sm" style={{ color: "var(--destructive)" }} onClick={() => setRevoking(a)}>
            Revoke
          </Button>
        </Can>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Assignments"
        description="Role grants of subjects at scopes."
        actions={
          <Can permission="platform.assignment.create">
            <Button onClick={() => setCreateOpen(true)}>Grant assignment</Button>
          </Can>
        }
      />
      <div className="mb-3">
        <Input
          placeholder="Filter by subjectId..."
          value={subjectId}
          onChange={(e) => setSubjectId(e.target.value)}
          className="max-w-xs"
        />
      </div>
      <DataTable
        columns={columns}
        rows={q.data}
        loading={q.isLoading}
        empty="No assignments."
        rowKey={(a) => a.id}
      />
      {createOpen ? <GrantDialog open onOpenChange={setCreateOpen} /> : null}
      <ConfirmDialog
        open={!!revoking}
        onOpenChange={(v) => !v && setRevoking(null)}
        title="Revoke assignment"
        description="A reason is required for the audit trail."
        target={revoking ? `${revoking.roleName ?? revoking.roleId} → ${revoking.subjectId}` : undefined}
        confirmLabel="Revoke"
        destructive
        pending={revoke.isPending}
        onConfirm={() => reason.trim() && revoke.mutate()}
      >
        <div className="mt-2 space-y-1.5">
          <Label htmlFor="reason">Reason</Label>
          <Input id="reason" value={reason} onChange={(e) => setReason(e.target.value)} required />
        </div>
      </ConfirmDialog>
    </div>
  );
}

function GrantDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const rolesQ = useQuery({ queryKey: ["roles"], queryFn: rolesApi.list });
  const [subjectId, setSubjectId] = useState("");
  const [subjectType, setSubjectType] = useState("USER");
  const [roleId, setRoleId] = useState("");
  const [scopeId, setScopeId] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [conditions, setConditions] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const m = useMutation({
    mutationFn: () => {
      let parsedConditions: unknown = undefined;
      if (conditions.trim()) {
        try {
          parsedConditions = JSON.parse(conditions);
        } catch {
          throw new Error("Conditions must be valid JSON.");
        }
      }
      return assignmentsApi.create({
        subjectId,
        subjectType,
        roleId,
        scopeId: scopeId || null,
        expiresAt: expiresAt || null,
        conditions: parsedConditions,
      });
    },
    onSuccess: () => {
      toast.success("Assignment granted");
      qc.invalidateQueries({ queryKey: ["assignments"] });
      onOpenChange(false);
    },
    onError: (e: Error) => setErr(e.message),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Grant assignment</DialogTitle>
        </DialogHeader>
        <div className="space-y-2">
          <Label htmlFor="a-sub">Subject ID</Label>
          <Input id="a-sub" value={subjectId} onChange={(e) => setSubjectId(e.target.value)} />
          <Label htmlFor="a-st">Subject type</Label>
          <select
            id="a-st"
            value={subjectType}
            onChange={(e) => setSubjectType(e.target.value)}
            className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
          >
            <option value="USER">USER</option>
            <option value="GROUP">GROUP</option>
            <option value="SERVICE">SERVICE</option>
          </select>
          <Label htmlFor="a-role">Role</Label>
          <select
            id="a-role"
            value={roleId}
            onChange={(e) => setRoleId(e.target.value)}
            className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
          >
            <option value="">Select…</option>
            {(rolesQ.data ?? []).map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </select>
          <Label htmlFor="a-scope">Scope ID (optional)</Label>
          <Input id="a-scope" value={scopeId} onChange={(e) => setScopeId(e.target.value)} />
          <Label htmlFor="a-exp">Expires at (ISO, optional)</Label>
          <Input id="a-exp" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} placeholder="2026-12-31T00:00:00Z" />
          <Label htmlFor="a-cond">Conditions JSON (optional)</Label>
          <textarea
            id="a-cond"
            value={conditions}
            onChange={(e) => setConditions(e.target.value)}
            rows={4}
            className="w-full rounded border border-[var(--border)] bg-[var(--card)] p-2 font-mono text-xs"
          />
          {err ? <p className="text-sm text-[var(--destructive)]">{err}</p> : null}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => m.mutate()} disabled={m.isPending || !subjectId || !roleId}>
            {m.isPending ? "Granting..." : "Grant"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}