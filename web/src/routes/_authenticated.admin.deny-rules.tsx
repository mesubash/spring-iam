import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { denyRulesApi } from "@/api/resources";
import type { DenyRule } from "@/api/types";
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
import { formatDate } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/admin/deny-rules")({
  head: () => ({ meta: [{ title: "Deny Rules — IAM Console" }] }),
  component: () => (
    <PermissionGuardedPage permission="platform.deny_rule.read">
      <DenyRulesPage />
    </PermissionGuardedPage>
  ),
});

function DenyRulesPage() {
  const q = useQuery({ queryKey: ["denyRules"], queryFn: denyRulesApi.list });
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [toDelete, setToDelete] = useState<DenyRule | null>(null);

  const del = useMutation({
    mutationFn: () => denyRulesApi.del(toDelete!.id),
    onSuccess: () => {
      toast.success("Deny rule removed");
      qc.invalidateQueries({ queryKey: ["denyRules"] });
      setToDelete(null);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<DenyRule>[] = [
    { key: "d", header: "", width: "70px", render: () => <Tag tone="destructive">DENY</Tag> },
    { key: "sub", header: "Subject", render: (r) => <span className="font-mono text-xs">{r.subjectId}</span> },
    { key: "perm", header: "Permission", render: (r) => <span className="font-mono text-xs">{r.permissionKey}</span> },
    { key: "scope", header: "Scope", render: (r) => (r.scopeId ? <span className="font-mono text-xs">{r.scopeId}</span> : <Tag>Global</Tag>) },
    { key: "reason", header: "Reason", render: (r) => r.reason },
    { key: "exp", header: "Expires", render: (r) => formatDate(r.expiresAt) },
    {
      key: "act",
      header: "",
      width: "100px",
      render: (r) => (
        <Can permission="platform.deny_rule.delete">
          <Button variant="ghost" size="sm" style={{ color: "var(--destructive)" }} onClick={() => setToDelete(r)}>
            Remove
          </Button>
        </Can>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Deny Rules"
        description="Explicit denies that override any allow. Use sparingly."
        actions={
          <Can permission="platform.deny_rule.create">
            <Button style={{ backgroundColor: "var(--destructive)", color: "#fff" }} onClick={() => setCreateOpen(true)}>
              New deny rule
            </Button>
          </Can>
        }
      />
      <DataTable
        columns={columns}
        rows={q.data}
        loading={q.isLoading}
        empty="No deny rules."
        rowKey={(r) => r.id}
      />
      {createOpen ? <CreateDialog open onOpenChange={setCreateOpen} /> : null}
      <ConfirmDialog
        open={!!toDelete}
        onOpenChange={(v) => !v && setToDelete(null)}
        title="Remove deny rule"
        description="Access denied by this rule will no longer be blocked."
        target={toDelete ? `${toDelete.permissionKey} → ${toDelete.subjectId}` : undefined}
        destructive
        confirmLabel="Remove"
        pending={del.isPending}
        onConfirm={() => del.mutate()}
      />
    </div>
  );
}

function CreateDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const [subjectId, setSubjectId] = useState("");
  const [subjectType, setSubjectType] = useState("USER");
  const [permissionKey, setPermissionKey] = useState("");
  const [scopeId, setScopeId] = useState("");
  const [reason, setReason] = useState("");
  const [referenceId, setReferenceId] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const m = useMutation({
    mutationFn: () =>
      denyRulesApi.create({
        subjectId,
        subjectType,
        permissionKey,
        scopeId: scopeId || null,
        reason,
        referenceId: referenceId || null,
        expiresAt: expiresAt || null,
      }),
    onSuccess: () => {
      toast.success("Deny rule created");
      qc.invalidateQueries({ queryKey: ["denyRules"] });
      onOpenChange(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader><DialogTitle>New deny rule</DialogTitle></DialogHeader>
        <div className="space-y-2">
          <Label htmlFor="d-sub">Subject ID</Label>
          <Input id="d-sub" value={subjectId} onChange={(e) => setSubjectId(e.target.value)} />
          <Label htmlFor="d-st">Subject type</Label>
          <select
            id="d-st"
            value={subjectType}
            onChange={(e) => setSubjectType(e.target.value)}
            className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
          >
            <option value="USER">USER</option>
            <option value="GROUP">GROUP</option>
            <option value="SERVICE">SERVICE</option>
          </select>
          <Label htmlFor="d-perm">Permission key (supports * and **)</Label>
          <Input id="d-perm" value={permissionKey} onChange={(e) => setPermissionKey(e.target.value)} />
          <Label htmlFor="d-scope">Scope ID (optional)</Label>
          <Input id="d-scope" value={scopeId} onChange={(e) => setScopeId(e.target.value)} />
          <Label htmlFor="d-reason">Reason (required)</Label>
          <Input id="d-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
          <Label htmlFor="d-ref">Reference ID (optional)</Label>
          <Input id="d-ref" value={referenceId} onChange={(e) => setReferenceId(e.target.value)} />
          <Label htmlFor="d-exp">Expires at ISO (optional)</Label>
          <Input id="d-exp" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            style={{ backgroundColor: "var(--destructive)", color: "#fff" }}
            onClick={() => m.mutate()}
            disabled={m.isPending || !subjectId || !permissionKey || !reason}
          >
            {m.isPending ? "Creating..." : "Create deny rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}