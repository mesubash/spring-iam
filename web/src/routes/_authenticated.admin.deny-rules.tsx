import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { denyRulesApi, scopesApi } from "@/api/resources";
import type { DenyRule } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { Can } from "@/components/iam/Can";
import { SubjectPicker } from "@/components/iam/SubjectPicker";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { Tag } from "@/components/iam/badges";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { formatDate, isExpiring } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/admin/deny-rules")({
  component: () => (
    <PermissionGuardedPage permission="platform.deny_rule.read">
      <DenyRulesPage />
    </PermissionGuardedPage>
  ),
});

function DenyRulesPage() {
  const qc = useQueryClient();
  const [subjectId, setSubjectId] = useState("");
  const trimmedSubject = subjectId.trim();
  const q = useQuery({
    queryKey: ["denyRules", trimmedSubject],
    queryFn: () => denyRulesApi.list(trimmedSubject),
    enabled: !!trimmedSubject,
  });
  const scopesQ = useQuery({ queryKey: ["scopes"], queryFn: () => scopesApi.list() });
  const scopePathById = useMemo(
    () => new Map((scopesQ.data ?? []).map((s) => [s.id, s.path])),
    [scopesQ.data],
  );
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
    {
      key: "perm",
      header: "Permission",
      render: (r) => (
        <span className="font-mono text-xs font-medium text-[var(--destructive)]">{r.permissionKey}</span>
      ),
    },
    {
      key: "scope",
      header: "Scope",
      render: (r) =>
        r.scopeId ? (
          <span className="font-mono text-xs">{scopePathById.get(r.scopeId) ?? r.scopeId}</span>
        ) : (
          <Tag tone="neutral">Global</Tag>
        ),
    },
    { key: "reason", header: "Reason", render: (r) => <span className="text-sm">{r.reason}</span> },
    {
      key: "ref",
      header: "Reference",
      render: (r) =>
        r.referenceId ? (
          <span className="font-mono text-xs">{r.referenceId}</span>
        ) : (
          <span className="text-[var(--muted-foreground)]">—</span>
        ),
    },
    {
      key: "exp",
      header: "Expires",
      render: (r) =>
        r.expiresAt ? (
          <span className={isExpiring(r.expiresAt) ? "text-xs text-[var(--destructive)]" : "text-xs"}>
            {formatDate(r.expiresAt)}
          </span>
        ) : (
          <span className="text-xs text-[var(--muted-foreground)]">Never</span>
        ),
    },
    {
      key: "act",
      header: "",
      width: "100px",
      render: (r) => (
        <Can permission="platform.deny_rule.delete">
          <Button
            variant="ghost"
            size="sm"
            style={{ color: "var(--destructive)" }}
            onClick={() => setToDelete(r)}
          >
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
        description="Explicit denies that override every allow — assignments, grants and policies included. Use sparingly."
        actions={
          <Can permission="platform.deny_rule.create">
            <Button
              style={{ backgroundColor: "var(--destructive)", color: "#fff" }}
              onClick={() => setCreateOpen(true)}
            >
              New deny rule
            </Button>
          </Can>
        }
      />
      <div className="mb-3 max-w-md">
        <SubjectPicker
          value={subjectId}
          onChange={setSubjectId}
          placeholder="Select a user to view their deny rules…"
        />
      </div>
      <DataTable
        columns={columns}
        rows={trimmedSubject ? q.data : []}
        loading={!!trimmedSubject && q.isLoading}
        empty={
          trimmedSubject
            ? "No deny rules for this subject."
            : "Select a user to view their deny rules."
        }
        rowKey={(r) => r.id}
      />
      {createOpen ? (
        <CreateDialog open onOpenChange={setCreateOpen} initialSubjectId={trimmedSubject} />
      ) : null}
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

function CreateDialog({
  open,
  onOpenChange,
  initialSubjectId,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  initialSubjectId?: string;
}) {
  const qc = useQueryClient();
  const scopesQ = useQuery({ queryKey: ["scopes"], queryFn: () => scopesApi.list() });
  const [subjectId, setSubjectId] = useState(initialSubjectId ?? "");
  const [subjectType, setSubjectType] = useState("USER");
  const [permissionKey, setPermissionKey] = useState("");
  const [scopeId, setScopeId] = useState("");
  const [reason, setReason] = useState("");
  const [referenceId, setReferenceId] = useState("");
  const [expiresAt, setExpiresAt] = useState("");

  const m = useMutation({
    mutationFn: () =>
      denyRulesApi.create({
        subjectId: subjectId.trim(),
        subjectType,
        permissionKey: permissionKey.trim(),
        scopeId: scopeId || null,
        reason: reason.trim(),
        referenceId: referenceId.trim() || null,
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
      }),
    onSuccess: () => {
      toast.success("Deny rule created");
      qc.invalidateQueries({ queryKey: ["denyRules"] });
      onOpenChange(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const valid = !!subjectId.trim() && !!permissionKey.trim() && !!reason.trim();

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New deny rule</DialogTitle>
          <DialogDescription>
            An explicit deny beats every allow. It applies immediately and is audited.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <Label htmlFor="d-sub">Subject</Label>
          <SubjectPicker id="d-sub" value={subjectId} onChange={setSubjectId} />
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
          <Label htmlFor="d-perm">Permission key</Label>
          <Input
            id="d-perm"
            className="font-mono"
            placeholder="invoice.payment.write"
            value={permissionKey}
            onChange={(e) => setPermissionKey(e.target.value)}
          />
          <p className="text-xs text-[var(--muted-foreground)]">
            Wildcards supported: <span className="font-mono">invoice.*.*</span> denies a whole domain,{" "}
            <span className="font-mono">**</span> denies everything.
          </p>
          <Label htmlFor="d-scope">Scope (optional)</Label>
          <select
            id="d-scope"
            value={scopeId}
            onChange={(e) => setScopeId(e.target.value)}
            className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
          >
            <option value="">Global (all scopes)</option>
            {(scopesQ.data ?? []).map((s) => (
              <option key={s.id} value={s.id}>
                {s.path}
              </option>
            ))}
          </select>
          <Label htmlFor="d-reason">Reason (required)</Label>
          <Input
            id="d-reason"
            placeholder="e.g. Security incident SEC-142"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          <Label htmlFor="d-ref">Reference ID (optional)</Label>
          <Input
            id="d-ref"
            className="font-mono"
            placeholder="Ticket / incident id"
            value={referenceId}
            onChange={(e) => setReferenceId(e.target.value)}
          />
          <Label htmlFor="d-exp">Expires at (optional)</Label>
          <Input
            id="d-exp"
            type="datetime-local"
            value={expiresAt}
            onChange={(e) => setExpiresAt(e.target.value)}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            style={{ backgroundColor: "var(--destructive)", color: "#fff" }}
            onClick={() => m.mutate()}
            disabled={m.isPending || !valid}
          >
            {m.isPending ? "Creating…" : "Create deny rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
