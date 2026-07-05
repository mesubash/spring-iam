import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { resourceGrantsApi } from "@/api/resources";
import type { ResourceGrant } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { Can } from "@/components/iam/Can";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
import { SubjectPicker } from "@/components/iam/SubjectPicker";
import { Tag } from "@/components/iam/badges";
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
import { useAuthz } from "@/context/AuthzContext";
import { formatDate, isExpiring } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/admin/resource-grants")({
  component: () => (
    <PermissionGuardedPage permission="platform.resource_grant.read">
      <ResourceGrantsPage />
    </PermissionGuardedPage>
  ),
});

function ResourceGrantsPage() {
  const { features } = useAuthz();
  const [subjectId, setSubjectId] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [resourceId, setResourceId] = useState("");
  const qc = useQueryClient();

  const bySubject = !!subjectId.trim();
  const byResource = !!resourceType.trim() && !!resourceId.trim();
  const enabled = bySubject || byResource;

  const q = useQuery({
    queryKey: ["resource-grants", subjectId.trim(), resourceType.trim(), resourceId.trim()],
    queryFn: () =>
      resourceGrantsApi.list(
        bySubject
          ? { subjectId: subjectId.trim() }
          : { resourceType: resourceType.trim(), resourceId: resourceId.trim() },
      ),
    enabled,
  });

  const [creating, setCreating] = useState(false);
  const [toDelete, setToDelete] = useState<ResourceGrant | null>(null);

  const del = useMutation({
    mutationFn: (id: string) => resourceGrantsApi.del(id),
    onSuccess: () => {
      toast.success("Grant deleted");
      qc.invalidateQueries({ queryKey: ["resource-grants"] });
      setToDelete(null);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  if (features && !features["resource-grants"]) {
    return (
      <p className="text-sm text-[var(--muted-foreground)]">
        The resource-grants feature is disabled on this deployment.
      </p>
    );
  }

  const columns: Column<ResourceGrant>[] = [
    {
      key: "sub",
      header: "Subject",
      render: (r) => <span className="font-mono text-xs">{r.subjectId}</span>,
    },
    {
      key: "perm",
      header: "Permission",
      render: (r) => <span className="font-mono text-xs">{r.permissionKey}</span>,
    },
    { key: "rt", header: "Resource type", render: (r) => r.resourceType },
    {
      key: "rid",
      header: "Resource ID",
      render: (r) => <span className="font-mono text-xs">{r.resourceId}</span>,
    },
    {
      key: "exp",
      header: "Expires",
      render: (r) =>
        r.expiresAt ? (
          isExpiring(r.expiresAt) ? (
            <Tag tone="warning">{formatDate(r.expiresAt)}</Tag>
          ) : (
            formatDate(r.expiresAt)
          )
        ) : (
          "—"
        ),
    },
    {
      key: "act",
      header: "",
      width: "90px",
      render: (r) =>
        r.revokedAt ? (
          <Tag tone="neutral">Revoked</Tag>
        ) : (
          <Can permission="platform.resource_grant.manage">
            <Button
              variant="ghost"
              size="sm"
              style={{ color: "var(--destructive)" }}
              onClick={() => setToDelete(r)}
            >
              Delete
            </Button>
          </Can>
        ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Resource Grants"
        description="Per-resource permission grants that bypass role assignment for a single object."
        actions={
          <Can permission="platform.resource_grant.manage">
            <Button onClick={() => setCreating(true)}>New grant</Button>
          </Can>
        }
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <SubjectPicker
          className="w-full max-w-xs"
          placeholder="Select a user…"
          value={subjectId}
          onChange={setSubjectId}
        />
        <span className="text-xs text-[var(--muted-foreground)]">or</span>
        <Input
          className="max-w-[180px]"
          placeholder="Resource type"
          value={resourceType}
          onChange={(e) => setResourceType(e.target.value)}
        />
        <Input
          className="max-w-[220px] font-mono text-xs"
          placeholder="Resource ID"
          value={resourceId}
          onChange={(e) => setResourceId(e.target.value)}
        />
      </div>
      <DataTable
        columns={columns}
        rows={enabled ? q.data : []}
        loading={enabled && q.isLoading}
        empty={
          enabled
            ? "No grants match this filter."
            : "Enter a subject ID, or a resource type and resource ID, to load grants."
        }
        rowKey={(r) => r.id}
      />
      {creating ? <CreateGrantDialog open onOpenChange={setCreating} /> : null}
      <ConfirmDialog
        open={!!toDelete}
        onOpenChange={(v) => !v && setToDelete(null)}
        title="Delete resource grant"
        description="The subject immediately loses this per-resource permission."
        target={
          toDelete
            ? `${toDelete.subjectId} · ${toDelete.permissionKey} → ${toDelete.resourceType}:${toDelete.resourceId}`
            : undefined
        }
        destructive
        confirmLabel="Delete"
        pending={del.isPending}
        onConfirm={() => toDelete && del.mutate(toDelete.id)}
      />
    </div>
  );
}

function CreateGrantDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const qc = useQueryClient();
  const [subjectId, setSubjectId] = useState("");
  const [permissionKey, setPermissionKey] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [resourceId, setResourceId] = useState("");
  const [scopeId, setScopeId] = useState("");
  const [expiresAt, setExpiresAt] = useState("");

  const m = useMutation({
    mutationFn: () =>
      resourceGrantsApi.create({
        subjectId: subjectId.trim(),
        permissionKey: permissionKey.trim(),
        resourceType: resourceType.trim(),
        resourceId: resourceId.trim(),
        scopeId: scopeId.trim() || null,
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
      }),
    onSuccess: () => {
      toast.success("Grant created");
      qc.invalidateQueries({ queryKey: ["resource-grants"] });
      onOpenChange(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const valid =
    subjectId.trim() && permissionKey.trim() && resourceType.trim() && resourceId.trim();

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New resource grant</DialogTitle>
        </DialogHeader>
        <div className="space-y-2">
          <div>
            <Label>Subject</Label>
            <div className="mt-1">
              <SubjectPicker value={subjectId} onChange={setSubjectId} />
            </div>
          </div>
          <div>
            <Label>Permission key</Label>
            <Input
              className="mt-1 font-mono text-xs"
              placeholder="domain.resource.action"
              value={permissionKey}
              onChange={(e) => setPermissionKey(e.target.value)}
            />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <Label>Resource type</Label>
              <Input
                className="mt-1"
                value={resourceType}
                onChange={(e) => setResourceType(e.target.value)}
              />
            </div>
            <div>
              <Label>Resource ID</Label>
              <Input
                className="mt-1 font-mono text-xs"
                value={resourceId}
                onChange={(e) => setResourceId(e.target.value)}
              />
            </div>
          </div>
          <div>
            <Label>Scope ID (optional)</Label>
            <Input
              className="mt-1 font-mono text-xs"
              value={scopeId}
              onChange={(e) => setScopeId(e.target.value)}
            />
          </div>
          <div>
            <Label>Expires at (optional)</Label>
            <Input
              className="mt-1"
              type="datetime-local"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={m.isPending}>
            Cancel
          </Button>
          <Button onClick={() => m.mutate()} disabled={m.isPending || !valid}>
            {m.isPending ? "Creating…" : "Create grant"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
