import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { resourceGrantsApi } from "@/api/resources";
import type { ResourceGrant } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
import { useAuthz } from "@/context/AuthzContext";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { formatDate } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/admin/resource-grants")({
  component: ResourceGrantsPage,
});

function ResourceGrantsPage() {
  const { features } = useAuthz();
  const [subjectId, setSubjectId] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [resourceId, setResourceId] = useState("");
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["rg", subjectId, resourceType, resourceId],
    queryFn: () =>
      resourceGrantsApi.list({
        subjectId: subjectId || undefined,
        resourceType: resourceType || undefined,
        resourceId: resourceId || undefined,
      }),
  });
  const [creating, setCreating] = useState(false);
  const [toDelete, setToDelete] = useState<ResourceGrant | null>(null);

  const del = useMutation({
    mutationFn: () => resourceGrantsApi.del(toDelete!.id),
    onSuccess: () => {
      toast.success("Grant revoked");
      qc.invalidateQueries({ queryKey: ["rg"] });
      setToDelete(null);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  if (features && !features["resource-grants"]) {
    return <p className="text-sm text-[var(--muted-foreground)]">Resource grants are disabled.</p>;
  }

  const columns: Column<ResourceGrant>[] = [
    { key: "sub", header: "Subject", render: (r) => <span className="font-mono text-xs">{r.subjectId}</span> },
    { key: "perm", header: "Permission", render: (r) => <span className="font-mono text-xs">{r.permissionKey}</span> },
    { key: "rt", header: "Resource", render: (r) => `${r.resourceType}:${r.resourceId}` },
    { key: "exp", header: "Expires", render: (r) => formatDate(r.expiresAt) },
    {
      key: "act",
      header: "",
      width: "100px",
      render: (r) => (
        <Button variant="ghost" size="sm" style={{ color: "var(--destructive)" }} onClick={() => setToDelete(r)}>
          Revoke
        </Button>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Resource Grants"
        description="Per-resource permissions outside role assignments."
        actions={<Button onClick={() => setCreating(true)}>New grant</Button>}
      />
      <div className="mb-3 flex gap-2">
        <Input placeholder="Subject ID" value={subjectId} onChange={(e) => setSubjectId(e.target.value)} />
        <Input placeholder="Resource type" value={resourceType} onChange={(e) => setResourceType(e.target.value)} />
        <Input placeholder="Resource ID" value={resourceId} onChange={(e) => setResourceId(e.target.value)} />
      </div>
      <DataTable columns={columns} rows={q.data} loading={q.isLoading} empty="No grants." rowKey={(r) => r.id} />
      {creating ? <CreateDialog open onOpenChange={setCreating} /> : null}
      <ConfirmDialog
        open={!!toDelete}
        onOpenChange={(v) => !v && setToDelete(null)}
        title="Revoke resource grant"
        target={toDelete ? `${toDelete.permissionKey} → ${toDelete.resourceType}:${toDelete.resourceId}` : undefined}
        destructive
        confirmLabel="Revoke"
        pending={del.isPending}
        onConfirm={() => del.mutate()}
      />
    </div>
  );
}

function CreateDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
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
        subjectId,
        permissionKey,
        resourceType,
        resourceId,
        scopeId: scopeId || null,
        expiresAt: expiresAt || null,
      }),
    onSuccess: () => {
      toast.success("Grant created");
      qc.invalidateQueries({ queryKey: ["rg"] });
      onOpenChange(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader><DialogTitle>New resource grant</DialogTitle></DialogHeader>
        <div className="space-y-2">
          <Label>Subject ID</Label>
          <Input value={subjectId} onChange={(e) => setSubjectId(e.target.value)} />
          <Label>Permission key</Label>
          <Input value={permissionKey} onChange={(e) => setPermissionKey(e.target.value)} />
          <Label>Resource type</Label>
          <Input value={resourceType} onChange={(e) => setResourceType(e.target.value)} />
          <Label>Resource ID</Label>
          <Input value={resourceId} onChange={(e) => setResourceId(e.target.value)} />
          <Label>Scope ID (optional)</Label>
          <Input value={scopeId} onChange={(e) => setScopeId(e.target.value)} />
          <Label>Expires at (optional)</Label>
          <Input value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => m.mutate()} disabled={m.isPending || !subjectId || !permissionKey || !resourceType || !resourceId}>
            {m.isPending ? "Creating..." : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}