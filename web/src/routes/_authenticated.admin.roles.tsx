import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { permissionsApi, rolesApi } from "@/api/resources";
import type { Permission, Role } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { Can } from "@/components/iam/Can";
import { DataTable, type Column } from "@/components/iam/DataTable";
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

export const Route = createFileRoute("/_authenticated/admin/roles")({
  component: () => (
    <PermissionGuardedPage permission="platform.role.read">
      <RolesPage />
    </PermissionGuardedPage>
  ),
});

function RolesPage() {
  const q = useQuery({ queryKey: ["roles"], queryFn: () => rolesApi.list() });
  const [filter, setFilter] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<Role | null>(null);

  const rows = useMemo(() => {
    const arr = q.data ?? [];
    const f = filter.toLowerCase();
    return f ? arr.filter((r) => r.name.toLowerCase().includes(f)) : arr;
  }, [q.data, filter]);

  const columns: Column<Role>[] = [
    { key: "name", header: "Name", render: (r) => <span className="font-mono text-[13px]">{r.name}</span> },
    { key: "display", header: "Display name", render: (r) => r.displayName ?? "—" },
    {
      key: "scope",
      header: "Scope",
      render: (r) => (r.ownerScopeId ? <span className="font-mono text-xs">{r.ownerScopeId}</span> : <Tag>Global</Tag>),
    },
    { key: "system", header: "", width: "80px", render: (r) => (r.isSystemRole ? <Tag>System</Tag> : null) },
  ];

  return (
    <div>
      <PageHeader
        title="Roles"
        description="Named bundles of permissions granted within a scope."
        actions={
          <Can permission="platform.role.create">
            <Button onClick={() => setCreateOpen(true)}>New role</Button>
          </Can>
        }
      />
      <div className="mb-3">
        <Input
          placeholder="Filter roles..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="max-w-xs"
        />
      </div>
      <DataTable
        columns={columns}
        rows={rows}
        loading={q.isLoading}
        empty="No roles."
        rowKey={(r) => r.id}
        onRowClick={(r) => setEditing(r)}
      />
      {createOpen ? <RoleDialog open onOpenChange={setCreateOpen} /> : null}
      {editing ? (
        <RoleDialog open onOpenChange={(v) => !v && setEditing(null)} role={editing} />
      ) : null}
    </div>
  );
}

function RoleDialog({
  open,
  onOpenChange,
  role,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  role?: Role;
}) {
  const qc = useQueryClient();
  const permsQ = useQuery({ queryKey: ["permissions"], queryFn: () => permissionsApi.list() });
  const rolePermsQ = useQuery({
    queryKey: ["role-permissions", role?.id],
    queryFn: () => rolesApi.permissions(role!.id),
    enabled: !!role,
  });
  const [name, setName] = useState(role?.name ?? "");
  const [displayName, setDisplayName] = useState(role?.displayName ?? "");
  const [description, setDescription] = useState(role?.description ?? "");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState("");
  const readOnly = role?.isSystemRole;

  useEffect(() => {
    if (rolePermsQ.data) setSelected(new Set(rolePermsQ.data.map((p) => p.id)));
  }, [rolePermsQ.data]);

  const create = useMutation({
    mutationFn: () =>
      rolesApi.create({
        name,
        displayName,
        description,
        permissionIds: Array.from(selected),
      }),
    onSuccess: () => {
      toast.success("Role created");
      qc.invalidateQueries({ queryKey: ["roles"] });
      onOpenChange(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const update = useMutation({
    mutationFn: () => rolesApi.updatePermissions(role!.id, Array.from(selected)),
    onSuccess: () => {
      toast.success("Permissions updated");
      qc.invalidateQueries({ queryKey: ["roles"] });
      onOpenChange(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const grouped = useMemo(() => {
    const perms = permsQ.data ?? [];
    const filtered = filter
      ? perms.filter((p) => p.key.toLowerCase().includes(filter.toLowerCase()))
      : perms;
    const map = new Map<string, Permission[]>();
    for (const p of filtered) {
      const d = p.domain ?? p.key.split(".")[0] ?? "other";
      if (!map.has(d)) map.set(d, []);
      map.get(d)!.push(p);
    }
    return Array.from(map.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [permsQ.data, filter]);

  const toggle = (id: string) => {
    if (readOnly) return;
    const s = new Set(selected);
    if (s.has(id)) s.delete(id);
    else s.add(id);
    setSelected(s);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{role ? `Edit role: ${role.name}` : "New role"}</DialogTitle>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label htmlFor="r-name">Name</Label>
            <Input id="r-name" value={name} disabled={!!role} onChange={(e) => setName(e.target.value)} />
            <Label htmlFor="r-dn">Display name</Label>
            <Input id="r-dn" value={displayName} disabled={readOnly} onChange={(e) => setDisplayName(e.target.value)} />
            <Label htmlFor="r-desc">Description</Label>
            <Input id="r-desc" value={description} disabled={readOnly} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label>Permissions ({selected.size} selected)</Label>
            <Input placeholder="Search permissions..." value={filter} onChange={(e) => setFilter(e.target.value)} />
            <div className="h-64 overflow-y-auto rounded border border-[var(--border)] p-2 text-sm">
              {permsQ.isLoading ? "Loading..." : null}
              {grouped.map(([domain, perms]) => (
                <div key={domain} className="mb-2">
                  <div className="pb-1 text-[11px] font-medium uppercase tracking-wide text-[var(--muted-foreground)]">
                    {domain}
                  </div>
                  {perms.map((p) => (
                    <label key={p.id} className="flex items-center gap-2 py-0.5">
                      <input
                        type="checkbox"
                        checked={selected.has(p.id)}
                        onChange={() => toggle(p.id)}
                        disabled={readOnly}
                      />
                      <span className="font-mono text-xs">{p.key}</span>
                    </label>
                  ))}
                </div>
              ))}
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Close</Button>
          {readOnly ? null : role ? (
            <Button onClick={() => update.mutate()} disabled={update.isPending}>
              {update.isPending ? "Saving..." : "Save permissions"}
            </Button>
          ) : (
            <Button onClick={() => create.mutate()} disabled={create.isPending || !name}>
              {create.isPending ? "Creating..." : "Create"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}