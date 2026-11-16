import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState, type ReactNode } from "react";
import { toast } from "sonner";
import { assignmentsApi, permissionsApi, rolesApi, scopesApi } from "@/api/resources";
import type { Assignment, Role, Scope } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { PermissionTree } from "@/components/iam/PermissionTree";
import { Can } from "@/components/iam/Can";
import { Tag } from "@/components/iam/badges";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Network } from "lucide-react";
import { useAuthz } from "@/context/AuthzContext";
import { buildScopeTree, withAncestors, type ScopeNode } from "@/lib/scope-tree";
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

// Roles are placed on the scope tree where they are actually assigned: a role
// shows under every scope holding an active assignment of it, with the count.
type RoleCount = { role: Role; count: number };
type Placement = {
  byScope: Map<string, RoleCount[]>;
  /** assignments whose scope is not in the visible scope list */
  other: RoleCount[];
  unassigned: RoleCount[];
};

function placeRoles(roles: Role[], scopes: Scope[], assignments: Assignment[]): Placement {
  const known = new Set(scopes.map((s) => s.id));
  const now = Date.now();
  // role id -> scope key -> active assignment count
  const counts = new Map<string, Map<string, number>>();
  for (const a of assignments) {
    if (!a.active || a.revokedAt || (a.expiresAt && Date.parse(a.expiresAt) < now)) continue;
    const key = known.has(a.scopeId) ? a.scopeId : "other";
    const perScope = counts.get(a.roleId) ?? new Map<string, number>();
    perScope.set(key, (perScope.get(key) ?? 0) + 1);
    counts.set(a.roleId, perScope);
  }

  const byScope = new Map<string, RoleCount[]>();
  const other: RoleCount[] = [];
  const unassigned: RoleCount[] = [];
  for (const role of roles) {
    const perScope = counts.get(role.id);
    if (!perScope) {
      unassigned.push({ role, count: 0 });
      continue;
    }
    for (const [key, count] of perScope) {
      if (key === "other") other.push({ role, count });
      else byScope.set(key, [...(byScope.get(key) ?? []), { role, count }]);
    }
  }
  const byName = (a: RoleCount, b: RoleCount) => a.role.name.localeCompare(b.role.name);
  byScope.forEach((list) => list.sort(byName));
  return { byScope, other: other.sort(byName), unassigned: unassigned.sort(byName) };
}

/* ------------------------------- Tree UI -------------------------------- */

function TreeBranch({
  title,
  hint,
  count,
  open,
  onToggle,
  children,
}: {
  title: string;
  hint?: string;
  count: number;
  open: boolean;
  onToggle: () => void;
  children: ReactNode;
}) {
  return (
    <div>
      <button
        type="button"
        aria-expanded={open}
        onClick={onToggle}
        className="flex w-full items-center gap-2 rounded py-1 text-left hover:bg-[var(--muted)]"
      >
        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded border border-[var(--border)] text-xs leading-none text-[var(--muted-foreground)]">
          {open ? "−" : "+"}
        </span>
        <Network className="h-4 w-4 shrink-0 text-[var(--muted-foreground)]" />
        <span className="text-sm font-semibold">{title}</span>
        {hint ? (
          <span className="truncate font-mono text-[11px] text-[var(--muted-foreground)]">
            {hint}
          </span>
        ) : null}
        <span className="shrink-0 text-xs text-[var(--muted-foreground)]">
          · {count} role{count === 1 ? "" : "s"}
        </span>
      </button>
      {/* children hang off a drawn vertical guide */}
      {open ? <div className="ml-2.5 border-l border-[var(--border)] pl-4">{children}</div> : null}
    </div>
  );
}

function RoleLeaf({ rc, onOpen }: { rc: RoleCount; onOpen: () => void }) {
  const { role, count } = rc;
  return (
    <button
      type="button"
      onClick={onOpen}
      className="group relative flex w-full cursor-pointer items-center gap-3 rounded px-2 py-1.5 text-left transition-colors hover:bg-[var(--muted)]"
    >
      {/* horizontal tick connecting the row to the guide line */}
      <span className="absolute -left-4 top-1/2 h-px w-3 bg-[var(--border)]" />
      <span className="flex min-w-0 flex-col">
        <span className="text-sm font-medium group-hover:underline">
          {role.displayName ?? role.name}
        </span>
        <span className="font-mono text-[11px] text-[var(--muted-foreground)]">{role.name}</span>
      </span>
      <span className="ml-auto flex shrink-0 items-center gap-2">
        {count > 0 ? (
          <span className="text-xs text-[var(--muted-foreground)]">
            {count} assignment{count === 1 ? "" : "s"}
          </span>
        ) : null}
        {role.ownerScopeId ? (
          <span title="Custom role: usable only within its owner scope's subtree">
            <Tag>Custom</Tag>
          </span>
        ) : (
          <span title="Shared role: any scope may assign it; its power is bounded by where it is assigned">
            <Tag>Shared</Tag>
          </span>
        )}
        {role.isSystemRole ? <Tag>System</Tag> : null}
        <span className="text-[var(--muted-foreground)] transition-transform group-hover:translate-x-0.5">
          ›
        </span>
      </span>
    </button>
  );
}

function RolesPage() {
  const navigate = useNavigate();
  const { can } = useAuthz();
  const q = useQuery({ queryKey: ["roles"], queryFn: () => rolesApi.list() });
  const scopesQ = useQuery({ queryKey: ["scopes"], queryFn: () => scopesApi.list() });
  const canPlace = can("platform.assignment.read");
  const assignmentsQ = useQuery({
    queryKey: ["assignments", "all"],
    queryFn: () => assignmentsApi.list(),
    enabled: canPlace,
  });
  const [filter, setFilter] = useState("");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [createOpen, setCreateOpen] = useState(false);

  const f = filter.toLowerCase();
  const roles = useMemo(
    () =>
      (q.data ?? []).filter(
        (r) =>
          !f || r.name.toLowerCase().includes(f) || (r.displayName ?? "").toLowerCase().includes(f),
      ),
    [q.data, f],
  );
  const placement = useMemo(
    () => placeRoles(roles, scopesQ.data ?? [], assignmentsQ.data ?? []),
    [roles, scopesQ.data, assignmentsQ.data],
  );
  // Only scopes holding a role, plus their ancestors so the tree stays connected.
  const tree = useMemo(
    () => buildScopeTree(withAncestors(scopesQ.data ?? [], placement.byScope.keys())),
    [scopesQ.data, placement],
  );

  const loading = q.isLoading || scopesQ.isLoading || (canPlace && assignmentsQ.isLoading);
  const placed = canPlace && !assignmentsQ.isError;
  const open = (role: Role) =>
    navigate({ to: "/admin/roles/$roleId", params: { roleId: role.id } });
  const isOpen = (key: string) => !!f || !collapsed.has(key);
  const toggle = (key: string) =>
    setCollapsed((prev) => {
      const s = new Set(prev);
      if (s.has(key)) s.delete(key);
      else s.add(key);
      return s;
    });

  const leaves = (list: RoleCount[]) =>
    list.map((rc) => <RoleLeaf key={rc.role.id} rc={rc} onOpen={() => open(rc.role)} />);

  const renderNode = (n: ScopeNode): ReactNode => {
    const here = placement.byScope.get(n.scope.id) ?? [];
    return (
      <TreeBranch
        key={n.scope.id}
        title={n.scope.name}
        hint={n.scope.type}
        count={here.length}
        open={isOpen(n.scope.id)}
        onToggle={() => toggle(n.scope.id)}
      >
        {leaves(here)}
        {n.children.map(renderNode)}
      </TreeBranch>
    );
  };

  const bucket = (key: string, title: string, hint: string, list: RoleCount[]) =>
    list.length > 0 ? (
      <div className="mt-3">
        <TreeBranch
          title={title}
          hint={hint}
          count={list.length}
          open={isOpen(key)}
          onToggle={() => toggle(key)}
        >
          {leaves(list)}
        </TreeBranch>
      </div>
    ) : null;

  return (
    <div>
      <PageHeader
        title="Roles"
        description="Named bundles of permissions, shown on the scope tree where they are assigned."
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
          className="w-full sm:max-w-sm"
        />
      </div>
      {loading ? (
        <div className="py-8 text-sm text-[var(--muted-foreground)]">Loading...</div>
      ) : roles.length === 0 ? (
        <div className="py-8 text-sm text-[var(--muted-foreground)]">No roles.</div>
      ) : !placed ? (
        <div className="rounded border border-[var(--border)] bg-[var(--card)] p-4">
          {bucket("all", "All roles", "assignments not visible to you", placement.unassigned)}
        </div>
      ) : (
        <div className="rounded border border-[var(--border)] bg-[var(--card)] p-4">
          {tree.map(renderNode)}
          {bucket("other", "Other scopes", "assigned outside the visible scopes", placement.other)}
          {bucket(
            "unassigned",
            "Not assigned",
            "in the catalog, no active assignments",
            placement.unassigned,
          )}
        </div>
      )}
      {createOpen ? <CreateRoleDialog open onOpenChange={setCreateOpen} /> : null}
    </div>
  );
}

/* ------------------------------ Create role ----------------------------- */

function CreateRoleDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const qc = useQueryClient();
  const permsQ = useQuery({ queryKey: ["permissions"], queryFn: () => permissionsApi.list() });
  const [name, setName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [description, setDescription] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());

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

  const setMany = (ids: string[], on: boolean) =>
    setSelected((prev) => {
      const s = new Set(prev);
      ids.forEach((id) => (on ? s.add(id) : s.delete(id)));
      return s;
    });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>New role</DialogTitle>
        </DialogHeader>
        <div className="grid gap-2 sm:grid-cols-3">
          <div className="space-y-1">
            <Label htmlFor="r-name">Name</Label>
            <Input id="r-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="r-dn">Display name</Label>
            <Input id="r-dn" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="r-desc">Description</Label>
            <Input
              id="r-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
        </div>
        <div className="max-h-[50vh] overflow-y-auto">
          {permsQ.isLoading ? (
            <p className="text-sm text-[var(--muted-foreground)]">Loading...</p>
          ) : (
            <PermissionTree perms={permsQ.data ?? []} selected={selected} onSetMany={setMany} />
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
          <Button onClick={() => create.mutate()} disabled={create.isPending || !name}>
            {create.isPending ? "Creating..." : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
