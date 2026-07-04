import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { scopesApi } from "@/api/resources";
import type { Scope } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { Can } from "@/components/iam/Can";
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
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
import { Tag } from "@/components/iam/badges";
import { cn } from "@/lib/utils";
import { useAuthz } from "@/context/AuthzContext";

export const Route = createFileRoute("/_authenticated/admin/scopes")({
  head: () => ({ meta: [{ title: "Scopes — IAM Console" }] }),
  component: () => (
    <PermissionGuardedPage permission="platform.scope.read">
      <ScopesPage />
    </PermissionGuardedPage>
  ),
});

type TreeNode = Scope & { children: TreeNode[] };

function buildTree(scopes: Scope[]): TreeNode[] {
  const map = new Map<string, TreeNode>();
  scopes.forEach((s) => map.set(s.id, { ...s, children: [] }));
  const roots: TreeNode[] = [];
  map.forEach((n) => {
    if (n.parentId && map.has(n.parentId)) map.get(n.parentId)!.children.push(n);
    else roots.push(n);
  });
  return roots;
}

function ScopesPage() {
  const q = useQuery({ queryKey: ["scopes"], queryFn: scopesApi.list });
  const [selected, setSelected] = useState<Scope | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [moveOpen, setMoveOpen] = useState(false);
  const { can } = useAuthz();

  const tree = useMemo(() => buildTree(q.data ?? []), [q.data]);
  const descendants = useMemo(() => {
    if (!selected || !q.data) return 0;
    let count = 0;
    const stack = [selected.id];
    while (stack.length) {
      const id = stack.pop()!;
      for (const s of q.data) {
        if (s.parentId === id) {
          count++;
          stack.push(s.id);
        }
      }
    }
    return count;
  }, [selected, q.data]);

  return (
    <div>
      <PageHeader
        title="Scopes"
        description="Hierarchical containers for roles, assignments and policies."
        actions={
          <Can permission="platform.scope.create">
            <Button onClick={() => setCreateOpen(true)}>New scope</Button>
          </Can>
        }
      />
      <div className="grid grid-cols-[1fr_320px] gap-4">
        <div className="rounded border border-[var(--border)] bg-[var(--card)]">
          {q.isLoading ? (
            <div className="p-3 text-sm text-[var(--muted-foreground)]">Loading…</div>
          ) : tree.length === 0 ? (
            <div className="p-6 text-center text-sm text-[var(--muted-foreground)]">No scopes yet.</div>
          ) : (
            <ul className="py-2">
              {tree.map((n) => (
                <TreeRow key={n.id} node={n} depth={0} selected={selected} onSelect={setSelected} />
              ))}
            </ul>
          )}
        </div>
        <aside className="rounded border border-[var(--border)] bg-[var(--card)] p-4 text-sm">
          {!selected ? (
            <p className="text-[var(--muted-foreground)]">Select a scope to see details.</p>
          ) : (
            <div className="space-y-3">
              <div>
                <div className="text-xs text-[var(--muted-foreground)]">Name</div>
                <div className="font-medium">{selected.name}</div>
              </div>
              <MetaRow label="Code" mono value={selected.code} />
              <MetaRow label="Type" value={selected.type} />
              <MetaRow label="Path" mono value={selected.path} />
              <MetaRow label="Depth" value={String(selected.depth)} />
              <MetaRow label="Active" value={selected.active ? "Yes" : "No"} />
              <MetaRow label="Descendants" value={String(descendants)} />
              {can("platform.scope.move") ? (
                <Button variant="outline" size="sm" onClick={() => setMoveOpen(true)}>
                  Move scope
                </Button>
              ) : null}
            </div>
          )}
        </aside>
      </div>
      <CreateScopeDialog open={createOpen} onOpenChange={setCreateOpen} parent={selected} />
      {selected ? (
        <MoveScopeDialog
          open={moveOpen}
          onOpenChange={setMoveOpen}
          scope={selected}
          all={q.data ?? []}
        />
      ) : null}
    </div>
  );
}

function MetaRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs text-[var(--muted-foreground)]">{label}</div>
      <div className={cn("text-sm", mono && "font-mono text-[13px]")}>{value}</div>
    </div>
  );
}

function TreeRow({
  node,
  depth,
  selected,
  onSelect,
}: {
  node: TreeNode;
  depth: number;
  selected: Scope | null;
  onSelect: (s: Scope) => void;
}) {
  const isActive = selected?.id === node.id;
  return (
    <>
      <li>
        <button
          type="button"
          onClick={() => onSelect(node)}
          className={cn(
            "flex w-full items-center gap-2 px-2 py-1.5 text-left text-sm hover:bg-[var(--background)] focus:outline-none focus:ring-1 focus:ring-[var(--ring)]",
            isActive && "bg-[var(--primary-subtle)] text-[var(--primary)]",
          )}
          style={{ paddingLeft: 8 + depth * 16 }}
        >
          <span className="font-medium">{node.name}</span>
          <span className="font-mono text-xs text-[var(--muted-foreground)]">{node.code}</span>
          <Tag className="ml-auto">{node.type}</Tag>
        </button>
      </li>
      {node.children.map((c) => (
        <TreeRow key={c.id} node={c} depth={depth + 1} selected={selected} onSelect={onSelect} />
      ))}
    </>
  );
}

function CreateScopeDialog({
  open,
  onOpenChange,
  parent,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  parent: Scope | null;
}) {
  const qc = useQueryClient();
  const [type, setType] = useState("ORG");
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [parentId, setParentId] = useState<string>(parent?.id ?? "");
  const m = useMutation({
    mutationFn: () =>
      scopesApi.create({ type, name, code, parentId: parentId || null }),
    onSuccess: () => {
      toast.success("Scope created");
      qc.invalidateQueries({ queryKey: ["scopes"] });
      onOpenChange(false);
      setName("");
      setCode("");
    },
    onError: (e: Error) => toast.error(e.message),
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New scope</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <Label htmlFor="s-type">Type</Label>
          <Input id="s-type" value={type} onChange={(e) => setType(e.target.value)} />
          <Label htmlFor="s-name">Name</Label>
          <Input id="s-name" value={name} onChange={(e) => setName(e.target.value)} />
          <Label htmlFor="s-code">Code</Label>
          <Input id="s-code" value={code} onChange={(e) => setCode(e.target.value)} />
          <Label htmlFor="s-parent">Parent ID (optional)</Label>
          <Input id="s-parent" value={parentId} onChange={(e) => setParentId(e.target.value)} />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            onClick={() => m.mutate()}
            disabled={m.isPending || !name || !code || !type}
          >
            {m.isPending ? "Creating..." : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function MoveScopeDialog({
  open,
  onOpenChange,
  scope,
  all,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  scope: Scope;
  all: Scope[];
}) {
  const qc = useQueryClient();
  const [target, setTarget] = useState("");
  const m = useMutation({
    mutationFn: () => scopesApi.move(scope.id, target),
    onSuccess: () => {
      toast.success("Scope moved");
      qc.invalidateQueries({ queryKey: ["scopes"] });
      onOpenChange(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={`Move ${scope.name}`}
      description="Moving a scope re-parents its whole subtree."
      confirmLabel="Move"
      destructive
      pending={m.isPending}
      onConfirm={() => target && m.mutate()}
    >
      <div className="space-y-2">
        <Label htmlFor="m-parent">New parent</Label>
        <select
          id="m-parent"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
        >
          <option value="">Select…</option>
          {all
            .filter((s) => s.id !== scope.id)
            .map((s) => (
              <option key={s.id} value={s.id}>
                {s.path}
              </option>
            ))}
        </select>
      </div>
    </ConfirmDialog>
  );
}