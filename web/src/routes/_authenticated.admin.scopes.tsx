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
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
import { Tag } from "@/components/iam/badges";
import { cn } from "@/lib/utils";
import { useAuthz } from "@/context/AuthzContext";
import { buildScopeTree, withAncestors, type ScopeNode } from "@/lib/scope-tree";
import { Network } from "lucide-react";

export const Route = createFileRoute("/_authenticated/admin/scopes")({
  component: () => (
    <PermissionGuardedPage permission="platform.scope.read">
      <ScopesPage />
    </PermissionGuardedPage>
  ),
});

const CODE_RE = /^[A-Za-z0-9_]{1,50}$/;

function ScopesPage() {
  const q = useQuery({ queryKey: ["scopes"], queryFn: () => scopesApi.list() });
  const [filter, setFilter] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [moveOpen, setMoveOpen] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const { can } = useAuthz();

  const sorted = useMemo(
    () => [...(q.data ?? [])].sort((a, b) => a.path.localeCompare(b.path)),
    [q.data],
  );

  // Filtering keeps every ancestor of a match so the tree stays connected,
  // and holds the matched branches open.
  const f = filter.trim().toLowerCase();
  const tree = useMemo(() => {
    const all = q.data ?? [];
    if (!f) return buildScopeTree(all);
    const matches = all.filter(
      (s) =>
        s.name.toLowerCase().includes(f) ||
        s.code.toLowerCase().includes(f) ||
        s.path.toLowerCase().includes(f) ||
        s.type.toLowerCase().includes(f),
    );
    return buildScopeTree(
      withAncestors(
        all,
        matches.map((s) => s.id),
      ),
    );
  }, [q.data, f]);

  const toggleCollapse = (id: string) => {
    if (f) return;
    setCollapsed((prev) => {
      const s = new Set(prev);
      if (s.has(id)) s.delete(id);
      else s.add(id);
      return s;
    });
  };

  const selected = useMemo(
    () => sorted.find((s) => s.id === selectedId) ?? null,
    [sorted, selectedId],
  );

  const descQ = useQuery({
    queryKey: ["scopes", "descendants", selected?.id],
    queryFn: () => scopesApi.descendants(selected!.id),
    enabled: !!selected,
  });
  // The descendants endpoint includes the scope itself.
  const descendantCount = descQ.data ? Math.max(0, descQ.data.length - 1) : undefined;

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
      <div className="mb-3">
        <Input
          placeholder="Filter by name, code, path or type..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="max-w-xs"
        />
      </div>
      <div className="grid grid-cols-[1fr_320px] items-start gap-4">
        <div className="overflow-x-auto rounded border border-[var(--border)] bg-[var(--card)]">
          {q.isLoading ? (
            <div className="p-3 text-sm text-[var(--muted-foreground)]">Loading…</div>
          ) : tree.length === 0 ? (
            <div className="p-6 text-center text-sm text-[var(--muted-foreground)]">
              {filter ? "No scopes match the filter." : "No scopes yet."}
            </div>
          ) : (
            <ul className="py-1">
              {tree.map((n) => (
                <ScopeTreeRow
                  key={n.scope.id}
                  node={n}
                  depth={0}
                  selectedId={selectedId}
                  collapsed={collapsed}
                  onSelect={setSelectedId}
                  onToggle={toggleCollapse}
                />
              ))}
            </ul>
          )}
        </div>
        <aside className="rounded border border-[var(--border)] bg-[var(--card)] p-4 text-sm">
          {!selected ? (
            <p className="text-[var(--muted-foreground)]">Select a scope to see details.</p>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                <div className="font-medium">{selected.name}</div>
                <Tag tone="accent">{selected.type}</Tag>
              </div>
              <MetaRow label="Code" mono value={selected.code} />
              <MetaRow label="Path" mono value={selected.path} />
              <MetaRow label="Depth" value={String(selected.depth)} />
              <MetaRow label="Active" value={selected.active ? "Yes" : "No"} />
              <MetaRow
                label="Descendants"
                value={
                  descQ.isLoading
                    ? "…"
                    : descQ.isError
                      ? "unavailable"
                      : String(descendantCount ?? 0)
                }
              />
              <div>
                <div className="text-xs text-[var(--muted-foreground)]">Metadata</div>
                {selected.metadata && Object.keys(selected.metadata).length > 0 ? (
                  <pre className="mt-1 overflow-x-auto rounded border border-[var(--border)] bg-[var(--background)] p-2 font-mono text-xs">
                    {JSON.stringify(selected.metadata, null, 2)}
                  </pre>
                ) : (
                  <div className="text-sm text-[var(--muted-foreground)]">None</div>
                )}
              </div>
              {can("platform.scope.move") && selected.parentId ? (
                <Button variant="outline" size="sm" onClick={() => setMoveOpen(true)}>
                  Move scope
                </Button>
              ) : null}
            </div>
          )}
        </aside>
      </div>
      <CreateScopeDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        scopes={sorted}
        defaultParentId={selected?.id}
      />
      {selected ? (
        <MoveScopeDialog open={moveOpen} onOpenChange={setMoveOpen} scope={selected} all={sorted} />
      ) : null}
    </div>
  );
}

function ScopeTreeRow({
  node,
  depth,
  selectedId,
  collapsed,
  onSelect,
  onToggle,
}: {
  node: ScopeNode;
  depth: number;
  selectedId: string | null;
  collapsed: Set<string>;
  onSelect: (id: string) => void;
  onToggle: (id: string) => void;
}) {
  const { scope, children } = node;
  const active = selectedId === scope.id;
  const hasChildren = children.length > 0;
  const open = !collapsed.has(scope.id);

  return (
    <li>
      <div
        role="button"
        tabIndex={0}
        onClick={() => onSelect(scope.id)}
        onKeyDown={(e) => e.key === "Enter" && onSelect(scope.id)}
        className={cn(
          "flex w-full cursor-pointer items-stretch px-2 text-left text-sm hover:bg-[var(--background)] focus:outline-none focus:ring-1 focus:ring-inset focus:ring-[var(--ring)]",
          active && "bg-[var(--primary-subtle)]",
        )}
      >
        {/* drawn tree guides, one per ancestor level */}
        {Array.from({ length: depth }, (_, i) => (
          <span
            key={i}
            className="relative w-5 shrink-0 self-stretch border-l border-[var(--border)]"
          >
            {i === depth - 1 ? (
              <span className="absolute left-0 top-1/2 h-px w-4 bg-[var(--border)]" />
            ) : null}
          </span>
        ))}
        <span className="flex min-w-0 flex-1 items-center gap-2 py-1.5">
          {hasChildren ? (
            <button
              type="button"
              aria-label={open ? "Collapse" : "Expand"}
              aria-expanded={open}
              onClick={(e) => {
                e.stopPropagation();
                onToggle(scope.id);
              }}
              className="flex h-5 w-5 shrink-0 items-center justify-center rounded border border-[var(--border)] text-xs leading-none text-[var(--muted-foreground)] hover:bg-[var(--muted)]"
            >
              {open ? "−" : "+"}
            </button>
          ) : (
            <Network
              className={cn(
                "h-4 w-4 shrink-0",
                active ? "text-[var(--primary)]" : "text-[var(--muted-foreground)]",
              )}
            />
          )}
          <span className="flex min-w-0 flex-col">
            <span className={cn("font-medium leading-tight", active && "text-[var(--primary)]")}>
              {scope.name}
              {hasChildren ? (
                <span className="ml-2 text-xs font-normal text-[var(--muted-foreground)]">
                  {children.length}
                </span>
              ) : null}
            </span>
            <span className="truncate font-mono text-[11px] text-[var(--muted-foreground)]">
              {scope.code} · {scope.path}
            </span>
          </span>
          <span className="ml-auto shrink-0">
            <Tag tone="neutral">{scope.type}</Tag>
          </span>
        </span>
      </div>
      {hasChildren && open ? (
        <ul>
          {children.map((c) => (
            <ScopeTreeRow
              key={c.scope.id}
              node={c}
              depth={depth + 1}
              selectedId={selectedId}
              collapsed={collapsed}
              onSelect={onSelect}
              onToggle={onToggle}
            />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function MetaRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs text-[var(--muted-foreground)]">{label}</div>
      <div className={cn("break-all text-sm", mono && "font-mono text-[13px]")}>{value}</div>
    </div>
  );
}

function CreateScopeDialog({
  open,
  onOpenChange,
  scopes,
  defaultParentId,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  scopes: Scope[];
  defaultParentId?: string;
}) {
  const qc = useQueryClient();
  const [type, setType] = useState("");
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [parentId, setParentId] = useState<string>(defaultParentId ?? "");

  const codeInvalid = code.length > 0 && !CODE_RE.test(code);
  const canSubmit = !!type.trim() && !!name.trim() && CODE_RE.test(code) && !!parentId;

  const reset = () => {
    setType("");
    setName("");
    setCode("");
    setParentId(defaultParentId ?? "");
  };

  const m = useMutation({
    mutationFn: () => scopesApi.create({ type: type.trim(), name: name.trim(), code, parentId }),
    onSuccess: () => {
      toast.success("Scope created");
      qc.invalidateQueries({ queryKey: ["scopes"] });
      onOpenChange(false);
      reset();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New scope</DialogTitle>
          <DialogDescription>
            The scope is created under the selected parent and inherits its position in the tree.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="s-type">Type</Label>
            <Input
              id="s-type"
              value={type}
              onChange={(e) => setType(e.target.value)}
              placeholder="e.g. REGION, COUNTRY, ORG"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="s-name">Name</Label>
            <Input id="s-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="s-code">Code</Label>
            <Input
              id="s-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="ALNUM_AND_UNDERSCORE"
            />
            {codeInvalid ? (
              <p className="text-xs text-[var(--destructive)]">
                Code must be 1-50 letters, digits or underscores.
              </p>
            ) : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="s-parent">Parent</Label>
            <select
              id="s-parent"
              value={parentId}
              onChange={(e) => setParentId(e.target.value)}
              className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
            >
              <option value="">Select a parent scope…</option>
              {scopes.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.path}
                </option>
              ))}
            </select>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={m.isPending}>
            Cancel
          </Button>
          <Button onClick={() => m.mutate()} disabled={m.isPending || !canSubmit}>
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
      setTarget("");
    },
    onError: (e: Error) => toast.error(e.message),
  });
  // A scope cannot be moved under itself or one of its own descendants.
  const candidates = all.filter(
    (s) => s.id !== scope.id && s.id !== scope.parentId && !s.path.startsWith(`${scope.path}.`),
  );
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(v) => {
        onOpenChange(v);
        if (!v) setTarget("");
      }}
      title={`Move ${scope.name}`}
      description="Moving a scope re-parents its entire subtree: every descendant path, and everything resolved through them, changes."
      target={scope.path}
      confirmLabel="Move subtree"
      destructive
      pending={m.isPending}
      onConfirm={() => {
        if (!target) {
          toast.error("Select a new parent scope.");
          return;
        }
        m.mutate();
      }}
    >
      <div className="space-y-1.5">
        <Label htmlFor="m-parent">New parent</Label>
        <select
          id="m-parent"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
        >
          <option value="">Select…</option>
          {candidates.map((s) => (
            <option key={s.id} value={s.id}>
              {s.path}
            </option>
          ))}
        </select>
      </div>
    </ConfirmDialog>
  );
}
