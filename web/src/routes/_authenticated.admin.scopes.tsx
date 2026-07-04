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
  const { can } = useAuthz();

  const sorted = useMemo(
    () => [...(q.data ?? [])].sort((a, b) => a.path.localeCompare(b.path)),
    [q.data],
  );
  const visible = useMemo(() => {
    const f = filter.trim().toLowerCase();
    if (!f) return sorted;
    return sorted.filter(
      (s) =>
        s.name.toLowerCase().includes(f) ||
        s.code.toLowerCase().includes(f) ||
        s.path.toLowerCase().includes(f) ||
        s.type.toLowerCase().includes(f),
    );
  }, [sorted, filter]);

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
          ) : visible.length === 0 ? (
            <div className="p-6 text-center text-sm text-[var(--muted-foreground)]">
              {filter ? "No scopes match the filter." : "No scopes yet."}
            </div>
          ) : (
            <ul className="py-1">
              {visible.map((s) => (
                <ScopeRow
                  key={s.id}
                  scope={s}
                  indent={filter ? 0 : s.depth}
                  active={selectedId === s.id}
                  onSelect={() => setSelectedId(s.id)}
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
        <MoveScopeDialog
          open={moveOpen}
          onOpenChange={setMoveOpen}
          scope={selected}
          all={sorted}
        />
      ) : null}
    </div>
  );
}

function ScopeRow({
  scope,
  indent,
  active,
  onSelect,
}: {
  scope: Scope;
  indent: number;
  active: boolean;
  onSelect: () => void;
}) {
  return (
    <li>
      <button
        type="button"
        onClick={onSelect}
        className={cn(
          "flex w-full items-center gap-2 px-2 py-1.5 text-left text-sm hover:bg-[var(--background)] focus:outline-none focus:ring-1 focus:ring-[var(--ring)]",
          active && "bg-[var(--primary-subtle)]",
        )}
        style={{ paddingLeft: 10 + indent * 18 }}
      >
        <span className={cn("font-medium", active && "text-[var(--primary)]")}>
          {scope.name}
        </span>
        <span className="font-mono text-xs text-[var(--muted-foreground)]">{scope.code}</span>
        <span className="hidden truncate font-mono text-xs text-[var(--muted-foreground)] md:inline">
          {scope.path}
        </span>
        <span className="ml-auto flex items-center gap-2">
          <span className="text-xs text-[var(--muted-foreground)]">d{scope.depth}</span>
          <Tag tone="neutral">{scope.type}</Tag>
        </span>
      </button>
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
