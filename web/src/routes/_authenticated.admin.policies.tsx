import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { contextAttributesApi, policiesApi, scopesApi } from "@/api/resources";
import type { Policy } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { Can } from "@/components/iam/Can";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { DecisionBadge, EnforcementBadge } from "@/components/iam/badges";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export const Route = createFileRoute("/_authenticated/admin/policies")({
  component: () => (
    <PermissionGuardedPage permission="platform.policy.read">
      <PoliciesPage />
    </PermissionGuardedPage>
  ),
});

function PoliciesPage() {
  const q = useQuery({ queryKey: ["policies"], queryFn: policiesApi.list });
  const qc = useQueryClient();
  const [filter, setFilter] = useState("");
  const [editing, setEditing] = useState<Policy | null>(null);
  const [creating, setCreating] = useState(false);
  const [toDelete, setToDelete] = useState<Policy | null>(null);

  const rows = useMemo(() => {
    if (!q.data) return undefined;
    const f = filter.trim().toLowerCase();
    if (!f) return q.data;
    return q.data.filter((p) =>
      [p.name, p.permissionKey, p.resourceType, p.description]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(f)),
    );
  }, [q.data, filter]);

  const del = useMutation({
    mutationFn: () => policiesApi.del(toDelete!.id),
    onSuccess: () => {
      toast.success("Policy deleted");
      qc.invalidateQueries({ queryKey: ["policies"] });
      setToDelete(null);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<Policy>[] = [
    { key: "name", header: "Name", render: (p) => <span className="font-medium">{p.name}</span> },
    { key: "effect", header: "Effect", width: "90px", render: (p) => <DecisionBadge decision={p.effect} /> },
    { key: "mode", header: "Mode", width: "110px", render: (p) => <EnforcementBadge mode={p.enforcementMode} /> },
    { key: "pri", header: "Priority", width: "80px", render: (p) => p.priority },
    {
      key: "perm",
      header: "Permission",
      render: (p) =>
        p.permissionKey ? (
          <span className="font-mono text-xs">{p.permissionKey}</span>
        ) : (
          <span className="text-[var(--muted-foreground)]">any</span>
        ),
    },
    {
      key: "rt",
      header: "Resource type",
      render: (p) => p.resourceType ?? <span className="text-[var(--muted-foreground)]">—</span>,
    },
  ];

  return (
    <div>
      <PageHeader
        title="Policies"
        description="Attribute-based rules evaluated after RBAC. Higher priority wins; DENY beats ALLOW at equal priority."
        actions={
          <Can permission="platform.policy.create">
            <Button onClick={() => setCreating(true)}>New policy</Button>
          </Can>
        }
      />
      <div className="mb-3 max-w-md">
        <Input
          placeholder="Filter by name, permission, resource type…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>
      <DataTable
        columns={columns}
        rows={rows}
        loading={q.isLoading}
        empty={filter ? "No policies match the filter." : "No policies yet."}
        rowKey={(p) => p.id}
        onRowClick={setEditing}
      />
      {creating ? <PolicyDialog open onOpenChange={setCreating} /> : null}
      {editing ? (
        <PolicyDialog
          open
          onOpenChange={(v) => !v && setEditing(null)}
          policy={editing}
          onDelete={() => {
            setToDelete(editing);
            setEditing(null);
          }}
        />
      ) : null}
      <ConfirmDialog
        open={!!toDelete}
        onOpenChange={(v) => !v && setToDelete(null)}
        title="Delete policy"
        description="The policy stops being evaluated immediately."
        target={toDelete?.name}
        destructive
        confirmLabel="Delete"
        pending={del.isPending}
        onConfirm={() => del.mutate()}
      />
    </div>
  );
}

const OPERATORS = "eq, neq, in, not_in, contains, exists, gt, gte, lt, lte, regex, before, after";
const FIELD_PATHS = ["subject", "permission", "resource.type", "resource.id", "resource.scopeId"];

function PolicyDialog({
  open,
  onOpenChange,
  policy,
  onDelete,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  policy?: Policy;
  onDelete?: () => void;
}) {
  const qc = useQueryClient();
  const scopesQ = useQuery({ queryKey: ["scopes"], queryFn: () => scopesApi.list() });
  const attrsQ = useQuery({ queryKey: ["contextAttributes"], queryFn: contextAttributesApi.list });
  const [name, setName] = useState(policy?.name ?? "");
  const [description, setDescription] = useState(policy?.description ?? "");
  const [effect, setEffect] = useState<"ALLOW" | "DENY">(policy?.effect ?? "ALLOW");
  const [enforcementMode, setEnforcementMode] = useState<"ENFORCE" | "SHADOW">(
    policy?.enforcementMode ?? "SHADOW",
  );
  const [priority, setPriority] = useState<string>(String(policy?.priority ?? 100));
  const [permissionKey, setPermissionKey] = useState(policy?.permissionKey ?? "");
  const [resourceType, setResourceType] = useState(policy?.resourceType ?? "");
  const [scopeId, setScopeId] = useState(policy?.scopeId ?? "");
  const [conditions, setConditions] = useState<string>(
    policy?.conditions ? JSON.stringify(policy.conditions, null, 2) : "{}",
  );
  const [jsonErr, setJsonErr] = useState<string | null>(null);
  const [showRef, setShowRef] = useState(false);

  const validateJson = (v: string) => {
    try {
      JSON.parse(v);
      setJsonErr(null);
      return true;
    } catch (e) {
      setJsonErr((e as Error).message);
      return false;
    }
  };

  const save = useMutation({
    mutationFn: () => {
      if (!validateJson(conditions)) throw new Error("Fix the conditions JSON first.");
      const body: Partial<Policy> = {
        name: name.trim(),
        description: description.trim() || null,
        effect,
        enforcementMode,
        priority: Number(priority) || 0,
        permissionKey: permissionKey.trim() || null,
        resourceType: resourceType.trim() || null,
        scopeId: scopeId || null,
        conditions: JSON.parse(conditions),
      };
      return policy ? policiesApi.update(policy.id, body) : policiesApi.create(body);
    },
    onSuccess: () => {
      toast.success(policy ? "Policy updated" : "Policy created");
      qc.invalidateQueries({ queryKey: ["policies"] });
      onOpenChange(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{policy ? `Edit policy: ${policy.name}` : "New policy"}</DialogTitle>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label htmlFor="p-name">Name</Label>
            <Input id="p-name" value={name} onChange={(e) => setName(e.target.value)} />
            <Label htmlFor="p-desc">Description</Label>
            <Textarea
              id="p-desc"
              rows={2}
              value={description ?? ""}
              onChange={(e) => setDescription(e.target.value)}
            />
            <Label htmlFor="p-effect">Effect</Label>
            <select
              id="p-effect"
              value={effect}
              onChange={(e) => setEffect(e.target.value as "ALLOW" | "DENY")}
              className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
            >
              <option>ALLOW</option>
              <option>DENY</option>
            </select>
            <Label htmlFor="p-mode">Enforcement mode</Label>
            <select
              id="p-mode"
              value={enforcementMode}
              onChange={(e) => setEnforcementMode(e.target.value as "ENFORCE" | "SHADOW")}
              className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
            >
              <option>SHADOW</option>
              <option>ENFORCE</option>
            </select>
            <p className="text-xs text-[var(--muted-foreground)]">
              Shadow policies are evaluated and audited but never affect decisions.
            </p>
            <Label htmlFor="p-pri">Priority</Label>
            <Input
              id="p-pri"
              type="number"
              value={priority}
              onChange={(e) => setPriority(e.target.value)}
            />
            <Label htmlFor="p-perm">Permission key (optional)</Label>
            <Input
              id="p-perm"
              className="font-mono"
              value={permissionKey ?? ""}
              onChange={(e) => setPermissionKey(e.target.value)}
            />
            <Label htmlFor="p-rt">Resource type (optional)</Label>
            <Input
              id="p-rt"
              value={resourceType ?? ""}
              onChange={(e) => setResourceType(e.target.value)}
            />
            <Label htmlFor="p-scope">Scope (optional)</Label>
            <select
              id="p-scope"
              value={scopeId ?? ""}
              onChange={(e) => setScopeId(e.target.value)}
              className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
            >
              <option value="">Any scope</option>
              {(scopesQ.data ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.path}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="p-cond">Conditions (JSON)</Label>
            <textarea
              id="p-cond"
              value={conditions}
              onChange={(e) => {
                setConditions(e.target.value);
                validateJson(e.target.value);
              }}
              rows={14}
              spellCheck={false}
              className="w-full rounded border border-[var(--border)] bg-[var(--card)] p-2 font-mono text-xs"
            />
            {jsonErr ? <p className="text-xs text-[var(--destructive)]">{jsonErr}</p> : null}
            <button
              type="button"
              onClick={() => setShowRef((v) => !v)}
              className="text-xs text-[var(--primary)] hover:underline"
            >
              {showRef ? "Hide" : "Show"} condition reference
            </button>
            {showRef ? (
              <div className="space-y-1 rounded border border-[var(--border)] bg-[var(--background)] p-2 text-[11px] text-[var(--muted-foreground)]">
                <p>
                  <span className="text-[var(--foreground)]">Operators:</span>{" "}
                  <span className="font-mono">{OPERATORS}</span>
                </p>
                <p>
                  <span className="text-[var(--foreground)]">Field paths:</span>{" "}
                  <span className="font-mono">{FIELD_PATHS.join(", ")}</span>
                  {", "}
                  <span className="font-mono">context.additional.&lt;attr&gt;</span>
                </p>
                {attrsQ.data && attrsQ.data.length > 0 ? (
                  <p>
                    <span className="text-[var(--foreground)]">Registered context attributes:</span>{" "}
                    <span className="font-mono">
                      {attrsQ.data.map((a) => `context.additional.${a.name}`).join(", ")}
                    </span>
                  </p>
                ) : null}
                <p>
                  <span className="text-[var(--foreground)]">Example:</span>{" "}
                  <span className="font-mono">
                    {'{"op":"eq","field":"context.additional.mfa","value":true}'}
                  </span>
                </p>
              </div>
            ) : null}
          </div>
        </div>
        <DialogFooter>
          {policy && onDelete ? (
            <Can permission="platform.policy.delete">
              <Button variant="outline" style={{ color: "var(--destructive)" }} onClick={onDelete}>
                Delete
              </Button>
            </Can>
          ) : null}
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => save.mutate()}
            disabled={save.isPending || !name.trim() || !!jsonErr}
          >
            {save.isPending ? "Saving…" : policy ? "Save changes" : "Create policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
