import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { contextAttributesApi } from "@/api/resources";
import type { ContextAttribute } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { Can } from "@/components/iam/Can";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { Tag } from "@/components/iam/badges";
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export const Route = createFileRoute("/_authenticated/admin/context-attributes")({
  component: () => (
    <PermissionGuardedPage permission="platform.policy.read">
      <ContextAttributesPage />
    </PermissionGuardedPage>
  ),
});

const VALUE_TYPES = ["STRING", "NUMBER", "BOOLEAN", "TIMESTAMP"] as const;
type ValueType = (typeof VALUE_TYPES)[number];

function ContextAttributesPage() {
  const q = useQuery({ queryKey: ["contextAttributes"], queryFn: contextAttributesApi.list });
  const qc = useQueryClient();
  const [filter, setFilter] = useState("");
  const [creating, setCreating] = useState(false);
  const [toDelete, setToDelete] = useState<ContextAttribute | null>(null);

  const rows = useMemo(() => {
    if (!q.data) return undefined;
    const f = filter.trim().toLowerCase();
    if (!f) return q.data;
    return q.data.filter((a) =>
      [a.name, a.description].filter(Boolean).some((v) => String(v).toLowerCase().includes(f)),
    );
  }, [q.data, filter]);

  const del = useMutation({
    mutationFn: () => contextAttributesApi.del(toDelete!.id),
    onSuccess: () => {
      toast.success("Context attribute deleted");
      qc.invalidateQueries({ queryKey: ["contextAttributes"] });
      setToDelete(null);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<ContextAttribute>[] = [
    {
      key: "name",
      header: "Name",
      render: (a) => <span className="font-mono text-[13px]">{a.name}</span>,
    },
    { key: "type", header: "Type", width: "120px", render: (a) => <Tag>{a.valueType}</Tag> },
    {
      key: "desc",
      header: "Description",
      render: (a) => a.description ?? <span className="text-[var(--muted-foreground)]">—</span>,
    },
    {
      key: "actions",
      header: "",
      width: "80px",
      render: (a) => (
        <Can permission="platform.policy.delete">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setToDelete(a);
            }}
            className="text-xs text-[var(--destructive)] hover:underline"
          >
            Delete
          </button>
        </Can>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Context attributes"
        description="Registered keys usable in policy conditions as context.additional.<name>. Values are supplied per request at authorization time."
        actions={
          <Can permission="platform.policy.create">
            <Button onClick={() => setCreating(true)}>New attribute</Button>
          </Can>
        }
      />
      <div className="mb-3 max-w-md">
        <Input
          placeholder="Filter by name or description…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>
      <DataTable
        columns={columns}
        rows={rows}
        loading={q.isLoading}
        empty={filter ? "No attributes match the filter." : "No context attributes registered yet."}
        rowKey={(a) => a.id}
      />
      {creating ? <AttributeDialog open onOpenChange={setCreating} /> : null}
      <ConfirmDialog
        open={!!toDelete}
        onOpenChange={(v) => !v && setToDelete(null)}
        title="Delete context attribute"
        description="Policies referencing this attribute will no longer resolve it from the registry."
        target={toDelete?.name}
        destructive
        confirmLabel="Delete"
        pending={del.isPending}
        onConfirm={() => del.mutate()}
      />
    </div>
  );
}

function AttributeDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [valueType, setValueType] = useState<ValueType>("STRING");
  const [description, setDescription] = useState("");

  const create = useMutation({
    mutationFn: () =>
      contextAttributesApi.create({
        name: name.trim(),
        valueType,
        description: description.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Context attribute created");
      qc.invalidateQueries({ queryKey: ["contextAttributes"] });
      onOpenChange(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>New context attribute</DialogTitle>
        </DialogHeader>
        <div className="space-y-2">
          <Label htmlFor="ca-name">Name</Label>
          <Input
            id="ca-name"
            className="font-mono"
            placeholder="e.g. mfa, department, ip_range"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <p className="text-xs text-[var(--muted-foreground)]">
            Referenced in conditions as{" "}
            <span className="font-mono">context.additional.{name.trim() || "<name>"}</span>
          </p>
          <Label htmlFor="ca-type">Value type</Label>
          <select
            id="ca-type"
            value={valueType}
            onChange={(e) => setValueType(e.target.value as ValueType)}
            className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
          >
            {VALUE_TYPES.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
          <Label htmlFor="ca-desc">Description (optional)</Label>
          <Textarea
            id="ca-desc"
            rows={2}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={() => create.mutate()} disabled={create.isPending || !name.trim()}>
            {create.isPending ? "Creating…" : "Create attribute"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
