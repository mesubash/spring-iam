import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { groupsApi } from "@/api/resources";
import type { GroupMember, SubjectGroup } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
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
import { formatDate } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/admin/groups")({
  component: GroupsPage,
});

function GroupsPage() {
  const { features } = useAuthz();
  const q = useQuery({ queryKey: ["groups"], queryFn: groupsApi.list });
  const [filter, setFilter] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const rows = useMemo(() => {
    const arr = q.data ?? [];
    const f = filter.trim().toLowerCase();
    return f
      ? arr.filter(
          (g) =>
            g.name.toLowerCase().includes(f) ||
            (g.description ?? "").toLowerCase().includes(f),
        )
      : arr;
  }, [q.data, filter]);

  const selected = (q.data ?? []).find((g) => g.id === selectedId) ?? null;

  if (features && !features.groups) {
    return (
      <p className="text-sm text-[var(--muted-foreground)]">
        The groups feature is disabled on this deployment.
      </p>
    );
  }

  const columns: Column<SubjectGroup>[] = [
    {
      key: "name",
      header: "Name",
      render: (g) => <span className="font-mono text-[13px]">{g.name}</span>,
    },
    { key: "desc", header: "Description", render: (g) => g.description || "—" },
  ];

  return (
    <div>
      <PageHeader
        title="Groups"
        description="Subject groups — assign a role to a group once and every member inherits it."
        actions={<Button onClick={() => setCreating(true)}>New group</Button>}
      />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_380px]">
        <div>
          <Input
            className="mb-3 max-w-xs"
            placeholder="Filter groups…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <DataTable
            columns={columns}
            rows={rows}
            loading={q.isLoading}
            empty="No groups."
            rowKey={(g) => g.id}
            onRowClick={(g) => setSelectedId(g.id)}
          />
        </div>
        {selected ? (
          <MembersPanel group={selected} onClose={() => setSelectedId(null)} />
        ) : (
          <div className="h-fit rounded border border-[var(--border)] bg-[var(--card)] p-4 text-sm text-[var(--muted-foreground)]">
            Select a group to manage its members.
          </div>
        )}
      </div>
      {creating ? <CreateGroupDialog open onOpenChange={setCreating} /> : null}
    </div>
  );
}

function MembersPanel({ group, onClose }: { group: SubjectGroup; onClose: () => void }) {
  const qc = useQueryClient();
  const members = useQuery({
    queryKey: ["group-members", group.id],
    queryFn: () => groupsApi.members(group.id),
  });
  const [subjectId, setSubjectId] = useState("");
  const [toRemove, setToRemove] = useState<GroupMember | null>(null);

  const invalidate = () => qc.invalidateQueries({ queryKey: ["group-members", group.id] });

  const add = useMutation({
    mutationFn: () => groupsApi.addMember(group.id, subjectId.trim()),
    onSuccess: () => {
      toast.success("Member added");
      invalidate();
      setSubjectId("");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const remove = useMutation({
    mutationFn: (sid: string) => groupsApi.removeMember(group.id, sid),
    onSuccess: () => {
      toast.success("Member removed");
      invalidate();
      setToRemove(null);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <div className="h-fit rounded border border-[var(--border)] bg-[var(--card)] p-4 text-sm">
      <div className="mb-3 flex items-start justify-between gap-2">
        <div>
          <div className="font-mono text-[13px] font-semibold">{group.name}</div>
          <div className="mt-0.5 text-xs text-[var(--muted-foreground)]">
            {group.description || "No description"}
          </div>
        </div>
        <button
          className="text-xs text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
          onClick={onClose}
        >
          Close
        </button>
      </div>
      <form
        className="mb-3 space-y-1.5"
        onSubmit={(e) => {
          e.preventDefault();
          if (subjectId.trim()) add.mutate();
        }}
      >
        <Label htmlFor="gm-subject">Add member</Label>
        <div className="flex gap-2">
          <Input
            id="gm-subject"
            className="font-mono text-xs"
            placeholder="Subject ID"
            value={subjectId}
            onChange={(e) => setSubjectId(e.target.value)}
          />
          <Button type="submit" size="sm" disabled={!subjectId.trim() || add.isPending}>
            {add.isPending ? "Adding…" : "Add"}
          </Button>
        </div>
      </form>
      <div className="mb-1 text-xs font-medium uppercase tracking-wide text-[var(--muted-foreground)]">
        Members
      </div>
      {members.isLoading ? (
        <p className="py-3 text-xs text-[var(--muted-foreground)]">Loading members…</p>
      ) : (members.data ?? []).length === 0 ? (
        <p className="py-3 text-xs text-[var(--muted-foreground)]">No members yet.</p>
      ) : (
        <ul className="divide-y divide-[var(--border)]">
          {(members.data ?? []).map((m) => (
            <li key={m.subjectId} className="flex items-center justify-between gap-2 py-1.5">
              <div className="min-w-0">
                <div className="truncate font-mono text-xs">{m.subjectId}</div>
                <div className="text-[11px] text-[var(--muted-foreground)]">
                  Added {formatDate(m.addedAt)}
                </div>
              </div>
              <button
                className="shrink-0 text-xs text-[var(--destructive)] hover:underline"
                onClick={() => setToRemove(m)}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      <ConfirmDialog
        open={!!toRemove}
        onOpenChange={(v) => !v && setToRemove(null)}
        title="Remove group member"
        description="The subject loses any role assignments it inherits through this group."
        target={toRemove ? `${toRemove.subjectId} ← ${group.name}` : undefined}
        destructive
        confirmLabel="Remove"
        pending={remove.isPending}
        onConfirm={() => toRemove && remove.mutate(toRemove.subjectId)}
      />
    </div>
  );
}

function CreateGroupDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const m = useMutation({
    mutationFn: () =>
      groupsApi.create({
        name: name.trim(),
        description: description.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Group created");
      qc.invalidateQueries({ queryKey: ["groups"] });
      onOpenChange(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New group</DialogTitle>
        </DialogHeader>
        <div className="space-y-2">
          <div>
            <Label>Name</Label>
            <Input className="mt-1" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div>
            <Label>Description (optional)</Label>
            <Input
              className="mt-1"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={m.isPending}>
            Cancel
          </Button>
          <Button onClick={() => m.mutate()} disabled={m.isPending || !name.trim()}>
            {m.isPending ? "Creating…" : "Create group"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
