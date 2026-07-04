import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { groupsApi } from "@/api/resources";
import type { Group } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuthz } from "@/context/AuthzContext";

export const Route = createFileRoute("/_authenticated/admin/groups")({
  component: GroupsPage,
});

function GroupsPage() {
  const { features } = useAuthz();
  const q = useQuery({ queryKey: ["groups"], queryFn: groupsApi.list });
  const [selected, setSelected] = useState<Group | null>(null);

  if (features && !features.groups) {
    return <p className="text-sm text-[var(--muted-foreground)]">Groups are disabled.</p>;
  }

  const columns: Column<Group>[] = [
    { key: "name", header: "Name", render: (g) => <span className="font-mono text-[13px]">{g.name}</span> },
    { key: "dn", header: "Display name", render: (g) => g.displayName ?? "—" },
    { key: "desc", header: "Description", render: (g) => g.description ?? "—" },
  ];

  return (
    <div>
      <PageHeader title="Groups" description="Collections of subjects that receive shared assignments." />
      <div className="grid grid-cols-[1fr_360px] gap-4">
        <DataTable
          columns={columns}
          rows={q.data}
          loading={q.isLoading}
          empty="No groups."
          rowKey={(g) => g.id}
          onRowClick={setSelected}
        />
        {selected ? <GroupDetail group={selected} onClose={() => setSelected(null)} /> : (
          <div className="rounded border border-[var(--border)] bg-[var(--card)] p-4 text-sm text-[var(--muted-foreground)]">
            Select a group to view members.
          </div>
        )}
      </div>
    </div>
  );
}

function GroupDetail({ group, onClose }: { group: Group; onClose: () => void }) {
  const qc = useQueryClient();
  const members = useQuery({
    queryKey: ["group-members", group.id],
    queryFn: () => groupsApi.members(group.id),
  });
  const [subjectId, setSubjectId] = useState("");
  const [subjectType, setSubjectType] = useState("USER");

  const add = useMutation({
    mutationFn: () => groupsApi.addMember(group.id, { subjectId, subjectType }),
    onSuccess: () => {
      toast.success("Member added");
      qc.invalidateQueries({ queryKey: ["group-members", group.id] });
      setSubjectId("");
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const remove = useMutation({
    mutationFn: (memberId: string) => groupsApi.removeMember(group.id, memberId),
    onSuccess: () => {
      toast.success("Member removed");
      qc.invalidateQueries({ queryKey: ["group-members", group.id] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <div className="rounded border border-[var(--border)] bg-[var(--card)] p-4 text-sm">
      <div className="mb-3 flex items-start justify-between">
        <div>
          <div className="font-semibold">{group.name}</div>
          <div className="text-xs text-[var(--muted-foreground)]">{group.description ?? "No description"}</div>
        </div>
        <button className="text-xs text-[var(--muted-foreground)]" onClick={onClose}>Close</button>
      </div>
      <div className="mb-3 space-y-2">
        <Label htmlFor="gm-sub">Add member</Label>
        <div className="flex gap-2">
          <Input id="gm-sub" placeholder="Subject ID" value={subjectId} onChange={(e) => setSubjectId(e.target.value)} />
          <select
            value={subjectType}
            onChange={(e) => setSubjectType(e.target.value)}
            className="h-9 rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
          >
            <option value="USER">USER</option>
            <option value="GROUP">GROUP</option>
            <option value="SERVICE">SERVICE</option>
          </select>
          <Button size="sm" onClick={() => add.mutate()} disabled={!subjectId || add.isPending}>
            Add
          </Button>
        </div>
      </div>
      <ul className="divide-y divide-[var(--border)]">
        {(members.data ?? []).map((m) => (
          <li key={m.id} className="flex items-center justify-between py-1.5">
            <span className="font-mono text-xs">{m.subjectType}:{m.subjectId}</span>
            <button className="text-xs text-[var(--destructive)]" onClick={() => remove.mutate(m.id)}>
              Remove
            </button>
          </li>
        ))}
        {!members.isLoading && (members.data ?? []).length === 0 ? (
          <li className="py-4 text-center text-xs text-[var(--muted-foreground)]">No members.</li>
        ) : null}
      </ul>
    </div>
  );
}