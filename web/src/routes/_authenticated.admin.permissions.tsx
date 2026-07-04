import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { permissionsApi } from "@/api/resources";
import type { Permission } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { Tag } from "@/components/iam/badges";
import { Input } from "@/components/ui/input";

export const Route = createFileRoute("/_authenticated/admin/permissions")({
  component: () => (
    <PermissionGuardedPage permission="platform.permission.read">
      <PermissionsPage />
    </PermissionGuardedPage>
  ),
});

function PermissionsPage() {
  const q = useQuery({ queryKey: ["permissions"], queryFn: () => permissionsApi.list() });
  const [filter, setFilter] = useState("");
  const rows = useMemo(() => {
    const arr = q.data ?? [];
    const f = filter.toLowerCase();
    return f ? arr.filter((p) => p.key.toLowerCase().includes(f)) : arr;
  }, [q.data, filter]);

  const columns: Column<Permission>[] = [
    { key: "key", header: "Key", render: (p) => <span className="font-mono text-[13px]">{p.key}</span> },
    { key: "d", header: "Domain", render: (p) => p.domain ?? p.key.split(".")[0] },
    { key: "r", header: "Resource", render: (p) => p.resource ?? "—" },
    { key: "a", header: "Action", render: (p) => p.action ?? "—" },
    { key: "dep", header: "", width: "100px", render: (p) => (p.isDeprecated ? <Tag tone="warning">Deprecated</Tag> : null) },
  ];

  return (
    <div>
      <PageHeader title="Permissions catalog" description="Every permission the server recognises." />
      <div className="mb-3">
        <Input placeholder="Filter permissions..." value={filter} onChange={(e) => setFilter(e.target.value)} className="max-w-xs" />
      </div>
      <DataTable columns={columns} rows={rows} loading={q.isLoading} empty="No permissions." rowKey={(p) => p.id} />
    </div>
  );
}