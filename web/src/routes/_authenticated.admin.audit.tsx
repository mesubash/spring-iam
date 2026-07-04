import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { auditApi } from "@/api/resources";
import type { AuditEntry } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { DecisionBadge } from "@/components/iam/badges";
import { Input } from "@/components/ui/input";
import { formatDate } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/admin/audit")({
  component: () => (
    <PermissionGuardedPage permission="platform.audit.read">
      <AuditPage />
    </PermissionGuardedPage>
  ),
});

function AuditPage() {
  const [subjectId, setSubjectId] = useState("");
  const [decision, setDecision] = useState<"" | "ALLOW" | "DENY">("");
  const q = useQuery({
    queryKey: ["audit", subjectId],
    queryFn: () => (subjectId ? auditApi.bySubject(subjectId) : auditApi.recent()),
  });
  const [expanded, setExpanded] = useState<string | null>(null);

  const rows = useMemo(() => {
    const arr = q.data ?? [];
    return decision ? arr.filter((e) => e.decision === decision) : arr;
  }, [q.data, decision]);

  const columns: Column<AuditEntry>[] = [
    { key: "ts", header: "Time", width: "160px", render: (e) => formatDate(e.timestamp) },
    { key: "sub", header: "Subject", render: (e) => <span className="font-mono text-xs">{e.subjectId}</span> },
    { key: "perm", header: "Permission", render: (e) => <span className="font-mono text-xs">{e.permissionKey}</span> },
    { key: "d", header: "Decision", width: "90px", render: (e) => <DecisionBadge decision={e.decision} /> },
    { key: "reason", header: "Reason", render: (e) => e.reason ?? "—" },
    { key: "scope", header: "Scope", render: (e) => e.scopeId ?? "—" },
  ];

  return (
    <div>
      <PageHeader title="Audit" description="Authorization decisions recorded by the server." />
      <div className="mb-3 flex gap-2">
        <Input
          className="max-w-xs"
          placeholder="Filter by subjectId..."
          value={subjectId}
          onChange={(e) => setSubjectId(e.target.value)}
        />
        <select
          value={decision}
          onChange={(e) => setDecision(e.target.value as "" | "ALLOW" | "DENY")}
          className="h-9 rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
        >
          <option value="">All decisions</option>
          <option value="ALLOW">ALLOW</option>
          <option value="DENY">DENY</option>
        </select>
      </div>
      <DataTable
        columns={columns}
        rows={rows}
        loading={q.isLoading}
        empty="No audit entries."
        rowKey={(e) => e.id}
        onRowClick={(e) => setExpanded(expanded === e.id ? null : e.id)}
      />
      {expanded ? (
        <div className="mt-3 rounded border border-[var(--border)] bg-[var(--card)] p-3">
          <div className="mb-2 text-xs font-medium text-[var(--muted-foreground)]">Context</div>
          <pre className="max-h-64 overflow-auto text-xs">
            {JSON.stringify(rows.find((r) => r.id === expanded)?.context ?? {}, null, 2)}
          </pre>
        </div>
      ) : null}
    </div>
  );
}