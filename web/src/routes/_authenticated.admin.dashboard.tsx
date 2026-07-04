import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { assignmentsApi, auditApi, denyRulesApi, policiesApi, rolesApi } from "@/api/resources";
import { PageHeader } from "@/components/iam/PageHeader";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { DecisionBadge } from "@/components/iam/badges";
import { formatDate } from "@/lib/format";
import type { AuditEntry } from "@/api/types";
import { useAuthz } from "@/context/AuthzContext";

export const Route = createFileRoute("/_authenticated/admin/dashboard")({
  component: DashboardPage,
});

function Stat({ label, value, loading }: { label: string; value: number | string; loading?: boolean }) {
  return (
    <div className="rounded border border-[var(--border)] bg-[var(--card)] px-4 py-3">
      <div className="text-xs text-[var(--muted-foreground)]">{label}</div>
      <div className="mt-1 text-[22px] font-semibold">
        {loading ? <span className="inline-block h-5 w-10 animate-pulse rounded bg-[var(--muted)]" /> : value}
      </div>
    </div>
  );
}

function DashboardPage() {
  const { can } = useAuthz();

  const roles = useQuery({ queryKey: ["roles"], queryFn: rolesApi.list, enabled: can("platform.role.read") });
  const assignments = useQuery({
    queryKey: ["assignments"],
    queryFn: () => assignmentsApi.list(),
    enabled: can("platform.assignment.read"),
  });
  const denyRules = useQuery({
    queryKey: ["denyRules"],
    queryFn: denyRulesApi.list,
    enabled: can("platform.deny_rule.read"),
  });
  const policies = useQuery({
    queryKey: ["policies"],
    queryFn: policiesApi.list,
    enabled: can("platform.policy.read"),
  });
  const audit = useQuery({
    queryKey: ["audit", "recent"],
    queryFn: auditApi.recent,
    enabled: can("platform.audit.read"),
  });

  const columns: Column<AuditEntry>[] = [
    { key: "ts", header: "Time", width: "160px", render: (e) => formatDate(e.timestamp) },
    { key: "subject", header: "Subject", render: (e) => <span className="font-mono text-xs">{e.subjectId}</span> },
    { key: "perm", header: "Permission", render: (e) => <span className="font-mono text-xs">{e.permissionKey}</span> },
    { key: "dec", header: "Decision", width: "90px", render: (e) => <DecisionBadge decision={e.decision} /> },
    { key: "reason", header: "Reason", render: (e) => e.reason ?? "—" },
  ];

  return (
    <div>
      <PageHeader title="Dashboard" description="Snapshot of your authorization system." />
      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Roles" value={roles.data?.length ?? "—"} loading={roles.isLoading} />
        <Stat label="Active assignments" value={assignments.data?.length ?? "—"} loading={assignments.isLoading} />
        <Stat label="Deny rules" value={denyRules.data?.length ?? "—"} loading={denyRules.isLoading} />
        <Stat label="Policies" value={policies.data?.length ?? "—"} loading={policies.isLoading} />
      </div>
      <h2 className="mb-2 text-sm font-semibold">Recent audit entries</h2>
      <DataTable
        columns={columns}
        rows={(audit.data ?? []).slice(0, 20)}
        loading={audit.isLoading}
        empty="No recent activity."
        rowKey={(e) => e.id}
      />
    </div>
  );
}