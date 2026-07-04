import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { assignmentsApi, auditApi, policiesApi, rolesApi, scopesApi } from "@/api/resources";
import { PageHeader } from "@/components/iam/PageHeader";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { DecisionBadge } from "@/components/iam/badges";
import { formatDate } from "@/lib/format";
import type { AuditEntry } from "@/api/types";
import { useAuthz } from "@/context/AuthzContext";
import { useAuth } from "@/context/AuthContext";

export const Route = createFileRoute("/_authenticated/admin/dashboard")({
  component: DashboardPage,
});

function Stat({ label, value, loading }: { label: string; value: number | string; loading?: boolean }) {
  return (
    <div className="rounded border border-border bg-card px-4 py-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 text-[22px] font-semibold tabular-nums">
        {loading ? <span className="inline-block h-5 w-10 animate-pulse rounded bg-muted" /> : value}
      </div>
    </div>
  );
}

function DashboardPage() {
  const { can } = useAuthz();
  const { identity } = useAuth();
  const subjectId = identity?.id;

  const roles = useQuery({
    queryKey: ["roles"],
    queryFn: () => rolesApi.list(),
    enabled: can("platform.role.read"),
  });
  const assignments = useQuery({
    queryKey: ["assignments"],
    queryFn: () => assignmentsApi.list(),
    enabled: can("platform.assignment.read"),
  });
  const scopes = useQuery({
    queryKey: ["scopes"],
    queryFn: () => scopesApi.list(),
    enabled: can("platform.scope.read"),
  });
  const policies = useQuery({
    queryKey: ["policies"],
    queryFn: () => policiesApi.list(),
    enabled: can("platform.policy.read"),
  });
  const audit = useQuery({
    queryKey: ["audit", "subject", subjectId],
    queryFn: () => auditApi.bySubject(subjectId!, 20),
    enabled: !!subjectId && can("platform.audit.read"),
  });

  const activeAssignments = assignments.data?.filter((a) => a.active).length;

  const columns: Column<AuditEntry>[] = [
    { key: "ts", header: "Time", width: "170px", render: (e) => formatDate(e.timestamp) },
    {
      key: "perm",
      header: "Permission",
      render: (e) => <span className="font-mono text-xs">{e.permissionKey}</span>,
    },
    {
      key: "dec",
      header: "Decision",
      width: "90px",
      render: (e) => <DecisionBadge decision={e.decision ? "ALLOW" : "DENY"} />,
    },
    {
      key: "reason",
      header: "Reason",
      render: (e) => <span className="text-muted-foreground">{e.reason ?? "—"}</span>,
    },
  ];

  return (
    <div>
      <PageHeader title="Dashboard" description="Snapshot of your authorization system." />
      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Roles" value={roles.data?.length ?? "—"} loading={roles.isLoading} />
        <Stat label="Active assignments" value={activeAssignments ?? "—"} loading={assignments.isLoading} />
        <Stat label="Scopes" value={scopes.data?.length ?? "—"} loading={scopes.isLoading} />
        <Stat label="Policies" value={policies.data?.length ?? "—"} loading={policies.isLoading} />
      </div>
      <div className="mb-2">
        <h2 className="text-sm font-semibold">Recent decisions (you)</h2>
        <p className="text-xs text-muted-foreground">
          Authorization decisions recorded for your own account{identity?.email ? ` (${identity.email})` : ""}.
        </p>
      </div>
      <DataTable
        columns={columns}
        rows={audit.data}
        loading={audit.isLoading}
        empty="No recent decisions recorded for your account."
        rowKey={(e) => e.id}
      />
    </div>
  );
}
