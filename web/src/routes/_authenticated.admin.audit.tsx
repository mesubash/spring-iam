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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { formatDate } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/admin/audit")({
  component: () => (
    <PermissionGuardedPage permission="platform.audit.read">
      <AuditPage />
    </PermissionGuardedPage>
  ),
});

function AuditPage() {
  return (
    <div>
      <PageHeader
        title="Audit"
        description="Authorization decisions recorded by the PDP. Look up entries by subject, or view a subject's decision statistics."
      />
      <Tabs defaultValue="subject">
        <TabsList>
          <TabsTrigger value="subject">By subject</TabsTrigger>
          <TabsTrigger value="stats">Statistics</TabsTrigger>
        </TabsList>
        <TabsContent value="subject" className="mt-4">
          <BySubjectTab />
        </TabsContent>
        <TabsContent value="stats" className="mt-4">
          <StatisticsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

/* ------------------------------- By subject ------------------------------ */

function BySubjectTab() {
  const [subjectId, setSubjectId] = useState("");
  const [decision, setDecision] = useState<"" | "ALLOW" | "DENY">("");
  const [filter, setFilter] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const subject = subjectId.trim();
  const q = useQuery({
    queryKey: ["audit", "subject", subject],
    queryFn: () => auditApi.bySubject(subject, 100),
    enabled: !!subject,
  });

  const rows = useMemo(() => {
    let arr = q.data ?? [];
    if (decision) arr = arr.filter((e) => (e.decision ? "ALLOW" : "DENY") === decision);
    if (filter.trim()) {
      const f = filter.trim().toLowerCase();
      arr = arr.filter(
        (e) =>
          e.permissionKey.toLowerCase().includes(f) ||
          (e.reason ?? "").toLowerCase().includes(f) ||
          (e.scopeId ?? "").toLowerCase().includes(f),
      );
    }
    return arr;
  }, [q.data, decision, filter]);

  const expandedEntry = expanded ? rows.find((r) => r.id === expanded) : undefined;

  const columns: Column<AuditEntry>[] = [
    { key: "ts", header: "Time", width: "160px", render: (e) => formatDate(e.timestamp) },
    {
      key: "perm",
      header: "Permission",
      render: (e) => <span className="font-mono text-xs">{e.permissionKey}</span>,
    },
    {
      key: "d",
      header: "Decision",
      width: "90px",
      render: (e) => <DecisionBadge decision={e.decision ? "ALLOW" : "DENY"} />,
    },
    {
      key: "reason",
      header: "Reason",
      render: (e) => <span className="font-mono text-xs">{e.reason || "—"}</span>,
    },
    {
      key: "scope",
      header: "Scope",
      render: (e) => <span className="font-mono text-xs">{e.scopeId ?? "—"}</span>,
    },
  ];

  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-2">
        <Input
          className="max-w-xs font-mono text-xs"
          placeholder="Subject ID (required)"
          value={subjectId}
          onChange={(e) => {
            setSubjectId(e.target.value);
            setExpanded(null);
          }}
        />
        <Input
          className="max-w-xs"
          placeholder="Filter permission / reason / scope…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
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
        rows={subject ? rows : []}
        loading={q.isLoading && !!subject}
        empty={
          subject
            ? "No audit entries for this subject."
            : "Enter a subject ID to load its audit trail — there is no global feed."
        }
        rowKey={(e) => e.id}
        onRowClick={(e) => setExpanded(expanded === e.id ? null : e.id)}
      />
      {expandedEntry ? (
        <div className="mt-3 rounded border border-[var(--border)] bg-[var(--card)] p-3">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-xs font-medium text-[var(--muted-foreground)]">
              Entry <span className="font-mono">{expandedEntry.id}</span>
              {expandedEntry.ipAddress ? (
                <>
                  {" "}
                  · from <span className="font-mono">{expandedEntry.ipAddress}</span>
                </>
              ) : null}
              {expandedEntry.resourceType ? (
                <>
                  {" "}
                  · resource{" "}
                  <span className="font-mono">
                    {expandedEntry.resourceType}:{expandedEntry.resourceId ?? "?"}
                  </span>
                </>
              ) : null}
            </span>
            <button
              className="text-xs text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
              onClick={() => setExpanded(null)}
            >
              Close
            </button>
          </div>
          <div className="mb-1 text-xs font-medium text-[var(--muted-foreground)]">Context</div>
          <pre className="max-h-64 overflow-auto rounded bg-[var(--background)] p-2 font-mono text-xs">
            {JSON.stringify(expandedEntry.context ?? {}, null, 2)}
          </pre>
        </div>
      ) : null}
    </div>
  );
}

/* ------------------------------- Statistics ------------------------------ */

function StatisticsTab() {
  const [subjectId, setSubjectId] = useState("");
  const [days, setDays] = useState("7");

  const subject = subjectId.trim();
  const sinceDaysAgo = Math.max(1, Number.parseInt(days, 10) || 7);
  const q = useQuery({
    queryKey: ["audit", "stats", subject, sinceDaysAgo],
    queryFn: () => auditApi.statistics(subject, sinceDaysAgo),
    enabled: !!subject,
  });

  const byPermission = useMemo(
    () => Object.entries(q.data?.byPermission ?? {}).sort((a, b) => b[1] - a[1]),
    [q.data],
  );

  const permColumns: Column<[string, number]>[] = [
    {
      key: "perm",
      header: "Permission",
      render: ([k]) => <span className="font-mono text-xs">{k}</span>,
    },
    { key: "count", header: "Decisions", width: "120px", render: ([, v]) => v },
  ];

  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-2">
        <Input
          className="max-w-xs font-mono text-xs"
          placeholder="Subject ID (required)"
          value={subjectId}
          onChange={(e) => setSubjectId(e.target.value)}
        />
        <Input
          className="w-28"
          type="number"
          min={1}
          placeholder="Days"
          value={days}
          onChange={(e) => setDays(e.target.value)}
        />
        <span className="self-center text-xs text-[var(--muted-foreground)]">
          Window: last {sinceDaysAgo} day{sinceDaysAgo === 1 ? "" : "s"}
        </span>
      </div>
      {!subject ? (
        <div className="rounded border border-[var(--border)] bg-[var(--card)] px-4 py-8 text-center text-sm text-[var(--muted-foreground)]">
          Enter a subject ID to compute its decision statistics.
        </div>
      ) : q.isLoading ? (
        <div className="rounded border border-[var(--border)] bg-[var(--card)] px-4 py-8 text-center text-sm text-[var(--muted-foreground)]">
          Loading statistics…
        </div>
      ) : q.data ? (
        <div>
          <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
            <StatTile label="Total decisions" value={String(q.data.total)} />
            <StatTile label="Allowed" value={String(q.data.allowed)} tone="success" />
            <StatTile label="Denied" value={String(q.data.denied)} tone="destructive" />
            <StatTile label="Allow rate" value={`${Math.round(q.data.allowRate * 100)}%`} />
          </div>
          <div className="mb-2 text-xs font-medium uppercase tracking-wide text-[var(--muted-foreground)]">
            By permission
          </div>
          <DataTable
            columns={permColumns}
            rows={byPermission}
            empty="No decisions in this window."
            rowKey={([k]) => k}
          />
        </div>
      ) : null}
    </div>
  );
}

function StatTile({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "success" | "destructive";
}) {
  return (
    <div className="rounded border border-[var(--border)] bg-[var(--card)] px-3 py-2.5">
      <div className="text-xs text-[var(--muted-foreground)]">{label}</div>
      <div
        className="mt-0.5 text-lg font-semibold tabular-nums"
        style={
          tone === "success"
            ? { color: "var(--success)" }
            : tone === "destructive"
              ? { color: "var(--destructive)" }
              : undefined
        }
      >
        {value}
      </div>
    </div>
  );
}
