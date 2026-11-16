import { createFileRoute, Link } from "@tanstack/react-router";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { auditApi } from "@/api/resources";
import type { AdminAuditEntry, SecurityEvent } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { Pager } from "@/components/iam/Pager";
import { SubjectPicker } from "@/components/iam/SubjectPicker";
import { Tag } from "@/components/iam/badges";
import { useAuthz } from "@/context/AuthzContext";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { formatDate } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/admin/security-audit")({
  validateSearch: (search: Record<string, unknown>): { identityId?: string } => ({
    identityId: typeof search.identityId === "string" ? search.identityId : undefined,
  }),
  component: () => (
    <PermissionGuardedPage permission="platform.audit.read">
      <SecurityAuditPage />
    </PermissionGuardedPage>
  ),
});

// Mirrors the server's SecurityEventType.
const EVENT_TYPES = [
  "LOGIN_SUCCESS",
  "LOGIN_FAILED",
  "PASSWORD_CHANGED",
  "PASSWORD_RESET",
  "ACCOUNT_LOCKED",
  "ACCOUNT_UNLOCKED",
  "ACCOUNT_SUSPENDED",
  "ACCOUNT_DEACTIVATED",
  "TOKEN_REVOKED",
  "SESSION_EVICTED",
  "REUSE_DETECTED",
  "OAUTH_LINKED",
  "EMAIL_CHANGED",
  "EMAIL_VERIFIED",
  "MFA_ENABLED",
  "MFA_DISABLED",
  "MFA_VERIFIED",
  "MFA_FAILED",
  "MFA_RECOVERY_USED",
  "MFA_RESET_BY_ADMIN",
];

function SecurityAuditPage() {
  const { identityId } = Route.useSearch();
  return (
    <div>
      <PageHeader
        title="Security & Admin Audit"
        description="Changes made through the admin API, and the authentication events of every account."
      />
      <Tabs defaultValue={identityId ? "security" : "admin"}>
        <TabsList>
          <TabsTrigger value="admin">Admin changes</TabsTrigger>
          <TabsTrigger value="security">Security events</TabsTrigger>
        </TabsList>
        <TabsContent value="admin" className="mt-4">
          <AdminChangesTab />
        </TabsContent>
        <TabsContent value="security" className="mt-4">
          <SecurityEventsTab initialIdentityId={identityId ?? ""} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function methodTone(method: string): "success" | "warning" | "destructive" | "neutral" {
  if (method === "DELETE") return "destructive";
  if (method === "POST") return "success";
  if (method === "PUT" || method === "PATCH") return "warning";
  return "neutral";
}

/** A user id, linked to the user's page when the viewer can open it. */
function SubjectCell({ id, label }: { id: string | null; label?: string | null }) {
  const { can } = useAuthz();
  if (!id) return <span className="text-[var(--muted-foreground)]">—</span>;
  const text = label ?? <span className="font-mono text-xs">{id}</span>;
  return can("platform.identity.read") ? (
    <Link
      to="/admin/users/$userId"
      params={{ userId: id }}
      className="text-[var(--primary)] hover:underline"
    >
      {text}
    </Link>
  ) : (
    text
  );
}

function AdminChangesTab() {
  const [actorId, setActorId] = useState("");
  const [page, setPage] = useState(0);
  const q = useQuery({
    queryKey: ["admin-actions", actorId, page],
    queryFn: () => auditApi.adminActions({ actorId: actorId || undefined, page, size: 50 }),
    placeholderData: keepPreviousData,
  });

  const columns: Column<AdminAuditEntry>[] = [
    { key: "when", header: "When", width: "170px", render: (r) => formatDate(r.createdAt) },
    {
      key: "actor",
      header: "Actor",
      render: (r) => <SubjectCell id={r.actorId} label={r.actorEmail} />,
    },
    {
      key: "action",
      header: "Action",
      render: (r) => (
        <span className="flex items-center gap-2">
          <Tag tone={methodTone(r.method)}>{r.method}</Tag>
          <span className="font-mono text-xs">{r.path}</span>
        </span>
      ),
    },
    { key: "status", header: "Status", width: "80px", render: (r) => r.status },
    {
      key: "ip",
      header: "IP",
      width: "140px",
      render: (r) => (
        <span className="font-mono text-xs" title={r.userAgent ?? undefined}>
          {r.ip ?? "—"}
        </span>
      ),
    },
  ];

  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-2">
        <SubjectPicker
          className="w-full max-w-xs"
          placeholder="Filter by actor…"
          value={actorId}
          onChange={(id) => {
            setActorId(id);
            setPage(0);
          }}
        />
      </div>
      <DataTable
        columns={columns}
        rows={q.data?.content}
        loading={q.isLoading}
        empty="No admin changes recorded."
        rowKey={(r) => r.id}
      />
      <Pager page={page} onPage={setPage} totalPages={q.data?.totalPages ?? 0} />
    </div>
  );
}

function SecurityEventsTab({ initialIdentityId }: { initialIdentityId: string }) {
  const [identityId, setIdentityId] = useState(initialIdentityId);
  const [eventType, setEventType] = useState("");
  const [since, setSince] = useState("");
  const [page, setPage] = useState(0);
  // A date input gives YYYY-MM-DD; read it as local midnight.
  const sinceIso = since ? new Date(`${since}T00:00`).toISOString() : undefined;

  const q = useQuery({
    queryKey: ["security-events", { identityId, eventType, sinceIso, page }],
    queryFn: () =>
      auditApi.securityEvents({
        identityId: identityId || undefined,
        eventType: eventType || undefined,
        since: sinceIso,
        page,
        size: 50,
      }),
    placeholderData: keepPreviousData,
  });

  const columns: Column<SecurityEvent>[] = [
    { key: "when", header: "When", width: "170px", render: (e) => formatDate(e.createdAt) },
    {
      key: "type",
      header: "Event",
      render: (e) => <span className="font-mono text-xs">{e.eventType}</span>,
    },
    { key: "subject", header: "User", render: (e) => <SubjectCell id={e.identityId} /> },
    {
      key: "ip",
      header: "IP",
      width: "140px",
      render: (e) => (
        <span className="font-mono text-xs" title={e.userAgent ?? undefined}>
          {e.ipAddress ?? "—"}
        </span>
      ),
    },
    {
      key: "meta",
      header: "Details",
      render: (e) => {
        const text =
          e.metadata && Object.keys(e.metadata).length > 0 ? JSON.stringify(e.metadata) : "";
        return (
          <span className="block max-w-xs truncate font-mono text-xs" title={text}>
            {text || "—"}
          </span>
        );
      },
    },
  ];

  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-2">
        <SubjectPicker
          className="w-full max-w-xs"
          placeholder="Filter by user…"
          value={identityId}
          onChange={(id) => {
            setIdentityId(id);
            setPage(0);
          }}
        />
        <select
          aria-label="Event type"
          value={eventType}
          onChange={(e) => {
            setEventType(e.target.value);
            setPage(0);
          }}
          className="h-9 rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
        >
          <option value="">All events</option>
          {EVENT_TYPES.map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
        <Input
          type="date"
          aria-label="Since"
          className="w-40"
          value={since}
          onChange={(e) => {
            setSince(e.target.value);
            setPage(0);
          }}
        />
      </div>
      <DataTable
        columns={columns}
        rows={q.data?.content}
        loading={q.isLoading}
        empty="No security events match."
        rowKey={(e) => e.id}
      />
      <Pager page={page} onPage={setPage} totalPages={q.data?.totalPages ?? 0} />
    </div>
  );
}
