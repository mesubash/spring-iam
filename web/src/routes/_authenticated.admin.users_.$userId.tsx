import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { toast } from "sonner";
import { auditApi, identitiesApi } from "@/api/resources";
import type { IdentityAdmin } from "@/api/types";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { Tag } from "@/components/iam/badges";
import {
  AdminPasswordSection,
  MfaResetSection,
  StatusSection,
  UserRolesSection,
  copyToClipboard,
  statusTone,
} from "@/components/iam/user-sections";
import { useAuthz } from "@/context/AuthzContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { formatDate } from "@/lib/format";
import { Copy } from "lucide-react";

export const Route = createFileRoute("/_authenticated/admin/users_/$userId")({
  component: () => (
    <PermissionGuardedPage permission="platform.identity.read">
      <UserDetailPage />
    </PermissionGuardedPage>
  ),
});

function UserDetailPage() {
  const { userId } = Route.useParams();
  const qc = useQueryClient();
  const { can } = useAuthz();
  const userQ = useQuery({
    queryKey: ["identity", userId],
    queryFn: () => identitiesApi.get(userId),
  });
  const u = userQ.data;

  if (userQ.isLoading) {
    return <div className="py-8 text-sm text-[var(--muted-foreground)]">Loading...</div>;
  }
  if (!u) {
    return <div className="py-8 text-sm text-[var(--muted-foreground)]">User not found.</div>;
  }

  const canUpdate = can("platform.identity.update");
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["identities"] });
    qc.invalidateQueries({ queryKey: ["identity", u.id] });
  };

  return (
    <div>
      <div className="mb-4 flex items-start gap-3 border-b border-[var(--border)] pb-4">
        <Link
          to="/admin/users"
          className="rounded p-1 text-lg leading-none hover:bg-[var(--muted)]"
          aria-label="Back to users"
        >
          ←
        </Link>
        <div className="min-w-0">
          <h1 className="flex flex-wrap items-center gap-2 text-lg font-semibold">
            {u.email}
            <Tag tone={statusTone(u.accountStatus)}>{u.accountStatus}</Tag>
            {u.emailVerified ? null : <Tag tone="warning">Unverified</Tag>}
          </h1>
          <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-[var(--muted-foreground)]">
            <span className="font-mono">{u.id}</span>
            <button
              type="button"
              onClick={() => copyToClipboard("Subject ID", u.id)}
              aria-label="Copy subject id"
              className="rounded p-0.5 hover:text-[var(--foreground)]"
            >
              <Copy className="h-3 w-3" />
            </button>
            <span>·</span>
            <span>Last login {u.lastLoginAt ? formatDate(u.lastLoginAt) : "never"}</span>
            <span>·</span>
            <span>Created {formatDate(u.createdAt)}</span>
          </div>
          {/* Keyed so a name saved elsewhere resets the field. */}
          <NameEditor key={u.displayName ?? ""} user={u} canEdit={canUpdate} onSaved={refresh} />
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <IdentitySection user={u} canUpdate={canUpdate} onChanged={refresh} />
        <CredentialsSection userId={u.id} />
        {can("platform.assignment.read") ? (
          <div className="lg:col-span-2">
            <UserRolesSection subjectId={u.id} />
          </div>
        ) : null}
        {canUpdate ? (
          <>
            <AdminPasswordSection user={u} />
            <StatusSection key={u.accountStatus} user={u} onChanged={refresh} />
            {u.mfaEnabled ? <MfaResetSection user={u} /> : null}
          </>
        ) : null}
        {can("platform.audit.read") ? (
          <div className="lg:col-span-2">
            <SecurityEventsSection userId={u.id} />
          </div>
        ) : null}
      </div>
    </div>
  );
}

function NameEditor({
  user,
  canEdit,
  onSaved,
}: {
  user: IdentityAdmin;
  canEdit: boolean;
  onSaved: () => void;
}) {
  const [name, setName] = useState(user.displayName ?? "");
  const save = useMutation({
    // Blank clears the name.
    mutationFn: () => identitiesApi.setDisplayName(user.id, name.trim() || null),
    onSuccess: () => {
      toast.success("Display name saved");
      onSaved();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  if (!canEdit) {
    return user.displayName ? <div className="mt-1 text-sm">{user.displayName}</div> : null;
  }
  const dirty = name.trim() !== (user.displayName ?? "");
  return (
    <form
      className="mt-2 flex items-center gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (dirty) save.mutate();
      }}
    >
      <Input
        aria-label="Display name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder="Display name"
        maxLength={150}
        className="h-8 w-full sm:max-w-xs"
      />
      <Button type="submit" size="sm" disabled={!dirty || save.isPending}>
        {save.isPending ? "Saving..." : "Save"}
      </Button>
    </form>
  );
}

function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <div className="text-xs text-[var(--muted-foreground)]">{label}</div>
      <div className="text-sm">{value}</div>
    </div>
  );
}

const none = <span className="text-[var(--muted-foreground)]">—</span>;

/** What support checks first when a user cannot sign in. */
function IdentitySection({
  user: u,
  canUpdate,
  onChanged,
}: {
  user: IdentityAdmin;
  canUpdate: boolean;
  onChanged: () => void;
}) {
  const verify = useMutation({
    mutationFn: () => identitiesApi.markEmailVerified(u.id),
    onSuccess: () => {
      toast.success("Email marked verified");
      onChanged();
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const lockedUntil =
    u.accountLockedUntil && new Date(u.accountLockedUntil).getTime() > Date.now()
      ? u.accountLockedUntil
      : null;

  return (
    <section className="rounded border border-[var(--border)] p-3">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-sm font-semibold">Identity</h3>
        {canUpdate && !u.emailVerified ? (
          <Button
            variant="outline"
            size="sm"
            disabled={verify.isPending}
            onClick={() => verify.mutate()}
          >
            Mark email verified
          </Button>
        ) : null}
      </div>
      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-3">
        <Fact
          label="Email verified"
          value={u.emailVerified ? <Tag tone="success">Yes</Tag> : <Tag tone="warning">No</Tag>}
        />
        <Fact
          label="MFA"
          value={u.mfaEnabled ? <Tag tone="success">Enabled</Tag> : <Tag>Off</Tag>}
        />
        <Fact
          label="Failed sign-in attempts"
          value={
            (u.failedLoginAttempts ?? 0) > 0 ? (
              <Tag tone="warning">{u.failedLoginAttempts}</Tag>
            ) : (
              "0"
            )
          }
        />
        <Fact
          label="Locked until"
          value={lockedUntil ? <Tag tone="destructive">{formatDate(lockedUntil)}</Tag> : none}
        />
        <Fact
          label="Last sign-in IP"
          value={
            u.lastLoginIp ? <span className="font-mono text-[13px]">{u.lastLoginIp}</span> : none
          }
        />
        <Fact label="Updated" value={u.updatedAt ? formatDate(u.updatedAt) : none} />
      </div>
    </section>
  );
}

function CredentialsSection({ userId }: { userId: string }) {
  const q = useQuery({
    queryKey: ["identity", userId, "credentials"],
    queryFn: () => identitiesApi.credentials(userId),
    retry: false,
  });
  return (
    <section className="rounded border border-[var(--border)] p-3">
      <h3 className="text-sm font-semibold">Sign-in methods</h3>
      {q.isLoading ? (
        <p className="mt-2 text-xs text-[var(--muted-foreground)]">Loading…</p>
      ) : q.isError ? (
        <p className="mt-2 text-xs text-[var(--muted-foreground)]">Not available.</p>
      ) : (q.data ?? []).length === 0 ? (
        <p className="mt-2 text-xs text-[var(--muted-foreground)]">No credentials.</p>
      ) : (
        <ul className="mt-2 divide-y divide-[var(--border)]">
          {(q.data ?? []).map((c, i) => (
            <li key={i} className="flex items-center gap-3 py-1.5">
              <Tag tone={c.active ? "success" : "warning"}>{c.type}</Tag>
              <span className="min-w-0 truncate font-mono text-xs text-[var(--muted-foreground)]">
                {c.identifier ?? ""}
              </span>
              <span className="ml-auto shrink-0 text-xs text-[var(--muted-foreground)]">
                {c.lastUsedAt
                  ? `used ${formatDate(c.lastUsedAt)}`
                  : `added ${formatDate(c.createdAt)}`}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function SecurityEventsSection({ userId }: { userId: string }) {
  const q = useQuery({
    queryKey: ["security-events", { identityId: userId }],
    queryFn: () => auditApi.securityEvents({ identityId: userId, page: 0, size: 10 }),
    retry: false,
  });
  const events = q.data?.content ?? [];
  return (
    <section className="rounded border border-[var(--border)] p-3">
      <h3 className="text-sm font-semibold">Recent security events</h3>
      {q.isLoading ? (
        <p className="mt-2 text-xs text-[var(--muted-foreground)]">Loading…</p>
      ) : q.isError ? (
        <p className="mt-2 text-xs text-[var(--muted-foreground)]">Not available.</p>
      ) : events.length === 0 ? (
        <p className="mt-2 text-xs text-[var(--muted-foreground)]">No events recorded.</p>
      ) : (
        <ul className="mt-2 divide-y divide-[var(--border)]">
          {events.map((e) => (
            <li key={e.id} className="flex items-center gap-3 py-1.5">
              <span className="font-mono text-xs">{e.eventType}</span>
              {e.ipAddress ? (
                <span className="font-mono text-xs text-[var(--muted-foreground)]">
                  {e.ipAddress}
                </span>
              ) : null}
              <span className="ml-auto shrink-0 text-xs text-[var(--muted-foreground)]">
                {formatDate(e.createdAt)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
