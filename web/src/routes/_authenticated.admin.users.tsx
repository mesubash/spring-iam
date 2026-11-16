import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { assignmentsApi, identitiesApi, rolesApi, scopesApi } from "@/api/resources";
import type { IdentityAdmin } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { Can } from "@/components/iam/Can";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { Tag } from "@/components/iam/badges";
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
import { Pager } from "@/components/iam/Pager";
import { copyToClipboard, statusTone } from "@/components/iam/user-sections";
import { useAuthz } from "@/context/AuthzContext";
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { formatDate } from "@/lib/format";
import { Copy, MoreHorizontal } from "lucide-react";

export const Route = createFileRoute("/_authenticated/admin/users")({
  component: () => (
    <PermissionGuardedPage permission="platform.identity.read">
      <UsersPage />
    </PermissionGuardedPage>
  ),
});

const PAGE_SIZE = 50;
type StatusTarget = "ACTIVE" | "SUSPENDED" | "DEACTIVATED";

function UsersPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { can } = useAuthz();
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const [creating, setCreating] = useState(false);
  const [statusChange, setStatusChange] = useState<{
    user: IdentityAdmin;
    to: StatusTarget;
  } | null>(null);

  useEffect(() => {
    // A new filter starts from the first page.
    const t = setTimeout(() => {
      setDebounced(query.trim());
      setPage(0);
    }, 250);
    return () => clearTimeout(t);
  }, [query]);

  const q = useQuery({
    queryKey: ["identities", debounced, status, page],
    queryFn: () =>
      identitiesApi.list({
        query: debounced || undefined,
        status: status || undefined,
        limit: PAGE_SIZE,
        page,
      }),
    placeholderData: keepPreviousData,
  });

  const changeStatus = useMutation({
    mutationFn: () => identitiesApi.setStatus(statusChange!.user.id, statusChange!.to),
    onSuccess: (updated) => {
      toast.success(`Account is now ${updated.accountStatus}`);
      setStatusChange(null);
      qc.invalidateQueries({ queryKey: ["identities"] });
      qc.invalidateQueries({ queryKey: ["identity", updated.id] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const openUser = (u: IdentityAdmin) =>
    navigate({ to: "/admin/users/$userId", params: { userId: u.id } });
  const canUpdate = can("platform.identity.update");

  const columns: Column<IdentityAdmin>[] = [
    {
      key: "email",
      header: "Email",
      render: (u) => (
        <div className="min-w-0">
          <span className="group/email flex items-center gap-1.5 text-[13px]">
            {u.email}
            <button
              type="button"
              aria-label="Copy email"
              onClick={(e) => {
                e.stopPropagation();
                copyToClipboard("Email", u.email);
              }}
              className="rounded p-0.5 text-[var(--muted-foreground)] opacity-0 transition-opacity hover:text-[var(--foreground)] focus-visible:opacity-100 group-hover/email:opacity-100"
            >
              <Copy className="h-3 w-3" />
            </button>
          </span>
          {u.displayName ? (
            <span className="text-xs text-[var(--muted-foreground)]">{u.displayName}</span>
          ) : null}
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      width: "110px",
      render: (u) => <Tag tone={statusTone(u.accountStatus)}>{u.accountStatus}</Tag>,
    },
    {
      key: "verified",
      header: "Verified",
      width: "90px",
      render: (u) =>
        u.emailVerified ? <Tag tone="success">Yes</Tag> : <Tag tone="warning">No</Tag>,
    },
    {
      key: "lastLogin",
      header: "Last login",
      width: "170px",
      render: (u) =>
        u.lastLoginAt ? formatDate(u.lastLoginAt) : <span className="text-[var(--muted-foreground)]">Never</span>,
    },
    { key: "created", header: "Created", width: "170px", render: (u) => formatDate(u.createdAt) },
    {
      key: "actions",
      header: "",
      width: "48px",
      render: (u) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
            <Button variant="ghost" size="sm" aria-label={`Actions for ${u.email}`}>
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
            <DropdownMenuItem onClick={() => openUser(u)}>View details</DropdownMenuItem>
            <DropdownMenuItem onClick={() => copyToClipboard("Subject ID", u.id)}>
              Copy subject ID
            </DropdownMenuItem>
            {canUpdate && u.accountStatus !== "ACTIVE" ? (
              <DropdownMenuItem onClick={() => setStatusChange({ user: u, to: "ACTIVE" })}>
                Activate
              </DropdownMenuItem>
            ) : null}
            {canUpdate && u.accountStatus === "ACTIVE" ? (
              <DropdownMenuItem onClick={() => setStatusChange({ user: u, to: "SUSPENDED" })}>
                Suspend
              </DropdownMenuItem>
            ) : null}
            {canUpdate && u.accountStatus !== "DEACTIVATED" ? (
              <DropdownMenuItem
                className="text-[var(--destructive)]"
                onClick={() => setStatusChange({ user: u, to: "DEACTIVATED" })}
              >
                Deactivate
              </DropdownMenuItem>
            ) : null}
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Users"
        description="Accounts known to this IAM instance. Open a user to manage roles, credentials and status."
        actions={
          <Can permission="platform.identity.create">
            <Button onClick={() => setCreating(true)}>New user</Button>
          </Can>
        }
      />
      <div className="mb-3 flex gap-2">
        <Input
          placeholder="Search by email…"
          aria-label="Search by email"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="max-w-xs"
        />
        <select
          aria-label="Filter by status"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(0);
          }}
          className="h-9 rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
        >
          <option value="">All statuses</option>
          <option>ACTIVE</option>
          <option>LOCKED</option>
          <option>SUSPENDED</option>
          <option>DEACTIVATED</option>
        </select>
      </div>
      <DataTable
        columns={columns}
        rows={q.data}
        loading={q.isLoading}
        empty={debounced || status ? "No users match the filter." : "No users."}
        rowKey={(u) => u.id}
        onRowClick={openUser}
      />
      <Pager page={page} onPage={setPage} hasNext={(q.data?.length ?? 0) === PAGE_SIZE} />
      {creating ? <CreateUserDialog open onOpenChange={setCreating} /> : null}
      <ConfirmDialog
        open={!!statusChange}
        onOpenChange={(v) => !v && setStatusChange(null)}
        title="Change account status"
        description={
          statusChange?.to === "ACTIVE"
            ? "The account is restored and the user can sign in again."
            : "The user is signed out everywhere and cannot log in until reactivated."
        }
        target={statusChange ? `${statusChange.user.email} → ${statusChange.to}` : undefined}
        confirmLabel="Change status"
        destructive={statusChange?.to !== "ACTIVE"}
        pending={changeStatus.isPending}
        onConfirm={() => changeStatus.mutate()}
      />
    </div>
  );
}

/* ------------------------------ Create user ----------------------------- */

function CreateUserDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const qc = useQueryClient();
  const { can } = useAuthz();
  const canAssign = can("platform.assignment.create");
  const rolesQ = useQuery({ queryKey: ["roles"], queryFn: () => rolesApi.list(), enabled: canAssign });
  const scopesQ = useQuery({ queryKey: ["scopes"], queryFn: () => scopesApi.list(), enabled: canAssign });

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [emailVerified, setEmailVerified] = useState(true);
  const [roleId, setRoleId] = useState("");
  const [scopeId, setScopeId] = useState("");
  const [tempPassword, setTempPassword] = useState<string | null>(null);
  const [createdEmail, setCreatedEmail] = useState("");

  const scopes = useMemo(
    () => [...(scopesQ.data ?? [])].sort((a, b) => a.path.localeCompare(b.path)),
    [scopesQ.data],
  );

  const create = useMutation({
    mutationFn: async () => {
      const created = await identitiesApi.create({
        email: email.trim(),
        password: password || undefined,
        emailVerified,
      });
      if (roleId && scopeId) {
        await assignmentsApi.create({
          subjectId: created.identity.id,
          subjectType: "USER",
          roleId,
          scopeId,
        });
      }
      return created;
    },
    onSuccess: (created) => {
      qc.invalidateQueries({ queryKey: ["identities"] });
      qc.invalidateQueries({ queryKey: ["assignments"] });
      if (created.temporaryPassword) {
        setCreatedEmail(created.identity.email);
        setTempPassword(created.temporaryPassword);
        toast.success("User created — copy the temporary password now");
      } else {
        toast.success("User created");
        onOpenChange(false);
      }
    },
    onError: (e: Error) => toast.error(e.message),
  });

  if (tempPassword) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Temporary password</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-[var(--muted-foreground)]">
            Share this with <span className="font-medium text-[var(--foreground)]">{createdEmail}</span>{" "}
            over a secure channel. It is shown only once.
          </p>
          <div className="flex items-center gap-2 rounded border border-[var(--border)] bg-[var(--background)] px-3 py-2">
            <code className="flex-1 break-all font-mono text-sm">{tempPassword}</code>
            <button
              type="button"
              onClick={() => copyToClipboard("Password", tempPassword)}
              aria-label="Copy password"
              className="rounded p-1 text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
            >
              <Copy className="h-4 w-4" />
            </button>
          </div>
          <DialogFooter>
            <Button onClick={() => onOpenChange(false)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>New user</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="u-email">Email</Label>
            <Input
              id="u-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="u-pass">Password</Label>
            <Input
              id="u-pass"
              type="text"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Leave blank to generate a temporary password"
              autoComplete="off"
            />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={emailVerified}
              onChange={(e) => setEmailVerified(e.target.checked)}
            />
            Mark email as verified (skip the verification loop)
          </label>
          <Can permission="platform.assignment.create">
            <div className="space-y-3 rounded border border-[var(--border)] p-3">
              <p className="text-xs font-medium text-[var(--muted-foreground)]">
                Initial role (optional)
              </p>
              <div className="space-y-1.5">
                <Label htmlFor="u-role">Role</Label>
                <select
                  id="u-role"
                  value={roleId}
                  onChange={(e) => setRoleId(e.target.value)}
                  className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
                >
                  <option value="">No role</option>
                  {(rolesQ.data ?? []).map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.displayName || r.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="u-scope">Scope</Label>
                <select
                  id="u-scope"
                  value={scopeId}
                  onChange={(e) => setScopeId(e.target.value)}
                  className="h-9 w-full rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm"
                >
                  <option value="">Select a scope…</option>
                  {scopes.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.path}
                    </option>
                  ))}
                </select>
              </div>
              {roleId && !scopeId ? (
                <p className="text-xs text-[var(--warning)]">Pick a scope for the initial role.</p>
              ) : null}
            </div>
          </Can>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            Cancel
          </Button>
          <Button
            onClick={() => create.mutate()}
            disabled={create.isPending || !email.trim() || (!!roleId && !scopeId)}
          >
            {create.isPending ? "Creating…" : "Create user"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
