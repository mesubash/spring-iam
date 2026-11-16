import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { assignmentsApi, permissionsApi, rolesApi } from "@/api/resources";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { PermissionTree } from "@/components/iam/PermissionTree";
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
import { Tag } from "@/components/iam/badges";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/context/AuthContext";
import { useAuthz } from "@/context/AuthzContext";

export const Route = createFileRoute("/_authenticated/admin/roles_/$roleId")({
  component: () => (
    <PermissionGuardedPage permission="platform.role.read">
      <RoleDetailPage />
    </PermissionGuardedPage>
  ),
});

function RoleDetailPage() {
  const { roleId } = Route.useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { identity } = useAuth();
  const { can } = useAuthz();

  const roleQ = useQuery({ queryKey: ["role", roleId], queryFn: () => rolesApi.get(roleId) });
  const permsQ = useQuery({ queryKey: ["permissions"], queryFn: () => permissionsApi.list() });
  const rolePermsQ = useQuery({
    queryKey: ["role-permissions", roleId],
    queryFn: () => rolesApi.permissions(roleId),
  });

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dirty, setDirty] = useState(false);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    if (rolePermsQ.data) {
      setSelected(new Set(rolePermsQ.data.map((p) => p.id)));
      setDirty(false);
    }
  }, [rolePermsQ.data]);

  // A role the signed-in user holds themselves. Editing it is how someone grants
  // themselves more, or locks themselves out of the console, so it stays read-only.
  const myAssignmentsQ = useQuery({
    queryKey: ["assignments", identity?.id],
    queryFn: () => assignmentsApi.list({ subjectId: identity!.id }),
    enabled: !!identity?.id,
  });
  const isOwnRole = (myAssignmentsQ.data ?? []).some(
    (a) => a.roleId === roleId && a.active && !a.revokedAt,
  );

  const role = roleQ.data;
  // The permission decides who may edit; the server refuses system roles.
  const canUpdate = can("platform.role.update");
  const readOnly = !canUpdate || isOwnRole || !!role?.isSystemRole;

  const save = useMutation({
    mutationFn: () => rolesApi.updatePermissions(roleId, Array.from(selected)),
    onSuccess: () => {
      toast.success("Permissions saved");
      setDirty(false);
      qc.invalidateQueries({ queryKey: ["role-permissions", roleId] });
      qc.invalidateQueries({ queryKey: ["roles"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // The server refuses a role still held by an active assignment (409); show its message.
  const remove = useMutation({
    mutationFn: () => rolesApi.del(roleId),
    onSuccess: () => {
      toast.success("Role deleted");
      setDeleting(false);
      qc.invalidateQueries({ queryKey: ["roles"] });
      navigate({ to: "/admin/roles" });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const setMany = (ids: string[], on: boolean) => {
    if (readOnly) return;
    setSelected((prev) => {
      const s = new Set(prev);
      ids.forEach((id) => (on ? s.add(id) : s.delete(id)));
      return s;
    });
    setDirty(true);
  };

  if (roleQ.isLoading || permsQ.isLoading || rolePermsQ.isLoading) {
    return <div className="py-8 text-sm text-[var(--muted-foreground)]">Loading...</div>;
  }
  if (!role) {
    return <div className="py-8 text-sm text-[var(--muted-foreground)]">Role not found.</div>;
  }

  const readOnlyReason = isOwnRole
    ? "You hold this role, so you cannot change its permissions."
    : role.isSystemRole
      ? "System role permissions cannot be changed."
      : "You do not have permission to change roles.";

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center gap-3 border-b border-[var(--border)] pb-4">
        <Link
          to="/admin/roles"
          className="rounded p-1 text-lg leading-none hover:bg-[var(--muted)]"
          aria-label="Back to roles"
        >
          ←
        </Link>
        <div className="min-w-0">
          <h1 className="flex flex-wrap items-center gap-2 text-lg font-semibold">
            {role.displayName ?? role.name}
            <span className="font-mono text-sm font-normal text-[var(--muted-foreground)]">
              {role.name}
            </span>
            {role.isSystemRole ? <Tag>System</Tag> : null}
            {isOwnRole ? <Tag>Your role</Tag> : null}
          </h1>
          {role.description ? (
            <p className="text-sm text-[var(--muted-foreground)]">{role.description}</p>
          ) : null}
        </div>
        <div className="ml-auto flex items-center gap-2">
          {can("platform.role.delete") && !role.isSystemRole ? (
            <Button
              variant="outline"
              style={{ color: "var(--destructive)" }}
              onClick={() => setDeleting(true)}
            >
              Delete
            </Button>
          ) : null}
          <Button variant="outline" onClick={() => navigate({ to: "/admin/roles" })}>
            {readOnly ? "Back" : "Cancel"}
          </Button>
          {readOnly ? (
            <span className="text-xs text-[var(--muted-foreground)]">{readOnlyReason}</span>
          ) : (
            <Button onClick={() => save.mutate()} disabled={!dirty || save.isPending}>
              {save.isPending ? "Saving..." : "Save"}
            </Button>
          )}
        </div>
      </div>

      <PermissionTree
        perms={permsQ.data ?? []}
        selected={selected}
        onSetMany={setMany}
        readOnly={readOnly}
      />

      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title="Delete role"
        description="Removes the role, its permission grants and its place in the hierarchy. A role still assigned to anyone cannot be deleted; revoke those assignments first."
        target={role.name}
        confirmLabel="Delete role"
        destructive
        pending={remove.isPending}
        onConfirm={() => remove.mutate()}
      />
    </div>
  );
}
