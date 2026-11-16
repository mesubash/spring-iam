import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { permissionsApi } from "@/api/resources";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { PermissionTree } from "@/components/iam/PermissionTree";

export const Route = createFileRoute("/_authenticated/admin/permissions")({
  component: () => (
    <PermissionGuardedPage permission="platform.permission.read">
      <PermissionsPage />
    </PermissionGuardedPage>
  ),
});

function PermissionsPage() {
  const q = useQuery({ queryKey: ["permissions"], queryFn: () => permissionsApi.list() });

  return (
    <div>
      <PageHeader
        title="Permissions catalog"
        description="Every permission the server recognises, grouped by domain and resource."
      />
      {q.isLoading ? (
        <div className="py-8 text-sm text-[var(--muted-foreground)]">Loading...</div>
      ) : (
        <PermissionTree perms={q.data ?? []} />
      )}
    </div>
  );
}
