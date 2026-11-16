import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { permissionsApi } from "@/api/resources";
import type { Permission } from "@/api/types";
import { useAuthz } from "@/context/AuthzContext";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionTree } from "@/components/iam/PermissionTree";

export const Route = createFileRoute("/_authenticated/me/access")({
  component: MyAccessPage,
});

function MyAccessPage() {
  const { permissions, isLoading } = useAuthz();

  // Catalog gives the human descriptions; forbidden for users without
  // catalog access, in which case the tree still renders from the bare keys.
  const catalogQ = useQuery({
    queryKey: ["permissions"],
    queryFn: () => permissionsApi.list(),
    retry: false,
  });

  const perms = useMemo<Permission[]>(() => {
    const byKey = new Map((catalogQ.data ?? []).map((p) => [p.key, p]));
    return Array.from(permissions)
      .sort()
      .map((key) => {
        const known = byKey.get(key);
        if (known) return known;
        const parts = key.split(".");
        return {
          id: key,
          key,
          domain: parts[0] ?? "other",
          resource: parts.slice(1, -1).join(".") || "other",
          action: parts[parts.length - 1] ?? "",
          description: null,
        };
      });
  }, [permissions, catalogQ.data]);

  return (
    <div>
      <PageHeader
        title="My Access"
        description="Permissions granted to you at the selected scope, grouped by domain and resource."
      />
      {isLoading ? (
        <div className="py-8 text-sm text-[var(--muted-foreground)]">Loading...</div>
      ) : (
        <PermissionTree perms={perms} />
      )}
    </div>
  );
}
