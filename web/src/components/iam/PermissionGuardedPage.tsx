import type { ReactNode } from "react";
import { useAuthz } from "@/context/AuthzContext";

export function PermissionGuardedPage({
  permission,
  children,
}: {
  permission: string;
  children: ReactNode;
}) {
  const { can } = useAuthz();
  if (!can(permission)) {
    return (
      <div className="rounded border border-[var(--border)] bg-[var(--card)] px-4 py-6 text-sm text-[var(--muted-foreground)]">
        Not available for your access level.
      </div>
    );
  }
  return <>{children}</>;
}