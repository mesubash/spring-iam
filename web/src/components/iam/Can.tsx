import type { ReactNode } from "react";
import { useAuthz } from "@/context/AuthzContext";

export function Can({
  permission,
  anyOf,
  children,
  fallback = null,
}: {
  permission?: string;
  anyOf?: string[];
  children: ReactNode;
  fallback?: ReactNode;
}) {
  const { can, canAny } = useAuthz();
  const ok = permission ? can(permission) : anyOf ? canAny(anyOf) : false;
  return <>{ok ? children : fallback}</>;
}