import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { authzApi, metaApi, type ScopeSummary } from "@/api/resources";
import type { FeatureFlags } from "@/api/types";
import { useAuth } from "./AuthContext";
import { setForbiddenHandler } from "@/api/client";
import { toast } from "sonner";

type AuthzState = {
  scopes: ScopeSummary[];
  scopeId: string | null;
  setScopeId: (id: string) => void;
  permissions: Set<string>;
  features: FeatureFlags | null;
  can: (key: string) => boolean;
  canAny: (keys: string[]) => boolean;
  refetchPermissions: () => void;
  isLoading: boolean;
};

const AuthzContext = createContext<AuthzState | null>(null);
const STORAGE_KEY = "iam.scopeId";

export function AuthzProvider({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth();
  const qc = useQueryClient();
  const [scopeId, setScopeIdState] = useState<string | null>(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      return params.get("scope") ?? sessionStorage.getItem(STORAGE_KEY);
    } catch {
      return null;
    }
  });

  const scopesQ = useQuery({
    queryKey: ["authz", "scopes"],
    queryFn: () => authzApi.myScopes(),
    enabled: isAuthenticated,
  });

  const featuresQ = useQuery({
    queryKey: ["meta", "features"],
    queryFn: () => metaApi.features(),
    enabled: isAuthenticated,
  });

  const scopes = scopesQ.data ?? [];

  useEffect(() => {
    if (!scopeId && scopes.length > 0) {
      setScopeIdState(scopes[0].id);
    }
  }, [scopeId, scopes]);

  const permsQ = useQuery({
    queryKey: ["authz", "perms", scopeId],
    queryFn: () => authzApi.myPermissions(scopeId!),
    enabled: isAuthenticated && !!scopeId,
  });

  // Global 403 handler: quiet toast + refetch permissions for current scope.
  useEffect(() => {
    let lastAt = 0;
    setForbiddenHandler(() => {
      const now = Date.now();
      if (now - lastAt > 1500) {
        lastAt = now;
        toast.message("Not available for your access level");
      }
      qc.invalidateQueries({ queryKey: ["authz", "perms"] });
    });
    return () => setForbiddenHandler(null);
  }, [qc]);

  const setScopeId = (id: string) => {
    setScopeIdState(id);
    try {
      sessionStorage.setItem(STORAGE_KEY, id);
      const url = new URL(window.location.href);
      url.searchParams.set("scope", id);
      window.history.replaceState({}, "", url.toString());
    } catch {
      /* ignore */
    }
  };

  const permissions = useMemo(() => new Set(permsQ.data ?? []), [permsQ.data]);

  const value = useMemo<AuthzState>(() => {
    const can = (key: string) => permissions.has(key);
    return {
      scopes,
      scopeId,
      setScopeId,
      permissions,
      features: featuresQ.data ?? null,
      can,
      canAny: (keys) => keys.some(can),
      refetchPermissions: () => qc.invalidateQueries({ queryKey: ["authz", "perms"] }),
      isLoading: scopesQ.isLoading || permsQ.isLoading,
    };
  }, [scopes, scopeId, permissions, featuresQ.data, qc, scopesQ.isLoading, permsQ.isLoading]);

  return <AuthzContext.Provider value={value}>{children}</AuthzContext.Provider>;
}

export function useAuthz() {
  const ctx = useContext(AuthzContext);
  if (!ctx) throw new Error("useAuthz must be used inside AuthzProvider");
  return ctx;
}