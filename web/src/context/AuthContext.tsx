import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { setAccessToken, setUnauthorizedHandler, refreshAccessToken } from "@/api/client";
import { authApi, authzApi } from "@/api/resources";
import type { Identity, MeBootstrap } from "@/api/types";

type AuthState = {
  identity: Identity | null;
  isAuthenticated: boolean;
  isBootstrapping: boolean;
  login: (email: string, password: string) => Promise<{ message?: string }>;
  logout: () => Promise<void>;
  setIdentity: (id: Identity | null) => void;
};

const AuthContext = createContext<AuthState | null>(null);
const SCOPE_KEY = "iam.scopeId";

/**
 * Seed the query cache from the bootstrap payload so AuthzContext's scopes /
 * features / permissions queries resolve from cache instead of firing their own
 * requests — one /bootstrap call replaces the old three-to-four on load.
 * Query keys must match AuthzContext exactly.
 */
function primeFromBootstrap(qc: QueryClient, b: MeBootstrap) {
  qc.setQueryData(["authz", "scopes"], b.scopes);
  qc.setQueryData(["meta", "features"], b.features);
  if (b.scopeId) qc.setQueryData(["authz", "perms", b.scopeId], b.permissions);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [isBootstrapping, setIsBootstrapping] = useState(true);

  useEffect(() => {
    // Silent session restore on load: the refresh cookie mints a fresh access
    // token, then one /bootstrap call returns identity + scopes + permissions +
    // features. The shared in-flight refresh dedupes StrictMode's double-invoke.
    let cancelled = false;
    (async () => {
      try {
        const { ok } = await refreshAccessToken();
        if (!ok || cancelled) return;
        const stored = sessionStorage.getItem(SCOPE_KEY) ?? undefined;
        const b = await authzApi.bootstrap(stored);
        if (cancelled) return;
        primeFromBootstrap(qc, b);
        setIdentity(b.identity);
      } catch {
        /* not signed in — fall through to the login redirect */
      } finally {
        if (!cancelled) setIsBootstrapping(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [qc]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setAccessToken(null);
      setIdentity(null);
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  const value = useMemo<AuthState>(
    () => ({
      identity,
      isAuthenticated: !!identity,
      isBootstrapping,
      setIdentity,
      login: async (email, password) => {
        const env = await authApi.login(email, password);
        setAccessToken(env.data.accessToken);
        const stored = sessionStorage.getItem(SCOPE_KEY) ?? undefined;
        const b = await authzApi.bootstrap(stored);
        primeFromBootstrap(qc, b);
        setIdentity(b.identity);
        return { message: env.message };
      },
      logout: async () => {
        try {
          await authApi.logout();
        } catch {
          /* ignore */
        }
        setAccessToken(null);
        setIdentity(null);
      },
    }),
    [identity, isBootstrapping, qc],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
