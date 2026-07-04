import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { setAccessToken, setUnauthorizedHandler, refreshAccessToken } from "@/api/client";
import { authApi } from "@/api/resources";
import type { Identity } from "@/api/types";

type AuthState = {
  identity: Identity | null;
  isAuthenticated: boolean;
  isBootstrapping: boolean;
  login: (email: string, password: string) => Promise<{ message?: string }>;
  logout: () => Promise<void>;
  setIdentity: (id: Identity | null) => void;
};

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [isBootstrapping, setIsBootstrapping] = useState(true);

  useEffect(() => {
    // Silent session restore on load. The refresh cookie lets /refresh mint a
    // fresh access token AND return the identity, so we can populate the user
    // (email shown in the header) without a separate /me round-trip — the JWT
    // itself carries only id/roles, not email/displayName. Shared in-flight
    // refresh dedupes StrictMode's double-invoke into one network call.
    let cancelled = false;
    (async () => {
      try {
        const { ok, identity } = await refreshAccessToken();
        if (ok && identity && !cancelled) setIdentity(identity as Identity);
      } finally {
        if (!cancelled) setIsBootstrapping(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

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
        setIdentity(env.data.identity);
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
    [identity, isBootstrapping],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}