import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { setAccessToken, setUnauthorizedHandler } from "@/api/client";
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
    // Attempt a silent refresh on load: cookie will let /refresh mint a token.
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(
          `${(import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8080"}/api/auth/refresh`,
          { method: "POST", credentials: "include", headers: { Accept: "application/json" } },
        );
        if (res.ok) {
          const body = await res.json();
          const token = body?.data?.accessToken ?? body?.accessToken;
          const id = body?.data?.identity ?? body?.identity ?? null;
          if (token) setAccessToken(token);
          if (!cancelled && id) setIdentity(id);
        }
      } catch {
        /* ignore */
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