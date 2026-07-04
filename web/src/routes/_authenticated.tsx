import { createFileRoute, redirect } from "@tanstack/react-router";
import { AppLayout } from "@/components/iam/AppLayout";
import { useAuth } from "@/context/AuthContext";
import { useEffect } from "react";
import { useNavigate } from "@tanstack/react-router";

export const Route = createFileRoute("/_authenticated")({
  beforeLoad: () => {
    // Client-side session bootstrap decides; layout renders a spinner while
    // isBootstrapping. If not authenticated after bootstrap, redirect below.
    if (typeof window === "undefined") return;
  },
  component: AuthGate,
});

function AuthGate() {
  const { isAuthenticated, isBootstrapping } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isBootstrapping && !isAuthenticated) {
      navigate({ to: "/login", replace: true });
    }
  }, [isBootstrapping, isAuthenticated, navigate]);

  if (isBootstrapping || !isAuthenticated) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[var(--background)]">
        <div className="h-3 w-24 animate-pulse rounded bg-[var(--muted)]" />
      </div>
    );
  }
  return <AppLayout />;
}

// unused imports guard
void redirect;