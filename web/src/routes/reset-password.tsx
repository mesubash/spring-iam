import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { authApi } from "@/api/resources";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError } from "@/api/client";
import { ShieldCheck, ArrowLeft } from "lucide-react";

export const Route = createFileRoute("/reset-password")({
  validateSearch: (search: Record<string, unknown>): { token?: string } => ({
    token: typeof search.token === "string" ? search.token : undefined,
  }),
  component: ResetPasswordPage,
});

function ResetPasswordPage() {
  const { token } = Route.useSearch();
  const navigate = useNavigate();
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!token) return setError("This reset link is invalid or incomplete.");
    if (next.length < 8) return setError("Password must be at least 8 characters.");
    if (next !== confirm) return setError("Passwords do not match.");
    setPending(true);
    try {
      await authApi.resetPassword(token, next);
      toast.success("Password reset. You can sign in now.");
      navigate({ to: "/login" });
    } catch (err) {
      setError(
        err instanceof ApiError && err.message
          ? err.message
          : "Could not reset password. The link may have expired.",
      );
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--background)] px-4">
      <div className="w-full max-w-sm rounded-xl border border-[var(--border)] bg-[var(--card)] p-8 shadow-sm">
        <div className="flex flex-col items-center text-center">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[var(--primary)] text-[var(--primary-foreground)]">
            <ShieldCheck size={20} strokeWidth={2.5} />
          </div>
          <h1 className="mt-4 text-xl font-semibold tracking-tight">Choose a new password</h1>
          <p className="mt-1 text-sm text-[var(--muted-foreground)]">
            Enter a new password for your account.
          </p>
        </div>

        {!token ? (
          <div className="mt-8 space-y-4 text-center">
            <div className="rounded-md bg-[var(--destructive-subtle)] px-3 py-3 text-sm text-[var(--destructive)]">
              This reset link is invalid or incomplete. Request a new one.
            </div>
            <Link to="/forgot-password" className="text-sm text-[var(--primary)] hover:underline">
              Request a new link
            </Link>
          </div>
        ) : (
          <form onSubmit={onSubmit} className="mt-8 space-y-5">
            <div className="space-y-1.5">
              <Label htmlFor="new" className="text-sm font-medium">
                New password
              </Label>
              <Input
                id="new"
                type="password"
                autoComplete="new-password"
                required
                value={next}
                onChange={(e) => setNext(e.target.value)}
                className="h-10"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="confirm" className="text-sm font-medium">
                Confirm new password
              </Label>
              <Input
                id="confirm"
                type="password"
                autoComplete="new-password"
                required
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                className="h-10"
              />
            </div>

            {error ? (
              <div
                className="rounded-md bg-[var(--destructive-subtle)] px-3 py-2 text-sm text-[var(--destructive)]"
                role="alert"
              >
                {error}
              </div>
            ) : null}

            <Button type="submit" disabled={pending} className="h-10 w-full">
              {pending ? "Resetting…" : "Reset password"}
            </Button>

            <div className="text-center">
              <Link
                to="/login"
                className="inline-flex items-center gap-1 text-sm text-[var(--primary)] hover:underline"
              >
                <ArrowLeft size={14} /> Back to sign in
              </Link>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
