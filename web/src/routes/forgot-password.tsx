import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { authApi } from "@/api/resources";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError } from "@/api/client";
import { ShieldCheck, ArrowLeft } from "lucide-react";

export const Route = createFileRoute("/forgot-password")({
  component: ForgotPasswordPage,
});

function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setPending(true);
    try {
      await authApi.forgotPassword(email.trim());
      setSent(true);
    } catch (err) {
      // The endpoint is deliberately non-revealing; only surface transport errors.
      if (err instanceof ApiError && err.status >= 500) {
        setError("Something went wrong. Please try again.");
      } else {
        setSent(true);
      }
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
          <h1 className="mt-4 text-xl font-semibold tracking-tight">Reset password</h1>
          <p className="mt-1 text-sm text-[var(--muted-foreground)]">
            Enter your email and we'll send a reset link.
          </p>
        </div>

        {sent ? (
          <div className="mt-8 space-y-4 text-center">
            <div className="rounded-md bg-[var(--primary-subtle)] px-3 py-3 text-sm text-[var(--foreground)]">
              If an account exists for <span className="font-medium">{email}</span>, a password
              reset link is on its way. Check your inbox.
            </div>
            <Link to="/login" className="inline-flex items-center gap-1 text-sm text-[var(--primary)] hover:underline">
              <ArrowLeft size={14} /> Back to sign in
            </Link>
          </div>
        ) : (
          <form onSubmit={onSubmit} className="mt-8 space-y-5">
            <div className="space-y-1.5">
              <Label htmlFor="email" className="text-sm font-medium">
                Email
              </Label>
              <Input
                id="email"
                type="email"
                autoComplete="email"
                placeholder="you@company.com"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
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
              {pending ? "Sending…" : "Send reset link"}
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
