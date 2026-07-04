import { createFileRoute } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { authApi } from "@/api/resources";
import { PageHeader } from "@/components/iam/PageHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError } from "@/api/client";
import { useAuth } from "@/context/AuthContext";

export const Route = createFileRoute("/_authenticated/me/security")({
  component: SecurityPage,
});

function SecurityPage() {
  return (
    <div className="space-y-6">
      <PageHeader title="Security" description="Manage your account credentials." />
      <ChangePasswordCard />
      <ChangeEmailCard />
    </div>
  );
}

function ChangePasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const m = useMutation({
    mutationFn: () => authApi.changePassword(current, next),
    onSuccess: (res) => {
      toast.success(res.message ?? "Password changed");
      setCurrent("");
      setNext("");
      setConfirm("");
      setErr(null);
    },
    onError: (e: Error) => setErr(e instanceof ApiError ? e.message : "Could not change password."),
  });

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    if (next.length < 8) return setErr("New password must be at least 8 characters.");
    if (next !== confirm) return setErr("Passwords do not match.");
    m.mutate();
  };

  return (
    <form
      onSubmit={onSubmit}
      className="max-w-md space-y-4 rounded border border-[var(--border)] bg-[var(--card)] p-4"
    >
      <h2 className="text-sm font-semibold">Change password</h2>
      <div className="space-y-1.5">
        <Label htmlFor="cur">Current password</Label>
        <Input id="cur" type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="new">New password</Label>
        <Input id="new" type="password" value={next} onChange={(e) => setNext(e.target.value)} required />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="conf">Confirm new password</Label>
        <Input id="conf" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
      </div>
      {err ? <p className="text-sm text-[var(--destructive)]">{err}</p> : null}
      <Button type="submit" disabled={m.isPending}>
        {m.isPending ? "Updating..." : "Update password"}
      </Button>
    </form>
  );
}

function ChangeEmailCard() {
  const { identity } = useAuth();
  const [newEmail, setNewEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const m = useMutation({
    mutationFn: () => authApi.changeEmail(newEmail.trim(), password),
    onSuccess: (res) => {
      toast.success(res.message ?? "Check your new inbox to confirm the change.");
      setNewEmail("");
      setPassword("");
      setErr(null);
    },
    onError: (e: Error) =>
      setErr(e instanceof ApiError ? e.message : "Could not change email."),
  });

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    if (!newEmail.trim()) return setErr("Enter a new email address.");
    if (newEmail.trim().toLowerCase() === identity?.email?.toLowerCase())
      return setErr("That is already your email address.");
    m.mutate();
  };

  return (
    <form
      onSubmit={onSubmit}
      className="max-w-md space-y-4 rounded border border-[var(--border)] bg-[var(--card)] p-4"
    >
      <div>
        <h2 className="text-sm font-semibold">Change email</h2>
        <p className="mt-0.5 text-xs text-[var(--muted-foreground)]">
          Current: <span className="font-mono">{identity?.email ?? "—"}</span>. A confirmation link
          is sent to the new address; the change applies once confirmed.
        </p>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="new-email">New email</Label>
        <Input
          id="new-email"
          type="email"
          value={newEmail}
          onChange={(e) => setNewEmail(e.target.value)}
          required
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="email-pw">Current password</Label>
        <Input
          id="email-pw"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </div>
      {err ? <p className="text-sm text-[var(--destructive)]">{err}</p> : null}
      <Button type="submit" disabled={m.isPending}>
        {m.isPending ? "Sending…" : "Send confirmation"}
      </Button>
    </form>
  );
}