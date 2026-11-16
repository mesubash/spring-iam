import { createFileRoute } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { authApi, mfaApi } from "@/api/resources";
import { OtpCodeInput } from "@/components/iam/OtpCodeInput";
import { QrCode } from "@/components/iam/QrCode";
import { RecoveryCodes } from "@/components/iam/RecoveryCodes";
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
      <MfaCard />
      <ChangePasswordCard />
      <ChangeEmailCard />
    </div>
  );
}

function MfaCard() {
  const { identity, setIdentity } = useAuth();
  const enabled = !!identity?.mfaEnabled;
  const [setup, setSetup] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [pending, setPending] = useState(false);
  const [codeInvalid, setCodeInvalid] = useState(false);

  const setMfaEnabled = (mfaEnabled: boolean) => {
    if (identity) setIdentity({ ...identity, mfaEnabled });
  };

  // One runner for every call here: pending flag, toast on failure.
  const run = async (fn: () => Promise<void>, onFail?: () => void) => {
    if (pending) return;
    setPending(true);
    try {
      await fn();
    } catch (e) {
      if (onFail) onFail();
      else toast.error(e instanceof ApiError ? e.message : "Request failed");
    } finally {
      setPending(false);
    }
  };

  const begin = () =>
    run(async () => {
      const env = await mfaApi.setup();
      setSetup(env.data);
      setCode("");
      setCodeInvalid(false);
    });

  const enableWith = (value: string) => {
    if (value.length < 6) return;
    return run(
      async () => {
        const env = await mfaApi.enable(value);
        setRecovery(env.data.recoveryCodes);
        setSetup(null);
        setCode("");
        setMfaEnabled(true);
        toast.success("MFA enabled");
      },
      () => setCodeInvalid(true),
    );
  };

  const regenerate = () =>
    run(async () => {
      const env = await mfaApi.recoveryCodes(code.trim());
      setRecovery(env.data.recoveryCodes);
      setCode("");
      toast.success("New recovery codes generated");
    });

  const disable = () =>
    run(async () => {
      await mfaApi.disable(code.trim());
      setCode("");
      setMfaEnabled(false);
      toast.success("MFA disabled");
    });

  return (
    <div className="max-w-md space-y-4 rounded border border-[var(--border)] bg-[var(--card)] p-4">
      <div>
        <h2 className="text-sm font-semibold">Two-factor authentication</h2>
        <p className="mt-0.5 text-xs text-[var(--muted-foreground)]">
          {enabled
            ? "MFA is on. To switch authenticator apps, disable MFA and set it up again."
            : "Require a time-based code from an authenticator app at sign-in."}
        </p>
      </div>
      {recovery ? (
        <div className="space-y-2">
          <p className="text-sm font-medium">Recovery codes: save these now</p>
          <p className="text-xs text-[var(--muted-foreground)]">
            Each works once if you lose your authenticator. They won't be shown again.
          </p>
          <RecoveryCodes codes={recovery} />
          <Button variant="outline" onClick={() => setRecovery(null)}>
            Done
          </Button>
        </div>
      ) : enabled ? (
        <div className="space-y-2">
          <Label htmlFor="mfa-current" className="text-xs">
            Current code (authenticator or recovery code)
          </Label>
          <Input
            id="mfa-current"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="123456"
            autoComplete="one-time-code"
            className="font-mono"
          />
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" disabled={pending || !code.trim()} onClick={regenerate}>
              New recovery codes
            </Button>
            <Button
              variant="outline"
              style={{ color: "var(--destructive)" }}
              disabled={pending || !code.trim()}
              onClick={disable}
            >
              Disable MFA
            </Button>
          </div>
        </div>
      ) : setup ? (
        <div className="space-y-2">
          <div className="flex justify-center">
            <QrCode value={setup.otpauthUri} />
          </div>
          <Label className="text-xs">Or enter this key manually</Label>
          <code className="block break-all rounded-md border border-[var(--border)] bg-[var(--muted)]/35 px-3 py-2 font-mono text-xs">
            {setup.secret}
          </code>
          <OtpCodeInput
            id="account-mfa-code"
            value={code}
            onValueChange={setCode}
            onComplete={enableWith}
            disabled={pending}
            label="Verification code"
            className="pt-1"
            invalid={codeInvalid}
            onInvalidReset={() => setCodeInvalid(false)}
          />
          <div className="flex gap-2">
            <Button
              disabled={pending || code.length < 6 || codeInvalid}
              onClick={() => enableWith(code)}
            >
              Enable MFA
            </Button>
            <Button variant="outline" disabled={pending} onClick={() => setSetup(null)}>
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <Button disabled={pending} onClick={begin}>
          Set up MFA
        </Button>
      )}
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