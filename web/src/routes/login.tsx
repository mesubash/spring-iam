import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/AuthContext";
import { ApiError, BASE_URL } from "@/api/client";
import { mfaApi } from "@/api/resources";
import { OtpCodeInput } from "@/components/iam/OtpCodeInput";
import { QrCode } from "@/components/iam/QrCode";
import { RecoveryCodes } from "@/components/iam/RecoveryCodes";
import { safeContinueUrl } from "@/lib/continue-url";
import { AlertCircle, Eye, EyeOff, LoaderCircle, ShieldCheck } from "lucide-react";

export const Route = createFileRoute("/login")({
  component: LoginPage,
});

type Mode =
  | { step: "password" }
  | { step: "mfa"; challenge: string }
  | { step: "enroll"; enrollmentToken: string };

const MFA_SESSION_EXPIRED_ERROR =
  "Your verification session expired. Sign in again to request a new code.";

function errMsg(err: unknown, fallback: string) {
  if (err instanceof ApiError) {
    if (err.message) return err.message;
    if (err.status === 401) return "Invalid credentials.";
    if (err.status === 403) return "Your account is not permitted to sign in.";
  }
  return fallback;
}

/** An exhausted or expired challenge/enrollment token: retrying won't help, start over. */
function isMfaSessionExpired(err: unknown) {
  if (!(err instanceof ApiError)) return false;
  const m = err.message.toLowerCase();
  return m.includes("expired") || m.includes("sign in again");
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--background)] px-4">
      <div className="w-full max-w-sm rounded-xl border border-[var(--border)] bg-[var(--card)] p-8 shadow-sm">
        <div className="flex flex-col items-center text-center">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[var(--primary)] text-[var(--primary-foreground)]">
            <ShieldCheck size={20} strokeWidth={2.5} />
          </div>
          <h1 className="mt-4 text-xl font-semibold tracking-tight">IAM Console</h1>
        </div>
        {children}
      </div>
    </div>
  );
}

function LoginPage() {
  const { login, completeMfaLogin, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>({ step: "password" });

  // SSO sends the user here with ?continue=<authorize URL>; resume it once signed in
  // (password or MFA step, or already signed in).
  const goOn = () => {
    const next = safeContinueUrl(
      new URLSearchParams(window.location.search).get("continue"),
      BASE_URL,
    );
    if (next) window.location.assign(next);
    else navigate({ to: "/me/access" });
  };

  useEffect(() => {
    if (isAuthenticated) goOn();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAuthenticated]);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setPending(true);
    try {
      const res = await login(email, password);
      if (res.kind === "mfa") {
        setMode({ step: "mfa", challenge: res.challenge });
      } else if (res.kind === "enroll") {
        setMode({ step: "enroll", enrollmentToken: res.enrollmentToken });
      } else {
        // The effect below navigates once the session is set.
        if (res.message) toast.success(res.message);
      }
    } catch (err) {
      let msg = "Sign-in failed. Please try again.";
      if (err instanceof ApiError) {
        // Prefer the server-provided message when available.
        if (err.message) {
          msg = err.message;
        } else if (err.status === 401) {
          msg = "Invalid email or password.";
        } else if (err.status === 403) {
          msg = "Your account is not permitted to sign in.";
        }
      }
      setError(msg);
      toast.error(msg);
    } finally {
      setPending(false);
    }
  };

  const backToPassword = (msg: string | null) => {
    setMode({ step: "password" });
    setPassword("");
    setError(msg);
  };

  if (mode.step === "mfa") {
    return (
      <Shell>
        <MfaCodeStep
          onSubmit={async (code) => {
            await completeMfaLogin(mode.challenge, code);
            toast.success("Signed in");
          }}
          onChallengeExpired={() => {
            backToPassword(MFA_SESSION_EXPIRED_ERROR);
            toast.error("Verification session expired", {
              description: "Sign in again to request a new code.",
            });
          }}
          onBack={() => backToPassword(null)}
        />
      </Shell>
    );
  }

  if (mode.step === "enroll") {
    return (
      <Shell>
        <EnrollStep
          enrollmentToken={mode.enrollmentToken}
          onExpired={() => {
            backToPassword(MFA_SESSION_EXPIRED_ERROR);
            toast.error("MFA setup session expired", {
              description: "Sign in again to restart MFA setup.",
            });
          }}
          onDone={() => {
            // Enrollment issues no session: sign in again, which now asks for a code.
            backToPassword(null);
            toast.success("MFA enabled. Sign in again to continue.");
          }}
        />
      </Shell>
    );
  }

  return (
    <Shell>
      <p className="mt-1 text-center text-sm text-[var(--muted-foreground)]">Sign in to continue</p>

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

        <div className="space-y-1.5">
          <Label htmlFor="password" className="text-sm font-medium">
            Password
          </Label>
          <div className="relative">
            <Input
              id="password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              placeholder="••••••••"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="h-10 pr-10"
            />
            <button
              type="button"
              onClick={() => setShowPassword((v) => !v)}
              className="absolute right-0 top-0 h-10 w-10 inline-flex items-center justify-center text-[var(--muted-foreground)] hover:text-[var(--foreground)] transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring rounded-r-md"
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
        </div>

        {error ? (
          <div
            className="rounded-md bg-[var(--destructive-subtle)] px-3 py-2 text-sm text-[var(--destructive)]"
            role="alert"
          >
            {error}
          </div>
        ) : null}

        <Button type="submit" disabled={pending} className="w-full h-10">
          {pending ? "Signing in…" : "Sign in"}
        </Button>

        <div className="text-center">
          <Link to="/forgot-password" className="text-sm text-[var(--primary)] hover:underline">
            Forgot password?
          </Link>
        </div>
      </form>
    </Shell>
  );
}
function MfaCodeStep({
  onSubmit,
  onChallengeExpired,
  onBack,
}: {
  onSubmit: (code: string) => Promise<void>;
  onChallengeExpired: () => void;
  onBack: () => void;
}) {
  const [view, setView] = useState<"totp" | "recovery">("totp");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (code: string) => {
    if (pending || !code.trim()) return;
    setError(null);
    setPending(true);
    try {
      await onSubmit(code.trim());
    } catch (err) {
      if (isMfaSessionExpired(err)) {
        onChallengeExpired();
        return;
      }
      // Surface the server message: it carries the remaining attempt count.
      setError(
        errMsg(
          err,
          view === "recovery"
            ? "The recovery code could not be verified. Check the code and try again."
            : "The code could not be verified. Try again.",
        ),
      );
    } finally {
      setPending(false);
    }
  };

  const switchTo = (v: "totp" | "recovery") => {
    setError(null);
    setView(v);
  };

  return view === "recovery" ? (
    <RecoveryEntry
      pending={pending}
      error={error}
      onSubmit={submit}
      onClearError={() => setError(null)}
      onUseAuthenticator={() => switchTo("totp")}
    />
  ) : (
    <TotpEntry
      pending={pending}
      error={error}
      onSubmit={submit}
      onUseRecovery={() => switchTo("recovery")}
      onBack={onBack}
      onClearError={() => setError(null)}
    />
  );
}

function TotpEntry({
  pending,
  error,
  onSubmit,
  onUseRecovery,
  onBack,
  onClearError,
}: {
  pending: boolean;
  error: string | null;
  onSubmit: (code: string) => void;
  onUseRecovery: () => void;
  onBack: () => void;
  onClearError: () => void;
}) {
  const [code, setCode] = useState("");

  return (
    <>
      <p className="mt-1 text-center text-sm text-[var(--muted-foreground)]">
        Enter the 6-digit code from your authenticator app.
      </p>
      <form
        className="mt-6 space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit(code);
        }}
      >
        <OtpCodeInput
          id="mfa-code"
          autoFocus
          value={code}
          onValueChange={(v) => {
            setCode(v);
            if (error) onClearError();
          }}
          onComplete={onSubmit}
          disabled={pending}
          label="Verification code"
          invalid={Boolean(error)}
          onInvalidReset={onClearError}
        />
        <Button
          type="submit"
          disabled={pending || code.length < 6 || Boolean(error)}
          className="h-10 w-full"
        >
          {pending ? (
            <>
              <LoaderCircle className="animate-spin" />
              Verifying…
            </>
          ) : (
            "Verify"
          )}
        </Button>
        {error ? (
          <div
            className="flex items-center justify-center gap-1.5 text-xs font-medium text-[var(--destructive)]"
            role="alert"
          >
            <AlertCircle size={14} />
            <span>{error}</span>
          </div>
        ) : null}
        <div className="flex items-center justify-between text-xs">
          <button
            type="button"
            onClick={onBack}
            className="text-[var(--muted-foreground)] hover:underline"
          >
            Back
          </button>
          <button
            type="button"
            onClick={onUseRecovery}
            className="text-[var(--primary)] hover:underline"
          >
            Use a recovery code
          </button>
        </div>
      </form>
    </>
  );
}

function RecoveryEntry({
  pending,
  error,
  onSubmit,
  onClearError,
  onUseAuthenticator,
}: {
  pending: boolean;
  error: string | null;
  onSubmit: (code: string) => void;
  onClearError: () => void;
  onUseAuthenticator: () => void;
}) {
  const [code, setCode] = useState("");

  return (
    <>
      <p className="mt-1 text-center text-sm font-medium text-[var(--foreground)]">
        Use a recovery code
      </p>
      <p className="mt-1 text-center text-xs text-[var(--muted-foreground)]">
        Enter one of the one-time codes you saved when you set up MFA.
      </p>
      <form
        className="mt-6 space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit(code);
        }}
      >
        <Input
          autoFocus
          aria-label="Recovery code"
          maxLength={17}
          placeholder="xxxxxxxx-xxxxxxxx"
          value={code}
          onChange={(e) => {
            // Recovery codes are 8 hex + dash + 8 hex: bound the input.
            setCode(e.target.value.replace(/[^a-fA-F0-9-]/g, "").slice(0, 17));
            if (error) onClearError();
          }}
          className="h-10 text-center font-mono tracking-widest"
        />
        {error ? (
          <div
            className="rounded-md bg-[var(--destructive-subtle)] px-3 py-2 text-sm text-[var(--destructive)]"
            role="alert"
          >
            {error}
          </div>
        ) : null}
        <Button type="submit" disabled={pending || !code.trim()} className="h-10 w-full">
          {pending ? (
            <>
              <LoaderCircle className="animate-spin" />
              Verifying…
            </>
          ) : (
            "Verify"
          )}
        </Button>
        <button
          type="button"
          onClick={onUseAuthenticator}
          className="w-full text-center text-xs text-[var(--primary)] hover:underline"
        >
          Use authenticator code instead
        </button>
      </form>
    </>
  );
}

function EnrollStep({
  enrollmentToken,
  onDone,
  onExpired,
}: {
  enrollmentToken: string;
  onDone: () => void;
  onExpired: () => void;
}) {
  const [setup, setSetup] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [codeInvalid, setCodeInvalid] = useState(false);

  const enable = async (value: string) => {
    if (pending || value.length < 6) return;
    setError(null);
    setPending(true);
    try {
      const env = await mfaApi.enable(value.trim(), enrollmentToken);
      setRecovery(env.data.recoveryCodes);
    } catch (err) {
      if (isMfaSessionExpired(err)) {
        onExpired();
        return;
      }
      setCodeInvalid(true);
    } finally {
      setPending(false);
    }
  };

  // Start setup once: StrictMode double-invokes effects and a second call would rotate the secret.
  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    mfaApi
      .setup(enrollmentToken)
      .then((env) => setSetup(env.data))
      .catch((err) => {
        if (isMfaSessionExpired(err)) onExpired();
        else setError(errMsg(err, "Could not start MFA setup."));
      });
  }, [enrollmentToken, onExpired]);

  if (recovery) {
    return (
      <>
        <p className="mt-1 text-center text-sm font-medium text-[var(--foreground)]">
          Save your recovery codes
        </p>
        <p className="mt-1 text-center text-xs text-[var(--muted-foreground)]">
          Each works once if you lose your authenticator. They won't be shown again.
        </p>
        <div className="mt-4">
          <RecoveryCodes codes={recovery} />
        </div>
        <Button className="mt-4 h-10 w-full" onClick={onDone}>
          I've saved them, continue
        </Button>
      </>
    );
  }

  return (
    <>
      <p className="mt-1 text-center text-sm font-medium text-[var(--foreground)]">
        Set up two-factor authentication
      </p>
      <p className="mt-1 text-center text-xs text-[var(--muted-foreground)]">
        Your account requires MFA. Scan the code with your authenticator app, then enter the code it
        shows.
      </p>
      {setup ? (
        <div className="mt-4 space-y-2">
          <div className="flex justify-center">
            <QrCode value={setup.otpauthUri} />
          </div>
          <Label className="text-xs">Or enter this key manually</Label>
          <code className="block break-all rounded-md border border-[var(--border)] bg-[var(--muted)]/35 px-3 py-2 font-mono text-xs">
            {setup.secret}
          </code>
        </div>
      ) : error ? null : (
        <p className="mt-4 text-center text-xs text-[var(--muted-foreground)]">Generating key…</p>
      )}
      <form
        className="mt-4 space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          enable(code);
        }}
      >
        <OtpCodeInput
          id="enroll-mfa-code"
          value={code}
          onValueChange={setCode}
          onComplete={enable}
          disabled={pending || !setup}
          label="Verification code"
          invalid={codeInvalid}
          onInvalidReset={() => setCodeInvalid(false)}
        />
        {codeInvalid ? (
          <p className="text-center text-xs text-[var(--destructive)]" role="alert">
            That code is invalid. Try again.
          </p>
        ) : null}
        {error ? (
          <div className="rounded-md bg-[var(--destructive-subtle)] px-3 py-2 text-sm text-[var(--destructive)]">
            {error}
          </div>
        ) : null}
        <Button
          type="submit"
          disabled={pending || !setup || code.length < 6 || codeInvalid}
          className="h-10 w-full"
        >
          {pending ? "Enabling…" : "Enable MFA"}
        </Button>
      </form>
    </>
  );
}
