import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

type Tone = "neutral" | "accent" | "success" | "warning" | "destructive";

const tones: Record<Tone, string> = {
  neutral: "bg-[var(--muted)] text-[var(--muted-foreground)]",
  accent: "bg-[var(--primary-subtle)] text-[var(--primary)]",
  success: "bg-[var(--success-subtle)] text-[var(--success)]",
  warning: "bg-[var(--warning-subtle)] text-[var(--warning)]",
  destructive: "bg-[var(--destructive-subtle)] text-[var(--destructive)]",
};

export function Tag({
  tone = "neutral",
  children,
  className,
  mono = false,
}: {
  tone?: Tone;
  children: ReactNode;
  className?: string;
  mono?: boolean;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium",
        mono && "font-mono",
        tones[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function DecisionBadge({ decision }: { decision: "ALLOW" | "DENY" }) {
  return <Tag tone={decision === "ALLOW" ? "success" : "destructive"}>{decision}</Tag>;
}

export function EnforcementBadge({ mode }: { mode: "ENFORCE" | "SHADOW" }) {
  return <Tag tone={mode === "SHADOW" ? "warning" : "neutral"}>{mode}</Tag>;
}