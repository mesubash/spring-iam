// Plain error reporting hook. Swap the body for your telemetry sink
// (Sentry, a /log endpoint, etc.) — kept dependency-free by default.
export function reportError(error: unknown, context: Record<string, unknown> = {}) {
  if (typeof window === "undefined") return;
  console.error("[iam-console]", error, {
    route: window.location.pathname,
    ...context,
  });
}
