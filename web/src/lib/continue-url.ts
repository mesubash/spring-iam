/**
 * Where to go after sign-in when the login page was opened with `?continue=`.
 * Only two shapes are followed: a same-site path ("/x", not "//x" or "/\x",
 * which browsers treat as another host) or an absolute URL on the IAM's own
 * origin (the SSO authorize URL). Anything else is dropped to avoid an open redirect.
 */
export function safeContinueUrl(raw: string | null, apiOrigin: string): string | null {
  if (!raw) return null;
  if (raw.startsWith("/")) {
    return raw[1] === "/" || raw[1] === "\\" ? null : raw;
  }
  try {
    const url = new URL(raw);
    return url.origin === new URL(apiOrigin).origin ? url.href : null;
  } catch {
    return null;
  }
}
