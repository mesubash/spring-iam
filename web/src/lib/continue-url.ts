/**
 * Where to go after sign-in when the login page was opened with `?continue=`.
 * The value is resolved the way the browser would (which also strips tabs and
 * newlines, so "/\t/evil.example" cannot sneak through as "//evil.example") and
 * followed only when it lands on this console's origin or on the IAM's own origin
 * (the SSO authorize URL). Anything else is dropped to avoid an open redirect.
 */
export function safeContinueUrl(
  raw: string | null,
  apiOrigin: string,
  selfOrigin: string = window.location.origin,
): string | null {
  if (!raw) return null;
  let url: URL;
  try {
    url = new URL(raw, selfOrigin);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  const allowed = [selfOrigin, new URL(apiOrigin, selfOrigin).origin];
  return allowed.includes(url.origin) ? url.href : null;
}
