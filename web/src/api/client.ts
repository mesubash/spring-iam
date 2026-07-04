// Typed API client with in-memory access token + 401→refresh→retry.
// Envelope { status, message, data } is unwrapped to `data` when present.

const BASE_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8080";

let accessToken: string | null = null;
let onUnauthorized: (() => void) | null = null;
let onForbidden: ((err: ApiError) => void) | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}
export function getAccessToken() {
  return accessToken;
}
export function setUnauthorizedHandler(fn: (() => void) | null) {
  onUnauthorized = fn;
}
export function setForbiddenHandler(fn: ((err: ApiError) => void) | null) {
  onForbidden = fn;
}

export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

type Options = {
  method?: string;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  skipAuthRetry?: boolean;
  headers?: Record<string, string>;
};

function buildUrl(path: string, query?: Options["query"]) {
  const url = new URL(path.startsWith("http") ? path : `${BASE_URL}${path}`);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined || v === null) continue;
      url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}

async function doFetch(path: string, opts: Options): Promise<Response> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(opts.headers ?? {}),
  };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (accessToken) headers["Authorization"] = `Bearer ${accessToken}`;
  return fetch(buildUrl(path, opts.query), {
    method: opts.method ?? "GET",
    headers,
    credentials: "include",
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
}

export type RefreshResult = { ok: boolean; identity: unknown };

let refreshInFlight: Promise<RefreshResult> | null = null;

async function doRefresh(): Promise<RefreshResult> {
  try {
    const res = await fetch(buildUrl("/api/auth/refresh"), {
      method: "POST",
      credentials: "include",
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return { ok: false, identity: null };
    const body = await res.json();
    const token = body?.data?.accessToken ?? body?.accessToken;
    const identity = body?.data?.identity ?? body?.identity ?? null;
    if (!token) return { ok: false, identity: null };
    accessToken = token;
    return { ok: true, identity };
  } catch {
    return { ok: false, identity: null };
  }
}

/**
 * Refresh the access token. The refresh cookie rotates on every use, so
 * concurrent callers MUST share one request — otherwise a second call replays
 * the already-rotated cookie and the backend revokes the session as reuse.
 */
export function refreshAccessToken(): Promise<RefreshResult> {
  if (!refreshInFlight) {
    refreshInFlight = doRefresh().finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

/** True when a response body is a `{ success|status, message, data }` envelope. */
function unwrapEnvelope<T>(body: unknown): T {
  if (
    body &&
    typeof body === "object" &&
    "data" in body &&
    ("success" in body || "status" in body)
  ) {
    return (body as { data: T }).data;
  }
  return body as T;
}

export async function request<T = unknown>(path: string, opts: Options = {}): Promise<T> {
  let res = await doFetch(path, opts);

  if (res.status === 401 && !opts.skipAuthRetry && !path.includes("/api/auth/")) {
    const { ok } = await refreshAccessToken();
    if (ok) {
      res = await doFetch(path, opts);
    } else {
      if (onUnauthorized) onUnauthorized();
      throw new ApiError(401, "Unauthorized", null);
    }
  }

  const text = await res.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }

  if (!res.ok) {
    let message = res.statusText || `HTTP ${res.status}`;
    if (body && typeof body === "object" && "message" in body) {
      const m = (body as { message: unknown }).message;
      if (typeof m === "string" && m.length > 0) message = m;
    }
    const err = new ApiError(res.status, message, body);
    if (res.status === 403 && onForbidden) {
      try {
        onForbidden(err);
      } catch {
        /* ignore */
      }
    }
    throw err;
  }

  return unwrapEnvelope<T>(body);
}

export const api = {
  get: <T,>(path: string, query?: Options["query"]) => request<T>(path, { query }),
  post: <T,>(path: string, body?: unknown, query?: Options["query"]) =>
    request<T>(path, { method: "POST", body, query }),
  put: <T,>(path: string, body?: unknown) => request<T>(path, { method: "PUT", body }),
  patch: <T,>(path: string, body?: unknown) => request<T>(path, { method: "PATCH", body }),
  del: <T,>(path: string, query?: Options["query"]) =>
    request<T>(path, { method: "DELETE", query }),
};

// Raw envelope call (used by login to read message + data together).
export async function requestEnvelope<T = unknown>(
  path: string,
  opts: Options = {},
): Promise<{ status?: string; message?: string; data: T }> {
  const res = await doFetch(path, { ...opts, skipAuthRetry: true });
  const text = await res.text();
  let body: { status?: string; message?: string; data?: T } | null = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    /* ignore */
  }
  if (!res.ok) {
    throw new ApiError(res.status, body?.message || res.statusText || `HTTP ${res.status}`, body);
  }
  return { status: body?.status, message: body?.message, data: (body?.data as T) };
}