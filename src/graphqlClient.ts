import { fetch } from "undici";
import { VERSION } from "./config.js";

const GQL_FETCH_TIMEOUT_MS = 30_000;

/** Strip HTML tags and truncate to a safe length for error messages. */
function sanitizeErrorBody(s: string, max = 200): string {
  const stripped = s.replace(/<[^>]*>/g, "").replace(/\s+/g, " ").trim();
  return stripped.length > max ? stripped.slice(0, max) + "..." : stripped;
}

export class GraphQLClient {
  private _headers: Record<string, string>;
  private authenticated: boolean = false;

  constructor(
    private opts: {
      endpoint: string;
      headers?: Record<string, string>;
      bearer?: string;
      /**
       * Session-cookie credential (e.g. `affine_session=<value>`). Used for the
       * per-user identity path — a bearer always takes priority if both are set.
       */
      cookie?: string;
      /**
       * Invoked once when a GraphQL request returns HTTP 401. Used by the per-user
       * path to invalidate a stale/expired AFFiNE session so the next exchange
       * refreshes it. The 401 is still thrown to the caller.
       */
      onUnauthorized?: () => void;
    },
  ) {
    this._headers = { ...(opts.headers || {}) };

    if (opts.cookie) {
      if (/[\r\n]/.test(opts.cookie)) {
        throw new Error("Cookie header contains illegal CR/LF characters");
      }
      this._headers["Cookie"] = opts.cookie;
    }

    // Set authentication in priority order
    if (opts.bearer) {
      this._headers["Authorization"] = `Bearer ${opts.bearer}`;
      this.authenticated = true;
      console.error("Using Bearer token authentication");
    } else if (this._headers.Cookie) {
      this.authenticated = true;
      console.error("Using Cookie authentication");
    }
  }

  /** The GraphQL endpoint URL */
  get endpoint(): string {
    return this.opts.endpoint;
  }

  /** Current request headers (including auth) */
  get headers(): Record<string, string> {
    return { ...this._headers };
  }

  /** Cookie header value, if set */
  get cookie(): string {
    return this._headers["Cookie"] || "";
  }

  /** Bearer token, if set */
  get bearer(): string {
    const auth = this._headers["Authorization"] || "";
    return auth.startsWith("Bearer ") ? auth.slice(7) : "";
  }

  setHeaders(next: Record<string, string>) {
    this._headers = { ...this._headers, ...next };
  }

  setCookie(cookieHeader: string) {
    if (/[\r\n]/.test(cookieHeader)) {
      throw new Error("Cookie header contains illegal CR/LF characters");
    }
    this._headers["Cookie"] = cookieHeader;
    this.authenticated = true;
    console.error("Session cookies set from email/password login");
  }

  isAuthenticated(): boolean {
    return this.authenticated;
  }

  async request<T>(query: string, variables?: Record<string, any>): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": `affine-mcp-server/${VERSION}`,
      ...this._headers,
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), GQL_FETCH_TIMEOUT_MS);
    let res;
    try {
      res = await fetch(this.opts.endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify({ query, variables }),
        signal: controller.signal,
      });
    } catch (err: any) {
      if (err.name === "AbortError") throw new Error(`GraphQL request timed out after ${GQL_FETCH_TIMEOUT_MS / 1000}s`);
      throw err;
    } finally {
      clearTimeout(timer);
    }

    // Handle redirects (undici may follow them but strip auth headers)
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      throw new Error(
        `GraphQL endpoint returned redirect ${res.status} -> ${location || "(no location)"}. ` +
        `Check AFFINE_BASE_URL.`
      );
    }

    const contentType = res.headers.get("content-type") || "";

    // Guard against non-JSON responses (Cloudflare challenges, HTML error pages)
    if (!contentType.includes("application/json") && !contentType.includes("application/graphql")) {
      const body = await res.text();
      const snippet = sanitizeErrorBody(body);
      throw new Error(
        `GraphQL endpoint returned non-JSON response (${res.status} ${res.statusText}, ` +
        `Content-Type: ${contentType || "(none)"}). Body: ${snippet}`
      );
    }

    if (res.status === 401 && this.opts.onUnauthorized) {
      // Let the per-user path invalidate its cached session before we throw.
      try { this.opts.onUnauthorized(); } catch { /* best-effort */ }
    }

    if (!res.ok) {
      // Try to parse error body as JSON
      let body: string;
      try {
        const json = await res.json() as any;
        body = json.errors?.map((e: any) => e.message).join("; ") || JSON.stringify(json);
      } catch {
        body = await res.text().catch(() => "(unreadable body)");
      }
      throw new Error(`GraphQL HTTP ${res.status}: ${sanitizeErrorBody(body)}`);
    }

    const json = await res.json() as any;
    if (json.errors) {
      const msg = json.errors.map((e: any) => e.message).join("; ");
      throw new Error(`GraphQL error: ${sanitizeErrorBody(msg)}`);
    }
    return json.data as T;
  }
}
