import { fetch } from "undici";
import { decodeJwt } from "jose";
import { VERSION } from "./config.js";

const EXCHANGE_FETCH_TIMEOUT_MS = 30_000;

/**
 * RFC 8693 token-exchange grant/token-type identifiers. The AFFiNE endpoint
 * expects these exact values.
 */
const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
/**
 * The `actor_token` is the user's OIDC **id_token**. AFFiNE reads the user's
 * `email` from it (the access token carries none for Zitadel-style providers).
 * Both tokens are required — there is no userinfo fallback on the AFFiNE side.
 */
const ACTOR_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";

/** Refresh a cached session this many seconds before the user token's `exp`. */
const EXPIRY_SKEW_SECONDS = 30;

/**
 * Fallback TTL (ms) for a resolved session when the user token has no usable
 * `exp` claim — keeps a hot cache without pinning a stale session indefinitely.
 */
const DEFAULT_SESSION_TTL_MS = 5 * 60_000;

/** Typed error so callers can distinguish exchange failures from GraphQL errors. */
export class TokenExchangeError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "TokenExchangeError";
  }
}

export type TokenExchangeOptions = {
  /** Full token-exchange endpoint URL (e.g. `${AFFINE_BASE}/api/auth/token-exchange`). */
  url: string;
  /** `x-affine-trusted-proxy-secret` value. Never logged. */
  proxySecret: string;
};

export type UserSession = {
  /** The AFFiNE session value — replay as `Cookie: affine_session=<value>`. */
  affineSession: string;
};

type CacheEntry = {
  session: UserSession;
  /** Epoch ms after which the entry is considered stale. */
  expiresAtMs: number;
  /** In-flight exchange, deduplicating concurrent requests for the same subject. */
  pending?: Promise<UserSession>;
};

/**
 * Per-subject session cache. Keyed by the user token's `sub` claim (non-verifying
 * peek). A single module-level cache is correct because each subject maps to
 * exactly one AFFiNE identity regardless of which MCP session triggered the
 * exchange.
 */
const sessionCache = new Map<string, CacheEntry>();

/** Non-verifying peek of the `sub` claim. Verification happens at the gateway/AFFiNE. */
function peekSubject(userAccessToken: string): string | undefined {
  try {
    const payload = decodeJwt(userAccessToken);
    return typeof payload.sub === "string" && payload.sub ? payload.sub : undefined;
  } catch {
    return undefined;
  }
}

/** Compute a cache-expiry epoch (ms) from the user token's `exp`, with skew. */
function computeExpiry(userAccessToken: string): number {
  try {
    const payload = decodeJwt(userAccessToken);
    if (typeof payload.exp === "number" && Number.isFinite(payload.exp)) {
      return (payload.exp - EXPIRY_SKEW_SECONDS) * 1000;
    }
  } catch {
    /* fall through to default TTL */
  }
  return Date.now() + DEFAULT_SESSION_TTL_MS;
}

async function performExchange(
  userAccessToken: string,
  userIdToken: string,
  opts: TokenExchangeOptions,
): Promise<UserSession> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), EXCHANGE_FETCH_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(opts.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": `affine-mcp-server/${VERSION}`,
        "x-affine-trusted-proxy-secret": opts.proxySecret,
      },
      body: JSON.stringify({
        grant_type: GRANT_TYPE,
        subject_token: userAccessToken,
        subject_token_type: SUBJECT_TOKEN_TYPE,
        actor_token: userIdToken,
        actor_token_type: ACTOR_TOKEN_TYPE,
      }),
      signal: controller.signal,
    });
  } catch (err: any) {
    if (err?.name === "AbortError") {
      throw new TokenExchangeError(
        `Token exchange timed out after ${EXCHANGE_FETCH_TIMEOUT_MS / 1000}s`,
      );
    }
    // Never surface the underlying message — it could echo the request body.
    throw new TokenExchangeError("Token exchange request failed (network error)");
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    // The RESPONSE body is AFFiNE's own error payload — it never echoes our
    // request's subject_token or proxy secret — so it is safe to surface, and
    // it carries the reason needed to fix the failure (e.g. which check the
    // verifier rejected). Truncate + collapse whitespace defensively.
    let body = "";
    try {
      body = (await res.text()).slice(0, 400).replace(/\s+/g, " ").trim();
    } catch {
      /* body unreadable — fall back to status alone */
    }
    throw new TokenExchangeError(
      `AFFiNE token-exchange returned ${res.status}${body ? `: ${body}` : ""}`,
      res.status,
    );
  }

  let json: any;
  try {
    json = await res.json();
  } catch {
    throw new TokenExchangeError("Token exchange returned a non-JSON response");
  }

  const accessToken = json?.access_token;
  if (typeof accessToken !== "string" || !accessToken) {
    throw new TokenExchangeError("Token exchange response missing access_token");
  }
  if (/[\r\n]/.test(accessToken)) {
    throw new TokenExchangeError("Token exchange access_token contains illegal CR/LF characters");
  }

  return { affineSession: accessToken };
}

/**
 * Exchange a chat user's Zitadel access token for that user's AFFiNE session.
 *
 * Caches the resolved session keyed by the token's `sub`, refreshing on expiry.
 * Concurrent calls for the same subject share a single in-flight exchange.
 *
 * @throws {TokenExchangeError} on non-2xx, malformed, or networkless responses.
 */
export async function exchangeUserSession(
  userAccessToken: string,
  userIdToken: string,
  opts: TokenExchangeOptions,
): Promise<UserSession> {
  const subject = peekSubject(userAccessToken);
  // No usable subject → still exchange, but bypass the cache (can't key it safely).
  if (!subject) {
    return performExchange(userAccessToken, userIdToken, opts);
  }

  const now = Date.now();
  const cached = sessionCache.get(subject);
  if (cached) {
    if (cached.pending) return cached.pending;
    if (cached.expiresAtMs > now) return cached.session;
  }

  const expiresAtMs = computeExpiry(userAccessToken);
  const pending = performExchange(userAccessToken, userIdToken, opts)
    .then((session) => {
      sessionCache.set(subject, { session, expiresAtMs });
      return session;
    })
    .catch((err) => {
      // Drop the failed in-flight marker so the next call retries.
      const entry = sessionCache.get(subject);
      if (entry?.pending === pending) sessionCache.delete(subject);
      throw err;
    });

  sessionCache.set(subject, {
    // Carry forward any still-present (possibly stale) session as a placeholder;
    // it is never returned because `pending` takes precedence above.
    session: cached?.session ?? { affineSession: "" },
    expiresAtMs,
    pending,
  });
  return pending;
}

/**
 * Invalidate a cached session for the subject of `userAccessToken`. Call this on
 * a 401 from GraphQL so the next request forces a fresh exchange.
 */
export function invalidateUserSession(userAccessToken: string): void {
  const subject = peekSubject(userAccessToken);
  if (subject) sessionCache.delete(subject);
}

/** Test-only: clear the entire session cache. */
export function _clearSessionCache(): void {
  sessionCache.clear();
}
