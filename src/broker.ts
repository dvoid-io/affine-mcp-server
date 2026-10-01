import { jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";

import {
  ALLOWED_JWT_ALGORITHMS,
  getJwks,
  loadAuthorizationServerMetadata,
} from "./oauth.js";

/**
 * Broker mode (AFFINE_MCP_AUTH_MODE=broker): the caller is the dvoid gateway, and
 * the bearer it presents is a token ZITADEL minted for this request by an RFC 8693
 * exchange in which the gateway was the actor (D45). This server verifies that
 * token itself and takes the identity from it alone. No header names a user.
 *
 * What a valid token is:
 *   - signed by the issuer's JWKS with an asymmetric algorithm (never `none` or HMAC);
 *   - `iss` is the configured issuer; `aud` contains the configured audience
 *     (the MCP project id); `exp`, `sub` are present;
 *   - the actor claim (default `act.sub`) names one of the allowed actors: the
 *     gateway's own service user. A token without it was not minted for us by
 *     the broker, even if every other check passes.
 */
export type BrokerConfig = {
  issuerUrl: string;
  audience: string;
  allowedActors: string[];
  /** Dotted path to the immediate actor's id in the payload. */
  actorClaim: string;
  /** Subjects that act as the shared service credential (ai-service's tool enumeration). */
  serviceSubjects: string[];
  clockSkewSeconds: number;
};

export type BrokerIdentity = {
  /** The verified bearer, handed on to AFFiNE's own exchange as the subject token. */
  token: string;
  subject: string;
  actor: string;
  /** True when the subject is a configured service subject: use the service credential. */
  isService: boolean;
  expiresAt: number;
};

export class BrokerTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BrokerTokenError";
  }
}

export function validateBrokerConfig(config: BrokerConfig, opts: { httpAuthToken?: string }) {
  if (opts.httpAuthToken) {
    throw new Error("AFFINE_MCP_HTTP_TOKEN is not allowed when AFFINE_MCP_AUTH_MODE=broker: the gateway presents a minted token, not a shared one.");
  }
  if (!config.audience) throw new Error("AFFINE_BROKER_AUDIENCE is required when AFFINE_MCP_AUTH_MODE=broker.");
  if (config.allowedActors.length === 0) {
    throw new Error("AFFINE_BROKER_ALLOWED_ACTORS is required when AFFINE_MCP_AUTH_MODE=broker.");
  }
  if (!/^[A-Za-z0-9_:-]+(\.[A-Za-z0-9_:-]+)*$/.test(config.actorClaim)) {
    throw new Error(`AFFINE_BROKER_ACTOR_CLAIM must be a dotted claim path. Received: ${config.actorClaim}`);
  }
  const issuer = new URL(config.issuerUrl);
  if (issuer.protocol !== "https:" && !["localhost", "127.0.0.1", "::1"].includes(issuer.hostname)) {
    throw new Error("AFFINE_BROKER_ISSUER_URL must use HTTPS for non-local deployments.");
  }
}

function readClaimPath(payload: JWTPayload, dotted: string): unknown {
  let cur: unknown = payload;
  for (const part of dotted.split(".")) {
    if (!cur || typeof cur !== "object" || Array.isArray(cur)) return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

/**
 * Verify a broker-minted bearer. `getKey` overrides discovery (tests only); in
 * service it is the issuer's JWKS, found through its discovery document and cached.
 */
export async function verifyBrokerToken(
  token: string,
  config: BrokerConfig,
  getKey?: JWTVerifyGetKey,
): Promise<BrokerIdentity> {
  let issuer = config.issuerUrl.replace(/\/+$/, "");
  let key = getKey;
  if (!key) {
    const metadata = await loadAuthorizationServerMetadata(config.issuerUrl);
    issuer = metadata.issuer;
    key = getJwks(metadata);
  }
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, key, {
      issuer,
      audience: config.audience,
      algorithms: [...ALLOWED_JWT_ALGORITHMS],
      clockTolerance: config.clockSkewSeconds,
      requiredClaims: ["exp", "sub"],
    }));
  } catch (err) {
    // jose's messages name the failed check (signature, "aud", "exp" …), never the token.
    throw new BrokerTokenError(err instanceof Error ? err.message : "token verification failed");
  }

  const subject = typeof payload.sub === "string" ? payload.sub.trim() : "";
  if (!subject) throw new BrokerTokenError("token has an empty sub");
  const actor = readClaimPath(payload, config.actorClaim);
  if (typeof actor !== "string" || !actor) {
    throw new BrokerTokenError(`token carries no actor at ${config.actorClaim}: it was not minted by the broker`);
  }
  if (!config.allowedActors.includes(actor)) {
    throw new BrokerTokenError(`actor at ${config.actorClaim} is not an allowed broker`);
  }
  return {
    token,
    subject,
    actor,
    isService: config.serviceSubjects.includes(subject),
    expiresAt: payload.exp as number,
  };
}

/** The identity the auth middleware verified for this request, if any. */
const IDENTITY = Symbol.for("affine-mcp.broker-identity");

export function setBrokerIdentity(req: object, identity: BrokerIdentity): void {
  (req as Record<symbol, BrokerIdentity>)[IDENTITY] = identity;
}

export function getBrokerIdentity(req: object | undefined): BrokerIdentity | undefined {
  return req ? (req as Record<symbol, BrokerIdentity | undefined>)[IDENTITY] : undefined;
}
