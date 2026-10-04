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
 *   - `iss` is the configured issuer; `exp`, `sub` are present;
 *   - `aud` contains the configured audience: THIS server's own project. Each brokered
 *     server has its own, and the broker asks for exactly one per exchange, so a token
 *     minted for any other server is refused here (D45, per-server audience);
 *   - an `act` claim is present, and `act.iss` is the issuer. Only a token exchange sets
 *     `act`; a user's own login token never carries one. Without this check, a user who
 *     got a token with this server's aud from any client could call this server directly
 *     and skip the gateway's per-tool rules. Which actor it was is the gateway's and
 *     Zitadel's business (one actor per org, each an impersonator in its own org only),
 *     so no list of actors is kept here.
 */
export type BrokerConfig = {
  issuerUrl: string;
  audience: string;
  /** Subjects that act as the shared service credential (ai-service's tool enumeration). */
  serviceSubjects: string[];
  clockSkewSeconds: number;
};

export type BrokerIdentity = {
  /** The verified bearer, handed on to AFFiNE's own exchange as the subject token. */
  token: string;
  subject: string;
  /** `act.sub`: the actor Zitadel recorded for the exchange. */
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
  const issuer = new URL(config.issuerUrl);
  if (issuer.protocol !== "https:" && !["localhost", "127.0.0.1", "::1"].includes(issuer.hostname)) {
    throw new Error("AFFINE_BROKER_ISSUER_URL must use HTTPS for non-local deployments.");
  }
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
  const act = payload.act;
  if (!act || typeof act !== "object" || Array.isArray(act)) {
    throw new BrokerTokenError("token carries no act claim: it was not minted by a token exchange");
  }
  const { iss: actIssuer, sub: actor } = act as Record<string, unknown>;
  if (actIssuer !== issuer) throw new BrokerTokenError("act.iss is not the issuer");
  if (typeof actor !== "string" || !actor) throw new BrokerTokenError("act.sub is empty");
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
