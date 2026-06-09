import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { loadConfig, VERSION } from "./config.js";
import { GraphQLClient } from "./graphqlClient.js";
import { registerWorkspaceTools } from "./tools/workspaces.js";
import { registerDocTools } from "./tools/docs.js";
import { registerCommentTools } from "./tools/comments.js";
import { registerHistoryTools } from "./tools/history.js";
import { registerUserTools } from "./tools/user.js";
import { registerUserCRUDTools } from "./tools/userCRUD.js";
import { registerAccessTokenTools } from "./tools/accessTokens.js";
import { registerBlobTools } from "./tools/blobStorage.js";
import { registerNotificationTools } from "./tools/notifications.js";
import { loginWithPassword } from "./auth.js";
import { registerAuthTools } from "./tools/auth.js";
import { registerOrganizeTools } from "./tools/organize.js";
import { runCli } from "./cli.js";
import { startHttpMcpServer } from "./sse.js";
import { existsSync } from "fs";
import { CONFIG_FILE } from "./config.js";
import { createToolFilter, toolFilterRequiresRegisterTool } from "./toolSurface.js";
import { exchangeUserSession, invalidateUserSession, TokenExchangeError } from "./tokenExchange.js";
import type { Request } from "express";

// CLI commands: affine-mcp login|status|logout|version
const rawArgs = process.argv.slice(2);
const cliArgs = rawArgs[0] === "--" ? rawArgs.slice(1) : rawArgs;
const subcommand = cliArgs[0];
if (subcommand === "--version" || subcommand === "-v" || subcommand === "version") {
  console.log(VERSION);
  process.exit(0);
}
if (subcommand === "--help" || subcommand === "-h") {
  await runCli("help");
  process.exit(0);
}
if (subcommand) {
  const handled = await runCli(subcommand, cliArgs.slice(1));
  if (!handled) {
    console.error(`Unknown command: ${subcommand}`);
    await runCli("help");
    process.exit(1);
  }
  process.exit(0);
}

// MCP server mode (default)
const config = loadConfig();
const transportMode = (process.env.MCP_TRANSPORT || "stdio").toLowerCase();
const useHttpTransport =
  transportMode === "sse" || transportMode === "http" || transportMode === "streamable";

// Tool filtering is parsed once at module load (not per-session in HTTP mode).
const toolFilter = createToolFilter(process.env);

// Startup diagnostics (visible in Claude Code MCP server logs via stderr)
console.error(`[affine-mcp] Config: ${CONFIG_FILE} (${existsSync(CONFIG_FILE) ? 'found' : 'missing'})`);
console.error(`[affine-mcp] Endpoint: ${config.baseUrl}${config.graphqlPath}`);
const hasAuth = !!(config.apiToken || config.cookie || (config.email && config.password));
console.error(`[affine-mcp] Auth: ${hasAuth ? 'configured' : 'not configured'}`);
console.error(`[affine-mcp] HTTP auth mode: ${config.authMode}`);
if (hasAuth && config.baseUrl.startsWith("http://")
    && !config.baseUrl.includes("localhost")
    && !config.baseUrl.includes("127.0.0.1")) {
  console.error("WARNING: Credentials configured over plain HTTP. Use HTTPS for remote servers.");
}
console.error(`[affine-mcp] Workspace: ${config.defaultWorkspaceId ? 'set' : '(none)'}`);

for (const warning of toolFilter.warnings) {
  console.error(`[affine-mcp] WARNING: ${warning}`);
}

if (config.authMode === "oauth" && !useHttpTransport) {
  throw new Error("AFFINE_MCP_AUTH_MODE=oauth requires MCP_TRANSPORT=http (or streamable/sse).");
}

/** True when the per-user token-exchange path is configured (both URL + secret). */
function isTokenExchangeEnabled(): boolean {
  return !!(config.tokenExchange.url && config.tokenExchange.proxySecret);
}

/**
 * Read the chat user's Zitadel access token from the configured inbound header.
 * Express lower-cases header names; the configured header name is normalised to
 * lower-case at load time to match.
 */
function readUserAccessToken(req: Request | undefined): string | undefined {
  if (!req) return undefined;
  const raw = req.headers[config.tokenExchange.userTokenHeader];
  const value = Array.isArray(raw) ? raw[0] : raw;
  const trimmed = typeof value === "string" ? value.trim() : "";
  // Tolerate a `Bearer ` prefix in case the gateway forwards it that way.
  const bearer = /^Bearer\s+(.+)$/i.exec(trimmed);
  const token = bearer ? bearer[1] : trimmed;
  return token || undefined;
}

/**
 * The shared service-credential GraphQL client. Built once on first use and
 * reused for every session that does NOT carry a per-user token — byte-identical
 * to the prior singleton behaviour (including the async email/password login
 * that mutates this instance after construction).
 */
let serviceGqlClientPromise: Promise<GraphQLClient> | undefined;

function buildServiceGraphQLClient(): Promise<GraphQLClient> {
  if (serviceGqlClientPromise) return serviceGqlClientPromise;
  serviceGqlClientPromise = buildServiceGraphQLClientImpl();
  return serviceGqlClientPromise;
}

async function buildServiceGraphQLClientImpl(): Promise<GraphQLClient> {

  const gqlHeaders = { ...(config.headers || {}) };
  const gqlBearer = config.apiToken;

  if (config.authMode === "oauth") {
    if (!gqlBearer) {
      throw new Error("AFFINE_API_TOKEN is required when AFFINE_MCP_AUTH_MODE=oauth.");
    }
    if (config.cookie || config.email || config.password) {
      console.error(
        "[affine-mcp] OAuth mode uses the configured AFFINE_API_TOKEN service credential. " +
        "Ignoring AFFINE_COOKIE / AFFINE_EMAIL / AFFINE_PASSWORD.",
      );
    }
    delete gqlHeaders.Cookie;
    if (process.env.AFFINE_LOGIN_AT_START) {
      console.error("[affine-mcp] AFFINE_LOGIN_AT_START is ignored when AFFINE_MCP_AUTH_MODE=oauth.");
    }
  }

  // Initialize GraphQL client with authentication
  const gql = new GraphQLClient({
    endpoint: `${config.baseUrl}${config.graphqlPath}`,
    headers: gqlHeaders,
    bearer: gqlBearer
  });

  // Try email/password authentication if no other auth method is configured.
  // To avoid startup timeouts in MCP clients, default to async login after the stdio handshake.
  if (config.authMode !== "oauth" && !gql.isAuthenticated() && config.email && config.password) {
    const mode = (process.env.AFFINE_LOGIN_AT_START || "async").toLowerCase();
    // In HTTP transport mode, buildServer() is called per session, so credentials
    // must be retained for subsequent sessions. Only clear in stdio mode (single session).
    const isHttpTransport = ["sse", "http", "streamable"].includes(
      (process.env.MCP_TRANSPORT || "stdio").toLowerCase()
    );
    if (mode === "sync") {
      console.error("No token/cookie; performing synchronous email/password authentication at startup...");
      try {
        const { cookieHeader } = await loginWithPassword(config.baseUrl, config.email, config.password);
        gql.setCookie(cookieHeader);
        console.error("Successfully authenticated with email/password");
      } catch (e) {
        console.error("Failed to authenticate with email/password:", e);
        console.error("WARNING: Continuing without authentication - some operations may fail");
      } finally {
        if (!isHttpTransport) {
          config.password = undefined;
          config.email = undefined;
        }
      }
    } else {
      console.error("No token/cookie; deferring email/password authentication (async after connect)...");
      // Capture credentials before clearing — async login needs them.
      const loginEmail = config.email!;
      const loginPassword = config.password!;
      if (!isHttpTransport) {
        config.password = undefined;
        config.email = undefined;
      }
      // Fire-and-forget async login so stdio handshake is not delayed.
      (async () => {
        try {
          const { cookieHeader } = await loginWithPassword(config.baseUrl, loginEmail, loginPassword);
          gql.setCookie(cookieHeader);
          console.error("Successfully authenticated with email/password (async)");
        } catch (e) {
          console.error("Failed to authenticate with email/password (async):", e);
        }
      })();
    }
  }

  // Log authentication status
  if (!gql.isAuthenticated()) {
    console.error("WARNING: No authentication configured. Some operations may fail.");
    console.error("Set AFFINE_API_TOKEN or run: affine-mcp login");
  }

  return gql;
}

/**
 * Build a per-user GraphQL client by exchanging the chat user's Zitadel access
 * token for that user's AFFiNE session (RFC 8693) and replaying it as a session
 * cookie. Throws {@link TokenExchangeError} on exchange failure so the caller can
 * decide whether to fall back to the service client.
 */
async function buildUserGraphQLClient(userAccessToken: string): Promise<GraphQLClient> {
  const { affineSession } = await exchangeUserSession(userAccessToken, {
    url: config.tokenExchange.url!,
    proxySecret: config.tokenExchange.proxySecret!,
  });
  return new GraphQLClient({
    endpoint: `${config.baseUrl}${config.graphqlPath}`,
    cookie: `affine_session=${affineSession}`,
    // On a 401 (expired/revoked session) drop the cache so the next request for
    // this subject forces a fresh exchange.
    onUnauthorized: () => invalidateUserSession(userAccessToken),
  });
}

/** Per-attempt backoff (ms) for {@link buildUserGraphQLClientWithRetry}. */
const EXCHANGE_RETRY_BACKOFF_MS = [250, 600];

/**
 * Build the per-user client, retrying transient exchange failures before the
 * caller falls back to the service credential.
 *
 * The exchange's email step depends on a Zitadel `userinfo` HTTP call — Zitadel
 * access tokens carry no `email` claim, so AFFiNE resolves it from userinfo on
 * every cache-miss. That network call can transiently time out or rate-limit and
 * surface as a non-2xx (the token itself is valid). A single blip must NOT
 * silently demote the entire MCP session to the service credential, which is not
 * a member of the user's workspace and so reads their docs as empty / could
 * mis-own a create. Retrying with small backoff turns a flaky userinfo into a
 * reliable per-user session; only after every attempt fails do we fall back.
 */
async function buildUserGraphQLClientWithRetry(
  userAccessToken: string,
): Promise<GraphQLClient> {
  let lastErr: unknown;
  const attempts = EXCHANGE_RETRY_BACKOFF_MS.length + 1;
  for (let i = 0; i < attempts; i++) {
    try {
      return await buildUserGraphQLClient(userAccessToken);
    } catch (err) {
      lastErr = err;
      const detail = err instanceof TokenExchangeError ? err.message : "unexpected error";
      if (i < attempts - 1) {
        console.error(
          `[affine-mcp] Per-user token exchange attempt ${i + 1}/${attempts} failed (${detail}); retrying.`,
        );
        await new Promise((resolve) => setTimeout(resolve, EXCHANGE_RETRY_BACKOFF_MS[i]));
      }
    }
  }
  throw lastErr;
}

/**
 * Per-session server build.
 *
 * - If the per-user token-exchange path is configured AND the inbound request
 *   carries the chat user's access token, the GraphQL client acts AS that user
 *   (session-cookie credential).
 * - Otherwise — unconfigured, no header, or an exchange failure — it falls back
 *   to the shared service-credential client (byte-identical to prior behaviour).
 */
async function buildServer(req?: Request): Promise<McpServer> {
  const server = new McpServer({ name: "affine-mcp", version: VERSION });

  let gql: GraphQLClient | undefined;
  if (isTokenExchangeEnabled()) {
    const userToken = readUserAccessToken(req);
    if (userToken) {
      // A user token is present → this request MUST act AS that user. If the
      // exchange fails even after retries, FAIL FAST with a clear error — never
      // silently demote to the service credential. The service account is not a
      // member of the user's workspace, so demoting would read their docs as
      // empty and could create docs under the wrong identity. A loud failure is
      // correct: the caller and our logs see exactly what broke, surfacing the
      // root cause (the AFFiNE token-exchange status + body) instead of masking
      // it as confusing wrong-identity behaviour.
      try {
        gql = await buildUserGraphQLClientWithRetry(userToken);
        console.error("[affine-mcp] Using per-user AFFiNE session (token-exchange)");
      } catch (err) {
        const detail = err instanceof TokenExchangeError ? err.message : String(err);
        const message =
          `Per-user AFFiNE identity could not be established (${detail}). ` +
          `Refusing to fall back to the mcp@dvoid.io service credential — failing ` +
          `the request so the real cause is visible, not masked as wrong-identity behaviour.`;
        console.error(`[affine-mcp] ${message}`);
        throw new TokenExchangeError(message);
      }
    }
  }
  // No user token (service-to-service: boot-time tools/list, or the per-user
  // path unconfigured) → the shared service credential is the correct identity.
  if (!gql) {
    gql = await buildServiceGraphQLClient();
  }

  const originalRegisterTool = (server as any).registerTool?.bind(server);
  if (typeof originalRegisterTool !== "function") {
    const message =
      "[affine-mcp] server.registerTool not found - tool filtering cannot be enforced. " +
      "The MCP SDK API may have changed.";
    if (toolFilterRequiresRegisterTool(toolFilter)) {
      throw new Error(
        `${message} Refusing to start because AFFINE_TOOL_PROFILE is not "full" ` +
        "or AFFINE_DISABLED_GROUPS/AFFINE_DISABLED_TOOLS is configured."
      );
    }
    console.error(`[affine-mcp] WARNING: ${message} Continuing with the full tool surface.`);
  } else {
    (server as any).registerTool = (name: string, options: any, handler: any) => {
      if (!toolFilter.isEnabled(name)) return;
      return originalRegisterTool(name, options, handler);
    };
  }
  console.error(`[affine-mcp] Tool profile: ${toolFilter.profile}`);
  console.error(`[affine-mcp] Disabled groups: ${process.env.AFFINE_DISABLED_GROUPS || "(none)"}`);
  console.error(`[affine-mcp] Disabled tools: ${process.env.AFFINE_DISABLED_TOOLS || "(none)"}`);
  console.error(`[affine-mcp] Enabled tools: ${toolFilter.enabledTools.length}/${toolFilter.totalToolCount}`);

  registerWorkspaceTools(server, gql);
  registerDocTools(server, gql, { workspaceId: config.defaultWorkspaceId });
  registerCommentTools(server, gql, { workspaceId: config.defaultWorkspaceId });
  registerHistoryTools(server, gql, { workspaceId: config.defaultWorkspaceId });
  registerOrganizeTools(server, gql, { workspaceId: config.defaultWorkspaceId });
  registerUserTools(server, gql);
  registerUserCRUDTools(server, gql);
  if (config.authMode !== "oauth") {
    registerAuthTools(server, gql, config.baseUrl);
  }
  registerAccessTokenTools(server, gql);
  registerBlobTools(server, gql);
  registerNotificationTools(server, gql);
  return server;
}

async function start() {
  if (useHttpTransport) {
    const DEFAULT_PORT = 3000;
    const portEnvValue = process.env.PORT;

    let port = DEFAULT_PORT;

    // Validate the HTTP server port if provided.
    if (portEnvValue != null && portEnvValue.trim() !== "") {
      const parsedPort = Number(portEnvValue);

      if (Number.isInteger(parsedPort) && parsedPort >= 0 && parsedPort <= 65535) {
        port = parsedPort;
      } else {
        console.warn(
          `[affine-mcp] Invalid PORT "${portEnvValue}" (expected 0..65535 integer). Falling back to ${DEFAULT_PORT}.`
        );
      }
    }

    await startHttpMcpServer(buildServer, port, config);
  } else {
    // stdio transport is the default for typical desktop MCP clients
    const server = await buildServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
  }
}

start().catch((err) => {
  console.error("Failed to start affine-mcp server:", err);
  process.exit(1);
});
