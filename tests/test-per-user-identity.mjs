#!/usr/bin/env node
/**
 * End-to-end wiring test for the per-user AFFiNE session path.
 *
 * Spins up:
 *   - a fake AFFiNE backend exposing /api/auth/token-exchange (RFC 8693) and
 *     /graphql (records the inbound auth: Cookie vs Bearer)
 *   - the real affine-mcp HTTP server pointed at that backend, with the
 *     token-exchange path configured
 *
 * Then drives the real MCP Streamable HTTP client and asserts:
 *   A. request carrying x-dvoid-access-token -> GraphQL sees
 *      `Cookie: affine_session=<exchanged>` (acting AS the user)
 *   B. request WITHOUT the user header -> GraphQL sees the service Bearer
 *      (backward-compatible fallback)
 *
 * Run after `npm run build`:  node tests/test-per-user-identity.mjs
 */
import http from "node:http";
import path from "node:path";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_DIR = path.resolve(__dirname, "..");
const MCP_SERVER_PATH = path.resolve(PROJECT_DIR, "dist", "index.js");

const SERVICE_TOKEN = "service-api-token";
const PROXY_SECRET = "trusted-proxy-secret";
const EXCHANGED_SESSION = "exchanged-affine-session-xyz";

function makeJwt(payload) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "none", typ: "JWT" })}.${b64(payload)}.sig`;
}

async function findFreePort() {
  return await new Promise((resolve, reject) => {
    const s = http.createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

// --- Fake AFFiNE backend (token-exchange + graphql) ---
const graphqlAuthSeen = [];
// Subjects AFFiNE has no ConnectedAccount for (never signed in on the web).
const UNLINKED_SUB = "user-unlinked";
const exchangeSubjects = [];
const fakeAffine = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    if (req.url.startsWith("/api/auth/token-exchange")) {
      if (req.headers["x-affine-trusted-proxy-secret"] !== PROXY_SECRET) {
        res.writeHead(403).end("forbidden");
        return;
      }
      const sub = JSON.parse(Buffer.from(JSON.parse(body).subject_token.split(".")[1], "base64url")).sub;
      exchangeSubjects.push(sub);
      if (sub === UNLINKED_SUB) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: 400, name: "INVALID_AUTH_STATE", message: "Invalid auth state." }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: EXCHANGED_SESSION, token_type: "Bearer" }));
      return;
    }
    if (req.url.startsWith("/graphql")) {
      graphqlAuthSeen.push({
        cookie: req.headers["cookie"] || null,
        authorization: req.headers["authorization"] || null,
      });
      // Minimal currentUser-shaped response so a tool call resolves.
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: { currentUser: { id: "u1", name: "Test", email: "t@e.co" } } }));
      return;
    }
    res.writeHead(404).end();
  });
});

let mcp;
let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failures++;
    console.error(`  FAIL ${name}: ${e?.message || e}`);
  }
}

try {
  const affinePort = await findFreePort();
  await new Promise((r) => fakeAffine.listen(affinePort, "127.0.0.1", r));
  const affineBase = `http://127.0.0.1:${affinePort}`;

  const mcpPort = await findFreePort();
  mcp = spawn("node", [MCP_SERVER_PATH], {
    env: {
      ...process.env,
      MCP_TRANSPORT: "http",
      PORT: String(mcpPort),
      AFFINE_MCP_HTTP_HOST: "127.0.0.1",
      AFFINE_BASE_URL: affineBase,
      AFFINE_API_TOKEN: SERVICE_TOKEN,
      AFFINE_TOKEN_EXCHANGE_URL: `${affineBase}/api/auth/token-exchange`,
      AFFINE_TRUSTED_PROXY_SECRET: PROXY_SECRET,
      AFFINE_PUBLIC_URL: "https://affine.example",
      // Restrict to a tiny surface so the test is fast & deterministic.
      AFFINE_TOOL_PROFILE: "full",
      XDG_CONFIG_HOME: "/tmp/affine-test-" + Date.now(),
    },
    stdio: ["ignore", "ignore", "inherit"],
  });

  const mcpUrl = `http://127.0.0.1:${mcpPort}/mcp`;
  // Wait for readiness.
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`http://127.0.0.1:${mcpPort}/healthz`);
      await r.body?.cancel();
      if (r.ok) break;
    } catch { /* retry */ }
    await delay(200);
  }

  async function callCurrentUser(extraHeaders) {
    const client = new Client({ name: "test", version: "1.0.0" }, { capabilities: {} });
    const transport = new StreamableHTTPClientTransport(new URL(mcpUrl), {
      requestInit: { headers: extraHeaders },
    });
    await client.connect(transport);
    const result = await client.callTool({ name: "current_user", arguments: {} });
    await transport.close();
    return result;
  }

  // A. With user token header -> GraphQL must see the exchanged session cookie.
  graphqlAuthSeen.length = 0;
  const userToken = makeJwt({ sub: "user-A", exp: Math.floor(Date.now() / 1000) + 3600 });
  await callCurrentUser({ "x-dvoid-access-token": userToken });
  check("user-token request acts AS the user via session cookie", () => {
    const seen = graphqlAuthSeen.find((s) => s.cookie);
    assert.ok(seen, "GraphQL received a Cookie header");
    assert.equal(seen.cookie, `affine_session=${EXCHANGED_SESSION}`);
    // Per-user client carries NO service bearer.
    assert.equal(seen.authorization, null, "no service bearer on the per-user path");
  });

  // B. Without user token header -> falls back to service bearer.
  graphqlAuthSeen.length = 0;
  await callCurrentUser(undefined);
  check("no user-token request falls back to service bearer", () => {
    const seen = graphqlAuthSeen.find((s) => s.authorization);
    assert.ok(seen, "GraphQL received an Authorization header");
    assert.equal(seen.authorization, `Bearer ${SERVICE_TOKEN}`);
    assert.equal(seen.cookie, null, "no per-user cookie on the fallback path");
  });

  // D. Unlinked account -> the caller is told to sign in once, and the exchange
  //    is attempted exactly once (INVALID_AUTH_STATE can never succeed on retry).
  exchangeSubjects.length = 0;
  const unlinked = makeJwt({ sub: UNLINKED_SUB, exp: Math.floor(Date.now() / 1000) + 3600 });
  const unlinkedErr = await callCurrentUser({ "x-dvoid-access-token": unlinked }).then(
    () => undefined,
    (e) => e,
  );
  check("unlinked account surfaces the sign-in-once instruction", () => {
    assert.ok(unlinkedErr, "the call fails");
    assert.match(
      String(unlinkedErr?.message),
      /Your AFFiNE account is not linked yet: sign in once at https:\/\/affine\.example \(Continue with OIDC\), then retry\./,
    );
  });
  check("unlinked account is not retried", () => {
    assert.deepEqual(exchangeSubjects, [UNLINKED_SUB]);
  });

  mcp.kill("SIGTERM");
  await delay(300);

  // C. Inert when unconfigured: a SECOND server WITHOUT token-exchange env must
  //    ignore the user header entirely and use the service bearer (byte-identical
  //    to pre-feature behaviour).
  const mcpPort2 = await findFreePort();
  mcp = spawn("node", [MCP_SERVER_PATH], {
    env: {
      ...process.env,
      MCP_TRANSPORT: "http",
      PORT: String(mcpPort2),
      AFFINE_MCP_HTTP_HOST: "127.0.0.1",
      AFFINE_BASE_URL: affineBase,
      AFFINE_API_TOKEN: SERVICE_TOKEN,
      // No AFFINE_TOKEN_EXCHANGE_URL / AFFINE_TRUSTED_PROXY_SECRET -> path inert.
      AFFINE_TOOL_PROFILE: "full",
      XDG_CONFIG_HOME: "/tmp/affine-test-" + Date.now(),
    },
    stdio: ["ignore", "ignore", "inherit"],
  });
  const deadline2 = Date.now() + 15000;
  while (Date.now() < deadline2) {
    try {
      const r = await fetch(`http://127.0.0.1:${mcpPort2}/healthz`);
      await r.body?.cancel();
      if (r.ok) break;
    } catch { /* retry */ }
    await delay(200);
  }
  graphqlAuthSeen.length = 0;
  {
    const client = new Client({ name: "test", version: "1.0.0" }, { capabilities: {} });
    const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${mcpPort2}/mcp`), {
      requestInit: { headers: { "x-dvoid-access-token": userToken } },
    });
    await client.connect(transport);
    await client.callTool({ name: "current_user", arguments: {} });
    await transport.close();
  }
  check("user header is inert when token-exchange is unconfigured", () => {
    const seen = graphqlAuthSeen.find((s) => s.authorization);
    assert.ok(seen, "GraphQL received an Authorization header");
    assert.equal(seen.authorization, `Bearer ${SERVICE_TOKEN}`);
    assert.equal(seen.cookie, null, "header ignored; no per-user cookie");
  });
} finally {
  if (mcp) mcp.kill("SIGTERM");
  fakeAffine.close();
}

if (failures > 0) {
  console.error(`\nper-user-identity tests: ${failures} failing`);
  process.exit(1);
}
console.log("\nper-user-identity tests: all passing");
