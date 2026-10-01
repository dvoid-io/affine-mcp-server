#!/usr/bin/env node
/**
 * Broker mode (AFFINE_MCP_AUTH_MODE=broker), end to end.
 *
 * Spins up a local OIDC issuer (discovery + JWKS), a fake AFFiNE (token-exchange +
 * graphql, both recording what they receive) and the real affine-mcp HTTP server
 * in broker mode, then drives it with tokens minted here:
 *
 *   - a valid broker token → the per-user path, and AFFiNE's exchange receives
 *     exactly that bearer as its subject token;
 *   - ai-service's own subject → the shared service credential, no exchange;
 *   - client-sent x-dvoid-mcp-enumerate / x-dvoid-access-token → ignored;
 *   - wrong aud, wrong issuer, no act, a disallowed actor, expired, an unknown
 *     kid, alg none, HS256 keyed with the RSA public key → 401;
 *   - one subject's token on another subject's session → 403;
 *   - broker mode refuses to start without the per-user exchange, or with a
 *     shared AFFINE_MCP_HTTP_TOKEN.
 *
 * Run after `npm run build`:  node tests/test-broker-auth.mjs
 */
import http from "node:http";
import path from "node:path";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { createHmac } from "node:crypto";
import { SignJWT, exportJWK, exportSPKI, generateKeyPair } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MCP_SERVER_PATH = path.resolve(__dirname, "..", "dist", "index.js");

const SERVICE_TOKEN = "service-api-token";
const PROXY_SECRET = "trusted-proxy-secret";
const EXCHANGED_SESSION = "exchanged-affine-session-xyz";
const PROJECT = "386781285248407674";
const GATEWAY = "svc-agentgateway";
const AI_SERVICE = "svc-ai-service";

let failures = 0;
function check(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => console.log(`  ok   ${name}`))
    .catch((e) => {
      failures++;
      console.error(`  FAIL ${name}: ${e?.message || e}`);
    });
}

async function freePort() {
  return await new Promise((resolve, reject) => {
    const s = http.createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

function listen(handler) {
  return new Promise(async (resolve) => {
    const port = await freePort();
    const srv = http.createServer(handler);
    srv.listen(port, "127.0.0.1", () => resolve({ srv, base: `http://127.0.0.1:${port}` }));
  });
}

// --- keys: the issuer's, and one nobody published -------------------------------
const issuerKey = await generateKeyPair("RS256", { extractable: true });
const strangerKey = await generateKeyPair("RS256", { extractable: true });
const issuerJwk = { ...(await exportJWK(issuerKey.publicKey)), kid: "issuer-1", alg: "RS256", use: "sig" };
const issuerSpki = await exportSPKI(issuerKey.publicKey);

// --- the issuer ------------------------------------------------------------------
let ISSUER = "";
const issuer = await listen((req, res) => {
  if (req.url === "/.well-known/openid-configuration" || req.url === "/.well-known/oauth-authorization-server") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      issuer: ISSUER,
      jwks_uri: `${ISSUER}/oauth/v2/keys`,
      authorization_endpoint: `${ISSUER}/oauth/v2/authorize`,
      token_endpoint: `${ISSUER}/oauth/v2/token`,
      response_types_supported: ["code"],
    }));
    return;
  }
  if (req.url === "/oauth/v2/keys") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ keys: [issuerJwk] }));
    return;
  }
  res.writeHead(404).end();
});
ISSUER = issuer.base;

// --- fake AFFiNE -------------------------------------------------------------------
const exchangeSubjects = [];
const graphqlAuth = [];
const affine = await listen((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    if (req.url.startsWith("/api/auth/token-exchange")) {
      if (req.headers["x-affine-trusted-proxy-secret"] !== PROXY_SECRET) {
        res.writeHead(403).end("forbidden");
        return;
      }
      exchangeSubjects.push(JSON.parse(body).subject_token);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: EXCHANGED_SESSION, token_type: "Bearer" }));
      return;
    }
    if (req.url.startsWith("/graphql")) {
      graphqlAuth.push({ cookie: req.headers.cookie || null, authorization: req.headers.authorization || null });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: { currentUser: { id: "u1", name: "Test", email: "t@e.co" } } }));
      return;
    }
    res.writeHead(404).end();
  });
});

// --- tokens ------------------------------------------------------------------------
const now = () => Math.floor(Date.now() / 1000);
async function mint(claims, opts = {}) {
  const key = opts.key ?? issuerKey.privateKey;
  const kid = opts.kid ?? "issuer-1";
  return await new SignJWT({ aud: [PROJECT, "client-id-x"], act: { sub: GATEWAY }, ...claims })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer(opts.iss ?? ISSUER)
    .setIssuedAt()
    .setExpirationTime(opts.exp ?? now() + 3600)
    .sign(key);
}
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
function unsigned(payload) {
  return `${b64({ alg: "none", typ: "JWT" })}.${b64(payload)}.`;
}
function hs256WithPublicKey(payload) {
  const head = b64({ alg: "HS256", typ: "JWT", kid: "issuer-1" });
  const body = b64(payload);
  const sig = createHmac("sha256", issuerSpki).update(`${head}.${body}`).digest("base64url");
  return `${head}.${body}.${sig}`;
}

// --- affine-mcp ---------------------------------------------------------------------
function startMcp(port, extraEnv = {}) {
  return spawn("node", [MCP_SERVER_PATH], {
    env: {
      ...process.env,
      MCP_TRANSPORT: "http",
      PORT: String(port),
      AFFINE_MCP_HTTP_HOST: "127.0.0.1",
      AFFINE_BASE_URL: affine.base,
      AFFINE_API_TOKEN: SERVICE_TOKEN,
      AFFINE_TOKEN_EXCHANGE_URL: `${affine.base}/api/auth/token-exchange`,
      AFFINE_TRUSTED_PROXY_SECRET: PROXY_SECRET,
      AFFINE_MCP_AUTH_MODE: "broker",
      AFFINE_BROKER_ISSUER_URL: ISSUER,
      AFFINE_BROKER_AUDIENCE: PROJECT,
      AFFINE_BROKER_ALLOWED_ACTORS: GATEWAY,
      AFFINE_BROKER_SERVICE_SUBJECTS: AI_SERVICE,
      AFFINE_TOOL_PROFILE: "full",
      XDG_CONFIG_HOME: "/tmp/affine-broker-test-" + Date.now(),
      ...extraEnv,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
}

async function waitHealthy(port) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/healthz`);
      await r.body?.cancel();
      if (r.ok) return;
    } catch { /* retry */ }
    await delay(150);
  }
  throw new Error("affine-mcp did not become healthy");
}

const INIT = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } },
};
async function rawPost(url, token, body = INIT, headers = {}) {
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  return { status: r.status, sid: r.headers.get("mcp-session-id"), text };
}

let mcp;
try {
  const port = await freePort();
  mcp = startMcp(port);
  let stderr = "";
  mcp.stderr.on("data", (d) => (stderr += d));
  await waitHealthy(port);
  const url = `http://127.0.0.1:${port}/mcp`;

  async function callCurrentUser(token, extraHeaders = {}) {
    const client = new Client({ name: "test", version: "1.0.0" }, { capabilities: {} });
    const transport = new StreamableHTTPClientTransport(new URL(url), {
      requestInit: { headers: { authorization: `Bearer ${token}`, ...extraHeaders } },
    });
    await client.connect(transport);
    const result = await client.callTool({ name: "current_user", arguments: {} });
    await transport.close();
    return result;
  }

  console.log("broker mode — verified token in, identity from the token only");

  const userToken = await mint({ sub: "user-A" });
  graphqlAuth.length = 0;
  exchangeSubjects.length = 0;
  await callCurrentUser(userToken);
  await check("a valid broker token acts AS the user (session cookie, no service bearer)", () => {
    const seen = graphqlAuth.find((s) => s.cookie);
    assert.ok(seen, "GraphQL received a Cookie");
    assert.equal(seen.cookie, `affine_session=${EXCHANGED_SESSION}`);
    assert.equal(seen.authorization, null);
  });
  await check("AFFiNE's exchange receives exactly the verified bearer", () => {
    assert.ok(exchangeSubjects.length >= 1);
    assert.ok(exchangeSubjects.every((t) => t === userToken));
  });

  graphqlAuth.length = 0;
  exchangeSubjects.length = 0;
  await callCurrentUser(await mint({ sub: AI_SERVICE }));
  await check("ai-service's own subject uses the service credential, with no exchange", () => {
    const seen = graphqlAuth.find((s) => s.authorization);
    assert.ok(seen, "GraphQL received the service bearer");
    assert.equal(seen.authorization, `Bearer ${SERVICE_TOKEN}`);
    assert.equal(seen.cookie, null);
    assert.equal(exchangeSubjects.length, 0);
  });

  graphqlAuth.length = 0;
  exchangeSubjects.length = 0;
  const forgedUserHeader = await mint({ sub: "user-B" });
  await callCurrentUser(userToken, { "x-dvoid-mcp-enumerate": "1", "x-dvoid-access-token": forgedUserHeader });
  await check("a client-sent x-dvoid-mcp-enumerate is ignored (still per-user, not the service account)", () => {
    assert.ok(graphqlAuth.some((s) => s.cookie), "per-user cookie used");
    assert.ok(!graphqlAuth.some((s) => s.authorization === `Bearer ${SERVICE_TOKEN}`), "service bearer never used");
  });
  await check("a client-sent x-dvoid-access-token is ignored (user-B's token in it never reaches the exchange)", () => {
    // user-A's AFFiNE session is cached by sub, so honouring the header is the only
    // way user-B's token could reach the exchange here.
    assert.ok(!exchangeSubjects.includes(forgedUserHeader), "the header's token was exchanged");
    assert.ok(exchangeSubjects.every((t) => t === userToken));
  });

  console.log("refused (401) before any session exists");
  const refusals = [
    ["no Authorization header", null],
    ["a wrong audience", await mint({ sub: "user-A", aud: ["some-other-project"] })],
    ["a wrong issuer", await mint({ sub: "user-A" }, { iss: "https://evil.example" })],
    ["no act claim", await mint({ sub: "user-A", act: undefined })],
    ["an actor that is not the broker", await mint({ sub: "user-A", act: { sub: "svc-someone-else" } })],
    ["an expired token", await mint({ sub: "user-A" }, { exp: now() - 3600 })],
    ["a key the issuer never published (unknown kid)", await mint({ sub: "user-A" }, { key: strangerKey.privateKey, kid: "stranger" })],
    ["a stranger's key under the issuer's kid", await mint({ sub: "user-A" }, { key: strangerKey.privateKey })],
    ["alg none", unsigned({ iss: ISSUER, aud: [PROJECT], sub: "user-A", act: { sub: GATEWAY }, exp: now() + 3600 })],
    ["HS256 keyed with the issuer's public key", hs256WithPublicKey({ iss: ISSUER, aud: [PROJECT], sub: "user-A", act: { sub: GATEWAY }, exp: now() + 3600 })],
  ];
  for (const [name, token] of refusals) {
    exchangeSubjects.length = 0;
    const r = await rawPost(url, token);
    await check(`${name} → 401, and nothing reaches AFFiNE`, () => {
      assert.equal(r.status, 401, r.text.slice(0, 200));
      assert.equal(exchangeSubjects.length, 0);
    });
  }
  const q = await fetch(`${url}?token=${encodeURIComponent(userToken)}`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify(INIT),
  });
  await check("a token in the query string → 401", () => assert.equal(q.status, 401));

  console.log("a session belongs to the subject that opened it");
  const a = await rawPost(url, userToken);
  await check("user-A opens a session", () => {
    assert.equal(a.status, 200, a.text.slice(0, 200));
    assert.ok(a.sid);
  });
  const notification = { jsonrpc: "2.0", method: "notifications/initialized" };
  const listReq = { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} };
  await rawPost(url, userToken, notification, { "mcp-session-id": a.sid });
  const asB = await rawPost(url, forgedUserHeader, listReq, { "mcp-session-id": a.sid });
  await check("user-B's valid token on user-A's session → 403", () => assert.equal(asB.status, 403, asB.text.slice(0, 200)));
  const asA = await rawPost(url, userToken, listReq, { "mcp-session-id": a.sid });
  await check("user-A continues on their own session", () => assert.equal(asA.status, 200, asA.text.slice(0, 200)));

  await check("no token or session secret is ever logged", () => {
    assert.ok(!stderr.includes(userToken), "the bearer was logged");
    assert.ok(!stderr.includes(EXCHANGED_SESSION), "the AFFiNE session was logged");
    assert.ok(!stderr.includes(PROXY_SECRET), "the proxy secret was logged");
  });

  mcp.kill("SIGTERM");
  await delay(200);

  console.log("broker mode refuses an unsafe configuration at startup");
  async function exitsNonZero(extraEnv) {
    const p = startMcp(await freePort(), extraEnv);
    let err = "";
    p.stderr.on("data", (d) => (err += d));
    const code = await Promise.race([
      new Promise((r) => p.on("exit", (c) => r(c))),
      delay(8000).then(() => "running"),
    ]);
    if (code === "running") p.kill("SIGTERM");
    return { code, err };
  }
  const noExchange = await exitsNonZero({ AFFINE_TOKEN_EXCHANGE_URL: "", AFFINE_TRUSTED_PROXY_SECRET: "" });
  await check("without the per-user exchange it will not start", () => {
    assert.notEqual(noExchange.code, 0);
    assert.notEqual(noExchange.code, "running");
    assert.match(noExchange.err, /requires AFFINE_TOKEN_EXCHANGE_URL/);
  });
  const sharedToken = await exitsNonZero({ AFFINE_MCP_HTTP_TOKEN: "shared" });
  await check("with a shared AFFINE_MCP_HTTP_TOKEN it will not start", () => {
    assert.notEqual(sharedToken.code, "running");
    assert.match(sharedToken.err, /AFFINE_MCP_HTTP_TOKEN is not allowed/);
  });
  const noActors = await exitsNonZero({ AFFINE_BROKER_ALLOWED_ACTORS: "" });
  await check("without allowed actors it will not start", () => {
    assert.notEqual(noActors.code, "running");
    assert.match(noActors.err, /AFFINE_BROKER_ALLOWED_ACTORS is required/);
  });
} catch (e) {
  failures++;
  console.error("FAIL (harness):", e);
} finally {
  mcp?.kill("SIGTERM");
  issuer.srv.close();
  affine.srv.close();
}

console.log(failures === 0 ? "PASS — broker mode" : `FAIL — ${failures} check(s)`);
process.exit(failures === 0 ? 0 : 1);
