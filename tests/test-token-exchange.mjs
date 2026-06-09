#!/usr/bin/env node
// Tests for the per-user RFC 8693 token-exchange client (src/tokenExchange.ts).
//
// Strategy: stand up a real local HTTP endpoint and drive the real exchange
// client against it (verify-through-real-protocol), asserting on:
//   1. happy path  -> POST shape + RFC 8693 body, returns affineSession
//   2. cache hit    -> second call for same `sub` does NOT re-hit the endpoint
//   3. distinct sub -> different subject DOES hit the endpoint again
//   4. invalidation -> invalidateUserSession() forces a re-exchange
//   5. non-2xx      -> throws TokenExchangeError with status, never leaks secret
//   6. no secret/token in any request log line
//
// Run with: npx tsx tests/test-token-exchange.mjs   (or node after build)
import http from "node:http";
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Import the TS source via tsx's loader (the test runner invokes with tsx) or the
// compiled dist if present. We import from src to keep tests source-of-truth.
const mod = await import(
  pathToFileURL(path.resolve(__dirname, "..", "src", "tokenExchange.ts")).href
);
const { exchangeUserSession, invalidateUserSession, TokenExchangeError, _clearSessionCache } = mod;

const PROXY_SECRET = "test-trusted-proxy-secret-do-not-leak";

/** Build an unsigned JWT (header.payload.sig) — decodeJwt only peeks, no verify. */
function makeJwt(payload) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "none", typ: "JWT" })}.${b64(payload)}.sig`;
}

let requestLog = [];
let responder = null;

const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    requestLog.push({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body,
    });
    responder(req, res, body);
  });
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const { port } = server.address();
const url = `http://127.0.0.1:${port}/api/auth/token-exchange`;
const opts = { url, proxySecret: PROXY_SECRET };

function ok(session = "session-value-abc") {
  responder = (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        access_token: session,
        issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
        token_type: "Bearer",
      }),
    );
  };
}

function fail(status) {
  responder = (_req, res) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "nope" }));
  };
}

function reset() {
  requestLog = [];
  _clearSessionCache();
}

let failures = 0;
async function testCase(name, fn) {
  reset();
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failures++;
    console.error(`  FAIL ${name}: ${e?.message || e}`);
  }
}

const future = Math.floor(Date.now() / 1000) + 3600;
const userA = makeJwt({ sub: "user-A", exp: future });
const userB = makeJwt({ sub: "user-B", exp: future });
// id_tokens (RFC 8693 actor_token) — carry the email AFFiNE resolves. The
// client only forwards them; it never verifies them.
const userAId = makeJwt({ sub: "user-A", email: "user-a@affine.pro", exp: future });
const userBId = makeJwt({ sub: "user-B", email: "user-b@affine.pro", exp: future });

// 1. Happy path: correct POST shape + RFC 8693 body, returns affineSession.
await testCase("happy path issues affineSession with RFC 8693 body + proxy secret", async () => {
  ok("affine-sess-1");
  const { affineSession } = await exchangeUserSession(userA, userAId, opts);
  assert.equal(affineSession, "affine-sess-1");
  assert.equal(requestLog.length, 1, "exactly one exchange request");
  const r = requestLog[0];
  assert.equal(r.method, "POST");
  assert.equal(r.headers["x-affine-trusted-proxy-secret"], PROXY_SECRET);
  assert.match(r.headers["content-type"], /application\/json/);
  const parsed = JSON.parse(r.body);
  assert.equal(parsed.grant_type, "urn:ietf:params:oauth:grant-type:token-exchange");
  assert.equal(parsed.subject_token, userA);
  assert.equal(parsed.subject_token_type, "urn:ietf:params:oauth:token-type:access_token");
  // RFC 8693 actor_token = the user's id_token (carries the email AFFiNE reads).
  assert.equal(parsed.actor_token, userAId);
  assert.equal(parsed.actor_token_type, "urn:ietf:params:oauth:token-type:id_token");
});

// 2. Cache hit: second call for same sub does not re-hit the endpoint.
await testCase("cache hit avoids a second exchange for the same subject", async () => {
  ok("affine-sess-2");
  const first = await exchangeUserSession(userA, userAId, opts);
  const second = await exchangeUserSession(userA, userAId, opts);
  assert.equal(first.affineSession, "affine-sess-2");
  assert.equal(second.affineSession, "affine-sess-2");
  assert.equal(requestLog.length, 1, "second call served from cache");
});

// 3. Distinct subject re-exchanges.
await testCase("distinct subject triggers a fresh exchange", async () => {
  ok("shared");
  await exchangeUserSession(userA, userAId, opts);
  await exchangeUserSession(userB, userBId, opts);
  assert.equal(requestLog.length, 2, "each subject exchanged once");
});

// 4. invalidateUserSession forces a re-exchange.
await testCase("invalidateUserSession forces re-exchange on next call", async () => {
  ok("sess");
  await exchangeUserSession(userA, userAId, opts);
  invalidateUserSession(userA);
  await exchangeUserSession(userA, userAId, opts);
  assert.equal(requestLog.length, 2, "invalidation re-exchanged");
});

// 5. Non-2xx -> typed error with status, no secret leak in message.
await testCase("non-2xx throws TokenExchangeError with status and no secret leak", async () => {
  fail(403);
  let err;
  try {
    await exchangeUserSession(userA, userAId, opts);
  } catch (e) {
    err = e;
  }
  assert.ok(err instanceof TokenExchangeError, "is TokenExchangeError");
  assert.equal(err.status, 403);
  assert.ok(!err.message.includes(PROXY_SECRET), "secret not in error message");
  assert.ok(!err.message.includes(userA), "token not in error message");
});

// 6. Concurrent calls for same subject share a single in-flight exchange.
await testCase("concurrent calls for same subject dedupe to one exchange", async () => {
  let resolveResp;
  responder = (_req, res) => {
    // Delay so both callers are in-flight simultaneously.
    resolveResp = () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "concurrent" }));
    };
  };
  const p1 = exchangeUserSession(userA, userAId, opts);
  const p2 = exchangeUserSession(userA, userAId, opts);
  await new Promise((r) => setTimeout(r, 20));
  resolveResp();
  const [a, b] = await Promise.all([p1, p2]);
  assert.equal(a.affineSession, "concurrent");
  assert.equal(b.affineSession, "concurrent");
  assert.equal(requestLog.length, 1, "single in-flight exchange for concurrent callers");
});

server.close();

if (failures > 0) {
  console.error(`\ntoken-exchange tests: ${failures} failing`);
  process.exit(1);
}
console.log("\ntoken-exchange tests: all passing");
