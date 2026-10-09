#!/usr/bin/env node
// Credential-boundary and cache regressions against real undici request handling.
// MockAgent denies all real network access, including on accidental redirects.
// Run after npm run build: node tests/test-token-exchange-security.mjs
import assert from "node:assert/strict";
import { MockAgent, getGlobalDispatcher, setGlobalDispatcher } from "undici";
import { exchangeUserSession, invalidateUserSession, _clearSessionCache, TokenExchangeError } from "../dist/tokenExchange.js";

const original = getGlobalDispatcher();
const mock = new MockAgent();
mock.disableNetConnect();
setGlobalDispatcher(mock);
const origin = "https://affine.test";
const foreign = "https://foreign.test";
const opts = { url: `${origin}/exchange`, proxySecret: "fixture-proxy-secret" };
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
// This component only peeks at sub/exp: broker middleware verifies the bearer
// before calling it. The endpoint is the final identity verifier in other modes.
const token = (sub, exp = Math.floor(Date.now() / 1000) + 300) =>
  `${b64({ alg: "none" })}.${b64({ sub, exp })}.fixture`;
const a = token("person-a");
const b = token("person-b");
let passed = 0;
let failed = 0;
async function check(name, fn) {
  _clearSessionCache();
  try { await fn(); passed++; console.log(`ok ${name}`); }
  catch (err) { failed++; console.error(`FAIL ${name}: ${err.message}`); }
}
const success = (value) => ({
  statusCode: 200,
  data: JSON.stringify({ access_token: value }),
  responseOptions: { headers: { "content-type": "application/json" } },
});

try {
  await check("2xx exchange keeps RFC8693 body and proxy secret at the configured endpoint", async () => {
    let request;
    mock.get(origin).intercept({ path: "/exchange", method: "POST" }).reply((input) => {
      request = input;
      return success("session-a");
    });
    assert.equal((await exchangeUserSession(a, opts)).affineSession, "session-a");
    assert.equal(request.headers["x-affine-trusted-proxy-secret"], opts.proxySecret);
    assert.deepEqual(JSON.parse(request.body), {
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: a,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    });
  });
  await check("same-subject cache hit remains supported; another subject exchanges separately", async () => {
    mock.get(origin).intercept({ path: "/exchange", method: "POST" }).reply(() => success("session-a"));
    assert.equal((await exchangeUserSession(a, opts)).affineSession, "session-a");
    assert.equal((await exchangeUserSession(a, opts)).affineSession, "session-a");
    mock.get(origin).intercept({ path: "/exchange", method: "POST" }).reply(() => success("session-b"));
    assert.equal((await exchangeUserSession(b, opts)).affineSession, "session-b");
  });
  await check("explicit invalidation forces a fresh exchange", async () => {
    mock.get(origin).intercept({ path: "/exchange", method: "POST" }).reply(() => success("session-a"));
    await exchangeUserSession(a, opts);
    invalidateUserSession(a);
    mock.get(origin).intercept({ path: "/exchange", method: "POST" }).reply(() => success("renewed-session-a"));
    assert.equal((await exchangeUserSession(a, opts)).affineSession, "renewed-session-a");
  });
  await check("expired cache entry is not reused", async () => {
    const expired = token("person-a", Math.floor(Date.now() / 1000) - 10);
    mock.get(origin).intercept({ path: "/exchange", method: "POST" }).reply(() => success("stale-session"));
    await exchangeUserSession(expired, opts);
    mock.get(origin).intercept({ path: "/exchange", method: "POST" }).reply(() => success("fresh-session"));
    assert.equal((await exchangeUserSession(a, opts)).affineSession, "fresh-session");
  });
  await check("failed exchange does not poison the cache or create a fallback session", async () => {
    mock.get(origin).intercept({ path: "/exchange", method: "POST" }).reply(403, JSON.stringify({ error: "refused" }), {
      headers: { "content-type": "application/json" },
    });
    await assert.rejects(exchangeUserSession(a, opts), (err) => {
      assert.ok(err instanceof TokenExchangeError);
      assert.equal(err.status, 403);
      assert.match(err.message, /refused/);
      assert.equal(err.message.includes(a), false);
      assert.equal(err.message.includes(opts.proxySecret), false);
      return true;
    });
    mock.get(origin).intercept({ path: "/exchange", method: "POST" }).reply(() => success("recovered-session"));
    assert.equal((await exchangeUserSession(a, opts)).affineSession, "recovered-session");
  });
  for (const status of [301, 302, 303, 307, 308]) {
    for (const target of [origin, foreign]) {
      await check(`${status} redirect to ${target === origin ? "same" : "foreign"} origin sends no second request`, async () => {
        mock.get(origin).intercept({ path: "/exchange", method: "POST" }).reply(status, "", {
          headers: { location: `${target}/redirect-${status}` },
        });
        let followed = false;
        // Persistent fixture avoids leftover unconsumed one-shot expectations;
        // the counter detects either GET conversion or a forwarded POST body.
        mock.get(target).intercept({ path: `/redirect-${status}`, method: /GET|POST/ }).reply(() => {
          followed = true;
          return success("must-never-return");
        }).persist();
        await assert.rejects(exchangeUserSession(a, opts), TokenExchangeError);
        assert.equal(followed, false, "redirect received a credential-bearing request");
      });
    }
  }
  for (const status of [200, 403]) {
    await check(`${status} response body stays under the exchange deadline and permits retry`, async () => {
      mock.get(origin).intercept({ path: "/exchange", method: "POST" }).reply(status, "", {
        headers: { "content-type": "application/json" },
      });
      const setTimer = globalThis.setTimeout;
      const clearTimer = globalThis.clearTimeout;
      const marker = {};
      let deadline;
      let cleared = false;
      let headersReceived = false;
      // Capture the existing 30s deadline instead of spending 30s per fixture.
      // The real fetch receives headers, but the dispatcher never finishes its
      // response body. Aborting must cancel that read and release the cache.
      globalThis.setTimeout = (callback, ms, ...args) => {
        if (ms === 30_000) { deadline = callback; return marker; }
        return setTimer(callback, ms, ...args);
      };
      globalThis.clearTimeout = (timer) => {
        if (timer === marker) cleared = true;
        else clearTimer(timer);
      };
      setGlobalDispatcher(mock.compose((dispatch) => (input, handler) => dispatch(input, {
        ...handler,
        onResponseStart(...args) { headersReceived = true; handler.onResponseStart(...args); },
        onResponseEnd() { /* Keep the real fetch's body pending until abort. */ },
      })));
      const pending = exchangeUserSession(a, opts);
      // Attach before firing the deadline to avoid an unhandled rejection.
      const outcome = pending.then((value) => ({ value }), (error) => ({ error }));
      try {
        await new Promise(setImmediate);
        assert.equal(headersReceived, true);
        assert.equal(typeof deadline, "function");
        assert.equal(cleared, false, "deadline cleared after headers, before body completion");
        deadline();
        const { error } = await outcome;
        assert.ok(error instanceof TokenExchangeError);
        assert.match(error.message, /timed out after 30s/);
      } finally {
        // Also clean up the intentionally broken baseline's pending request.
        deadline?.();
        await outcome;
        globalThis.setTimeout = setTimer;
        globalThis.clearTimeout = clearTimer;
        setGlobalDispatcher(mock);
      }
      mock.get(origin).intercept({ path: "/exchange", method: "POST" }).reply(() => success("recovered-after-timeout"));
      assert.equal((await exchangeUserSession(a, opts)).affineSession, "recovered-after-timeout");
    });
  }
} finally {
  setGlobalDispatcher(original);
  await mock.close();
  _clearSessionCache();
}
console.log(`${passed} passed; ${failed} failed`);
process.exitCode = failed ? 1 : 0;
