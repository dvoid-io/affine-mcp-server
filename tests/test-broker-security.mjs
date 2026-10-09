#!/usr/bin/env node
// Socket-free adversarial tests of the real JOSE broker verifier and discovery.
// Uses generated signing keys and an in-process HTTP response seam, never credentials.
// Run after npm run build: node tests/test-broker-security.mjs
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignJWT, exportJWK, exportSPKI, generateKeyPair } from "jose";
import { verifyBrokerToken } from "../dist/broker.js";
import { verifyOAuthAccessToken } from "../dist/oauth.js";

// Config captures its file path at module load. Point it at an empty disposable
// directory so these environment-to-verifier cases never read a user's config.
const configDir = mkdtempSync(join(tmpdir(), "affine-broker-config-"));
const originalConfigHome = process.env.XDG_CONFIG_HOME;
let loadConfig;
try {
  process.env.XDG_CONFIG_HOME = configDir;
  ({ loadConfig } = await import("../dist/config.js"));
} finally {
  if (originalConfigHome === undefined) delete process.env.XDG_CONFIG_HOME;
  else process.env.XDG_CONFIG_HOME = originalConfigHome;
  rmSync(configDir, { recursive: true, force: true });
}
function loadFixtureConfig(issuerUrl, mode) {
  const saved = Object.fromEntries(Object.entries(process.env).filter(([name]) => name.startsWith("AFFINE_")));
  for (const name of Object.keys(saved)) delete process.env[name];
  Object.assign(process.env, {
    AFFINE_MCP_AUTH_MODE: mode,
    AFFINE_BASE_URL: "https://affine.test/",
    AFFINE_MCP_PUBLIC_BASE_URL: "https://affine.test/",
    [mode === "broker" ? "AFFINE_BROKER_ISSUER_URL" : "AFFINE_OAUTH_ISSUER_URL"]: issuerUrl,
    AFFINE_BROKER_AUDIENCE: "affine-server-project",
  });
  try { return loadConfig(); }
  finally {
    for (const name of Object.keys(process.env)) if (name.startsWith("AFFINE_")) delete process.env[name];
    Object.assign(process.env, saved);
  }
}

const trusted = await generateKeyPair("RS256", { extractable: true });
const foreign = await generateKeyPair("RS256", { extractable: true });
const jwk = { ...await exportJWK(trusted.publicKey), kid: "trusted", alg: "RS256", use: "sig" };
const now = Math.floor(Date.now() / 1000);
const issuer = "https://issuer.test";
const audience = "affine-server-project";
const config = { issuerUrl: issuer, audience, serviceSubjects: ["service-enumerator"], clockSkewSeconds: 0 };
const base = { iss: issuer, aud: [audience], sub: "person-a", exp: now + 300, act: { iss: issuer, sub: "actor-org-a" } };
const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const mint = (payload, key = trusted.privateKey, header = {}) =>
  new SignJWT(payload).setProtectedHeader({ alg: "RS256", kid: "trusted", ...header }).sign(key);
let passed = 0;
let failed = 0;
async function check(name, fn) {
  try { await fn(); passed++; console.log(`ok ${name}`); }
  catch (err) { failed++; console.error(`FAIL ${name}: ${err.message}`); }
}
const verify = (token) => verifyBrokerToken(token, config, async () => trusted.publicKey);

await check("issuer config retains scheme/host/path normalization and explicit trailing slash", async () => {
  for (const [input, expected] of [
    [" HTTPS://ISSUER.TEST:443/old/../tenant/ ", "https://issuer.test/tenant/"],
    ["HTTPS://ISSUER.TEST:443", "https://issuer.test"],
  ]) {
    assert.equal(loadFixtureConfig(input, "broker").broker.issuerUrl, expected);
    assert.equal(loadFixtureConfig(input, "oauth").oauthIssuerUrl, expected);
  }
});
for (const mode of ["broker", "oauth"]) {
  for (const suffix of ["?tenant=foreign", "#foreign", "?", "#"]) {
    await check(`${mode} issuer config rejects ${suffix} before discovery`, async () => {
      assert.throws(() => loadFixtureConfig(`${issuer}/${suffix}`, mode), /Issuer URL must not contain a query or fragment/);
    });
  }
}

await check("authorized user: exact token/subject/actor preserved", async () => {
  const token = await mint(base);
  assert.deepEqual(await verify(token), {
    token, subject: "person-a", actor: "actor-org-a", isService: false, expiresAt: base.exp,
  });
});
await check("another authorized org actor remains accepted", async () => {
  const result = await verify(await mint({ ...base, sub: "person-b", act: { iss: issuer, sub: "actor-org-b" } }));
  assert.equal(result.subject, "person-b");
  assert.equal(result.actor, "actor-org-b");
});
await check("service subject uses only the configured subject match", async () => {
  const result = await verify(await mint({ ...base, sub: "service-enumerator" }));
  assert.equal(result.isService, true);
});
await check("audience string and multi-audience JWT remain supported", async () => {
  for (const aud of [audience, ["other-audience", audience]]) {
    assert.equal((await verify(await mint({ ...base, aud }))).subject, base.sub);
  }
});

const refused = [
  ["wrong issuer", { ...base, iss: "https://foreign.test" }],
  ["wrong server audience", { ...base, aud: ["other-server-project"] }],
  ["missing issuer", { ...base, iss: undefined }],
  ["missing audience", { ...base, aud: undefined }],
  ["missing expiry", { ...base, exp: undefined }],
  ["expired token", { ...base, exp: now - 60 }],
  ["string expiry", { ...base, exp: String(now + 300) }],
  ["not yet valid", { ...base, nbf: now + 60 }],
  ["missing subject", { ...base, sub: undefined }],
  ["numeric subject", { ...base, sub: 42 }],
  ["empty subject", { ...base, sub: "" }],
  ["blank subject", { ...base, sub: "   " }],
  ["missing actor", { ...base, act: undefined }],
  ["null actor", { ...base, act: null }],
  ["array actor", { ...base, act: [] }],
  ["string actor", { ...base, act: "actor-org-a" }],
  ["wrong actor issuer", { ...base, act: { iss: "https://foreign.test", sub: "actor-org-a" } }],
  ["missing actor issuer", { ...base, act: { sub: "actor-org-a" } }],
  ["missing actor subject", { ...base, act: { iss: issuer } }],
  ["numeric actor subject", { ...base, act: { iss: issuer, sub: 42 } }],
  ["empty actor subject", { ...base, act: { iss: issuer, sub: "" } }],
];
for (const [name, payload] of refused) {
  await check(`${name} refused`, async () => assert.rejects(verify(await mint(payload))));
}
await check("foreign signature under trusted kid refused", async () => {
  await assert.rejects(verify(await mint(base, foreign.privateKey)));
});
await check("alg none refused", async () => {
  await assert.rejects(verify(`${encode({ alg: "none" })}.${encode(base)}.`));
});
await check("HS256 with public key material refused", async () => {
  const message = `${encode({ alg: "HS256", kid: "trusted" })}.${encode(base)}`;
  const signature = createHmac("sha256", await exportSPKI(trusted.publicKey)).update(message).digest("base64url");
  await assert.rejects(verify(`${message}.${signature}`));
});
await check("unsupported critical header refused", async () => {
  const token = await mint(base);
  const [, body, signature] = token.split(".");
  await assert.rejects(verify(`${encode({ alg: "RS256", kid: "trusted", crit: ["unknown"], unknown: true })}.${body}.${signature}`));
});

// Preserve RFC 8693 semantics: a nested actor describes history, not an extra
// authorization principal. The current actor is the outer act. The estate's
// impersonation audit separately alerts on unexpected nested exchanges.
await check("nested actor history never replaces the current actor", async () => {
  const result = await verify(await mint({ ...base, act: {
    iss: issuer, sub: "actor-org-a", act: { iss: "https://historical.test", sub: "prior-actor" },
  } }));
  assert.equal(result.actor, "actor-org-a");
  assert.equal(result.subject, "person-a");
  assert.equal(result.isService, false);
});

// Exercise discovery without the getKey override. All fetches stay in process;
// JOSE still verifies the actual RSA signature against the returned public JWK.
const originalFetch = globalThis.fetch;
const calls = [];
const metadata = new Map();
globalThis.fetch = async (url) => {
  const value = String(url);
  calls.push(value);
  for (const [origin, doc] of metadata) {
    if (value === `${origin}/.well-known/oauth-authorization-server`) {
      return new Response(JSON.stringify({
        authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token`,
        response_types_supported: ["code"], ...doc,
      }), { headers: { "content-type": "application/json" } });
    }
  }
  if (value.endsWith("/keys")) {
    return new Response(JSON.stringify({ keys: [jwk] }), { headers: { "content-type": "application/json" } });
  }
  throw new Error("Unexpected fetch in socket-free test");
};
try {
  const legit = "https://legitimate.test";
  metadata.set(legit, { issuer: legit, jwks_uri: "https://keys.legitimate.test/keys" });
  await check("discovery permits a legitimate separate HTTPS JWKS host", async () => {
    const token = await mint({ ...base, iss: legit, act: { iss: legit, sub: "actor-org-a" } });
    assert.equal((await verifyBrokerToken(token, { ...config, issuerUrl: legit })).subject, "person-a");
  });
  for (const [name, configured, discovered] of [
    ["exact configured trailing slash", "https://trailing-issuer.test/", "https://trailing-issuer.test/"],
    ["configured slash with normalized metadata", "https://normalized-issuer.test/", "https://normalized-issuer.test"],
  ]) {
    metadata.set(new URL(configured).origin, { issuer: discovered, jwks_uri: `${new URL(configured).origin}/keys` });
    await check(`${name} remains valid for broker and OAuth`, async () => {
      const brokerConfig = loadFixtureConfig(configured, "broker");
      const oauthConfig = loadFixtureConfig(configured, "oauth");
      assert.equal(brokerConfig.broker.issuerUrl, configured);
      assert.equal(oauthConfig.oauthIssuerUrl, configured);
      assert.equal(oauthConfig.baseUrl, "https://affine.test", "ordinary base URL normalization is unchanged");
      assert.equal(oauthConfig.publicBaseUrl, "https://affine.test");
      const token = await mint({ ...base, iss: discovered, aud: [audience, "https://affine.test"], act: { iss: discovered, sub: "actor-org-a" } });
      assert.equal((await verifyBrokerToken(token, { ...brokerConfig.broker, clockSkewSeconds: 0 })).subject, "person-a");
      assert.equal((await verifyOAuthAccessToken(token, {
        issuerUrl: oauthConfig.oauthIssuerUrl, publicBaseUrl: oauthConfig.publicBaseUrl,
        scopes: oauthConfig.oauthScopes, clockSkewSeconds: 0,
      })).subject, "person-a");
    });
  }
  const confused = "https://configured.test";
  const attacker = "https://unconfigured.test";
  metadata.set(confused, { issuer: attacker, jwks_uri: `${attacker}/keys` });
  await check("discovery cannot replace the configured issuer", async () => {
    const before = calls.length;
    const token = await mint({ ...base, iss: attacker, act: { iss: attacker, sub: "actor-org-a" } });
    await assert.rejects(verifyBrokerToken(token, { ...config, issuerUrl: confused }), /issuer/i);
    assert.equal(calls.slice(before).includes(`${attacker}/keys`), false, "foreign JWKS was fetched");
  });
  const insecure = "https://secure-issuer.test";
  metadata.set(insecure, { issuer: insecure, jwks_uri: "http://insecure-keys.test/keys" });
  await check("HTTPS issuer cannot downgrade JWKS transport to public HTTP", async () => {
    const before = calls.length;
    const token = await mint({ ...base, iss: insecure, act: { iss: insecure, sub: "actor-org-a" } });
    await assert.rejects(verifyBrokerToken(token, { ...config, issuerUrl: insecure }), /HTTPS|jwks/i);
    assert.equal(calls.slice(before).includes("http://insecure-keys.test/keys"), false, "HTTP JWKS was fetched");
  });
  const localDowngrade = "https://another-secure-issuer.test";
  metadata.set(localDowngrade, { issuer: localDowngrade, jwks_uri: "http://127.0.0.1/keys" });
  await check("HTTPS issuer cannot redirect key custody to loopback HTTP", async () => {
    const before = calls.length;
    const token = await mint({ ...base, iss: localDowngrade, act: { iss: localDowngrade, sub: "actor-org-a" } });
    await assert.rejects(verifyBrokerToken(token, { ...config, issuerUrl: localDowngrade }), /HTTPS|jwks/i);
    assert.equal(calls.slice(before).includes("http://127.0.0.1/keys"), false);
  });
  const local = "http://127.0.0.1:12345";
  metadata.set(local, { issuer: local, jwks_uri: `${local}/keys` });
  await check("explicit local HTTP development remains supported", async () => {
    const token = await mint({ ...base, iss: local, act: { iss: local, sub: "actor-org-a" } });
    assert.equal((await verifyBrokerToken(token, { ...config, issuerUrl: local })).subject, "person-a");
  });
} finally {
  globalThis.fetch = originalFetch;
}

console.log(`${passed} passed; ${failed} failed`);
process.exitCode = failed ? 1 : 0;
