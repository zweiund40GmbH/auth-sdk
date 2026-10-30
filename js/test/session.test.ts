import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Core } from "../src/core.js";
import { parseCookieHeader } from "../src/cookies.js";
import { readSession, type SessionData } from "../src/session.js";
import { memorySessionStore } from "../src/store.js";
import { core, type Jar, warnings } from "./helpers.js";
import { MockProvider, type AuthorizeOptions } from "./mock-provider.js";
import { expireAccessToken as expireWith, load as loadWith, signedIn as signedInWith } from "./session-helpers.js";

let provider: MockProvider;
let c: Core;

beforeAll(async () => {
  provider = await new MockProvider().start();
});
afterAll(async () => {
  await provider.stop();
});
beforeEach(async () => {
  provider.refreshTweaks = {};
  provider.delayMs = 0;
  c = await core(provider, { sessionStore: memorySessionStore() });
});

/** Shorthands bound to this file's provider and core. */
const signedIn = (target = c, who: AuthorizeOptions = {}) => signedInWith(target, provider, who);
const expireAccessToken = (jar: Jar, data: SessionData, target = c) => expireWith(jar, data, target);
const load = (jar: Jar, target = c, writable = true) => loadWith(jar, target, writable);

describe("refresh", () => {
  it("leaves a fresh session alone", async () => {
    const { jar, data } = await signedIn();
    expect((await load(jar))?.accessToken).toBe(data.accessToken);
  });

  it("rotates tokens shortly before expiry and keeps the session", async () => {
    const { jar, data } = await signedIn();
    await expireAccessToken(jar, data);
    const refreshed = await load(jar);
    expect(refreshed?.accessToken).not.toBe(data.accessToken);
    expect(refreshed?.refreshToken).not.toBe(data.refreshToken);
    expect(refreshed?.claims.sub).toBe("user-1");
    expect(refreshed?.createdAt).toBe(data.createdAt);
    // The jar now holds the rotated tokens.
    expect((await load(jar))?.refreshToken).toBe(refreshed?.refreshToken);
  });

  it("does not refresh where cookies are read-only", async () => {
    const { jar, data } = await signedIn();
    await expireAccessToken(jar, data);
    const before = provider.calls["refresh_token"] ?? 0;
    expect((await load(jar, c, false))?.accessToken).toBe(data.accessToken);
    expect(provider.calls["refresh_token"] ?? 0).toBe(before);
  });

  it("shares one refresh between concurrent requests", async () => {
    const { jar, data } = await signedIn();
    await expireAccessToken(jar, data);
    provider.delayMs = 50;
    const before = provider.calls["refresh_token"] ?? 0;
    const results = await Promise.all([load(jar), load(jar), load(jar)]);
    expect(provider.calls["refresh_token"]).toBe(before + 1);
    expect(new Set(results.map((r) => r?.accessToken)).size).toBe(1);
  });

  it("ends the session when the provider rejects the refresh token", async () => {
    const { jar, data } = await signedIn();
    await expireAccessToken(jar, data);
    provider.revokeAll();
    expect(await load(jar)).toBeUndefined();
    expect(jar.cookies.has(c.names.session)).toBe(false);
  });

  it("ends the session when the refreshed ID token names another user", async () => {
    const { jar, data } = await signedIn();
    await expireAccessToken(jar, data);
    provider.refreshTweaks = { claims: { sub: "intruder" } };
    expect(await load(jar)).toBeUndefined();
    expect(warnings.some((w) => w.includes("wrong_subject"))).toBe(true);
  });

  it("ends the session when openid-client rejects the refreshed ID token", async () => {
    const { jar, data } = await signedIn();
    await expireAccessToken(jar, data);
    provider.refreshTweaks = { claims: { aud: "other-app" } };
    expect(await load(jar)).toBeUndefined();
  });

  it("rejects a nonce in the refreshed ID token", async () => {
    const { jar, data } = await signedIn();
    await expireAccessToken(jar, data);
    provider.refreshTweaks = { claims: { nonce: "n" } };
    expect(await load(jar)).toBeUndefined();
  });
});

describe("refresh with unreachable signing keys", () => {
  /** Answers the JWKS URL with `status` (until restored); everything else passes through. */
  function jwksDown(status: number) {
    const real = globalThis.fetch;
    return vi.spyOn(globalThis, "fetch").mockImplementation((input, init) =>
      String(input instanceof Request ? input.url : input).endsWith("/jwks.json")
        ? Promise.resolve(new Response("unavailable", { status }))
        : real(input, init),
    );
  }

  /** Signs in with `c`; a second core of the same app has not loaded the signing keys yet. */
  async function keysNotLoaded() {
    const { jar, data } = await signedIn();
    await expireAccessToken(jar, data);
    return { jar, data, fresh: await core(provider, { sessionStore: memorySessionStore() }) };
  }

  it.each([503, 500, 429])("keeps the new tokens on JWKS %i and catches the check up later", async (status) => {
    const { jar, data, fresh } = await keysNotLoaded();
    const spy = jwksDown(status);
    const kept = await load(jar, fresh);
    expect(kept?.refreshToken).not.toBe(data.refreshToken);
    expect(kept?.accessToken).not.toBe(data.accessToken);
    expect(kept?.pendingIdToken).toBeTypeOf("string");
    expect(kept?.idToken).toBe(data.idToken);
    const stored = await readSession(parseCookieHeader(jar.header()), fresh.names.session, fresh.sessionKey);
    expect(stored?.refreshToken).toBe(kept?.refreshToken);
    spy.mockRestore();

    // Keys are back (a new core: no back-off): the check is caught up without another refresh.
    const calls = provider.calls["refresh_token"];
    const settled = await load(jar, await core(provider, { sessionStore: memorySessionStore() }));
    expect(settled?.pendingIdToken).toBeUndefined();
    expect(settled?.idToken).not.toBe(data.idToken);
    expect(settled?.refreshToken).toBe(kept?.refreshToken);
    expect(provider.calls["refresh_token"]).toBe(calls);
  });

  it("does not hammer the keys while they are down", async () => {
    const { jar, fresh } = await keysNotLoaded();
    const spy = jwksDown(503);
    await load(jar, fresh);
    const calls = spy.mock.calls.length;
    expect((await load(jar, fresh))?.pendingIdToken).toBeTypeOf("string");
    expect(spy.mock.calls.length).toBe(calls);
    spy.mockRestore();
  });

  it("ends the session when the pending ID token turns out to name another user", async () => {
    const { jar, fresh } = await keysNotLoaded();
    provider.refreshTweaks = { claims: { sub: "intruder" } };
    const spy = jwksDown(503);
    expect((await load(jar, fresh))?.pendingIdToken).toBeTypeOf("string");
    spy.mockRestore();
    expect(await load(jar, await core(provider, { sessionStore: memorySessionStore() }))).toBeUndefined();
    expect(jar.cookies.has(c.names.session)).toBe(false);
  });
});

describe("refresh failures", () => {
  /** Replaces the answers of the token endpoint only. */
  function tokenEndpoint(answer: () => Promise<Response>) {
    const real = globalThis.fetch;
    return vi.spyOn(globalThis, "fetch").mockImplementation((input, init) =>
      String(input instanceof Request ? input.url : input).endsWith("/oauth2/token") ? answer() : real(input, init),
    );
  }
  const html = (status: number) => new Response("<html>Bad Gateway</html>", { status, headers: { "content-type": "text/html" } });
  const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
    Response.json(body, { status, headers });

  it.each([
    ["a timeout", () => Promise.reject(new DOMException("timed out", "TimeoutError"))],
    ["a network error", () => Promise.reject(new TypeError("fetch failed"))],
    ["502 with HTML", () => Promise.resolve(html(502))],
    ["503 with HTML", () => Promise.resolve(html(503))],
    ["503 with an OAuth body", () => Promise.resolve(json(503, { error: "temporarily_unavailable" }))],
    ["429 with invalid_grant", () => Promise.resolve(json(429, { error: "invalid_grant" }, { "retry-after": "5" }))],
    ["500 with invalid_grant", () => Promise.resolve(json(500, { error: "invalid_grant" }))],
  ])("keeps the session on %s and backs off", async (_name, answer) => {
    const { jar, data } = await signedIn();
    await expireAccessToken(jar, data);
    const cookie = jar.cookies.get(c.names.session);
    const spy = tokenEndpoint(answer);
    const kept = await load(jar);
    expect(kept?.accessToken).toBe(data.accessToken);
    expect(jar.cookies.get(c.names.session)).toBe(cookie);
    // Within the back-off the provider is not asked again.
    const calls = spy.mock.calls.length;
    await load(jar);
    expect(spy.mock.calls.length).toBe(calls);
    spy.mockRestore();
  });

  it("ends the session on 400 invalid_grant", async () => {
    const { jar, data } = await signedIn();
    await expireAccessToken(jar, data);
    const spy = tokenEndpoint(() => Promise.resolve(json(400, { error: "invalid_grant" })));
    expect(await load(jar)).toBeUndefined();
    expect(jar.cookies.has(c.names.session)).toBe(false);
    spy.mockRestore();
  });
});

describe("session cookie", () => {
  it("rejects a tampered cookie and expires with the session", async () => {
    const { jar } = await signedIn();
    const value = jar.cookies.get(c.names.session) ?? "";
    const tampered = `${value.slice(0, -4)}${value.endsWith("AAAA") ? "BBBB" : "AAAA"}`;
    jar.cookies.set(c.names.session, tampered);
    expect(await load(jar)).toBeUndefined();
    const fresh = await signedIn();
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 9 * 3600 * 1000);
      expect(await load(fresh.jar, c, false)).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("secret rotation", () => {
  it("keeps sessions of the previous secret and rewrites them with the new one", async () => {
    const before = await core(provider, { sessionSecret: "p".repeat(40) });
    const { jar, data } = await signedIn(before);
    const after = await core(provider, { sessionSecret: "n".repeat(40), previousSessionSecrets: ["p".repeat(40)] });
    expect((await load(jar, after))?.claims.sub).toBe("user-1");
    // A refresh writes the session with the new secret; the old secret alone no longer reads it.
    await expireAccessToken(jar, data, before);
    expect(await load(jar, after)).toBeDefined();
    expect(await load(jar, await core(provider, { sessionSecret: "n".repeat(40) }), false)).toBeDefined();
    expect(await load(jar, before, false)).toBeUndefined();
  });
});
