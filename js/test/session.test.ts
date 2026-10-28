import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { loadSession, type Core } from "../src/core.js";
import { headerSink, parseCookieHeader } from "../src/cookies.js";
import { handleBackchannel, handleLogout, routeHandlers } from "../src/handlers.js";
import { readSession, writeSession, type SessionData } from "../src/session.js";
import { memorySessionStore } from "../src/store.js";
import { APP, core, Jar, login, warnings } from "./helpers.js";
import { MockProvider, type AuthorizeOptions } from "./mock-provider.js";

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

/** Logs in and returns the jar plus its session data. */
async function signedIn(target = c, who: AuthorizeOptions = {}): Promise<{ jar: Jar; data: SessionData }> {
  const jar = new Jar();
  await login(target, provider, jar, who);
  const data = await readSession(parseCookieHeader(jar.header()), target.names.session, target.sessionKey);
  if (data === undefined) throw new Error("no session");
  return { jar, data };
}

/** Rewrites the session cookie of `jar` with the access token expiring now. */
async function expireAccessToken(jar: Jar, data: SessionData, target = c): Promise<void> {
  const sink = headerSink();
  const expired = { ...data, accessTokenExpiresAt: Math.floor(Date.now() / 1000) + 5 };
  await writeSession(sink, parseCookieHeader(jar.header()), target.names.session, target.sessionKey, false, expired);
  jar.apply(new Response(null, { headers: sink.headers.map((h) => ["set-cookie", h] as [string, string]) }));
}

/** Loads the session of `jar` with a writable sink; applies the written cookies. */
async function load(jar: Jar, target = c, writable = true) {
  const sink = headerSink();
  const data = await loadSession(target, parseCookieHeader(jar.header()), () => (writable ? sink : null));
  jar.apply(new Response(null, { headers: sink.headers.map((h) => ["set-cookie", h] as [string, string]) }));
  return data;
}

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

describe("back-channel logout", () => {
  /** POSTs a logout token. */
  const post = (token: string, type = "application/x-www-form-urlencoded") =>
    handleBackchannel(
      c,
      new Request(`${APP}/auth/backchannel-logout`, {
        method: "POST",
        headers: { "content-type": type },
        body: new URLSearchParams({ logout_token: token }).toString(),
      }),
    );

  it("ends only the sessions of the sid, or all of the sub", async () => {
    const a = await signedIn(c, { sub: "user-1", sid: "sid-a" });
    const b = await signedIn(c, { sub: "user-1", sid: "sid-b" });
    const d = await signedIn(c, { sub: "user-2", sid: "sid-d" });
    const res = await post(await provider.logoutToken({ sid: "sid-a", sub: "user-1" }));
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await load(a.jar)).toBeUndefined();
    expect(await load(b.jar)).toBeDefined();
    expect(await load(d.jar)).toBeDefined();
    expect((await post(await provider.logoutToken({ sid: undefined, sub: "user-2" }))).status).toBe(200);
    expect(await load(d.jar)).toBeUndefined();
    expect(await load(b.jar)).toBeDefined();
  });

  it("does not end a session created after the logout", async () => {
    await post(await provider.logoutToken({ sid: "sid-n", sub: "user-n" }));
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 2000);
      const again = await signedIn(c, { sub: "user-n", sid: "sid-n" });
      expect(await load(again.jar)).toBeDefined();
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects a replayed logout token", async () => {
    const token = await provider.logoutToken({ sid: "sid-r" });
    expect((await post(token)).status).toBe(200);
    expect((await post(token)).status).toBe(400);
  });

  it("answers 501 without a store, and warns at startup and per logout", async () => {
    warnings.length = 0;
    const noStore = await core(provider);
    expect(warnings.join()).toContain("no sessionStore");
    const s = await signedIn(noStore, { sid: "sid-x" });
    const res = await handleBackchannel(
      noStore,
      new Request(`${APP}/auth/backchannel-logout`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ logout_token: await provider.logoutToken({ sid: "sid-x" }) }).toString(),
      }),
    );
    expect(res.status).toBe(501);
    expect(warnings.join()).toContain("NOT ended");
    expect(await load(s.jar, noStore)).toBeDefined();
    expect(warnings.join()).not.toMatch(/eyJ/);
  });

  it.each([
    ["typ JWT", async () => provider.logoutToken({}, "JWT")],
    ["with nonce", async () => provider.logoutToken({ nonce: "n" })],
    ["without event", async () => provider.logoutToken({ events: {} })],
    ["without sub and sid", async () => provider.logoutToken({ sub: undefined, sid: undefined })],
    ["without jti", async () => provider.logoutToken({ jti: undefined })],
    ["foreign audience", async () => provider.logoutToken({ aud: "other-app" })],
    ["expired", async () => provider.logoutToken({ exp: Math.floor(Date.now() / 1000) - 3600 })],
  ])("rejects a logout token %s with 400", async (_n, make) => {
    const res = await post(await make());
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_request" });
  });

  it("rejects a wrong content type, a missing or repeated token and an oversized body", async () => {
    const token = await provider.logoutToken();
    expect((await post(token, "application/json")).status).toBe(400);
    const req = (body: string) =>
      handleBackchannel(
        c,
        new Request(`${APP}/auth/backchannel-logout`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body,
        }),
      );
    expect((await req("")).status).toBe(400);
    expect((await req(`logout_token=${token}&logout_token=${token}`)).status).toBe(400);
    expect((await req(`logout_token=${token}&x=${"a".repeat(17 * 1024)}`)).status).toBe(400);
  });
});

describe("logout", () => {
  it("deletes the session and redirects to the end-session endpoint with id_token_hint", async () => {
    const { jar, data } = await signedIn();
    const res = jar.apply(await handleLogout(c, jar.request("/auth/logout", { method: "POST", headers: { origin: APP } })));
    expect(res.status).toBe(303);
    const url = new URL(res.headers.get("location") ?? "");
    expect(url.origin + url.pathname).toBe(`${provider.issuer}/oauth2/logout`);
    expect(url.searchParams.get("id_token_hint")).toBe(data.idToken);
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(`${APP}/`);
    expect(url.searchParams.get("client_id")).toBe("my-app");
    expect(jar.cookies.size).toBe(0);
  });

  it("refuses cross-site logout requests and GET", async () => {
    const { jar } = await signedIn();
    const cross = await handleLogout(c, jar.request("/auth/logout", { method: "POST", headers: { origin: "https://evil.example" } }));
    expect(cross.status).toBe(403);
    expect(cross.headers.getSetCookie()).toEqual([]);
    const fetchSite = await handleLogout(c, jar.request("/auth/logout", { method: "POST", headers: { "sec-fetch-site": "cross-site" } }));
    expect(fetchSite.status).toBe(403);
    expect((await handleLogout(c, jar.request("/auth/logout", { method: "POST" }))).status).toBe(403);
    const viaFetchSite = await handleLogout(c, jar.request("/auth/logout", { method: "POST", headers: { "sec-fetch-site": "same-origin" } }));
    expect(viaFetchSite.status).toBe(303);
    const handlers = routeHandlers(() => Promise.resolve(c));
    expect((await handlers.GET(jar.request("/auth/logout"))).status).toBe(405);
    expect((await handlers.GET(jar.request("/auth/unknown"))).status).toBe(404);
    expect((await handlers.POST(jar.request("/auth/login", { method: "POST" }))).status).toBe(404);
  });
});
