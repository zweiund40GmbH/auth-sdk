import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Core } from "../src/core.js";
import { handleBackchannel, handleLogout, routeHandlers } from "../src/handlers.js";
import { memorySessionStore } from "../src/store.js";
import { APP, core, type Jar, warnings } from "./helpers.js";
import { MockProvider, type AuthorizeOptions } from "./mock-provider.js";
import { load as loadWith, signedIn as signedInWith } from "./session-helpers.js";

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
const load = (jar: Jar, target = c, writable = true) => loadWith(jar, target, writable);

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
