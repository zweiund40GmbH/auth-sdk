import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { handleCallback, handleLogin } from "../src/handlers.js";
import { readSession } from "../src/session.js";
import { parseCookieHeader } from "../src/cookies.js";
import type { Core } from "../src/core.js";
import { APP, core, Jar, login } from "./helpers.js";
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
  provider.discovery = {};
  c = await core(provider);
});

/** Starts a login and returns jar, authorize URL and response. */
async function start(path = "/auth/login") {
  const jar = new Jar();
  const res = jar.apply(await handleLogin(c, jar.request(path)));
  return { jar, res, url: new URL(res.headers.get("location") ?? "") };
}

/** Session of the jar, if any. */
function sessionOf(jar: Jar) {
  return readSession(parseCookieHeader(jar.header()), c.names.session, c.sessionKey);
}

describe("login start", () => {
  it("redirects with PKCE S256, state, nonce and the configured scopes", async () => {
    const { res, url, jar } = await start();
    expect(res.status).toBe(302);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(url.origin + url.pathname).toBe(`${provider.issuer}/oauth2/authorize`);
    const p = url.searchParams;
    expect(p.get("response_type")).toBe("code");
    expect(p.get("client_id")).toBe("my-app");
    expect(p.get("redirect_uri")).toBe(`${APP}/auth/callback`);
    expect(p.get("code_challenge_method")).toBe("S256");
    expect(p.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(p.get("state")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(p.get("nonce")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(p.get("scope")).toBe("openid profile email offline_access");
    const line = res.headers.getSetCookie()[0] ?? "";
    expect(line).toMatch(/^auth\.login\.[A-Za-z0-9_-]{16}=/);
    expect(line).toContain("HttpOnly");
    expect(line).toContain("SameSite=Lax");
    expect(line).toContain("Max-Age=600");
    // The cookie is encrypted: neither verifier nor nonce readable.
    expect([...jar.cookies.values()].join()).not.toContain(p.get("nonce"));
  });

  it("discards pending login states beyond the limit", async () => {
    const jar = new Jar();
    for (let i = 0; i < 3; i++) jar.apply(await handleLogin(c, jar.request("/auth/login")));
    expect(jar.cookies.size).toBe(3);
    jar.apply(await handleLogin(c, jar.request("/auth/login")));
    expect(jar.cookies.size).toBe(1);
  });

  it("answers 503 without leaking details when the provider is unreachable", async () => {
    const broken = await core(provider, { issuer: "http://127.0.0.1:9/" });
    const res = await handleLogin(broken, new Request(`${APP}/auth/login`));
    expect(res.status).toBe(503);
    expect(await res.text()).toContain("nicht möglich");
  });
});

describe("callback", () => {
  it("creates the session, deletes the login state and returns to a safe path", async () => {
    const jar = new Jar();
    const res = await login(c, provider, jar, {}, "/auth/login?returnTo=%2Fkonto%3Ftab%3D1");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`${APP}/konto?tab=1`);
    expect([...jar.cookies.keys()]).toEqual(["auth.session"]);
    const s = await sessionOf(jar);
    expect(s?.claims.sub).toBe("user-1");
    expect(s?.claims.sid).toBe("sid-1");
    expect(s?.claims.email).toBe("erika@example.com");
    expect(s?.refreshToken).toBeTypeOf("string");
  });

  it.each(["https://evil.example/", "//evil.example", "/\\evil.example", "javascript:alert(1)"])(
    "ignores unsafe returnTo %s",
    async (target) => {
      const res = await login(c, provider, new Jar(), {}, `/auth/login?returnTo=${encodeURIComponent(target)}`);
      expect(res.headers.get("location")).toBe(`${APP}/`);
    },
  );

  it("never uses the Host of the request for the redirect", async () => {
    const { jar, url } = await start();
    const cb = provider.authorize(url);
    const req = new Request(`http://internal.example:8080${cb.pathname}${cb.search}`, { headers: { cookie: jar.header() } });
    const res = await handleCallback(c, req);
    expect(res.headers.get("location")).toBe(`${APP}/`);
  });

  it("uses the login state only once", async () => {
    const { jar, url } = await start();
    const cb = provider.authorize(url);
    const saved = jar.header();
    const first = jar.apply(await handleCallback(c, jar.request(`${cb.pathname}${cb.search}`)));
    expect(first.headers.get("location")).toBe(`${APP}/`);
    // Replaying the callback with the old cookies: state cookie gone in the jar; with the saved
    // header the code is already redeemed – both fail.
    expect((await handleCallback(c, jar.request(`${cb.pathname}${cb.search}`))).status).toBe(400);
    const replay = new Request(`${APP}${cb.pathname}${cb.search}`, { headers: { cookie: saved } });
    expect((await handleCallback(c, replay)).status).toBe(400);
  });

  // [case, authorize options, error code the callback reports]
  const rejected: [string, AuthorizeOptions, string][] = [
    ["missing iss although announced", { iss: null }, "invalid_callback"],
    ["foreign iss", { iss: "https://login.example.com" }, "invalid_callback"],
    ["provider error", { error: "access_denied" }, "access_denied"],
    ["wrong nonce", { tweaks: { claims: { nonce: "other" } } }, "invalid_callback"],
    ["typ of an access token", { tweaks: { typ: "at+jwt" } }, "invalid_token"],
    ["typ of a logout token", { tweaks: { typ: "logout+jwt" } }, "invalid_token"],
    ["key not in the JWKS", { tweaks: { key: "foreign" } }, "invalid_token"],
    ["wrong audience", { tweaks: { claims: { aud: "other-app" } } }, "invalid_callback"],
    ["foreign azp", { tweaks: { claims: { azp: "other-app" } } }, "invalid_token"],
    ["at_hash mismatch", { tweaks: { claims: { at_hash: "AAAAAAAAAAAAAAAAAAAAAA" } } }, "invalid_token"],
    ["iat in the future", { tweaks: { claims: { iat: Math.floor(Date.now() / 1000) + 3600 } } }, "invalid_token"],
    ["no ID token", { tweaks: { noIdToken: true } }, "invalid_callback"],
  ];
  it.each(rejected)("rejects %s", async (_name, opts, code) => {
    const plain = new Jar();
    const res = await login(c, provider, plain, opts);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("fehlgeschlagen");
    expect(plain.cookies.size).toBe(0);
    const withPath = await core(provider, { errorPath: "/anmeldung" });
    const redirected = await login(withPath, provider, new Jar(), opts);
    expect(redirected.headers.get("location")).toBe(`${APP}/anmeldung?error=${code}`);
  });

  it("accepts ES256 ID tokens", async () => {
    const res = await login(c, provider, new Jar(), { tweaks: { key: "es" } });
    expect(res.status).toBe(302);
  });

  it("rejects a wrong state and a callback without login state", async () => {
    const { jar, url } = await start();
    const cb = provider.authorize(url);
    cb.searchParams.set("state", "x".repeat(43));
    expect((await handleCallback(c, jar.request(`${cb.pathname}${cb.search}`))).status).toBe(400);
    const dup = provider.authorize(url);
    dup.searchParams.append("state", "again");
    expect((await handleCallback(c, jar.request(`${dup.pathname}${dup.search}`))).status).toBe(400);
  });
});

describe("requirements", () => {
  const now = () => Math.floor(Date.now() / 1000);

  it("enforces max_age and prompt=login against auth_time", async () => {
    const step = (opts: Parameters<typeof handleLogin>[2], authorize: AuthorizeOptions) => async () => {
      const jar = new Jar();
      const s = jar.apply(await handleLogin(c, jar.request("/auth/login"), opts));
      const cb = provider.authorize(new URL(s.headers.get("location") ?? ""), authorize);
      return (await handleCallback(c, jar.request(`${cb.pathname}${cb.search}`))).status;
    };
    expect(await step({ maxAge: 60 }, { authTime: now() - 30 })()).toBe(302);
    expect(await step({ maxAge: 60 }, { authTime: now() - 3600 })()).toBe(400);
    expect(await step({ prompt: "login" }, { authTime: now() })()).toBe(302);
    expect(await step({ prompt: "login" }, { authTime: now() - 600 })()).toBe(400);
    expect(await step({ acrValues: ["urn:z40:mfa"] }, { acr: "urn:z40:mfa" })()).toBe(302);
    expect(await step({ acrValues: ["urn:z40:mfa"] }, { acr: "urn:z40:pwd" })()).toBe(400);
  });

  it("sends the requirements to the provider", async () => {
    const jar = new Jar();
    const res = await handleLogin(c, jar.request("/auth/login"), {
      prompt: "login",
      maxAge: 0,
      acrValues: ["urn:z40:mfa"],
      loginHint: "erika@example.com",
    });
    const p = new URL(res.headers.get("location") ?? "").searchParams;
    expect([p.get("prompt"), p.get("max_age"), p.get("acr_values"), p.get("login_hint")]).toEqual([
      "login",
      "0",
      "urn:z40:mfa",
      "erika@example.com",
    ]);
  });
});
