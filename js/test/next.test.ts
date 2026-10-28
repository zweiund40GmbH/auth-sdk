import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server.js";
import { createAuth, memorySessionStore, type Auth } from "../src/index.js";
import { headerSink, parseCookieHeader } from "../src/cookies.js";
import { createCore, type Core } from "../src/core.js";
import { readSession, writeSession } from "../src/session.js";
import { APP, Jar, login, options } from "./helpers.js";
import { MockProvider } from "./mock-provider.js";

/** The cookie store `next/headers` returns in the test; `readOnly` mimics a Server Component. */
const fakeStore = { jar: new Jar(), readOnly: false };

vi.mock("next/headers.js", () => ({
  cookies: () =>
    Promise.resolve({
      get: (n: string) => {
        const value = fakeStore.jar.cookies.get(n);
        return value === undefined ? undefined : { name: n, value };
      },
      getAll: () => [...fakeStore.jar.cookies].map(([name, value]) => ({ name, value })),
      set: (n: string, v: string, a: { maxAge: number }) => {
        if (fakeStore.readOnly) throw new Error("Cookies can only be modified in a Server Action or Route Handler.");
        if (a.maxAge === 0) fakeStore.jar.cookies.delete(n);
        else fakeStore.jar.cookies.set(n, v);
      },
    }),
}));

let provider: MockProvider;
let auth: Auth;
let c: Core;

beforeAll(async () => {
  provider = await new MockProvider().start();
});
afterAll(async () => {
  await provider.stop();
});
beforeEach(async () => {
  const store = memorySessionStore();
  auth = createAuth(options(provider, { sessionStore: store }));
  c = await createCore(options(provider, { sessionStore: store }));
  fakeStore.jar = new Jar();
  fakeStore.readOnly = false;
});

/** Signs the fake browser in; optionally lets the access token expire. */
async function signIn(expire = false): Promise<void> {
  await login(c, provider, fakeStore.jar);
  if (!expire) return;
  const source = parseCookieHeader(fakeStore.jar.header());
  const data = await readSession(source, c.names.session, c.sessionKey);
  if (data === undefined) throw new Error("no session");
  const sink = headerSink();
  await writeSession(sink, source, c.names.session, c.sessionKey, false, { ...data, accessTokenExpiresAt: 0 });
  fakeStore.jar.apply(new Response(null, { headers: sink.headers.map((h) => ["set-cookie", h] as [string, string]) }));
}

describe("getSession / getAccessToken", () => {
  it("returns null without a session", async () => {
    expect(await auth.getSession()).toBeNull();
    expect(await auth.getAccessToken()).toBeNull();
  });

  it("returns the user without any token", async () => {
    await signIn();
    const session = await auth.getSession();
    expect(session?.user).toEqual({ sub: "user-1", name: "Erika Mustermann", email: "erika@example.com", emailVerified: true });
    expect(session?.sid).toBe("sid-1");
    expect(JSON.stringify(session)).not.toMatch(/eyJ|token/i);
    expect(await auth.getAccessToken()).toMatch(/^[A-Za-z0-9_-]{32}$/);
  });

  it("refreshes where cookies are writable, not in Server Components", async () => {
    await signIn(true);
    fakeStore.readOnly = true;
    expect(await auth.getSession()).not.toBeNull();
    expect(await auth.getAccessToken()).toBeNull();
    fakeStore.readOnly = false;
    const token = await auth.getAccessToken();
    expect(token).not.toBeNull();
    expect(await auth.getAccessToken()).toBe(token);
  });

  it("withAuth answers 401 without a session", async () => {
    const handler = auth.withAuth((_req, _ctx: unknown, session) => Response.json({ sub: session.user.sub }));
    expect((await handler(new Request(`${APP}/api/x`), {})).status).toBe(401);
    await signIn();
    expect(await (await handler(new Request(`${APP}/api/x`), {})).json()).toEqual({ sub: "user-1" });
  });

  it("builds login URLs with a safe returnTo only", () => {
    expect(auth.loginUrl()).toBe("/auth/login");
    expect(auth.loginUrl("/konto?a=1")).toBe("/auth/login?returnTo=%2Fkonto%3Fa%3D1");
    expect(auth.loginUrl("https://evil.example")).toBe("/auth/login");
  });
});

describe("proxy", () => {
  /** A Next.js request with the fake browser's cookies. */
  const req = (path: string, method = "GET") =>
    new NextRequest(new URL(path, APP), { method, headers: { cookie: fakeStore.jar.header() } });

  it("redirects navigations to the login and answers 401 otherwise", async () => {
    const proxy = auth.proxy({ protect: ["/konto"] });
    const res = await proxy(req("/konto/daten?x=1"));
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe(`${APP}/auth/login?returnTo=%2Fkonto%2Fdaten%3Fx%3D1`);
    expect((await proxy(req("/konto", "POST"))).status).toBe(401);
    expect((await proxy(req("/kontoauszug"))).status).toBe(200);
    expect((await proxy(req("/auth/callback?code=x"))).status).toBe(200);
  });

  it("passes signed-in requests and forwards refreshed cookies", async () => {
    await signIn(true);
    const res = await auth.proxy()(req("/"));
    expect(res.status).toBe(200);
    const set = res.cookies.get(c.names.session);
    expect(set?.value).toBeTruthy();
    expect(set?.httpOnly).toBe(true);
    expect(set?.sameSite).toBe("lax");
    // Rendering of the same request sees the new cookie.
    expect(res.headers.get("x-middleware-request-cookie") ?? "").toContain(set?.value ?? "missing");
  });
});
