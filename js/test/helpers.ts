/**
 * Test helpers: a core configured against the mock provider, a tiny
 * browser cookie jar and a complete login round trip.
 */

import { createCore, type Core } from "../src/core.js";
import type { AuthOptions } from "../src/config.js";
import { handleCallback, handleLogin } from "../src/handlers.js";
import type { AuthorizeOptions, MockProvider } from "./mock-provider.js";
import { CLIENT_ID, CLIENT_SECRET } from "./mock-provider.js";

/** Origin of the test application. */
export const APP = "http://localhost:3000";
/** Session secret for tests (generated per run, never a real value). */
export const SECRET = crypto.randomUUID() + crypto.randomUUID();

/** Collected warnings of the core under test. */
export const warnings: string[] = [];

/** Options pointing at `provider`. */
export function options(provider: MockProvider, extra: AuthOptions = {}): AuthOptions {
  return {
    issuer: provider.issuer,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: `${APP}/auth/callback`,
    postLogoutRedirectUri: `${APP}/`,
    sessionSecret: SECRET,
    logger: { warn: (m) => warnings.push(m) },
    lookup: () => undefined,
    ...extra,
  };
}

/** A core pointing at `provider`. */
export function core(provider: MockProvider, extra: AuthOptions = {}): Promise<Core> {
  return createCore(options(provider, extra));
}

/** A browser cookie jar applying `Set-Cookie` headers. */
export class Jar {
  cookies = new Map<string, string>();

  /** Applies the `Set-Cookie` headers of `response`. */
  apply(response: Response): Response {
    for (const line of response.headers.getSetCookie()) {
      const [pair = "", ...attrs] = line.split("; ");
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq);
      if (attrs.includes("Max-Age=0")) this.cookies.delete(name);
      else this.cookies.set(name, pair.slice(eq + 1));
    }
    return response;
  }

  /** The `Cookie` header. */
  header(): string {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  /** A request to `path` on the app carrying the cookies. */
  request(path: string, init: RequestInit = {}): Request {
    const headers = new Headers(init.headers);
    headers.set("cookie", this.header());
    return new Request(new URL(path, APP), { ...init, headers });
  }
}

/** Runs login + authorize + callback; returns the callback response. */
export async function login(
  c: Core,
  provider: MockProvider,
  jar: Jar,
  authorize: AuthorizeOptions = {},
  path = "/auth/login",
): Promise<Response> {
  const start = jar.apply(await handleLogin(c, jar.request(path)));
  const callback = provider.authorize(new URL(start.headers.get("location") ?? ""), authorize);
  return jar.apply(await handleCallback(c, jar.request(`${callback.pathname}${callback.search}`)));
}
