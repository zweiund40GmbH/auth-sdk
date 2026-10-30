/**
 * Session test helpers: sign in against the mock provider, let the access
 * token expire, and load the session like a request would.
 */

import { loadSession, type Core } from "../src/core.js";
import { headerSink, parseCookieHeader } from "../src/cookies.js";
import { readSession, writeSession, type SessionData } from "../src/session.js";
import { Jar, login } from "./helpers.js";
import type { AuthorizeOptions, MockProvider } from "./mock-provider.js";

/** Applies collected `Set-Cookie` values to `jar`. */
function applyTo(jar: Jar, headers: string[]): void {
  jar.apply(new Response(null, { headers: headers.map((h) => ["set-cookie", h] as [string, string]) }));
}

/** Logs in and returns the jar plus its session data. */
export async function signedIn(
  target: Core,
  provider: MockProvider,
  who: AuthorizeOptions = {},
): Promise<{ jar: Jar; data: SessionData }> {
  const jar = new Jar();
  await login(target, provider, jar, who);
  const data = await readSession(parseCookieHeader(jar.header()), target.names.session, target.sessionKey);
  if (data === undefined) throw new Error("no session");
  return { jar, data };
}

/** Rewrites the session cookie of `jar` with `data`. */
export async function rewrite(jar: Jar, data: SessionData, target: Core): Promise<void> {
  const sink = headerSink();
  await writeSession(sink, parseCookieHeader(jar.header()), target.names.session, target.sessionKey, false, data);
  applyTo(jar, sink.headers);
}

/** Rewrites the session cookie of `jar` with the access token expiring now. */
export async function expireAccessToken(jar: Jar, data: SessionData, target: Core): Promise<void> {
  await rewrite(jar, { ...data, accessTokenExpiresAt: Math.floor(Date.now() / 1000) + 5 }, target);
}

/** Loads the session of `jar` (writable sink unless `writable` is false); applies the written cookies. */
export async function load(jar: Jar, target: Core, writable = true): Promise<SessionData | undefined> {
  const sink = headerSink();
  const data = await loadSession(target, parseCookieHeader(jar.header()), () => (writable ? sink : null));
  applyTo(jar, sink.headers);
  return data;
}
