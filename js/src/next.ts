/**
 * Next.js glue: `getSession` / `getAccessToken` on top of `next/headers`,
 * a route handler wrapper and the proxy (middleware) that refreshes tokens
 * and protects paths.
 */

import { cookies } from "next/headers.js";
import { NextResponse, type NextRequest } from "next/server.js";
import { attributes, type CookieAttributes, type CookieSink, type CookieSource } from "./cookies.js";
import { loadSession, type Core } from "./core.js";
import { loginPath } from "./handlers.js";
import { nowSeconds, toSession, type Session, type SessionData } from "./session.js";

/** The cookie store of `next/headers`. */
type NextCookieStore = Awaited<ReturnType<typeof cookies>>;

/** Cookie source on a Next.js cookie store (request cookies or `next/headers`). */
function sourceOf(store: { get(name: string): { value: string } | undefined; getAll(): { name: string }[] }): CookieSource {
  return { get: (n) => store.get(n)?.value, names: () => store.getAll().map((c) => c.name) };
}

/**
 * A sink on `next/headers` if cookies are writable here (Route Handler,
 * Server Action), else `null` (Server Component, where `set` throws).
 * Probed by deleting a cookie that does not exist.
 */
function writableSink(store: NextCookieStore, core: Core): CookieSink | null {
  try {
    store.set(`${core.names.session}-probe`, "", attributes(core.cfg.secureCookies, 0));
  } catch {
    return null;
  }
  return {
    set: (n, v, a) => {
      store.set(n, v, a);
    },
  };
}

/** Loads the session data of the current request via `next/headers`. */
export async function currentSessionData(core: Core): Promise<SessionData | undefined> {
  const store = await cookies();
  return loadSession(core, sourceOf(store), () => writableSink(store, core));
}

/** The session of the current request, or `null`. */
export async function getSession(core: Core): Promise<Session | null> {
  const data = await currentSessionData(core);
  return data === undefined ? null : toSession(data);
}

/** The access token of the current request (refreshed if needed), or `null` if none is valid. */
export async function getAccessToken(core: Core): Promise<string | null> {
  const data = await currentSessionData(core);
  return data !== undefined && data.accessTokenExpiresAt > nowSeconds() ? data.accessToken : null;
}

/** A route handler that receives the session. */
export type AuthedHandler<C> = (request: Request, context: C, session: Session) => Response | Promise<Response>;

/** Wraps a route handler: `401` without a session, else calls `handler` with it. */
export function withAuth<C>(core: () => Promise<Core>, handler: AuthedHandler<C>) {
  return async (request: Request, context: C): Promise<Response> => {
    const session = await getSession(await core());
    if (session === null) {
      return Response.json({ error: "unauthenticated" }, { status: 401, headers: { "cache-control": "no-store" } });
    }
    return handler(request, context, session);
  };
}

/** Which paths the proxy protects. */
export interface ProxyOptions {
  /** Path prefixes (segment-wise) or a predicate. Default: every path. */
  protect?: string[] | ((pathname: string) => boolean);
}

/** Whether `pathname` is protected by `protect`. */
export function isProtected(pathname: string, protect: ProxyOptions["protect"]): boolean {
  if (protect === undefined) return true;
  if (typeof protect === "function") return protect(pathname);
  return protect.some((p) => {
    const prefix = p.replace(/\/+$/, "");
    return prefix === "" || pathname === prefix || pathname.startsWith(`${prefix}/`);
  });
}

/** One pending cookie change of the proxy. */
interface CookieChange {
  name: string;
  value: string;
  attrs: CookieAttributes;
}

/** Sets `changes` on the response. */
function withCookies(response: NextResponse, changes: CookieChange[]): NextResponse {
  for (const c of changes) response.cookies.set(c.name, c.value, c.attrs);
  return response;
}

/**
 * Proxy (`proxy.ts` in Next.js 16, `middleware.ts` before): refreshes
 * tokens before they expire, passes updated cookies on to the rendering
 * of the same request, and protects paths – navigation (`GET`/`HEAD`)
 * without a session is redirected to the login, anything else gets `401`.
 * The auth routes themselves are passed through untouched.
 */
export function proxy(core: () => Promise<Core>, options: ProxyOptions = {}) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const c = await core();
    const { pathname, search } = request.nextUrl;
    if (pathname.startsWith(`${c.cfg.basePath}/`)) return NextResponse.next();
    const changes: CookieChange[] = [];
    const sink: CookieSink = { set: (name, value, attrs) => changes.push({ name, value, attrs }) };
    const data = await loadSession(c, sourceOf(request.cookies), () => sink);
    if (data === undefined && isProtected(pathname, options.protect)) {
      if (request.method !== "GET" && request.method !== "HEAD") {
        const denied = NextResponse.json({ error: "unauthenticated" }, { status: 401, headers: { "cache-control": "no-store" } });
        return withCookies(denied, changes);
      }
      const target = new URL(loginPath(c.cfg.basePath, `${pathname}${search}`), c.cfg.appOrigin);
      return withCookies(NextResponse.redirect(target), changes);
    }
    if (changes.length === 0) return NextResponse.next();
    // Forward the new cookies to the rendering of this request; must happen before `next()`.
    for (const ch of changes) {
      if (ch.attrs.maxAge === 0) request.cookies.delete(ch.name);
      else request.cookies.set(ch.name, ch.value);
    }
    return withCookies(NextResponse.next({ request: { headers: request.headers } }), changes);
  };
}
