/**
 * Route handlers on plain `Request`/`Response` (usable as Next.js App
 * Router route handlers): login, callback, logout (RP-initiated) and
 * back-channel logout. Every redirect goes to the application's configured
 * origin – the `Host` header of the request is never used.
 */

import * as oidc from "openid-client";
import { backchannelResponse, logoutTokenFrom, verifyLogoutToken } from "./backchannel.js";
import { headerSink, MAX_SESSION_BYTES, parseCookieHeader } from "./cookies.js";
import { loginDeps, type Core } from "./core.js";
import { AuthError } from "./errors.js";
import { completeLogin, startLogin } from "./login.js";
import { nowSeconds, readSession, writeSession } from "./session.js";
import { LEEWAY_SECONDS, type LoginOptions } from "./requirements.js";
import { recordLogout } from "./store.js";
import { onOrigin, safeReturnTo } from "./url.js";

/** Headers of every redirect and page of the handlers. */
const NO_STORE = { "cache-control": "no-store", "referrer-policy": "no-referrer" };

/** A redirect to `location` with `cookies` set. */
function redirect(location: URL, cookies: string[], status = 302): Response {
  const headers = new Headers({ ...NO_STORE, location: location.href });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(null, { status, headers });
}

/** A short German plain-text page. */
function page(status: number, text: string, cookies: string[] = [], extra: Record<string, string> = {}): Response {
  const headers = new Headers({ ...NO_STORE, ...extra, "content-type": "text/plain; charset=utf-8" });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(text, { status, headers });
}

/** Starts a login with `options` (e.g. a step-up with `acrValues`); `returnTo` defaults to the query parameter. */
export async function handleLogin(core: Core, request: Request, options: LoginOptions = {}): Promise<Response> {
  const sink = headerSink();
  const query = new URL(request.url).searchParams;
  const returnTo = options.returnTo ?? query.get("returnTo") ?? "/";
  try {
    const url = await startLogin(await loginDeps(core), parseCookieHeader(request.headers.get("cookie")), sink, { ...options, returnTo });
    return redirect(url, sink.headers);
  } catch {
    core.cfg.logger.warn("auth-next: login could not be started (provider unreachable or misconfigured).");
    return page(503, "Die Anmeldung ist gerade nicht möglich. Bitte versuchen Sie es später erneut.");
  }
}

/** Error code for the error redirect: the provider's OAuth code if well-formed, else the package's code. */
function errorCode(e: unknown): string {
  if (!(e instanceof AuthError)) return "login_failed";
  if (e.oauthError !== undefined && /^[a-z_]{1,40}$/.test(e.oauthError)) return e.oauthError;
  return e.code;
}

/** Handles the callback: session cookie and redirect to `returnTo`, or the error page / error path. */
export async function handleCallback(core: Core, request: Request): Promise<Response> {
  const sink = headerSink();
  const source = parseCookieHeader(request.headers.get("cookie"));
  const { cfg, names, sessionKey } = core;
  try {
    const { session, returnTo } = await completeLogin(await loginDeps(core), source, sink, new URL(request.url).searchParams);
    if (!(await writeSession(sink, source, names.session, sessionKey, cfg.secureCookies, session))) {
      core.cfg.logger.warn(
        `auth-next: login rejected – the encrypted session exceeds ${MAX_SESSION_BYTES} bytes of cookies; ` +
          "request fewer scopes or let the provider issue smaller tokens.",
      );
      throw new AuthError("session_too_large", "session does not fit into the cookies");
    }
    return redirect(onOrigin(cfg.appOrigin, returnTo), sink.headers);
  } catch (e) {
    const code = errorCode(e);
    if (cfg.errorPath !== undefined) {
      const target = onOrigin(cfg.appOrigin, cfg.errorPath);
      target.searchParams.set("error", code);
      return redirect(target, sink.headers);
    }
    return page(400, "Die Anmeldung ist fehlgeschlagen. Bitte versuchen Sie es erneut.", sink.headers);
  }
}

/** Whether a POST comes from the application's own pages (`Origin` / `Sec-Fetch-Site`). */
function sameOrigin(request: Request, appOrigin: string): boolean {
  const origin = request.headers.get("origin");
  if (origin !== null) return origin === appOrigin;
  const site = request.headers.get("sec-fetch-site");
  return site === null || site === "same-origin";
}

/**
 * Logout (POST only, from a form of the application): deletes the session
 * cookie and redirects to the provider's end-session endpoint with
 * `id_token_hint` and the post-logout redirect URI.
 */
export async function handleLogout(core: Core, request: Request): Promise<Response> {
  const { cfg, names, sessionKey } = core;
  if (!sameOrigin(request, cfg.appOrigin)) return page(403, "Abmelden nur über die Anwendung möglich.");
  const source = parseCookieHeader(request.headers.get("cookie"));
  const sink = headerSink();
  const data = await readSession(source, names.session, sessionKey);
  await writeSession(sink, source, names.session, sessionKey, cfg.secureCookies, undefined);
  const fallback = cfg.postLogoutRedirectUri !== undefined ? new URL(cfg.postLogoutRedirectUri) : onOrigin(cfg.appOrigin, "/");
  try {
    const ctx = await core.provider();
    if (ctx.endSessionEndpoint === undefined) return redirect(fallback, sink.headers, 303);
    const params: Record<string, string> = {};
    if (data !== undefined) params["id_token_hint"] = data.idToken;
    if (cfg.postLogoutRedirectUri !== undefined) params["post_logout_redirect_uri"] = cfg.postLogoutRedirectUri;
    return redirect(oidc.buildEndSessionUrl(ctx.oidc, params), sink.headers, 303);
  } catch {
    // Provider unreachable: the local session is gone anyway.
    return redirect(fallback, sink.headers, 303);
  }
}

/** Back-channel logout: verifies the logout token and records the logout in the store. */
export async function handleBackchannel(core: Core, request: Request): Promise<Response> {
  const token = await logoutTokenFrom(request);
  if (token === undefined) return backchannelResponse(false);
  let event;
  try {
    event = await verifyLogoutToken(await core.provider(), core.cfg.clientId, token);
  } catch {
    return backchannelResponse(false);
  }
  const store = core.cfg.sessionStore;
  if (store === undefined) {
    // §2.8: 200 only for a successful logout – make the misconfiguration visible at the provider.
    core.cfg.logger.warn(
      "auth-next: back-channel logout received, but no sessionStore is configured – the session was NOT ended (answered 501).",
    );
    return new Response(null, { status: 501, headers: { "cache-control": "no-store" } });
  }
  let recorded: boolean;
  try {
    recorded = await recordLogout(store, event, nowSeconds(), core.cfg.sessionMaxAge, LEEWAY_SECONDS);
  } catch {
    core.cfg.logger.warn("auth-next: sessionStore failed while recording a back-channel logout.");
    return new Response(null, { status: 500, headers: { "cache-control": "no-store" } });
  }
  return backchannelResponse(recorded);
}

/** Route handlers for `app/<basePath>/[action]/route.ts`, dispatching on the last path segment. */
export function routeHandlers(core: () => Promise<Core>) {
  const action = (request: Request) => new URL(request.url).pathname.split("/").pop() ?? "";
  return {
    /** GET `login` and `callback`. */
    async GET(request: Request): Promise<Response> {
      const c = await core();
      switch (action(request)) {
        case "login":
          return handleLogin(c, request);
        case "callback":
          return handleCallback(c, request);
        case "logout":
          return page(405, "Abmelden bitte per Formular (POST).", [], { allow: "POST" });
        default:
          return page(404, "Nicht gefunden.");
      }
    },
    /** POST `logout` and `backchannel-logout`. */
    async POST(request: Request): Promise<Response> {
      const c = await core();
      switch (action(request)) {
        case "logout":
          return handleLogout(c, request);
        case "backchannel-logout":
          return handleBackchannel(c, request);
        default:
          return page(404, "Nicht gefunden.");
      }
    },
  };
}

/** Path of the login handler with a safe `returnTo`. */
export function loginPath(basePath: string, returnTo?: string): string {
  const target = safeReturnTo(returnTo);
  return target === "/" ? `${basePath}/login` : `${basePath}/login?returnTo=${encodeURIComponent(target)}`;
}
