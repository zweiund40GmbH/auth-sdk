/**
 * `@zweiund40gmbh/auth-next`: OpenID Connect login for Next.js (App
 * Router) as a confidential server-side client. Tokens stay on the server
 * in an encrypted `HttpOnly` cookie; the browser never sees them.
 *
 * Also: a receiver for account events (`createEventsHandler`) and a client
 * of the management API (`createManagementClient`).
 *
 * Server-only: import this package only from route handlers, Server
 * Components, Server Actions, `proxy.ts`/`middleware.ts` and
 * `instrumentation.ts` – never from client components.
 */

import type { NextRequest, NextResponse } from "next/server.js";
import type { AuthOptions } from "./config.js";
import { lazyCore } from "./core.js";
import { handleLogin, loginPath, routeHandlers } from "./handlers.js";
import { getAccessToken, getSession, proxy, withAuth, type AuthedHandler, type ProxyOptions } from "./next.js";
import type { LoginOptions } from "./requirements.js";
import type { Session } from "./session.js";

export type { AuthOptions, Logger, TokenEndpointAuthMethod } from "./config.js";
export { AuthError, ManagementError, type AuthErrorCode } from "./errors.js";
export type { AccountEvent, SecurityEvent } from "./events.js";
export { createEventsHandler, type EventsHandlerOptions } from "./events-handler.js";
export {
  createManagementClient,
  type Link,
  type LinkReport,
  type ManagementClient,
  type ManagementOptions,
  type NewOnboarding,
  type Onboarding,
  type OnboardingStatus,
} from "./management.js";
export type { CaughtUpEvent, EventPage, EventsQuery } from "./catch-up.js";
export type { ServiceOptions } from "./service-config.js";
export type { LoginOptions } from "./requirements.js";
export type { Session } from "./session.js";
export { memorySessionStore, type SessionStore } from "./store.js";
export type { AuthedHandler, ProxyOptions } from "./next.js";
export { safeReturnTo } from "./url.js";

/** The API of one configured client, as returned by {@link createAuth}. */
export interface Auth {
  /** Route handlers for `app/<basePath>/[action]/route.ts`: `export const { GET, POST } = auth.handlers`. */
  handlers: {
    /** `login`, `callback`. */
    GET(request: Request): Promise<Response>;
    /** `logout`, `backchannel-logout`. */
    POST(request: Request): Promise<Response>;
  };
  /** Starts a login with options (step-up with `acrValues`, `maxAge`, `prompt`) from an own route handler. */
  login(request: Request, options?: LoginOptions): Promise<Response>;
  /** The session of the current request (Server Components, Route Handlers, Server Actions), or `null`. */
  getSession(): Promise<Session | null>;
  /** A valid access token for API calls from the server, or `null`. Never pass it to the browser. */
  getAccessToken(): Promise<string | null>;
  /** Wraps a route handler that requires a session (`401` otherwise). */
  withAuth<C>(handler: AuthedHandler<C>): (request: Request, context: C) => Promise<Response>;
  /** Proxy/middleware function: token refresh and path protection. */
  proxy(options?: ProxyOptions): (request: NextRequest) => Promise<NextResponse>;
  /** Path of the login handler with a safe (relative) `returnTo`. */
  loginUrl(returnTo?: string): string;
  /** Validates the configuration and connects to the provider; call it in `instrumentation.ts` to fail at startup. */
  validate(): Promise<void>;
}

/**
 * Creates the client. Options override the environment variables
 * (`AUTH_ISSUER`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`, `AUTH_REDIRECT_URI`,
 * `AUTH_POST_LOGOUT_REDIRECT_URI`, `AUTH_SESSION_SECRET`). The configuration
 * is read on first use (so `next build` works without secrets) and an
 * invalid one makes every call fail; {@link Auth.validate} checks it early.
 */
export function createAuth(options: AuthOptions = {}): Auth {
  const core = lazyCore(options);
  const basePath = (options.basePath ?? "/auth").replace(/\/+$/, "");
  return {
    handlers: routeHandlers(core),
    login: async (request, loginOptions) => handleLogin(await core(), request, loginOptions),
    getSession: async () => getSession(await core()),
    getAccessToken: async () => getAccessToken(await core()),
    withAuth: (handler) => withAuth(core, handler),
    proxy: (proxyOptions) => proxy(core, proxyOptions),
    loginUrl: (returnTo) => loginPath(basePath, returnTo),
    validate: async () => {
      await (await core()).provider();
    },
  };
}
