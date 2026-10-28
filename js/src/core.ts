/**
 * The framework-independent core: validated configuration, keys, provider
 * connection, refresher – and {@link loadSession}, the one place that
 * decides whether a request has a valid session (decryption, revocation
 * check, refresh).
 */

import { resolveConfig, type AuthOptions, type ResolvedConfig } from "./config.js";
import { cookieNames, MAX_SESSION_BYTES, type CookieNames, type CookieSink, type CookieSource } from "./cookies.js";
import { AuthError } from "./errors.js";
import type { LoginDeps } from "./login.js";
import { lazyProvider, type ProviderContext } from "./provider.js";
import { createRefresher, needsRefresh, type Refresher } from "./refresh.js";
import { deriveKeyRing, type KeyRing } from "./seal.js";
import { readSession, writeSession, type SessionData } from "./session.js";
import { isRevoked } from "./store.js";

/** Everything the handlers need. */
export interface Core {
  /** Validated configuration. */
  cfg: ResolvedConfig;
  /** Cookie names. */
  names: CookieNames;
  /** Key of the session cookie. */
  sessionKey: KeyRing;
  /** Key of the login state cookies. */
  loginKey: KeyRing;
  /** Provider connection (lazy, cached). */
  provider: () => Promise<ProviderContext>;
  /** Token refresh with de-duplication. */
  refresh: Refresher;
}

/** Builds the core; throws an `AuthError` (`config`) for invalid configuration. */
export async function createCore(options: AuthOptions): Promise<Core> {
  const cfg = resolveConfig(options);
  if (cfg.sessionStore === undefined) {
    cfg.logger.warn(
      "auth-next: no sessionStore configured – back-channel logouts cannot end sessions and are answered 501; " +
        "a session ends at its next token refresh or at the end of sessionMaxAge.",
    );
  }
  const provider = lazyProvider(cfg);
  return {
    cfg,
    names: cookieNames(cfg.cookieName, cfg.secureCookies),
    sessionKey: await deriveKeyRing(cfg.sessionSecret, cfg.previousSessionSecrets, "session"),
    loginKey: await deriveKeyRing(cfg.sessionSecret, cfg.previousSessionSecrets, "login"),
    provider,
    refresh: createRefresher(provider, cfg.clientId),
  };
}

/** Deletes the session cookies if a sink is available. */
async function drop(core: Core, source: CookieSource, sink: CookieSink | null): Promise<undefined> {
  if (sink !== null) await writeSession(sink, source, core.names.session, core.sessionKey, core.cfg.secureCookies, undefined);
  return undefined;
}

/**
 * Returns the valid session of a request, or `undefined`.
 *
 * `sinkFor` is asked for a cookie sink only when something must be written
 * (refresh, deletion). It returns `null` where cookies are read-only
 * (Server Components); then no refresh happens, because a rotated refresh
 * token that cannot be stored would end the session at the next refresh.
 * A failing store fails closed (no session).
 */
export async function loadSession(
  core: Core,
  source: CookieSource,
  sinkFor: () => CookieSink | null,
): Promise<SessionData | undefined> {
  const { cfg } = core;
  const data = await readSession(source, core.names.session, core.sessionKey);
  if (data === undefined) return undefined;
  if (cfg.sessionStore !== undefined) {
    let revoked: boolean;
    try {
      revoked = await isRevoked(cfg.sessionStore, { sub: data.claims.sub, sid: data.claims.sid, createdAt: data.createdAt });
    } catch {
      cfg.logger.warn("auth-next: sessionStore failed – treating the request as signed out.");
      return undefined;
    }
    if (revoked) return drop(core, source, sinkFor());
  }
  if (!needsRefresh(data)) return data;
  const sink = sinkFor();
  if (sink === null) return data;
  let outcome;
  try {
    outcome = await core.refresh(data);
  } catch (e) {
    // A token for another user or a forged token ends the session; anything else (provider
    // unreachable) keeps it, and the next request tries again.
    if (e instanceof AuthError && (e.code === "wrong_subject" || e.code === "invalid_token")) {
      cfg.logger.warn(`auth-next: refreshed tokens rejected (${e.code}) – signing out.`);
      return drop(core, source, sink);
    }
    cfg.logger.warn("auth-next: token refresh failed – keeping the session for now.");
    return data;
  }
  if (outcome.kind === "ended") return drop(core, source, sink);
  const written = await writeSession(sink, source, core.names.session, core.sessionKey, cfg.secureCookies, outcome.session);
  if (!written) {
    cfg.logger.warn(`auth-next: refreshed session exceeds ${MAX_SESSION_BYTES} bytes of cookies – signing out.`);
    return drop(core, source, sink);
  }
  return outcome.session;
}

/** Memoizes {@link createCore}; a configuration error is kept and raised on every use (fail closed). */
export function lazyCore(options: AuthOptions): () => Promise<Core> {
  let pending: Promise<Core> | undefined;
  return () => (pending ??= createCore(options));
}

/** What login and callback need (connects to the provider on first use). */
export async function loginDeps(core: Core): Promise<LoginDeps> {
  return { cfg: core.cfg, ctx: await core.provider(), names: core.names, loginKey: core.loginKey };
}
