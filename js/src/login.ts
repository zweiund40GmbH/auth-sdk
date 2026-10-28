/**
 * Login with Authorization Code + PKCE (S256), `state`, `nonce` and `iss`
 * (RFC 9207): start (authorize URL + encrypted login state cookie) and
 * callback (checks, code exchange, ID token verification, requirements).
 *
 * The login state lives in its own short-lived (10 minutes) encrypted
 * cookie per pending login, named after its `state`, so logins in several
 * tabs do not overwrite each other. It is deleted at the callback whatever
 * the outcome (single use).
 */

import * as oidc from "openid-client";
import type { ResolvedConfig } from "./config.js";
import { attributes, type CookieNames, type CookieSink, type CookieSource } from "./cookies.js";
import { AuthError } from "./errors.js";
import { mapGrantError } from "./grant-errors.js";
import { verifyIdToken } from "./id-token.js";
import type { ProviderContext } from "./provider.js";
import {
  authorizeParams,
  checkRequirements,
  requirementsFrom,
  type AuthRequirements,
  type LoginOptions,
} from "./requirements.js";
import { seal, unseal, type KeyRing } from "./seal.js";
import { nowSeconds, type SessionData } from "./session.js";
import { safeReturnTo } from "./url.js";

/** Lifetime of a login state in seconds. */
export const LOGIN_STATE_TTL = 600;
/** Pending logins kept per browser; starting one more discards all of them. */
const MAX_PENDING = 3;
/** Fallback access token lifetime when the provider sends no `expires_in`. */
const DEFAULT_EXPIRES_IN = 300;

/** What survives between redirect and callback (encrypted). */
interface LoginState {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
  req: AuthRequirements;
}

/** Keys and names the login needs. */
export interface LoginDeps {
  cfg: ResolvedConfig;
  ctx: ProviderContext;
  names: CookieNames;
  loginKey: KeyRing;
}

/** Name of the login state cookie for `state`. */
function loginCookie(names: CookieNames, state: string): string {
  return `${names.loginPrefix}${state.slice(0, 16)}`;
}

/** Starts a login: writes the login state cookie and returns the authorize URL. */
export async function startLogin(
  deps: LoginDeps,
  source: CookieSource,
  sink: CookieSink,
  options: LoginOptions,
): Promise<URL> {
  const { cfg, ctx, names } = deps;
  const pending = source.names().filter((n) => n.startsWith(names.loginPrefix));
  if (pending.length >= MAX_PENDING) {
    for (const n of pending) sink.set(n, "", attributes(cfg.secureCookies, 0));
  }
  const now = nowSeconds();
  const login: LoginState = {
    state: oidc.randomState(),
    nonce: oidc.randomNonce(),
    verifier: oidc.randomPKCECodeVerifier(),
    returnTo: safeReturnTo(options.returnTo),
    req: requirementsFrom(options, now),
  };
  const url = oidc.buildAuthorizationUrl(ctx.oidc, {
    ...authorizeParams(options),
    response_type: "code",
    redirect_uri: cfg.redirectUri,
    scope: cfg.scopes.join(" "),
    state: login.state,
    nonce: login.nonce,
    code_challenge: await oidc.calculatePKCECodeChallenge(login.verifier),
    code_challenge_method: "S256",
  });
  const sealed = await seal({ ...login }, deps.loginKey, "login", now + LOGIN_STATE_TTL);
  sink.set(loginCookie(names, login.state), sealed, attributes(cfg.secureCookies, LOGIN_STATE_TTL));
  return url;
}

/** Result of a successful callback. */
export interface CallbackResult {
  /** The new session. */
  session: SessionData;
  /** Where to send the browser (relative path). */
  returnTo: string;
}

/**
 * Handles the callback query `search` (`?code=…&state=…&iss=…`). Deletes
 * the login state cookie in every case.
 */
export async function completeLogin(
  deps: LoginDeps,
  source: CookieSource,
  sink: CookieSink,
  search: URLSearchParams,
): Promise<CallbackResult> {
  const { cfg, ctx, names } = deps;
  const states = search.getAll("state");
  const state = states[0];
  if (states.length !== 1 || state === undefined || state === "") {
    throw new AuthError("invalid_callback", "state missing or repeated");
  }
  const name = loginCookie(names, state);
  const raw = source.get(name);
  if (raw !== undefined) sink.set(name, "", attributes(cfg.secureCookies, 0));
  const login = raw === undefined ? undefined : ((await unseal(raw, deps.loginKey, "login")) as LoginState | undefined);
  if (login?.state === undefined) throw new AuthError("login_state_missing", "no login state for this callback");

  // The redirect URI as registered plus the received query – never the Host header of the request.
  const currentUrl = new URL(cfg.redirectUri);
  currentUrl.search = search.toString();
  let tokens: oidc.TokenEndpointResponse;
  try {
    tokens = await oidc.authorizationCodeGrant(ctx.oidc, currentUrl, {
      pkceCodeVerifier: login.verifier,
      expectedState: login.state,
      expectedNonce: login.nonce,
      idTokenExpected: true,
    });
  } catch (e) {
    throw mapGrantError(e);
  }
  if (typeof tokens.id_token !== "string") throw new AuthError("invalid_token", "no ID token");
  const claims = await verifyIdToken(ctx, cfg.clientId, tokens.id_token, tokens.access_token, login.nonce);
  const now = nowSeconds();
  checkRequirements(login.req, claims.authTime, claims.acr, now);
  const session: SessionData = {
    v: 1,
    claims,
    idToken: tokens.id_token,
    accessToken: tokens.access_token,
    accessTokenExpiresAt: now + (tokens.expires_in ?? DEFAULT_EXPIRES_IN),
    refreshToken: tokens.refresh_token,
    scope: tokens.scope ?? cfg.scopes.join(" "),
    createdAt: now,
    expiresAt: now + cfg.sessionMaxAge,
  };
  return { session, returnTo: safeReturnTo(login.returnTo) };
}
