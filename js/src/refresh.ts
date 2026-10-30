/**
 * Transparent token refresh. Refresh tokens rotate and a reused one makes
 * the provider revoke the whole family – so concurrent requests of the same
 * session must not each refresh. Within one process, refreshes of the same
 * token share one call, and the result is kept briefly for requests that
 * still carry the old cookie.
 */

import * as oidc from "openid-client";
import { base64url } from "jose";
import { AuthError } from "./errors.js";
import { verifyIdToken, type IdClaims } from "./id-token.js";
import { TokenCheckError } from "./jwt.js";
import { mapGrantError } from "./grant-errors.js";
import type { ProviderContext } from "./provider.js";
import { nowSeconds, type SessionData } from "./session.js";

/** Refresh this many seconds before the access token expires. */
export const REFRESH_WINDOW = 60;
/** How long a refresh result is reused for the old refresh token (milliseconds). */
const GRACE_MS = 30_000;
/** How long a transient failure is remembered before the next attempt (milliseconds). */
const BACKOFF_MS = 10_000;
/** Fallback access token lifetime when the provider sends no `expires_in`. */
const DEFAULT_EXPIRES_IN = 300;

/** Outcome of a refresh: new session data, or `ended` when the provider rejected the grant. */
export type RefreshOutcome = { kind: "refreshed"; session: SessionData } | { kind: "ended" };

/** Whether `data` should be refreshed now. */
export function needsRefresh(data: SessionData, now = nowSeconds()): boolean {
  return data.refreshToken !== undefined && data.accessTokenExpiresAt - now <= REFRESH_WINDOW;
}

/** Remembers for a few seconds that the signing keys were unreachable, so they are not hammered. */
export interface KeyBackoff {
  /** Starts the back-off. */
  block(): void;
  /** Whether a new attempt must wait. */
  blocked(): boolean;
}

/** Creates a {@link KeyBackoff} (shared by the refresher and the settler of one core). */
export function createKeyBackoff(): KeyBackoff {
  let until = 0;
  return { block: () => void (until = Date.now() + BACKOFF_MS), blocked: () => Date.now() < until };
}

/** Whether `e` says the signing keys could not be loaded: a passing disturbance, not a verdict on the token. */
function keysUnavailable(e: unknown): boolean {
  return e instanceof TokenCheckError && e.check === "keys_unavailable";
}

/**
 * Verifies the ID token of a refresh (no `nonce`, same `sub` as the session) and merges it into the claims of
 * `data`. Throws `wrong_subject` or `invalid_token` for a verdict, `keys_unavailable` errors for a passing failure.
 */
async function verifiedClaims(
  ctx: ProviderContext,
  clientId: string,
  data: SessionData,
  idToken: string,
  accessToken: string,
): Promise<IdClaims> {
  const fresh = await verifyIdToken(ctx, clientId, idToken, accessToken, null);
  if (fresh.sub !== data.claims.sub) throw new AuthError("wrong_subject", "refreshed ID token names another user");
  // Keep how and when the user authenticated; take updated profile claims.
  return { ...fresh, sid: data.claims.sid, acr: data.claims.acr, amr: data.claims.amr, authTime: data.claims.authTime };
}

/**
 * Performs one refresh. The rotated tokens are never dropped: if the new ID token cannot be checked because the
 * signing keys are unreachable, the session gets the new tokens and keeps the ID token as `pendingIdToken`
 * (see {@link createSettler}). A verdict against the token (other `sub`, bad signature) throws.
 */
async function doRefresh(ctx: ProviderContext, clientId: string, data: SessionData, backoff: KeyBackoff): Promise<RefreshOutcome> {
  let tokens: oidc.TokenEndpointResponse;
  try {
    tokens = await oidc.refreshTokenGrant(ctx.oidc, data.refreshToken ?? "");
  } catch (e) {
    const err = mapGrantError(e);
    if (err.code === "invalid_grant") return { kind: "ended" };
    // openid-client rejected the token response itself (e.g. ID token claims): not transient.
    if (err.code === "invalid_callback") throw new AuthError("invalid_token", "refresh response rejected");
    throw err;
  }
  let claims = data.claims;
  let idToken = data.idToken;
  let pendingIdToken: string | undefined;
  if (typeof tokens.id_token === "string") {
    try {
      claims = await verifiedClaims(ctx, clientId, data, tokens.id_token, tokens.access_token);
      idToken = tokens.id_token;
    } catch (e) {
      if (!keysUnavailable(e)) throw e;
      pendingIdToken = tokens.id_token;
      backoff.block();
    }
  }
  const now = nowSeconds();
  const { pendingIdToken: _old, ...rest } = data;
  return {
    kind: "refreshed",
    session: {
      ...rest,
      claims,
      idToken,
      ...(pendingIdToken === undefined ? {} : { pendingIdToken }),
      accessToken: tokens.access_token,
      accessTokenExpiresAt: now + (tokens.expires_in ?? DEFAULT_EXPIRES_IN),
      refreshToken: tokens.refresh_token ?? data.refreshToken,
      scope: tokens.scope ?? data.scope,
    },
  };
}

/**
 * Catches up the check of a `pendingIdToken` (left by a refresh while the signing keys were unreachable).
 * Resolves with the updated session data, or with `data` itself while the keys are still unreachable (the
 * attempt is not repeated for a few seconds). Throws `wrong_subject` or `invalid_token` when the token is
 * rejected for good; the caller ends the session then.
 */
export function createSettler(ctxOf: () => Promise<ProviderContext>, clientId: string, backoff: KeyBackoff) {
  return async function settle(data: SessionData): Promise<SessionData> {
    const pending = data.pendingIdToken;
    if (pending === undefined || backoff.blocked()) return data;
    try {
      const claims = await verifiedClaims(await ctxOf(), clientId, data, pending, data.accessToken);
      const { pendingIdToken: _done, ...rest } = data;
      return { ...rest, claims, idToken: pending };
    } catch (e) {
      // A failing provider connection (discovery) is as passing as unreachable keys.
      if (!keysUnavailable(e) && !(e instanceof AuthError && (e.code === "discovery" || e.code === "provider_error"))) throw e;
      backoff.block();
      return data;
    }
  };
}

/** A settle function as returned by {@link createSettler}. */
export type Settler = ReturnType<typeof createSettler>;

/** Creates a refresher with its own in-process de-duplication. */
export function createRefresher(ctxOf: () => Promise<ProviderContext>, clientId: string, backoff: KeyBackoff) {
  const inflight = new Map<string, { promise: Promise<RefreshOutcome>; until: number }>();

  /** Hash of the refresh token, so the map holds no token values as keys. */
  const keyOf = async (token: string) =>
    base64url.encode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))));

  /**
   * Refreshes `data` (which must have a refresh token). Concurrent and
   * recent calls with the same refresh token get the same outcome.
   * Throws an {@link AuthError} for transient failures (session unchanged).
   */
  return async function refresh(data: SessionData): Promise<RefreshOutcome> {
    if (data.refreshToken === undefined) throw new AuthError("invalid_grant", "no refresh token");
    const key = await keyOf(data.refreshToken);
    const now = Date.now();
    for (const [k, v] of inflight) if (v.until < now) inflight.delete(k);
    const hit = inflight.get(key);
    if (hit !== undefined) return hit.promise;
    const promise = ctxOf().then((ctx) => doRefresh(ctx, clientId, data, backoff));
    // Until settled: shared. Afterwards a result is kept for the grace period, a transient
    // failure for the back-off (no hammering of a provider that is down or rate-limiting),
    // any other failure is dropped at once.
    inflight.set(key, { promise, until: Number.POSITIVE_INFINITY });
    promise.then(
      () => inflight.set(key, { promise, until: Date.now() + GRACE_MS }),
      (e: unknown) => {
        if (e instanceof AuthError && e.code === "provider_error") inflight.set(key, { promise, until: Date.now() + BACKOFF_MS });
        else inflight.delete(key);
      },
    );
    return promise;
  };
}

/** A refresh function as returned by {@link createRefresher}. */
export type Refresher = ReturnType<typeof createRefresher>;
