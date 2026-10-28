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
import { verifyIdToken } from "./id-token.js";
import { mapGrantError } from "./login.js";
import type { ProviderContext } from "./provider.js";
import { nowSeconds, type SessionData } from "./session.js";

/** Refresh this many seconds before the access token expires. */
export const REFRESH_WINDOW = 60;
/** How long a refresh result is reused for the old refresh token (milliseconds). */
const GRACE_MS = 30_000;
/** Fallback access token lifetime when the provider sends no `expires_in`. */
const DEFAULT_EXPIRES_IN = 300;

/** Outcome of a refresh: new session data, or `ended` when the provider rejected the grant. */
export type RefreshOutcome = { kind: "refreshed"; session: SessionData } | { kind: "ended" };

/** Whether `data` should be refreshed now. */
export function needsRefresh(data: SessionData, now = nowSeconds()): boolean {
  return data.refreshToken !== undefined && data.accessTokenExpiresAt - now <= REFRESH_WINDOW;
}

/** Performs one refresh and checks the new ID token (no `nonce`, same `sub`). */
async function doRefresh(ctx: ProviderContext, clientId: string, data: SessionData): Promise<RefreshOutcome> {
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
  if (typeof tokens.id_token === "string") {
    const fresh = await verifyIdToken(ctx, clientId, tokens.id_token, tokens.access_token, null);
    if (fresh.sub !== data.claims.sub) throw new AuthError("wrong_subject", "refreshed ID token names another user");
    // Keep how and when the user authenticated; take updated profile claims.
    claims = { ...fresh, sid: data.claims.sid, acr: data.claims.acr, amr: data.claims.amr, authTime: data.claims.authTime };
  }
  const now = nowSeconds();
  return {
    kind: "refreshed",
    session: {
      ...data,
      claims,
      idToken: tokens.id_token ?? data.idToken,
      accessToken: tokens.access_token,
      accessTokenExpiresAt: now + (tokens.expires_in ?? DEFAULT_EXPIRES_IN),
      refreshToken: tokens.refresh_token ?? data.refreshToken,
      scope: tokens.scope ?? data.scope,
    },
  };
}

/** Creates a refresher with its own in-process de-duplication. */
export function createRefresher(ctxOf: () => Promise<ProviderContext>, clientId: string) {
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
    const promise = ctxOf().then((ctx) => doRefresh(ctx, clientId, data));
    // Until settled: shared; afterwards kept for the grace period, failures dropped at once.
    inflight.set(key, { promise, until: Number.POSITIVE_INFINITY });
    promise.then(
      () => inflight.set(key, { promise, until: Date.now() + GRACE_MS }),
      () => inflight.delete(key),
    );
    return promise;
  };
}

/** A refresh function as returned by {@link createRefresher}. */
export type Refresher = ReturnType<typeof createRefresher>;
