/**
 * Back-channel logout (OIDC Back-Channel Logout 1.0): the provider POSTs a
 * `logout_token` when an SSO session ends. The token is verified (§2.6) and
 * the logout recorded in the {@link SessionStore}; answers are `200` or
 * `400` (§2.8), never cached.
 */

import type { JWTPayload } from "jose";
import { AuthError } from "./errors.js";
import { stringClaim, TYP_LOGOUT, verifyJwt } from "./jwt.js";
import type { ProviderContext } from "./provider.js";

/** Event URI a logout token must carry in `events`. */
export const BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";
/** Largest accepted request body. */
export const MAX_BODY_BYTES = 16 * 1024;

/** What a verified logout token asks for; at least one of `sub` and `sid` is set. */
export interface LogoutEvent {
  /** The user whose session ended. */
  sub: string | undefined;
  /** The SSO session id (as in the ID token at login); with it, only that session ends. */
  sid: string | undefined;
  /** Token id (remembered until `exp` to reject replays). */
  jti: string;
  /** Issue time of the token (seconds since the epoch). */
  iat: number;
  /** Expiry of the token (seconds since the epoch). */
  exp: number;
}

/** The logout-token-specific rules on top of {@link verifyJwt} (§2.6 steps 3–5). */
export function logoutEvent(raw: JWTPayload): LogoutEvent {
  const events = raw["events"];
  const event =
    typeof events === "object" && events !== null && !Array.isArray(events)
      ? (events as Record<string, unknown>)[BACKCHANNEL_LOGOUT_EVENT]
      : undefined;
  if (typeof event !== "object" || event === null || Array.isArray(event)) {
    throw new AuthError("invalid_token", "logout event missing");
  }
  if (raw["nonce"] !== undefined) throw new AuthError("invalid_token", "logout token must not have a nonce");
  const jti = stringClaim(raw, "jti");
  if (jti === undefined) throw new AuthError("invalid_token", "logout token has no jti");
  const sub = stringClaim(raw, "sub");
  const sid = stringClaim(raw, "sid");
  if (sub === undefined && sid === undefined) throw new AuthError("invalid_token", "logout token has neither sub nor sid");
  // verifyJwt requires both; the fallback only satisfies the type checker.
  return { sub, sid, jti, iat: raw.iat ?? 0, exp: raw.exp ?? 0 };
}

/** Verifies a logout token (signature, `typ: logout+jwt`, `iss`, `aud`, `iat`, `exp`, then {@link logoutEvent}). */
export async function verifyLogoutToken(ctx: ProviderContext, clientId: string, token: string): Promise<LogoutEvent> {
  const raw = await verifyJwt(token, ctx.jwks, { typ: TYP_LOGOUT, issuer: ctx.issuer, audience: clientId, algs: ctx.algs });
  return logoutEvent(raw);
}

/** Reads at most `max` bytes of the body; `undefined` if it is larger. */
export async function readLimited(request: Request, max: number): Promise<string | undefined> {
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > max) return undefined;
  if (request.body === null) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      return undefined;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let offset = 0;
  for (const c of chunks) {
    all.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(all);
}

/**
 * Extracts exactly one non-empty `logout_token` from a form POST;
 * `undefined` for a wrong content type, an oversized body or a missing or
 * repeated parameter.
 */
export async function logoutTokenFrom(request: Request): Promise<string | undefined> {
  const type = (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (type !== "application/x-www-form-urlencoded") return undefined;
  const body = await readLimited(request, MAX_BODY_BYTES);
  if (body === undefined) return undefined;
  const values = new URLSearchParams(body).getAll("logout_token");
  return values.length === 1 && values[0] !== "" ? values[0] : undefined;
}

/** JSON answer of the back-channel endpoint. */
export function backchannelResponse(ok: boolean): Response {
  const headers = { "cache-control": "no-store", "content-type": "application/json" };
  return ok
    ? new Response(null, { status: 200, headers: { "cache-control": "no-store" } })
    : new Response(JSON.stringify({ error: "invalid_request" }), { status: 400, headers });
}
