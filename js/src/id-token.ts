/**
 * ID token checks on top of {@link verifyJwt} (OIDC Core §3.1.3.7):
 * non-empty `sub`, `azp`, `nonce` (expected at login, absent after a
 * refresh) and `at_hash`.
 */

import type { JWTPayload } from "jose";
import { AuthError } from "./errors.js";
import { stringClaim, tokenHash, TYP_ID, verifyJwt } from "./jwt.js";
import type { ProviderContext } from "./provider.js";

/** The ID token claims the package uses. */
export interface IdClaims {
  /** Stable user id; link local accounts with this, not with the e-mail address. */
  sub: string;
  /** SSO session id at this client (for back-channel logout). */
  sid: string | undefined;
  /** Authentication context, e.g. password only or with a second factor. */
  acr: string | undefined;
  /** Authentication methods (`pwd`, `otp`). */
  amr: string[];
  /** Time of the authentication (seconds since the epoch). */
  authTime: number | undefined;
  /** `production` or `test` application. */
  env: string | undefined;
  /** Scope `profile`: display name. */
  name: string | undefined;
  /** Scope `profile`: locale. */
  locale: string | undefined;
  /** Scope `email`: address. */
  email: string | undefined;
  /** Scope `email`: whether the address is verified. */
  emailVerified: boolean | undefined;
}

/** Checks the ID-token-specific rules. `nonce`: expected value, or `null` when none may be present. */
export async function checkIdClaims(
  raw: JWTPayload,
  clientId: string,
  nonce: string | null,
  accessToken: string,
): Promise<void> {
  if (stringClaim(raw, "sub") === undefined) throw new AuthError("invalid_token", "ID token has no sub");
  const several = Array.isArray(raw.aud) && raw.aud.length > 1;
  const azp = raw["azp"];
  if (azp !== undefined ? azp !== clientId : several) throw new AuthError("invalid_token", "wrong azp");
  const got = raw["nonce"];
  if (nonce === null ? got !== undefined : got !== nonce) throw new AuthError("invalid_token", "nonce mismatch");
  const atHash = raw["at_hash"];
  if (atHash !== undefined && atHash !== (await tokenHash(accessToken))) {
    throw new AuthError("invalid_token", "at_hash mismatch");
  }
}

/** Maps verified raw claims to {@link IdClaims}. */
export function toIdClaims(raw: JWTPayload): IdClaims {
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
  const amr = raw["amr"];
  const verified = raw["email_verified"];
  return {
    sub: raw.sub ?? "",
    sid: stringClaim(raw, "sid"),
    acr: stringClaim(raw, "acr"),
    amr: Array.isArray(amr) ? amr.filter((a): a is string => typeof a === "string") : [],
    authTime: num(raw["auth_time"]),
    env: stringClaim(raw, "env"),
    name: stringClaim(raw, "name"),
    locale: stringClaim(raw, "locale"),
    email: stringClaim(raw, "email"),
    emailVerified: typeof verified === "boolean" ? verified : undefined,
  };
}

/** Verifies an ID token completely (signature, `typ`, registered claims, then {@link checkIdClaims}). */
export async function verifyIdToken(
  ctx: ProviderContext,
  clientId: string,
  idToken: string,
  accessToken: string,
  nonce: string | null,
): Promise<IdClaims> {
  const raw = await verifyJwt(idToken, ctx.jwks, { typ: TYP_ID, issuer: ctx.issuer, audience: clientId, algs: ctx.algs });
  await checkIdClaims(raw, clientId, nonce, accessToken);
  return toIdClaims(raw);
}
