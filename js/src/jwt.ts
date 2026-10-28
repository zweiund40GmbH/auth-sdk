/**
 * JWT verification for ID tokens and back-channel logout tokens (jose).
 *
 * Strict: the algorithm must be RS256 or ES256 **and** offered by the
 * provider (no `none`, no HMAC), the header must name a `kid` from the
 * provider's JWKS, the header `typ` must be the one of the token kind (`JWT`
 * for ID tokens, `logout+jwt` for logout tokens – one cannot stand in for
 * the other), `crit` headers are rejected, and `iss`, `aud`, `exp`, `nbf`,
 * `iat` are checked with {@link LEEWAY_SECONDS} of clock skew.
 */

import { base64url, decodeProtectedHeader, errors, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";
import { AuthError } from "./errors.js";
import { LEEWAY_SECONDS } from "./requirements.js";

/** Signature algorithms this package accepts at all. */
export const SUPPORTED_ALGS = ["RS256", "ES256"] as const;

/** Header `typ` of ID tokens. */
export const TYP_ID = "JWT";
/** Header `typ` of back-channel logout tokens. */
export const TYP_LOGOUT = "logout+jwt";

/** What a token must look like. */
export interface Expect {
  /** Header `typ`. */
  typ: string;
  /** Expected `iss` (exact). */
  issuer: string;
  /** Value that `aud` must contain. */
  audience: string;
  /** Accepted algorithms (subset of {@link SUPPORTED_ALGS}). */
  algs: readonly string[];
}

/** `typ` comparison per RFC 7515 §4.1.9: case-insensitive, `application/` optional. */
export function sameTyp(actual: string, expected: string): boolean {
  const strip = (s: string) => s.toLowerCase().replace(/^application\//, "");
  return strip(actual) === strip(expected);
}

/** Verifies `token` against `jwks` and returns its claims. */
export async function verifyJwt(token: string, jwks: JWTVerifyGetKey, expect: Expect): Promise<JWTPayload> {
  let header;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    throw new AuthError("invalid_token", "token is not a JWS");
  }
  if (typeof header.alg !== "string" || !expect.algs.includes(header.alg)) {
    throw new AuthError("invalid_token", "signature algorithm not allowed");
  }
  if (typeof header.typ !== "string" || !sameTyp(header.typ, expect.typ)) {
    throw new AuthError("invalid_token", "unexpected token type");
  }
  if (typeof header.kid !== "string" || header.kid === "") {
    throw new AuthError("invalid_token", "token has no kid");
  }
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, jwks, {
      algorithms: [...expect.algs],
      issuer: expect.issuer,
      audience: expect.audience,
      clockTolerance: LEEWAY_SECONDS,
      requiredClaims: ["exp", "iat", "iss", "aud"],
    }));
  } catch (e) {
    // Only jose's error code is kept: its errors carry the full claims (personal data) otherwise.
    const code = e instanceof errors.JOSEError ? ` (${e.code})` : "";
    throw new AuthError("invalid_token", `token verification failed${code}`);
  }
  checkIat(payload, Math.floor(Date.now() / 1000));
  return payload;
}

/** `iat` must be a number and not in the future beyond the leeway (jose does not check the latter). */
export function checkIat(claims: JWTPayload, now: number): void {
  if (typeof claims.iat !== "number" || claims.iat > now + LEEWAY_SECONDS) {
    throw new AuthError("invalid_token", "iat is missing or in the future");
  }
}

/** `at_hash` of an access token for RS256/ES256: left half of its SHA-256, base64url. */
export async function tokenHash(accessToken: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessToken)));
  return base64url.encode(digest.slice(0, 16));
}

/** Reads a non-empty string claim. */
export function stringClaim(claims: JWTPayload, name: string): string | undefined {
  const v = claims[name];
  return typeof v === "string" && v !== "" ? v : undefined;
}
