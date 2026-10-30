/**
 * JWT verification for ID tokens, back-channel logout tokens and Security Event Tokens (jose).
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
/** Header `typ` of Security Event Tokens (RFC 8417 §2.3). */
export const TYP_SECEVENT = "secevent+jwt";

/**
 * Which check rejected a token, for answers that must tell the sender
 * (RFC 8935): `issuer`, `audience`, `key` (unknown key, signature,
 * algorithm), `keys_unavailable` (JWKS not loadable) or `other`.
 */
export type TokenCheck = "issuer" | "audience" | "key" | "keys_unavailable" | "other";

/** An `invalid_token` error that names the failed {@link TokenCheck} (internal, not exported by the package). */
export class TokenCheckError extends AuthError {
  /** The failed check. */
  readonly check: TokenCheck;

  /** Creates the error; `message` must not contain token values. */
  constructor(check: TokenCheck, message: string) {
    super("invalid_token", message);
    this.check = check;
  }
}

/** Classifies a failure of jose's `jwtVerify`. */
export function classify(e: unknown): TokenCheck {
  if (e instanceof errors.JWTClaimValidationFailed) {
    return e.claim === "iss" ? "issuer" : e.claim === "aud" ? "audience" : "other";
  }
  if (
    e instanceof errors.JWKSNoMatchingKey ||
    e instanceof errors.JWSSignatureVerificationFailed ||
    e instanceof errors.JOSEAlgNotAllowed
  ) {
    return "key";
  }
  // Network failures (no JOSEError), timeouts, unusable JWKS and non-200 JWKS answers (generic JOSEError).
  if (
    !(e instanceof errors.JOSEError) ||
    e instanceof errors.JWKSTimeout ||
    e instanceof errors.JWKSInvalid ||
    e.code === "ERR_JOSE_GENERIC"
  ) {
    return "keys_unavailable";
  }
  return "other";
}

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

/**
 * Verifies `token` against `jwks` and returns its claims. `at` (seconds since the epoch, default now): the time
 * `exp`, `nbf` and `iat` are judged at – for a check caught up later, the time the token was received.
 */
export async function verifyJwt(
  token: string,
  jwks: JWTVerifyGetKey,
  expect: Expect,
  at = Math.floor(Date.now() / 1000),
): Promise<JWTPayload> {
  let header;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    throw new TokenCheckError("other", "token is not a JWS");
  }
  if (typeof header.alg !== "string" || !expect.algs.includes(header.alg)) {
    throw new TokenCheckError("key", "signature algorithm not allowed");
  }
  if (typeof header.typ !== "string" || !sameTyp(header.typ, expect.typ)) {
    throw new TokenCheckError("other", "unexpected token type");
  }
  if (typeof header.kid !== "string" || header.kid === "") {
    throw new TokenCheckError("key", "token has no kid");
  }
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, jwks, {
      algorithms: [...expect.algs],
      issuer: expect.issuer,
      audience: expect.audience,
      clockTolerance: LEEWAY_SECONDS,
      currentDate: new Date(at * 1000),
      requiredClaims: ["exp", "iat", "iss", "aud"],
    }));
  } catch (e) {
    // Only jose's error code is kept: its errors carry the full claims (personal data) otherwise.
    const code = e instanceof errors.JOSEError ? ` (${e.code})` : "";
    throw new TokenCheckError(classify(e), `token verification failed${code}`);
  }
  checkIat(payload, at);
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
