/**
 * Authentication requirements of a login (`max_age`, `prompt=login`,
 * `acr_values`) and their check against the ID token (OIDC Core §3.1.2.1,
 * §3.1.3.7 items 11–12).
 *
 * The authorize URL passes through the browser, so the user could drop
 * these parameters. They are therefore recorded in the encrypted login
 * state and enforced at the callback.
 */

import { AuthError } from "./errors.js";

/** Allowed clock skew in seconds. */
export const LEEWAY_SECONDS = 60;

/** What the login asked for. */
export interface AuthRequirements {
  /** `max_age` sent: the authentication must be at most this many seconds old. */
  maxAge?: number;
  /** `acr_values` sent: the ID token's `acr` must be one of them. */
  acrValues?: string[];
  /** `prompt=login` sent: the authentication must be newer than the login start. */
  freshLogin?: boolean;
  /** When the login started (seconds since the epoch). */
  startedAt: number;
}

/** Options of a login that become requirements. */
export interface LoginOptions {
  /** Relative path to return to after the login. Default: `/`. */
  returnTo?: string;
  /** `prompt=login` forces a new authentication, `prompt=none` fails instead of showing a login page. */
  prompt?: "login" | "none";
  /** Maximum age of the authentication in seconds (`max_age`). */
  maxAge?: number;
  /** Required authentication contexts (`acr_values`), e.g. a second factor. */
  acrValues?: string[];
  /** Pre-fills the login form (`login_hint`). */
  loginHint?: string;
}

/** Builds the requirements of a login started at `now`; rejects an invalid `maxAge`. */
export function requirementsFrom(options: LoginOptions, now: number): AuthRequirements {
  if (options.maxAge !== undefined && (!Number.isInteger(options.maxAge) || options.maxAge < 0)) {
    throw new AuthError("config", "maxAge must be a non-negative integer");
  }
  const acrValues = (options.acrValues ?? []).filter((v) => v !== "");
  return {
    ...(options.maxAge !== undefined ? { maxAge: options.maxAge } : {}),
    ...(acrValues.length > 0 ? { acrValues } : {}),
    ...(options.prompt === "login" ? { freshLogin: true } : {}),
    startedAt: now,
  };
}

/** The authorize parameters for `options` (besides the ones the package always sets). */
export function authorizeParams(options: LoginOptions): Record<string, string> {
  const params: Record<string, string> = {};
  if (options.prompt !== undefined) params["prompt"] = options.prompt;
  if (options.maxAge !== undefined) params["max_age"] = String(options.maxAge);
  const acr = (options.acrValues ?? []).filter((v) => v !== "");
  if (acr.length > 0) params["acr_values"] = acr.join(" ");
  if (options.loginHint !== undefined && options.loginHint !== "") params["login_hint"] = options.loginHint;
  return params;
}

/** Checks `auth_time` and `acr` of a verified ID token at time `now` (seconds). */
export function checkRequirements(
  req: AuthRequirements,
  authTime: number | undefined,
  acr: string | undefined,
  now: number,
): void {
  if (req.maxAge !== undefined || req.freshLogin === true) {
    if (authTime === undefined) throw new AuthError("invalid_token", "ID token has no auth_time");
    if (req.maxAge !== undefined && now - authTime > req.maxAge + LEEWAY_SECONDS) {
      throw new AuthError("auth_too_old", "authentication is older than max_age");
    }
    if (req.freshLogin === true && authTime < req.startedAt - LEEWAY_SECONDS) {
      throw new AuthError("auth_too_old", "authentication is older than the login start (prompt=login)");
    }
  }
  if (req.acrValues !== undefined && req.acrValues.length > 0 && !(acr !== undefined && req.acrValues.includes(acr))) {
    throw new AuthError("insufficient_acr", "acr does not match the requested acr_values");
  }
}
