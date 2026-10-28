/**
 * Error types of the package. Messages are English and never contain token
 * values, secrets or codes; `code` is meant for decisions, not for display.
 */

/** Machine-readable reason of an {@link AuthError}. */
export type AuthErrorCode =
  /** Configuration is missing or invalid. */
  | "config"
  /** Discovery document or JWKS could not be loaded or failed validation. */
  | "discovery"
  /** Callback without a matching (or with an expired) login state cookie. */
  | "login_state_missing"
  /** Callback or token response rejected (missing/duplicate parameters, wrong `state`, `iss`, `nonce`, `aud`). */
  | "invalid_callback"
  /** The provider answered the authorization request with an error. */
  | "authorization_error"
  /** A token failed validation (signature, `typ`, claims, nonce, `at_hash`, …). */
  | "invalid_token"
  /** `max_age` / `prompt=login` not fulfilled by `auth_time`. */
  | "auth_too_old"
  /** `acr_values` not fulfilled by `acr`. */
  | "insufficient_acr"
  /** The refreshed ID token names another user. */
  | "wrong_subject"
  /** The provider rejected a grant (`invalid_grant`): the login is over. */
  | "invalid_grant"
  /** Token endpoint or network failure. */
  | "provider_error";

/** Error raised by the package. */
export class AuthError extends Error {
  /** Machine-readable reason. */
  readonly code: AuthErrorCode;
  /** OAuth error code of the provider (only for `authorization_error`). */
  readonly oauthError: string | undefined;

  /**
   * Creates an error. `message` must never contain token values or secrets.
   * `options.cause` is kept for debugging; it is never a token value.
   */
  constructor(code: AuthErrorCode, message: string, options?: { oauthError?: string; cause?: unknown }) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = "AuthError";
    this.code = code;
    this.oauthError = options?.oauthError;
  }
}

/** Shorthand for a configuration error. */
export function configError(message: string): AuthError {
  return new AuthError("config", message);
}
