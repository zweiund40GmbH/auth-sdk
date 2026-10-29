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
  | "provider_error"
  /** The encrypted session exceeds the cookie limit (too many scopes or large claims). */
  | "session_too_large"
  /** The management API answered with an error ({@link ManagementError}). */
  | "management_error";

/** Error raised by the package. */
export class AuthError extends Error {
  /** Machine-readable reason. */
  readonly code: AuthErrorCode;
  /** OAuth error code of the provider (only for `authorization_error`). */
  readonly oauthError: string | undefined;

  /**
   * Creates an error. `message` must never contain token values or secrets.
   * `options.cause` is kept for debugging; it never contains token values,
   * codes or claims (only discovery failures attach one).
   */
  constructor(code: AuthErrorCode, message: string, options?: { oauthError?: string; cause?: unknown }) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = "AuthError";
    this.code = code;
    this.oauthError = options?.oauthError;
  }
}

/** Error answer of the management API (`{ error: { code, message, fields } }`). */
export class ManagementError extends AuthError {
  /** HTTP status (`401`, `403`, `404`, `409`, `422`, `429`, `503`, …). */
  readonly status: number;
  /** Code of the API: `unauthorized`, `forbidden`, `not_found`, `conflict`, `validation`, `rate_limited`, `unavailable`, … */
  readonly apiCode: string;
  /** Message of the API for users (German), safe to show; empty if the answer had none. */
  readonly apiMessage: string;
  /** Field errors (only with `validation`): field name → message. */
  readonly fields: Record<string, string>;
  /** Seconds from `Retry-After` (with `429`), if sent. */
  readonly retryAfter: number | undefined;

  /** Creates the error from the parts of the answer. */
  constructor(
    status: number,
    apiCode: string,
    apiMessage: string,
    fields: Record<string, string> = {},
    retryAfter?: number,
  ) {
    super("management_error", `management API answered ${status} (${apiCode})`);
    this.name = "ManagementError";
    this.status = status;
    this.apiCode = apiCode;
    this.apiMessage = apiMessage;
    this.fields = fields;
    this.retryAfter = retryAfter;
  }
}

/** Shorthand for a configuration error. */
export function configError(message: string): AuthError {
  return new AuthError("config", message);
}
