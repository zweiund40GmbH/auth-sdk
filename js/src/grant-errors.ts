/**
 * Classification of openid-client failures at the token endpoint. Only a
 * definite answer of the provider ends a login: `400` with
 * `error=invalid_grant`. Everything that may be a passing disturbance –
 * timeouts, network errors, `429`, `5xx`, HTML or other non-OAuth answers
 * from a proxy in between – is `provider_error`, so a session survives a
 * short outage or maintenance of the provider.
 */

import * as oidc from "openid-client";
import { AuthError } from "./errors.js";

/** openid-client codes for answers that are not a (valid) OAuth response at all. */
const TRANSIENT_CODES = new Set([
  "OAUTH_TIMEOUT",
  "OAUTH_RESPONSE_IS_NOT_CONFORM",
  "OAUTH_RESPONSE_IS_NOT_JSON",
  "OAUTH_PARSE_ERROR",
]);

/**
 * Maps an openid-client failure to an {@link AuthError}. The original error
 * is deliberately not attached: it can carry callback parameters (the code)
 * or token claims, and errors tend to end up in logs.
 */
export function mapGrantError(e: unknown): AuthError {
  if (e instanceof AuthError) return e;
  if (e instanceof oidc.AuthorizationResponseError) {
    return new AuthError("authorization_error", "authorization failed", { oauthError: e.error });
  }
  if (e instanceof oidc.ResponseBodyError) {
    return e.status === 400 && e.error === "invalid_grant"
      ? new AuthError("invalid_grant", "grant rejected")
      : new AuthError("provider_error", `token endpoint answered ${e.status}`);
  }
  if (e instanceof oidc.ClientError) {
    return e.code !== undefined && TRANSIENT_CODES.has(e.code)
      ? new AuthError("provider_error", "token endpoint unreachable or answer not OAuth")
      : new AuthError("invalid_callback", "callback or token response rejected");
  }
  // TypeError (network), AbortError/TimeoutError and anything unexpected.
  return new AuthError("provider_error", "provider request failed");
}
