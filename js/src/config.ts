/**
 * Configuration: options passed to `createAuth` override environment
 * variables; everything is validated once and fails closed (an
 * {@link AuthError} with code `config`, raised on every use).
 */

import { configError } from "./errors.js";
import type { SessionStore } from "./store.js";
import { isSecureUrl, safeReturnTo } from "./url.js";

/** Receives warnings of the package (never token values or secrets). */
export interface Logger {
  /** Logs a warning. */
  warn(message: string): void;
}

/** How the client authenticates at the token endpoint. */
export type TokenEndpointAuthMethod = "client_secret_basic" | "client_secret_post";

/** Options of `createAuth`. Unset values are read from the environment variables named in brackets. */
export interface AuthOptions {
  /** Issuer URL, exactly as in the discovery document (`AUTH_ISSUER`). */
  issuer?: string;
  /** Client ID (`AUTH_CLIENT_ID`). */
  clientId?: string;
  /** Client secret (`AUTH_CLIENT_SECRET`). */
  clientSecret?: string;
  /** Registered redirect URI, must end with `<basePath>/callback` (`AUTH_REDIRECT_URI`). */
  redirectUri?: string;
  /** Registered post-logout redirect URI, optional (`AUTH_POST_LOGOUT_REDIRECT_URI`). */
  postLogoutRedirectUri?: string;
  /** Secret for the cookie encryption, at least 32 characters (`AUTH_SESSION_SECRET`). */
  sessionSecret?: string;
  /** Earlier session secrets, still accepted for decryption (`AUTH_SESSION_SECRET_PREVIOUS`, comma-separated). */
  previousSessionSecrets?: string[];
  /** Requested scopes; `openid` is added if missing. Default: `openid profile email offline_access`. */
  scopes?: string[];
  /** Path of the route handlers. Default: `/auth`. */
  basePath?: string;
  /** Prefix of the cookie names. Default: `auth`. */
  cookieName?: string;
  /** Absolute lifetime of a session in seconds. Default: 8 hours. */
  sessionMaxAge?: number;
  /** Client authentication at the token endpoint. Default: `client_secret_basic`. */
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
  /** Shared store for back-channel logout revocations (strongly recommended). */
  sessionStore?: SessionStore;
  /** Relative path the callback redirects to on failure (with `?error=<code>`). Default: plain `400` page. */
  errorPath?: string;
  /** Receives warnings. Default: `console`. */
  logger?: Logger;
  /**
   * Allow plain HTTP to loopback hosts (`localhost`, `127.0.0.1`, `[::1]`) for local development.
   * Only effective when `NODE_ENV` (always read from `process.env`) is set and not `production`.
   */
  allowInsecureLoopback?: boolean;
  /** Source of the `AUTH_*` environment variables. Default: `process.env`. */
  lookup?: (name: string) => string | undefined;
}

/** Validated configuration. */
export interface ResolvedConfig {
  /** Issuer string, compared exactly. */
  issuer: string;
  /** Client ID. */
  clientId: string;
  /** Client secret. */
  clientSecret: string;
  /** Redirect URI exactly as registered. */
  redirectUri: string;
  /** Post-logout redirect URI (optional). */
  postLogoutRedirectUri: string | undefined;
  /** Cookie encryption secret. */
  sessionSecret: string;
  /** Previous secrets (decryption only). */
  previousSessionSecrets: string[];
  /** Scopes, `openid` first. */
  scopes: string[];
  /** Path of the route handlers, without trailing slash. */
  basePath: string;
  /** Cookie name prefix. */
  cookieName: string;
  /** Session lifetime in seconds. */
  sessionMaxAge: number;
  /** Token endpoint authentication. */
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  /** Revocation store, if any. */
  sessionStore: SessionStore | undefined;
  /** Error redirect path, if any. */
  errorPath: string | undefined;
  /** Warning sink. */
  logger: Logger;
  /** Origin of the application (from the redirect URI); all redirects go here. */
  appOrigin: string;
  /** Whether cookies are `Secure` with `__Host-` prefix (HTTPS application). */
  secureCookies: boolean;
  /** Whether plain HTTP to loopback hosts is allowed (`allowInsecureLoopback` and NODE_ENV set, not production). */
  allowLoopbackHttp: boolean;
}

/** Shortest accepted session secret. */
const MIN_SECRET_LENGTH = 32;
/** Default session lifetime: 8 hours. */
const DEFAULT_MAX_AGE = 8 * 3600;
/** Default scopes. */
const DEFAULT_SCOPES = ["openid", "profile", "email", "offline_access"];

/** Default environment lookup (`process.env`, also available in the edge runtime). */
function processEnv(name: string): string | undefined {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  return env?.[name];
}

/** Picks the option or the environment variable; empty strings count as unset. */
function pick(option: string | undefined, lookup: (n: string) => string | undefined, name: string): string | undefined {
  const value = option ?? lookup(name);
  return value === undefined || value.trim() === "" ? undefined : value.trim();
}

/** Like {@link pick}, but required. */
function required(option: string | undefined, lookup: (n: string) => string | undefined, name: string): string {
  const value = pick(option, lookup, name);
  if (value === undefined) throw configError(`${name} is not set`);
  return value;
}

/** Parses `value` as URL that must be HTTPS (or loopback HTTP in development) and have no fragment. */
function secureUrl(value: string, name: string, allowLoopbackHttp: boolean): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw configError(`${name} is not a URL`);
  }
  if (!isSecureUrl(url, allowLoopbackHttp)) {
    throw configError(
      `${name} must use HTTPS (plain HTTP only for loopback hosts with allowInsecureLoopback and NODE_ENV not production)`,
    );
  }
  if (url.hash !== "" || url.username !== "" || url.password !== "") {
    throw configError(`${name} must not contain a fragment or credentials`);
  }
  return url;
}

/** Validates `options` (falling back to the environment) into a {@link ResolvedConfig}. */
export function resolveConfig(options: AuthOptions = {}): ResolvedConfig {
  const lookup = options.lookup ?? processEnv;
  // NODE_ENV comes from the real process environment, never from `lookup`: a custom lookup
  // that omits it must not turn a production server into "development".
  const nodeEnv = processEnv("NODE_ENV");
  const allowLoopbackHttp =
    options.allowInsecureLoopback === true && nodeEnv !== undefined && nodeEnv !== "" && nodeEnv !== "production";
  const issuer = required(options.issuer, lookup, "AUTH_ISSUER");
  const issuerUrl = secureUrl(issuer, "AUTH_ISSUER", allowLoopbackHttp);
  if (issuerUrl.search !== "") throw configError("AUTH_ISSUER must not contain a query");
  const clientId = required(options.clientId, lookup, "AUTH_CLIENT_ID");
  const clientSecret = required(options.clientSecret, lookup, "AUTH_CLIENT_SECRET");
  const sessionSecret = required(options.sessionSecret, lookup, "AUTH_SESSION_SECRET");
  if (sessionSecret.length < MIN_SECRET_LENGTH) {
    throw configError(`AUTH_SESSION_SECRET must have at least ${MIN_SECRET_LENGTH} characters`);
  }
  const previousSessionSecrets = (
    options.previousSessionSecrets ?? (pick(undefined, lookup, "AUTH_SESSION_SECRET_PREVIOUS") ?? "").split(",")
  )
    .map((p) => p.trim())
    .filter((p) => p !== "");
  if (previousSessionSecrets.some((p) => p.length < MIN_SECRET_LENGTH)) {
    throw configError(`AUTH_SESSION_SECRET_PREVIOUS: every secret must have at least ${MIN_SECRET_LENGTH} characters`);
  }
  const basePath = (options.basePath ?? "/auth").replace(/\/+$/, "");
  if (!/^(\/[A-Za-z0-9._~-]+)+$/.test(basePath)) throw configError("basePath must be a path like /auth");
  const redirectUri = required(options.redirectUri, lookup, "AUTH_REDIRECT_URI");
  const redirect = secureUrl(redirectUri, "AUTH_REDIRECT_URI", allowLoopbackHttp);
  if (redirect.pathname !== `${basePath}/callback` || redirect.search !== "") {
    throw configError(`AUTH_REDIRECT_URI must point to ${basePath}/callback without a query`);
  }
  const postLogout = pick(options.postLogoutRedirectUri, lookup, "AUTH_POST_LOGOUT_REDIRECT_URI");
  if (postLogout !== undefined) secureUrl(postLogout, "AUTH_POST_LOGOUT_REDIRECT_URI", allowLoopbackHttp);
  const scopes = ["openid", ...(options.scopes ?? DEFAULT_SCOPES).filter((s) => s !== "openid")];
  if (scopes.some((s) => !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(s))) throw configError("invalid scope");
  const sessionMaxAge = options.sessionMaxAge ?? DEFAULT_MAX_AGE;
  if (!Number.isInteger(sessionMaxAge) || sessionMaxAge < 300 || sessionMaxAge > 30 * 86400) {
    throw configError("sessionMaxAge must be an integer between 300 and 2592000 seconds");
  }
  const cookieName = options.cookieName ?? "auth";
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(cookieName)) throw configError("cookieName must match [A-Za-z0-9_-]{1,32}");
  if (options.errorPath !== undefined && safeReturnTo(options.errorPath, "") !== options.errorPath) {
    throw configError("errorPath must be a relative path");
  }
  return {
    issuer,
    clientId,
    clientSecret,
    redirectUri,
    postLogoutRedirectUri: postLogout,
    sessionSecret,
    previousSessionSecrets,
    scopes,
    basePath,
    cookieName,
    sessionMaxAge,
    tokenEndpointAuthMethod: options.tokenEndpointAuthMethod ?? "client_secret_basic",
    sessionStore: options.sessionStore,
    errorPath: options.errorPath,
    // eslint-disable-next-line no-console -- default sink, replaceable via `logger`
    logger: options.logger ?? { warn: (m) => { console.warn(m); } },
    appOrigin: redirect.origin,
    secureCookies: redirect.protocol === "https:",
    allowLoopbackHttp,
  };
}
