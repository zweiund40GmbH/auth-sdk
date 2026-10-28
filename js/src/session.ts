/**
 * The session: what the encrypted session cookie holds ({@link SessionData},
 * including tokens – server-side only) and what the application sees
 * ({@link Session}, without any token, safe to pass to client components).
 */

import type { JWTPayload } from "jose";
import type { IdClaims } from "./id-token.js";
import { attributes, readChunked, writeChunked, type CookieSink, type CookieSource } from "./cookies.js";
import { seal, unseal, type KeyRing } from "./seal.js";

/** Content of the session cookie. Never sent to the browser in readable form. */
export interface SessionData {
  /** Format version. */
  v: 1;
  /** Verified ID token claims of the login (profile claims updated by refreshes). */
  claims: IdClaims;
  /** Latest ID token (`id_token_hint` for the logout). */
  idToken: string;
  /** Access token. */
  accessToken: string;
  /** Expiry of the access token (seconds since the epoch). */
  accessTokenExpiresAt: number;
  /** Refresh token (scope `offline_access`), rotated on every use. */
  refreshToken: string | undefined;
  /** Granted scopes, space separated. */
  scope: string;
  /** Creation of the session at the application (seconds since the epoch). */
  createdAt: number;
  /** Absolute end of the session (seconds since the epoch). */
  expiresAt: number;
}

/** The signed-in user as the application sees it. Contains no tokens. */
export interface Session {
  /** The user. */
  user: {
    /** Stable user id; link local data with this, not with the e-mail address. */
    sub: string;
    /** Display name (scope `profile`). */
    name?: string;
    /** E-mail address (scope `email`). */
    email?: string;
    /** Whether the address is verified (scope `email`). */
    emailVerified?: boolean;
    /** Locale (scope `profile`). */
    locale?: string;
  };
  /** SSO session id at this application. */
  sid?: string;
  /** Authentication context of the login (check it for sensitive actions). */
  acr?: string;
  /** Authentication methods of the login. */
  amr: string[];
  /** Time of the authentication (seconds since the epoch). */
  authTime?: number;
  /** `production` or `test` application. */
  env?: string;
  /** Granted scopes. */
  scopes: string[];
  /** Absolute end of the session (seconds since the epoch). */
  expiresAt: number;
}

/** Drops `undefined` values so the public object stays small and serializable. */
function defined<T extends object>(o: T): T {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;
}

/** The public view of `data`. */
export function toSession(data: SessionData): Session {
  const c = data.claims;
  return defined({
    user: defined({ sub: c.sub, name: c.name, email: c.email, emailVerified: c.emailVerified, locale: c.locale }),
    sid: c.sid,
    acr: c.acr,
    amr: c.amr,
    authTime: c.authTime,
    env: c.env,
    scopes: data.scope.split(" ").filter((s) => s !== ""),
    expiresAt: data.expiresAt,
  });
}

/** Seconds since the epoch. */
export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Minimal shape check of a decrypted payload (the encryption already guarantees integrity). */
function isSessionData(p: JWTPayload): boolean {
  const claims = p["claims"] as { sub?: unknown } | undefined;
  return (
    p["v"] === 1 &&
    typeof claims?.sub === "string" &&
    claims.sub !== "" &&
    typeof p["accessToken"] === "string" &&
    typeof p["idToken"] === "string" &&
    typeof p["createdAt"] === "number" &&
    typeof p["expiresAt"] === "number"
  );
}

/** Reads and decrypts the session cookie; `undefined` if absent, invalid or expired. */
export async function readSession(source: CookieSource, name: string, key: KeyRing): Promise<SessionData | undefined> {
  const raw = readChunked(source, name);
  if (raw === undefined) return undefined;
  const payload = await unseal(raw, key, "session");
  if (payload === undefined || !isSessionData(payload)) return undefined;
  const { iat: _iat, exp: _exp, ...data } = payload;
  const session = data as unknown as SessionData;
  return session.expiresAt > nowSeconds() ? session : undefined;
}

/**
 * Encrypts and writes `data` (or deletes the session with `undefined`).
 * Returns `false` if the session does not fit into the cookies.
 */
export async function writeSession(
  sink: CookieSink,
  source: CookieSource,
  name: string,
  key: KeyRing,
  secure: boolean,
  data: SessionData | undefined,
): Promise<boolean> {
  if (data === undefined) return writeChunked(sink, source, name, undefined, attributes(secure, 0));
  const value = await seal({ ...data }, key, "session", data.expiresAt);
  return writeChunked(sink, source, name, value, attributes(secure, data.expiresAt - nowSeconds()));
}
