/**
 * Cookie handling independent of Next.js: reading from a `Cookie` header,
 * writing through a small sink interface, names (`__Host-` prefix on HTTPS)
 * and splitting a large session value over several cookies (browsers keep
 * at most about 4 KiB per cookie).
 */

/** Attributes of every cookie the package sets. */
export interface CookieAttributes {
  /** Always `true`: never readable by scripts. */
  httpOnly: true;
  /** `true` on HTTPS applications. */
  secure: boolean;
  /** `lax`: the cookies must arrive on the top-level navigation back from the provider. */
  sameSite: "lax";
  /** Always `/` (required by `__Host-`). */
  path: "/";
  /** Lifetime in seconds; `0` deletes. */
  maxAge: number;
}

/** Read access to the request cookies. */
export interface CookieSource {
  /** Value of cookie `name`. */
  get(name: string): string | undefined;
  /** Names of all cookies. */
  names(): string[];
}

/** Write access to the response cookies. */
export interface CookieSink {
  /** Sets (or with `maxAge: 0` deletes) cookie `name`. */
  set(name: string, value: string, attributes: CookieAttributes): void;
}

/** Largest value stored in one cookie (leaves room for name and attributes). */
export const CHUNK_SIZE = 3800;
/** Most cookies one session may use. */
export const MAX_CHUNKS = 5;

/** Parses a `Cookie` request header (first occurrence of a name wins). */
export function parseCookieHeader(header: string | null): CookieSource {
  const map = new Map<string, string>();
  for (const part of (header ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    if (!map.has(name)) map.set(name, part.slice(eq + 1).trim());
  }
  return { get: (n) => map.get(n), names: () => [...map.keys()] };
}

/** Serializes a `Set-Cookie` header value. Values are base64url/JWE and need no encoding. */
export function serializeCookie(name: string, value: string, a: CookieAttributes): string {
  const parts = [`${name}=${value}`, `Path=${a.path}`, `Max-Age=${a.maxAge}`, "HttpOnly", "SameSite=Lax"];
  if (a.secure) parts.push("Secure");
  return parts.join("; ");
}

/** A sink that collects `Set-Cookie` header values (for plain `Response`s). */
export function headerSink(): CookieSink & { headers: string[] } {
  const headers: string[] = [];
  return { headers, set: (n, v, a) => headers.push(serializeCookie(n, v, a)) };
}

/** Cookie names of one application. */
export interface CookieNames {
  /** Session cookie (chunks get `.1`, `.2`, … appended). */
  session: string;
  /** Prefix of the login state cookies (one per pending login, keyed by `state`). */
  loginPrefix: string;
}

/** Names for prefix `base`; `__Host-` on HTTPS. */
export function cookieNames(base: string, secure: boolean): CookieNames {
  const p = secure ? "__Host-" : "";
  return { session: `${p}${base}.session`, loginPrefix: `${p}${base}.login.` };
}

/** Attributes for a cookie living `maxAge` seconds. */
export function attributes(secure: boolean, maxAge: number): CookieAttributes {
  return { httpOnly: true, secure, sameSite: "lax", path: "/", maxAge: Math.max(0, Math.floor(maxAge)) };
}

/** Name of chunk `i` of cookie `name` (chunk 0 is `name` itself). */
function chunkName(name: string, i: number): string {
  return i === 0 ? name : `${name}.${i}`;
}

/** Reads a value written by {@link writeChunked}; missing chunks end the value. */
export function readChunked(source: CookieSource, name: string): string | undefined {
  let value = "";
  for (let i = 0; i < MAX_CHUNKS; i++) {
    const part = source.get(chunkName(name, i));
    if (part === undefined) break;
    value += part;
  }
  return value === "" ? undefined : value;
}

/**
 * Writes `value` (or deletes with `undefined`) over as many chunks as
 * needed and deletes chunks of an older, longer value. Returns `false`
 * (writing nothing) if the value is too large.
 */
export function writeChunked(
  sink: CookieSink,
  source: CookieSource,
  name: string,
  value: string | undefined,
  attrs: CookieAttributes,
): boolean {
  const parts: string[] = [];
  for (let i = 0; value !== undefined && i < value.length; i += CHUNK_SIZE) parts.push(value.slice(i, i + CHUNK_SIZE));
  if (parts.length > MAX_CHUNKS) return false;
  parts.forEach((part, i) => {
    sink.set(chunkName(name, i), part, attrs);
  });
  const deleteAttrs = { ...attrs, maxAge: 0 };
  for (let i = parts.length; i < MAX_CHUNKS; i++) {
    if (source.get(chunkName(name, i)) !== undefined) sink.set(chunkName(name, i), "", deleteAttrs);
  }
  return true;
}
