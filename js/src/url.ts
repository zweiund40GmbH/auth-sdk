/**
 * URL rules: which URLs may talk to the provider (HTTPS, plain HTTP only to
 * loopback hosts) and which `returnTo` values are safe redirect targets
 * (relative paths on the application's own origin only).
 */

/** Whether `url` is a loopback host (`localhost`, `127.0.0.0/8`, `[::1]`). */
export function isLoopback(url: URL): boolean {
  const host = url.hostname.toLowerCase();
  return host === "localhost" || host === "[::1]" || /^127(\.\d{1,3}){3}$/.test(host);
}

/**
 * HTTPS, or plain HTTP to a loopback host when `allowLoopbackHttp` is set
 * (local development only).
 */
export function isSecureUrl(url: URL, allowLoopbackHttp: boolean): boolean {
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && allowLoopbackHttp && isLoopback(url);
}

/** Longest `returnTo` accepted; longer values fall back to `/`. */
const MAX_RETURN_TO = 2048;

/** Fixed dummy origin the value is resolved against. */
const DUMMY_ORIGIN = "https://return-to.invalid";

/**
 * Normalizes `value` with the WHATWG URL parser against {@link DUMMY_ORIGIN}
 * and returns path, query and fragment – or `undefined` if the value leaves
 * that origin or the normalized path does not start with exactly one `/`.
 */
function normalizePath(value: string): string | undefined {
  let parsed: URL;
  try {
    parsed = new URL(value, DUMMY_ORIGIN);
  } catch {
    return undefined;
  }
  if (parsed.origin !== DUMMY_ORIGIN) return undefined;
  const path = `${parsed.pathname}${parsed.search}${parsed.hash}`;
  // Dot segments can turn `/.//host` or `/a/..//host` into the protocol-relative `//host`.
  if (!path.startsWith("/") || path.startsWith("//")) return undefined;
  return path;
}

/**
 * Returns `value` if it is a safe redirect target, else `fallback`.
 *
 * Safe means: a relative path that stays on the application's origin. The
 * raw value must start with a single `/` and contain no backslashes or
 * control characters (browsers treat `\` as `/`, URL parsers drop tabs and
 * newlines). It is then normalized (dot segments, percent-encoded dots)
 * and the **normalized** result must still be on the dummy origin and
 * start with exactly one `/`; it is checked a second time so the function
 * is idempotent. Only path, query and fragment are returned, so the result
 * can be appended to the application's origin or used as `Location` as is.
 */
export function safeReturnTo(value: string | null | undefined, fallback = "/"): string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_RETURN_TO) return fallback;
  if (!value.startsWith("/") || value.startsWith("//")) return fallback;
  // eslint-disable-next-line no-control-regex
  if (/[\\\u0000-\u001f\u007f]/.test(value)) return fallback;
  const once = normalizePath(value);
  if (once === undefined || normalizePath(once) !== once) return fallback;
  return once;
}

/** Builds an absolute URL on `origin` from a path that passed {@link safeReturnTo}. */
export function onOrigin(origin: string, path: string): URL {
  return new URL(safeReturnTo(path), origin);
}
