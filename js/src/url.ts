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

/**
 * Returns `value` if it is a safe redirect target, else `fallback`.
 *
 * Safe means: a path starting with exactly one `/` (no `//host`, no `/\host`),
 * no backslashes, no control characters, and – after resolving against a
 * dummy origin – still on that origin. Only path, query and fragment are
 * kept, so the result can be appended to the application's origin.
 */
export function safeReturnTo(value: string | null | undefined, fallback = "/"): string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_RETURN_TO) return fallback;
  if (!value.startsWith("/") || value.startsWith("//")) return fallback;
  // Backslashes are treated as slashes by browsers (`/\evil.example`); control characters
  // (including tab and newline, which URL parsers strip) could smuggle a host.
  // eslint-disable-next-line no-control-regex
  if (/[\\\u0000-\u001f\u007f]/.test(value)) return fallback;
  let parsed: URL;
  try {
    parsed = new URL(value, "https://return-to.invalid");
  } catch {
    return fallback;
  }
  if (parsed.origin !== "https://return-to.invalid") return fallback;
  return `${parsed.pathname}${parsed.search}${parsed.hash}`;
}

/** Builds an absolute URL on `origin` from a path that passed {@link safeReturnTo}. */
export function onOrigin(origin: string, path: string): URL {
  return new URL(safeReturnTo(path), origin);
}
