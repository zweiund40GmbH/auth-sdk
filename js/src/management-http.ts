/**
 * Request layer of the management API: a client-credentials token (cached
 * until shortly before it expires, renewed after a `401`), JSON bodies,
 * `X-On-Behalf-Of` and the API's error format. Uses the package's one
 * fetch (timeout, no redirects).
 */

import * as oidc from "openid-client";
import { readLimited } from "./backchannel.js";
import { AuthError, configError, ManagementError } from "./errors.js";
import { noRedirectFetch } from "./provider.js";
import type { Service } from "./service-config.js";

/** Largest answer read. */
const MAX_ANSWER_BYTES = 1024 * 1024;
/** A cached token is renewed this many seconds before it expires. */
const RENEW_BEFORE_SECONDS = 30;
/** Largest length of `X-On-Behalf-Of`. */
const MAX_ON_BEHALF_OF = 128;

/** A request to the management API. */
export interface ApiRequest {
  /** HTTP method. */
  method: "GET" | "POST" | "PUT" | "DELETE";
  /** Path segments below `/api/v1/manage/` (each is percent-encoded). */
  path: string[];
  /** Query parameters. */
  query?: Record<string, string>;
  /** JSON body. */
  body?: unknown;
}

/** Sends management API requests for one application. */
export interface ApiCaller {
  /** Sends `request`; resolves with the parsed JSON (or `undefined` for an empty answer). */
  (request: ApiRequest): Promise<unknown>;
}

/** Whether `value` is a valid `X-On-Behalf-Of`: 1–128 visible ASCII characters. */
export function validOnBehalfOf(value: string): boolean {
  return value.length >= 1 && value.length <= MAX_ON_BEHALF_OF && /^[\x21-\x7e]+$/.test(value);
}

/** Maps an error answer to {@link ManagementError}. */
export function apiError(status: number, text: string, retryAfter: string | null): ManagementError {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  const error = (body as { error?: unknown } | undefined)?.error as Record<string, unknown> | undefined;
  const code = typeof error?.["code"] === "string" ? error["code"] : "unknown";
  const message = typeof error?.["message"] === "string" ? error["message"] : "";
  const rawFields = error?.["fields"];
  const fields: Record<string, string> = {};
  if (typeof rawFields === "object" && rawFields !== null) {
    for (const [k, v] of Object.entries(rawFields)) if (typeof v === "string") fields[k] = v;
  }
  const seconds = retryAfter !== null && /^\d+$/.test(retryAfter.trim()) ? Number(retryAfter.trim()) : undefined;
  return new ManagementError(status, code, message, fields, seconds);
}

/** Whether `segment` addresses exactly one path segment (not empty, `.` or `..`). */
export function validSegment(segment: string): boolean {
  return segment !== "" && segment !== "." && segment !== "..";
}

/**
 * Token cache with single flight: concurrent callers share one token request. `rejected` is a token the API
 * answered `401` to; it is renewed only if it is still the cached one, so callers hit by the same `401` share
 * one new token.
 */
export function tokenCache(service: () => Service, scopes: string[] | undefined): (rejected?: string) => Promise<string> {
  let current: { token: string; renewAt: number } | undefined;
  let pending: Promise<string> | undefined;
  const fetchToken = async (): Promise<string> => {
    const ctx = await service().provider();
    let res: oidc.TokenEndpointResponse;
    try {
      res = await oidc.clientCredentialsGrant(ctx.oidc, scopes === undefined ? {} : { scope: scopes.join(" ") });
    } catch {
      throw new AuthError("provider_error", "client credentials grant failed");
    }
    const lifetime = typeof res.expires_in === "number" ? res.expires_in : 0;
    current = { token: res.access_token, renewAt: Date.now() + (lifetime - RENEW_BEFORE_SECONDS) * 1000 };
    return res.access_token;
  };
  return (rejected) => {
    if (current !== undefined && current.renewAt > Date.now() && current.token !== rejected) {
      return Promise.resolve(current.token);
    }
    pending ??= fetchToken().finally(() => {
      pending = undefined;
    });
    return pending;
  };
}

/** Builds the URL of `request` below the issuer; an empty, `.` or `..` segment (e.g. an empty id) is a config error. */
function apiUrl(issuer: string, request: ApiRequest): URL {
  if (!request.path.every(validSegment)) throw configError("id must not be empty, '.' or '..'");
  const path = request.path.map(encodeURIComponent).join("/");
  const url = new URL(`${issuer.replace(/\/+$/, "")}/api/v1/manage/${path}`);
  for (const [k, v] of Object.entries(request.query ?? {})) url.searchParams.set(k, v);
  return url;
}

/** An {@link ApiCaller} with the token from `token`, sending `onBehalfOf` if set. */
export function apiCaller(service: () => Service, token: (rejected?: string) => Promise<string>, onBehalfOf?: string): ApiCaller {
  return async (request) => {
    const url = apiUrl(service().cfg.issuer, request);
    let rejected: string | undefined;
    for (;;) {
      const current = await token(rejected);
      const headers: Record<string, string> = { accept: "application/json", authorization: `Bearer ${current}` };
      if (onBehalfOf !== undefined) headers["x-on-behalf-of"] = onBehalfOf;
      if (request.body !== undefined) headers["content-type"] = "application/json";
      let res: Response;
      try {
        res = await noRedirectFetch(url, {
          method: request.method,
          headers,
          ...(request.body === undefined ? {} : { body: JSON.stringify(request.body) }),
        });
      } catch {
        throw new AuthError("provider_error", "management API not reachable");
      }
      if (res.status === 401 && rejected === undefined) {
        await res.body?.cancel();
        rejected = current;
        continue;
      }
      const text = await readLimited(res, MAX_ANSWER_BYTES);
      if (text === undefined) throw new AuthError("provider_error", "management API answer too large");
      if (!res.ok) throw apiError(res.status, text, res.headers.get("retry-after"));
      if (text === "") return undefined;
      try {
        return JSON.parse(text) as unknown;
      } catch {
        throw new AuthError("provider_error", "management API answer is not JSON");
      }
    }
  };
}
