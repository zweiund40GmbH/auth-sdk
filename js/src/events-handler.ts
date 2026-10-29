/**
 * Push receiver for account events (RFC 8935) as a route handler:
 * `export const POST = createEventsHandler({ onEvent })`.
 *
 * Answers: `202` without body (also for an already processed `jti`, so the
 * provider stops retrying); `400` with `{ err, description }` (RFC 8935
 * §2.3: `invalid_request`, `invalid_key`, `invalid_issuer`,
 * `invalid_audience`); `503` if the signing keys or the store are
 * unavailable; `500` if `onEvent` throws. On anything but `2xx` the
 * provider retries.
 */

import { readLimited } from "./backchannel.js";
import { securityEvent, type SecurityEvent } from "./events.js";
import { TokenCheckError, TYP_SECEVENT, verifyJwt } from "./jwt.js";
import type { ProviderContext } from "./provider.js";
import { consoleLogger } from "./config.js";
import { lazyService, type Service, type ServiceOptions } from "./service-config.js";
import { memorySessionStore, type SessionStore } from "./store.js";

/** `Content-Type` of a pushed token. */
export const CONTENT_TYPE_SECEVENT = "application/secevent+jwt";
/** Largest accepted body (a token is about 1 KiB). */
const MAX_EVENT_BYTES = 64 * 1024;
/**
 * How long a processed `jti` is remembered (seconds). The contract asks for at least 72 hours; the
 * catch-up repeats events of the last 30 days with the same `jti`.
 */
export const EVENT_JTI_TTL_SECONDS = 31 * 86400;

/** Options of {@link createEventsHandler}. */
export interface EventsHandlerOptions extends ServiceOptions {
  /**
   * Processes one verified event. Throwing makes the provider retry (`500`). Should be idempotent:
   * events arrive at least once.
   */
  onEvent(event: SecurityEvent): Promise<void> | void;
  /**
   * Remembers processed `jti`s; must be shared by all instances (e.g. Redis). Default: in memory
   * (only for a single instance, with a warning).
   */
  store?: SessionStore;
}

/** Store key of a processed event. */
export function eventJtiKey(jti: string): string {
  return `auth-next:event:jti:${jti}`;
}

/** A response without body. */
function bare(status: number): Response {
  return new Response(null, { status, headers: { "cache-control": "no-store" } });
}

/** `400` with the RFC 8935 error object. */
function rejected(err: string, description: string): Response {
  return new Response(JSON.stringify({ err, description }), {
    status: 400,
    headers: { "cache-control": "no-store", "content-type": "application/json" },
  });
}

/** The answer for a failed verification. */
function rejection(e: unknown): Response {
  if (!(e instanceof TokenCheckError)) return rejected("invalid_request", "invalid security event token");
  switch (e.check) {
    case "issuer":
      return rejected("invalid_issuer", e.message);
    case "audience":
      return rejected("invalid_audience", e.message);
    case "key":
      return rejected("invalid_key", e.message);
    case "keys_unavailable":
      return bare(503);
    case "other":
      return rejected("invalid_request", e.message);
  }
}

/** Verifies a pushed token: JWT checks with `typ: secevent+jwt`, then the event rules. */
export async function verifySecurityEvent(ctx: ProviderContext, clientId: string, token: string): Promise<SecurityEvent> {
  const raw = await verifyJwt(token, ctx.jwks, { typ: TYP_SECEVENT, issuer: ctx.issuer, audience: clientId, algs: ctx.algs });
  return securityEvent(raw, Math.floor(Date.now() / 1000));
}

/** Whether the request declares `application/secevent+jwt` (parameters allowed). */
function isSecevent(request: Request): boolean {
  return (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase() === CONTENT_TYPE_SECEVENT;
}

/**
 * Creates the route handler for the events URI. Issuer and client ID come from the options or
 * `AUTH_ISSUER` / `AUTH_CLIENT_ID` (the client secret is not needed). An invalid configuration
 * answers `503` and logs a warning.
 */
export function createEventsHandler(options: EventsHandlerOptions): (request: Request) => Promise<Response> {
  const service = lazyService(options, false);
  let store = options.store;
  return async (request) => {
    let ctx: ProviderContext;
    let svc: Service;
    try {
      svc = service();
      ctx = await svc.provider();
    } catch {
      (options.logger ?? consoleLogger).warn("auth-next: events handler not configured or provider unreachable.");
      return bare(503);
    }
    if (store === undefined) {
      svc.cfg.logger.warn("auth-next: events handler without store – duplicates are only detected per instance.");
      store = memorySessionStore();
    }
    if (request.method !== "POST") return new Response(null, { status: 405, headers: { allow: "POST" } });
    if (!isSecevent(request)) return rejected("invalid_request", "content type must be application/secevent+jwt");
    const token = (await readLimited(request, MAX_EVENT_BYTES))?.trim();
    if (token === undefined || token === "") return rejected("invalid_request", "empty or oversized body");
    let event: SecurityEvent;
    try {
      event = await verifySecurityEvent(ctx, svc.cfg.clientId, token);
    } catch (e) {
      return rejection(e);
    }
    try {
      if ((await store.get(eventJtiKey(event.jti))) !== undefined) return bare(202);
    } catch {
      return bare(503);
    }
    try {
      await options.onEvent(event);
    } catch {
      return bare(500);
    }
    // Processed: a failing store must not make the provider retry a handled event.
    await store.set(eventJtiKey(event.jti), "1", EVENT_JTI_TTL_SECONDS).catch(() => undefined);
    return bare(202);
  };
}
