/**
 * Account events (Security Event Tokens, RFC 8417): what the provider tells
 * an application about accounts in its scope between two logins. The same
 * events arrive pushed (RFC 8935, {@link createEventsHandler}) and from the
 * management API's catch-up, both with the same `jti`.
 *
 * Types this version does not know arrive as `{ type: "unknown" }`
 * (forward compatible: ignore them); unknown fields are ignored.
 */

import type { JWTPayload } from "jose";
import { AuthError } from "./errors.js";
import { LEEWAY_SECONDS } from "./requirements.js";

/** Prefix of the event type URIs (keys of the `events` claim). */
export const EVENT_URN_PREFIX = "urn:z40:event:";

/** Oldest accepted `iat` relative to now in seconds: 2 minutes token lifetime plus the clock leeway. */
export const MAX_EVENT_AGE_SECONDS = 120 + LEEWAY_SECONDS;

/** One event about an account, discriminated by `type`. */
export type AccountEvent =
  /** The address changed or was confirmed (`emailVerified: false` after an admin set it). */
  | { type: "user.email_changed"; email: string; emailVerified: boolean }
  /** Display, given or family name changed; the values are the current ones (`null` = not set). */
  | {
      type: "user.profile_changed";
      changed: string[];
      displayName: string;
      givenName: string | null;
      familyName: string | null;
    }
  /** The account was disabled centrally. */
  | { type: "user.disabled" }
  /** The disabled account was enabled again. */
  | { type: "user.enabled" }
  /**
   * The grant for this application was withdrawn. `reason` is optional and open (e.g. `expired`; new values may
   * appear); a non-string value is dropped, never an error.
   */
  | { type: "access.revoked"; reason?: string }
  /** A link to a local account was removed. */
  | { type: "link.removed"; localId: string }
  /** An onboarding link of this application was accepted; `localId` is now linked to `sub`. */
  | { type: "onboarding.accepted"; localId: string }
  /** Test event from the admin UI (push only, without `sub`). */
  | { type: "verification" }
  /** A type this version does not know (`eventType` without prefix); ignore it. */
  | { type: "unknown"; eventType: string; data: Record<string, unknown> };

/** A verified, pushed Security Event Token. */
export interface SecurityEvent {
  /** Event id, the same in every delivery attempt and in the catch-up: deduplicate on it. */
  jti: string;
  /** The user (`undefined` only for `verification`). */
  sub: string | undefined;
  /** Time of the change (seconds since the epoch; `undefined` for `verification`). */
  toe: number | undefined;
  /** Time of this delivery attempt (seconds since the epoch). */
  iat: number;
  /** Production or test application, passed through from the token; compare it with your own environment if a mix-up matters. */
  env: "production" | "test";
  /** The event. */
  event: AccountEvent;
}

/** Whether `v` is a plain JSON object. */
function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A non-empty string field, or `undefined`. */
function str(d: Record<string, unknown>, key: string): string | undefined {
  const v = d[key];
  return typeof v === "string" && v !== "" ? v : undefined;
}

/** A string-or-null field (`undefined` if it has another type). */
function nullableStr(d: Record<string, unknown>, key: string): string | null | undefined {
  const v = d[key];
  if (v === undefined || v === null) return null;
  return typeof v === "string" ? v : undefined;
}

/** `user.profile_changed`, or `undefined` if malformed. */
function profileChanged(d: Record<string, unknown>): AccountEvent | undefined {
  const changed = d["changed"];
  const displayName = d["displayName"];
  const givenName = nullableStr(d, "givenName");
  const familyName = nullableStr(d, "familyName");
  if (!Array.isArray(changed) || !changed.every((c) => typeof c === "string") || typeof displayName !== "string") {
    return undefined;
  }
  if (givenName === undefined || familyName === undefined) return undefined;
  return { type: "user.profile_changed", changed, displayName, givenName, familyName };
}

/**
 * Builds the event from its type name (without prefix) and data object;
 * `undefined` if a known type has malformed data (e.g. an empty `localId`)
 * or the data is no object.
 */
export function parseAccountEvent(type: string, data: unknown): AccountEvent | undefined {
  if (!isObject(data)) return undefined;
  switch (type) {
    case "user.email_changed": {
      const email = str(data, "email");
      const verified = data["emailVerified"];
      return email !== undefined && typeof verified === "boolean"
        ? { type, email, emailVerified: verified }
        : undefined;
    }
    case "user.profile_changed":
      return profileChanged(data);
    case "user.disabled":
    case "user.enabled":
    case "verification":
      return { type };
    case "access.revoked": {
      // Tolerant on purpose: `reason` is optional and its values are open.
      const reason = data["reason"];
      return typeof reason === "string" ? { type, reason } : { type };
    }
    case "link.removed":
    case "onboarding.accepted": {
      const localId = str(data, "localId");
      return localId === undefined ? undefined : { type, localId };
    }
    default:
      return { type: "unknown", eventType: type, data };
  }
}

/** The one event of the `events` claim (exactly one `urn:z40:event:` key with an object value). */
function singleEvent(events: unknown): AccountEvent | undefined {
  if (!isObject(events)) return undefined;
  const entries = Object.entries(events);
  const [entry] = entries;
  if (entries.length !== 1 || entry === undefined) return undefined;
  const [uri, data] = entry;
  if (!uri.startsWith(EVENT_URN_PREFIX) || uri.length === EVENT_URN_PREFIX.length) return undefined;
  return parseAccountEvent(uri.slice(EVENT_URN_PREFIX.length), data);
}

/**
 * The SET rules on top of the generic JWT checks: `iat` at most
 * {@link MAX_EVENT_AGE_SECONDS} old, `jti`, `env`, exactly one event,
 * `sub` (except for `verification`), numeric `toe`.
 */
export function securityEvent(raw: JWTPayload, now: number): SecurityEvent {
  const fail = (what: string) => new AuthError("invalid_token", `security event token: ${what}`);
  if (typeof raw.iat !== "number") throw fail("iat missing");
  if (raw.iat < now - MAX_EVENT_AGE_SECONDS) throw fail("too old");
  const jti = typeof raw.jti === "string" && raw.jti !== "" ? raw.jti : undefined;
  if (jti === undefined) throw fail("jti missing");
  const env = raw["env"];
  if (env !== "production" && env !== "test") throw fail("env missing");
  const event = singleEvent(raw["events"]);
  if (event === undefined) throw fail("events claim invalid");
  const sub = typeof raw.sub === "string" && raw.sub !== "" ? raw.sub : undefined;
  if (sub === undefined && event.type !== "verification") throw fail("sub missing");
  const toe = raw["toe"];
  if (toe !== undefined && toe !== null && typeof toe !== "number") throw fail("toe invalid");
  return { jti, sub, toe: typeof toe === "number" ? toe : undefined, iat: raw.iat, env, event };
}
