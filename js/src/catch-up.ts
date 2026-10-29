/**
 * Event catch-up (`GET /manage/events`, scope `manage:events.read`): the
 * events of the last 30 days in cursor order, whether or not the push
 * reached the application.
 *
 * Keep the `nextCursor` of the last processed page. A page with
 * `gap: true` means events after the cursor were already deleted by the
 * provider's retention: its items are still valid, but the application
 * missed events and must resync its users completely before continuing.
 */

import { AuthError } from "./errors.js";
import { parseAccountEvent, type AccountEvent } from "./events.js";
import type { ApiCaller } from "./management-http.js";

/** One event of the catch-up. */
export interface CaughtUpEvent {
  /** Position in the catch-up (opaque). */
  cursor: string;
  /** Event id, the same as in the pushed token: deduplicate on it. */
  jti: string;
  /** The user. */
  sub: string;
  /** Time of the change (ISO 8601). */
  occurredAt: string;
  /** The event. */
  event: AccountEvent;
}

/** One page of the catch-up. */
export interface EventPage {
  /** Events in cursor order. */
  items: CaughtUpEvent[];
  /** Cursor for the next call (store it after processing the items). */
  nextCursor: string;
  /** More events are ready (call again right away). */
  hasMore: boolean;
  /** Events after `since` were deleted before they were fetched: resync completely. */
  gap: boolean;
}

/** Options of a single catch-up call. */
export interface EventsQuery {
  /** `nextCursor` of the last call; without it from the oldest kept event. */
  since?: string;
  /** Page size 1–500 (default 100). */
  limit?: number;
}

/** Thrown for answers that do not have the contract's form. */
function invalid(): AuthError {
  return new AuthError("provider_error", "invalid catch-up answer");
}

/** Validates one item. */
function item(raw: unknown): CaughtUpEvent {
  const r = raw as Record<string, unknown> | null;
  const s = (k: string) => (typeof r?.[k] === "string" ? r[k] : undefined);
  const [cursor, jti, type, sub, occurredAt] = [s("cursor"), s("jti"), s("type"), s("sub"), s("occurredAt")];
  if (cursor === undefined || jti === undefined || type === undefined || sub === undefined || occurredAt === undefined) {
    throw invalid();
  }
  const event = parseAccountEvent(type, r?.["data"]);
  if (event === undefined) throw invalid();
  return { cursor, jti, sub, occurredAt, event };
}

/** Validates a page answer. */
export function eventPage(raw: unknown): EventPage {
  const r = raw as Record<string, unknown> | null;
  const items = r?.["items"];
  const nextCursor = r?.["nextCursor"];
  const hasMore = r?.["hasMore"];
  const gap = r?.["gap"];
  if (!Array.isArray(items) || typeof nextCursor !== "string" || typeof hasMore !== "boolean" || typeof gap !== "boolean") {
    throw invalid();
  }
  return { items: items.map(item), nextCursor, hasMore, gap };
}

/** One page of events. A `ManagementError` with status `503` means "try again". */
export async function fetchEvents(call: ApiCaller, query: EventsQuery = {}): Promise<EventPage> {
  const q: Record<string, string> = {};
  if (query.since !== undefined) q["since"] = query.since;
  if (query.limit !== undefined) q["limit"] = String(query.limit);
  return eventPage(await call({ method: "GET", path: ["events"], query: q }));
}

/** Pages from `since` until a page has `hasMore: false`. */
export async function* eventPages(call: ApiCaller, since?: string): AsyncGenerator<EventPage, void, undefined> {
  let cursor = since;
  for (;;) {
    const page = await fetchEvents(call, cursor === undefined ? {} : { since: cursor });
    cursor = page.nextCursor;
    yield page;
    if (!page.hasMore) return;
  }
}
