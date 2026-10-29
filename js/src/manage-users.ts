/**
 * Users with a grant for the application (`GET /manage/users`, scope
 * `manage:users.read`): the full list for a resync, e.g. after a catch-up
 * page with `gap: true`, or a lookup by address.
 */

import { AuthError } from "./errors.js";
import type { ApiCaller } from "./management-http.js";

/** A user in the application's scope. */
export interface ManagedUser {
  /** The central account. */
  sub: string;
  /** Current address. */
  email: string;
  /** Display name. */
  displayName: string;
  /** Given name (`null` = not set). */
  givenName: string | null;
  /** Family name (`null` = not set). */
  familyName: string | null;
  /** Account status (`locked` is reserved; other values may be added). */
  status: "invited" | "active" | "disabled" | (string & {});
  /** Role keys of this application (sorted). */
  roles: string[];
  /** End of the grant (ISO 8601; `null` = unlimited, in the past = expired). */
  validUntil: string | null;
}

/** One page of users. */
export interface UserPage {
  /** Users, sorted by address. */
  items: ManagedUser[];
  /** Number of matching users over all pages. */
  total: number;
}

/** Filter and page of the user list. */
export interface UsersQuery {
  /** Exact address (case-insensitive); without it all users. */
  email?: string;
  /** Page, starting at 1 (provider default 1). */
  page?: number;
  /** Page size up to 200 (provider default 50). */
  pageSize?: number;
}

/** One page of the users with a grant for the application (also expired ones). */
export async function fetchUsers(call: ApiCaller, query: UsersQuery = {}): Promise<UserPage> {
  const q: Record<string, string> = {};
  if (query.email !== undefined) q["email"] = query.email;
  if (query.page !== undefined) q["page"] = String(query.page);
  if (query.pageSize !== undefined) q["pageSize"] = String(query.pageSize);
  const r = (await call({ method: "GET", path: ["users"], query: q })) as { items?: unknown; total?: unknown } | undefined;
  if (!Array.isArray(r?.items) || typeof r.total !== "number") {
    throw new AuthError("provider_error", "invalid management API answer (users)");
  }
  return { items: r.items as ManagedUser[], total: r.total };
}
