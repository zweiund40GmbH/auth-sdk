/**
 * Client of the management API (`/api/v1/manage/…`): server-to-server
 * calls of the application with a client-credentials token, always limited
 * to the calling application by the provider. Onboarding links, links to
 * local accounts and the event catch-up.
 *
 * Errors: `ManagementError` (code `management_error`) with status, API
 * code, message and field errors; network or token failures as
 * `AuthError` (`provider_error`, `config`).
 */

import { eventPages, fetchEvents, type EventPage, type EventsQuery } from "./catch-up.js";
import { AuthError, configError } from "./errors.js";
import { apiCaller, tokenCache, validOnBehalfOf, type ApiCaller } from "./management-http.js";
import { mailClient, type MailClient } from "./manage-mail.js";
import { fetchUsers, type UserPage, type UsersQuery } from "./manage-users.js";
import { lazyService, type ServiceOptions } from "./service-config.js";

/** Options of {@link createManagementClient}. */
export interface ManagementOptions extends ServiceOptions {
  /** Requested scopes, e.g. `["manage:onboarding"]`. Default: all `manage:*` scopes registered for the application. */
  scopes?: string[];
}

/** Request of an onboarding link (`POST /manage/onboarding`). */
export interface NewOnboarding {
  /** Address of the person (the mail goes there). */
  email: string;
  /** Id of the local account (1–128 visible ASCII characters). */
  localId: string;
  /** Suggested display name for a new account. */
  displayName?: string;
  /** Suggested given name. */
  givenName?: string;
  /** Suggested family name. */
  familyName?: string;
  /** An admin of the application: a second factor becomes mandatory. Default `false`. */
  appAdmin?: boolean;
  /** Role keys of the grant. Default: the application's default roles. */
  roles?: string[];
  /** End of a grant created or renewed on acceptance (ISO 8601 or `Date`). Default: unlimited. */
  validUntil?: string | Date;
  /** Mail the link (default `true`) or return it as `url` (`false`). */
  sendMail?: boolean;
}

/** Status of an onboarding link. */
export type OnboardingStatus = "open" | "accepted" | "expired" | "revoked";

/** An onboarding link as the application sees it. */
export interface Onboarding {
  /** Id (store it with the local account). */
  id: string;
  /** The local account. */
  localId: string;
  /** Requested address. */
  email: string;
  /** Admin of the application. */
  appAdmin: boolean;
  /** Role keys of the grant. */
  roles: string[];
  /** End of a grant created on acceptance (`null` = unlimited). */
  validUntil: string | null;
  /** Current status (other values may be added later). */
  status: OnboardingStatus | (string & {});
  /** Created (ISO 8601). */
  createdAt: string;
  /** End of the current link (ISO 8601). */
  expiresAt: string;
  /** Last mail (`null` = never mailed). */
  sentAt: string | null;
  /** Accepted (`null` = not yet). */
  acceptedAt: string | null;
  /** The linked account, only once accepted. */
  sub: string | null;
  /** The link, only with `sendMail: false`. Hand it only to the user it was made for; never log it. */
  url?: string;
}

/** A link to report (`POST /manage/links`). */
export interface LinkReport {
  /** The central account. */
  sub: string;
  /** Id of the local account. */
  localId: string;
}

/** A link of a user to a local account. */
export interface Link {
  /** Id of the local account. */
  localId: string;
  /** Origin: `reported` (by the application) or `onboarding` (accepted link). */
  source: "reported" | "onboarding" | (string & {});
  /** When it was created (ISO 8601). */
  linkedAt: string;
}

/** The management API of one application, as returned by {@link createManagementClient}. */
export interface ManagementClient {
  /**
   * Requests an onboarding link (scope `manage:onboarding`); replaces an open link of the same `localId`.
   * An empty `localId` is a config error (nothing is sent).
   */
  createOnboarding(input: NewOnboarding): Promise<Onboarding>;
  /** The status of an own onboarding link (`404` for unknown or deleted ids). */
  getOnboarding(id: string): Promise<Onboarding>;
  /** Revokes an open or expired link (idempotent); `409` once accepted. */
  revokeOnboarding(id: string): Promise<void>;
  /** Sends a new link with a new lifetime; `sendMail: false` returns it as `url`. */
  resendOnboarding(id: string, options?: { sendMail?: boolean }): Promise<Onboarding>;
  /** The links of user `sub` (scope `manage:users.read`), sorted by `localId`. */
  userLinks(sub: string): Promise<Link[]>;
  /** Reports 1–500 links (scope `manage:users.write`, idempotent). An empty `localId` is a config error. */
  reportLinks(items: LinkReport[]): Promise<{ linked: number; ignored: number }>;
  /** One page of the users with a grant (scope `manage:users.read`), e.g. for a full resync after `gap: true`. */
  users(query?: UsersQuery): Promise<UserPage>;
  /** One page of the event catch-up (scope `manage:events.read`). */
  events(query?: EventsQuery): Promise<EventPage>;
  /** All pages from `since` until caught up; check `page.gap` on each. */
  eventPages(since?: string): AsyncGenerator<EventPage, void, undefined>;
  /** Mail sending for the application (scope `manage:mail.send`), see {@link MailClient}. */
  mail: MailClient;
  /** The same client sending `X-On-Behalf-Of` (the local user who triggered the calls; audit only). */
  onBehalfOf(localUserId: string): ManagementClient;
}

/** Thrown for answers that do not have the contract's form. */
function invalid(what: string): AuthError {
  return new AuthError("provider_error", `invalid management API answer (${what})`);
}

/** Checks the identifying fields of an onboarding answer. */
function onboarding(raw: unknown): Onboarding {
  const r = raw as Record<string, unknown> | null;
  if (typeof r?.["id"] !== "string" || typeof r["status"] !== "string" || !Array.isArray(r["roles"])) {
    throw invalid("onboarding");
  }
  return r as unknown as Onboarding;
}

/** The request body with exactly the contract's fields (unknown fields are rejected by the API). */
function onboardingBody(input: NewOnboarding): Record<string, unknown> {
  const validUntil = input.validUntil instanceof Date ? input.validUntil.toISOString() : input.validUntil;
  return {
    email: input.email,
    localId: input.localId,
    displayName: input.displayName,
    givenName: input.givenName,
    familyName: input.familyName,
    appAdmin: input.appAdmin ?? false,
    roles: input.roles,
    validUntil,
    sendMail: input.sendMail ?? true,
  };
}

/** Rejects an empty `localId` before sending (the API would answer `422`). */
function checkLocalId(localId: string): void {
  if (localId === "") throw configError("localId must not be empty");
}

/** The client on top of `call`; `derive` makes the variant with `X-On-Behalf-Of`. */
function client(call: ApiCaller, derive: (onBehalfOf: string) => ManagementClient): ManagementClient {
  return {
    createOnboarding: async (input) => {
      checkLocalId(input.localId);
      return onboarding(await call({ method: "POST", path: ["onboarding"], body: onboardingBody(input) }));
    },
    getOnboarding: async (id) => onboarding(await call({ method: "GET", path: ["onboarding", id] })),
    revokeOnboarding: async (id) => {
      await call({ method: "DELETE", path: ["onboarding", id] });
    },
    resendOnboarding: async (id, options = {}) =>
      onboarding(
        await call({ method: "POST", path: ["onboarding", id, "resend"], body: { sendMail: options.sendMail ?? true } }),
      ),
    userLinks: async (sub) => {
      const r = (await call({ method: "GET", path: ["users", sub, "links"] })) as { items?: unknown } | undefined;
      if (!Array.isArray(r?.items)) throw invalid("links");
      return r.items as Link[];
    },
    reportLinks: async (items) => {
      for (const i of items) checkLocalId(i.localId);
      const body = { items: items.map((i) => ({ sub: i.sub, localId: i.localId })) };
      const r = (await call({ method: "POST", path: ["links"], body })) as { linked?: unknown; ignored?: unknown } | undefined;
      if (typeof r?.linked !== "number" || typeof r.ignored !== "number") throw invalid("links");
      return { linked: r.linked, ignored: r.ignored };
    },
    users: (query) => fetchUsers(call, query),
    events: (query) => fetchEvents(call, query),
    eventPages: (since) => eventPages(call, since),
    mail: mailClient(call),
    onBehalfOf: derive,
  };
}

/**
 * Creates the management client. Issuer, client ID and secret come from the options or
 * `AUTH_ISSUER`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`; the configuration is checked on first use
 * (so `next build` works without secrets). Server-only: never use it in client components.
 */
export function createManagementClient(options: ManagementOptions = {}): ManagementClient {
  const service = lazyService(options, true);
  const token = tokenCache(service, options.scopes);
  const make = (onBehalfOf?: string): ManagementClient =>
    client(apiCaller(service, token, onBehalfOf), (id) => {
      if (!validOnBehalfOf(id)) throw configError("X-On-Behalf-Of must be 1-128 visible ASCII characters");
      return make(id);
    });
  return make();
}
