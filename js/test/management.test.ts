import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AuthError, ManagementError } from "../src/errors.js";
import { createManagementClient, type ManagementClient, type ManagementOptions } from "../src/management.js";
import { CLIENT_ID, CLIENT_SECRET } from "./mock-provider.js";
import { MockManageProvider } from "./mock-manage.js";

let provider: MockManageProvider;
let mgmt: ManagementClient;

beforeAll(async () => {
  provider = await new MockManageProvider().start();
});
afterAll(async () => {
  await provider.stop();
});
beforeEach(() => {
  provider.answers = [];
  provider.seen = [];
  provider.calls = {};
  mgmt = client();
});

/** A management client against the mock provider. */
function client(extra: ManagementOptions = {}): ManagementClient {
  return createManagementClient({
    issuer: provider.issuer,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    lookup: () => undefined,
    allowInsecureLoopback: true,
    ...extra,
  });
}

/** An onboarding answer. */
function onboarding(status: string, url?: string) {
  return {
    id: "0192-a",
    localId: "7:42",
    email: "lena@example.com",
    appAdmin: false,
    roles: ["operator"],
    validUntil: null,
    status,
    createdAt: "2026-10-29T10:00:00Z",
    expiresAt: "2026-11-12T10:00:00Z",
    sentAt: null,
    acceptedAt: null,
    sub: null,
    ...(url === undefined ? {} : { url }),
  };
}

describe("onboarding", () => {
  it("creates, reads, resends and revokes with one cached token", async () => {
    provider.answers.push({ status: 201, json: onboarding("open", "https://login.example.com/x#t=abc") });
    const o = await mgmt.onBehalfOf("17").createOnboarding({
      email: "lena@example.com",
      localId: "7:42",
      familyName: "Berg",
      sendMail: false,
      validUntil: new Date("2027-03-31T00:00:00Z"),
    });
    expect([o.status, o.url]).toEqual(["open", "https://login.example.com/x#t=abc"]);
    const seen = provider.last();
    expect([seen.method, seen.url, seen.authorization, seen.onBehalfOf]).toEqual([
      "POST",
      "/api/v1/manage/onboarding",
      "Bearer cc-1",
      "17",
    ]);
    expect(seen.body).toEqual({
      email: "lena@example.com",
      localId: "7:42",
      familyName: "Berg",
      appAdmin: false,
      validUntil: "2027-03-31T00:00:00.000Z",
      sendMail: false,
    });
    expect(provider.lastScope).toBeUndefined();

    provider.answers.push({ status: 200, json: onboarding("accepted") });
    expect((await mgmt.getOnboarding("0192-a")).status).toBe("accepted");
    expect([provider.last().url, provider.last().onBehalfOf]).toEqual(["/api/v1/manage/onboarding/0192-a", undefined]);

    provider.answers.push({ status: 200, json: onboarding("open") });
    await mgmt.resendOnboarding("0192-a");
    expect([provider.last().url, provider.last().body]).toEqual(["/api/v1/manage/onboarding/0192-a/resend", { sendMail: true }]);

    provider.answers.push({ status: 204 });
    await mgmt.revokeOnboarding("0192-a");
    expect(provider.last().method).toBe("DELETE");
    expect(provider.calls["client_credentials"]).toBe(1);
  });

  it("maps API errors and renews the token after a 401", async () => {
    provider.answers.push({
      status: 429,
      json: { error: { code: "rate_limited", message: "Zu viele Anfragen." } },
      headers: { "retry-after": "30" },
    });
    const e = await mgmt.createOnboarding({ email: "a@example.com", localId: "1" }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ManagementError);
    expect(e).toMatchObject({ code: "management_error", status: 429, apiCode: "rate_limited", retryAfter: 30 });

    provider.answers.push({ status: 422, json: { error: { code: "validation", message: "Bitte Eingaben prüfen.", fields: { localId: "Ungültig." } } } });
    const v = await mgmt.getOnboarding("x").catch((x: unknown) => x);
    expect(v).toMatchObject({ status: 422, fields: { localId: "Ungültig." } });

    provider.answers.push({ status: 401 }, { status: 200, json: { items: [] } });
    expect(await mgmt.userLinks("sub-1")).toEqual([]);
    expect(provider.calls["client_credentials"]).toBe(2);
    expect(provider.last().authorization).toBe("Bearer cc-2");

    provider.answers.push({ status: 401 }, { status: 401 });
    await expect(mgmt.userLinks("sub-1")).rejects.toMatchObject({ status: 401 });
    expect(() => mgmt.onBehalfOf("a b")).toThrow(AuthError);
  });

  it("requests the configured scopes", async () => {
    provider.answers.push({ status: 200, json: onboarding("open") });
    await client({ scopes: ["manage:onboarding", "manage:events.read"] }).getOnboarding("x");
    expect(provider.lastScope).toBe("manage:onboarding manage:events.read");
  });
});

describe("links", () => {
  it("reports and reads links", async () => {
    provider.answers.push({ status: 200, json: { linked: 1, ignored: 0 } });
    expect(await mgmt.reportLinks([{ sub: "s", localId: "7:42" }])).toEqual({ linked: 1, ignored: 0 });
    expect(provider.last().body).toEqual({ items: [{ sub: "s", localId: "7:42" }] });
    provider.answers.push({ status: 200, json: { items: [{ localId: "7:42", source: "onboarding", linkedAt: "2026-10-29T10:00:00Z" }] } });
    const links = await mgmt.userLinks("a/b");
    expect(links[0]?.source).toBe("onboarding");
    expect(provider.last().url).toBe("/api/v1/manage/users/a%2Fb/links");
  });
});

describe("event catch-up", () => {
  const event = (cursor: string, type: string, data: unknown) => ({
    cursor,
    jti: `j${cursor}`,
    type,
    sub: "s",
    occurredAt: "2026-10-29T10:00:00Z",
    data,
  });

  it("pages until caught up and reports the gap", async () => {
    provider.answers.push(
      { status: 200, json: { items: [event("3", "user.disabled", {})], nextCursor: "3", hasMore: true, gap: true } },
      { status: 200, json: { items: [event("9", "user.future", { a: 1 })], nextCursor: "9", hasMore: false, gap: false } },
    );
    const pages = [];
    for await (const page of mgmt.eventPages()) pages.push(page);
    expect(pages.map((p) => [p.gap, p.nextCursor])).toEqual([
      [true, "3"],
      [false, "9"],
    ]);
    expect(pages[0]?.items[0]?.event).toEqual({ type: "user.disabled" });
    expect(pages[1]?.items[0]?.event).toMatchObject({ type: "unknown", eventType: "user.future" });
    expect(provider.seen.map((s) => s.url)).toEqual(["/api/v1/manage/events", "/api/v1/manage/events?since=3"]);
  });

  it("passes since and limit and rejects malformed answers", async () => {
    provider.answers.push({ status: 200, json: { items: [], nextCursor: "9", hasMore: false, gap: false } });
    await mgmt.events({ since: "9", limit: 50 });
    expect(provider.last().url).toBe("/api/v1/manage/events?since=9&limit=50");
    // A malformed known type does not block the catch-up: it comes as "unknown" with its raw data.
    provider.answers.push({ status: 200, json: { items: [event("1", "link.removed", {})], nextCursor: "1", hasMore: false, gap: false } });
    expect((await mgmt.events()).items[0]?.event).toEqual({ type: "unknown", eventType: "link.removed", data: {} });
    provider.answers.push({ status: 200, json: { items: "x", nextCursor: "1", hasMore: false, gap: false } });
    await expect(mgmt.events()).rejects.toMatchObject({ code: "provider_error" });
    provider.answers.push({ status: 503, json: { error: { code: "unavailable", message: "Bitte erneut versuchen." } } });
    await expect(mgmt.events()).rejects.toMatchObject({ status: 503, apiCode: "unavailable" });
  });
});

describe("guards and users", () => {
  it("stops the catch-up if the cursor does not advance", async () => {
    const stuck = { items: [], nextCursor: "4", hasMore: true, gap: false };
    provider.answers.push({ status: 200, json: stuck }, { status: 200, json: stuck });
    const seen: unknown[] = [];
    const run = async () => {
      for await (const page of mgmt.eventPages()) seen.push(page);
    };
    await expect(run()).rejects.toMatchObject({ code: "provider_error" });
    expect(seen).toHaveLength(1);
  });

  it("rejects empty and dot ids and an empty localId before sending", async () => {
    for (const id of ["", ".", ".."]) {
      await expect(mgmt.getOnboarding(id)).rejects.toMatchObject({ code: "config" });
      await expect(mgmt.userLinks(id)).rejects.toMatchObject({ code: "config" });
    }
    await expect(mgmt.createOnboarding({ email: "a@example.com", localId: "" })).rejects.toMatchObject({ code: "config" });
    await expect(mgmt.reportLinks([{ sub: "s", localId: "" }])).rejects.toMatchObject({ code: "config" });
    expect(provider.seen).toHaveLength(0);
  });

  it("lists users for a resync", async () => {
    const user = { sub: "s", email: "a@example.com", displayName: "A", givenName: null, familyName: null, status: "active", roles: [], validUntil: null };
    provider.answers.push({ status: 200, json: { items: [user], total: 51 } });
    const page = await mgmt.users({ page: 2, pageSize: 50 });
    expect([page.total, page.items[0]?.status]).toEqual([51, "active"]);
    expect(provider.last().url).toBe("/api/v1/manage/users?page=2&pageSize=50");
    provider.answers.push({ status: 200, json: { items: [], total: 0 } });
    await mgmt.users({ email: "a+b@example.com" });
    expect(provider.last().url).toBe("/api/v1/manage/users?email=a%2Bb%40example.com");
  });
});
