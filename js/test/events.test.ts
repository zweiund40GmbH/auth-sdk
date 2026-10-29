import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { SecurityEvent } from "../src/events.js";
import { createEventsHandler, type EventsHandlerOptions } from "../src/events-handler.js";
import { memorySessionStore } from "../src/store.js";
import { CLIENT_ID } from "./mock-provider.js";
import { MockManageProvider } from "./mock-manage.js";

let provider: MockManageProvider;
let received: SecurityEvent[];
const warnings: string[] = [];

beforeAll(async () => {
  provider = await new MockManageProvider().start();
});
afterAll(async () => {
  await provider.stop();
});
beforeEach(() => {
  received = [];
});

/** A handler against the mock provider. */
function handler(extra: Partial<EventsHandlerOptions> = {}) {
  return createEventsHandler({
    issuer: provider.issuer,
    clientId: CLIENT_ID,
    lookup: () => undefined,
    allowInsecureLoopback: true,
    logger: { warn: (m) => warnings.push(m) },
    store: memorySessionStore(),
    onEvent: (e) => {
      received.push(e);
    },
    ...extra,
  });
}

/** A push request carrying `token`. */
function push(token: string, type = "application/secevent+jwt", method = "POST"): Request {
  return new Request("https://app.example.com/auth/events", {
    method,
    headers: { "content-type": type, accept: "application/json" },
    ...(method === "POST" ? { body: token } : {}),
  });
}

/** The RFC 8935 `err` of a response. */
async function err(res: Response): Promise<string | undefined> {
  return ((await res.json()) as { err?: string }).err;
}

describe("events handler", () => {
  it("accepts a valid event once and passes it typed", async () => {
    const h = handler();
    const token = await provider.eventToken({ jti: "jti-1" });
    const res = await h(push(token));
    expect(res.status).toBe(202);
    expect(await res.text()).toBe("");
    expect(received).toHaveLength(1);
    expect(received[0]?.event).toEqual({ type: "user.email_changed", email: "erika@example.com", emailVerified: true });
    expect(received[0]?.sub).toBe("user-1");
    // Provider retry with the same jti: accepted, not handled again.
    expect((await h(push(token))).status).toBe(202);
    expect(received).toHaveLength(1);
  });

  it.each([
    ["wrong typ", { typ: "logout+jwt" }, "invalid_request"],
    ["ID token typ", { typ: "JWT" }, "invalid_request"],
    ["wrong audience", { claims: { aud: "other-app" } }, "invalid_audience"],
    ["wrong issuer", { claims: { iss: "https://evil.example.com" } }, "invalid_issuer"],
    ["expired", { claims: { iat: Math.floor(Date.now() / 1000) - 600, exp: Math.floor(Date.now() / 1000) - 480 } }, "invalid_request"],
    ["bad signature", { key: "foreign" as const }, "invalid_key"],
    ["no event", { claims: { events: {} } }, "invalid_request"],
  ])("rejects %s with 400", async (_n, t: { typ?: string; claims?: Record<string, unknown>; key?: "foreign" }, code) => {
    const token = await provider.eventToken(t.claims ?? {}, t.typ ?? "secevent+jwt", t.key ?? "es");
    const res = await handler()(push(token));
    expect(res.status).toBe(400);
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(await err(res)).toBe(code);
    expect(received).toHaveLength(0);
  });

  it("passes unknown event types on", async () => {
    const token = await provider.eventToken({ events: { "urn:z40:event:user.archived": { a: 1 } } });
    expect((await handler()(push(token))).status).toBe(202);
    expect(received[0]?.event).toEqual({ type: "unknown", eventType: "user.archived", data: { a: 1 } });
  });

  it("rejects wrong content types and methods", async () => {
    const token = await provider.eventToken();
    const res = await handler()(push(token, "application/jwt"));
    expect([res.status, await err(res)]).toEqual([400, "invalid_request"]);
    expect((await handler()(push("", "application/secevent+jwt", "GET"))).status).toBe(405);
    const empty = await handler()(push(" "));
    expect(empty.status).toBe(400);
  });

  it("answers 500 when onEvent fails, so the retry is handled", async () => {
    const store = memorySessionStore();
    const token = await provider.eventToken({ jti: "jti-f" });
    const failing = handler({ store, onEvent: () => Promise.reject(new Error("db down")) });
    expect((await failing(push(token))).status).toBe(500);
    expect((await handler({ store })(push(token))).status).toBe(202);
    expect(received).toHaveLength(1);
  });

  it("answers 503 when not configured and warns without a store", async () => {
    const res = await createEventsHandler({ lookup: () => undefined, onEvent: () => undefined, logger: { warn: () => undefined } })(
      push("x"),
    );
    expect(res.status).toBe(503);
    warnings.length = 0;
    const token = await provider.eventToken();
    expect((await handler({ store: undefined })(push(token))).status).toBe(202);
    expect(warnings.some((w) => w.includes("without store"))).toBe(true);
  });
});
