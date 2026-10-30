import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AuthError, ManagementError } from "../src/errors.js";
import { mailIdempotencyKey } from "../src/manage-mail.js";
import { createManagementClient, type ManagementClient } from "../src/management.js";
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
  mgmt = createManagementClient({
    issuer: provider.issuer,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    lookup: () => undefined,
    allowInsecureLoopback: true,
  });
});

/** A valid mail. */
const mail = {
  to: ["anna@example.com", "bert@example.com"],
  subject: "Ihre Anfrage ist eingegangen",
  text: "Hallo",
  idempotencyKey: "request:4711",
};

/** An error answer in the API's format. */
function failure(status: number, code: string, extra: Record<string, unknown> = {}) {
  return { status, json: { error: { code, message: "Fehler.", ...extra } } };
}

describe("mail.send", () => {
  it("queues a new mail (202) and sends exactly the contract's fields", async () => {
    provider.answers.push({ status: 202, json: { id: "m-1", status: "pending", recipients: 2 } });
    const r = await mgmt.mail.send({ ...mail, html: "<p>Hallo</p>", replyTo: "team@example.com" });
    expect(r).toEqual({ id: "m-1", status: "pending", recipients: 2, repeated: false });
    const seen = provider.last();
    expect([seen.method, seen.url]).toEqual(["POST", "/api/v1/manage/mail"]);
    expect(seen.body).toEqual({ ...mail, html: "<p>Hallo</p>", replyTo: "team@example.com" });
  });

  it("reports a repetition (200) as repeated", async () => {
    provider.answers.push({ status: 200, json: { id: "m-1", status: "sent", recipients: 2 } });
    expect(await mgmt.mail.send(mail)).toEqual({ id: "m-1", status: "sent", recipients: 2, repeated: true });
  });

  it("maps 409 idempotency_conflict and mail_disabled", async () => {
    provider.answers.push(failure(409, "idempotency_conflict"), failure(409, "mail_disabled"));
    await expect(mgmt.mail.send(mail)).rejects.toMatchObject({ status: 409, apiCode: "idempotency_conflict" });
    const e = await mgmt.mail.send(mail).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ManagementError);
    expect(e).toMatchObject({ status: 409, apiCode: "mail_disabled" });
  });

  it("maps 429 with Retry-After in seconds", async () => {
    provider.answers.push({ ...failure(429, "rate_limited"), headers: { "retry-after": "120" } });
    await expect(mgmt.mail.send(mail)).rejects.toMatchObject({ status: 429, retryAfter: 120 });
  });

  it("maps 422 field errors and 413", async () => {
    provider.answers.push(failure(422, "validation", { fields: { "to[1]": "Ungültige Adresse." } }), failure(413, "payload_too_large"));
    await expect(mgmt.mail.send(mail)).rejects.toMatchObject({ status: 422, fields: { "to[1]": "Ungültige Adresse." } });
    await expect(mgmt.mail.send(mail)).rejects.toMatchObject({ status: 413, apiCode: "payload_too_large" });
  });

  it("rejects a bad key or empty recipients before sending", async () => {
    await expect(mgmt.mail.send({ ...mail, idempotencyKey: "bad key" })).rejects.toBeInstanceOf(AuthError);
    await expect(mgmt.mail.send({ ...mail, idempotencyKey: "" })).rejects.toMatchObject({ code: "config" });
    await expect(mgmt.mail.send({ ...mail, to: [] })).rejects.toMatchObject({ code: "config" });
    expect(provider.seen).toEqual([]);
  });

  it("rejects an answer of the wrong form", async () => {
    provider.answers.push({ status: 202, json: { id: 1 } });
    await expect(mgmt.mail.send(mail)).rejects.toMatchObject({ code: "provider_error" });
  });
});

describe("mail.status", () => {
  it("reads the progress and maps 404", async () => {
    const progress = { id: "m-1", status: "pending", recipients: 2, sent: 1, failed: 0, pending: 1, createdAt: "2026-10-30T10:00:00Z" };
    provider.answers.push({ status: 200, json: progress }, failure(404, "not_found"));
    expect(await mgmt.mail.status("m-1")).toEqual(progress);
    expect([provider.last().method, provider.last().url]).toEqual(["GET", "/api/v1/manage/mail/m-1"]);
    await expect(mgmt.mail.status("gone")).rejects.toMatchObject({ status: 404 });
  });

  it("rejects an empty id and an answer of the wrong form", async () => {
    await expect(mgmt.mail.status("")).rejects.toMatchObject({ code: "config" });
    provider.answers.push({ status: 200, json: { id: "m-1", status: "sent" } });
    await expect(mgmt.mail.status("m-1")).rejects.toMatchObject({ code: "provider_error" });
  });
});

describe("mailIdempotencyKey", () => {
  it("encodes the example vectors", () => {
    expect(mailIdempotencyKey("order", 123)).toBe("order:123");
    expect(mailIdempotencyKey("Müller", "a_b:c")).toBe("M_c3_bcller:a_5fb_3ac");
    expect(mailIdempotencyKey("a", "", "b")).toBe("a::b");
    expect(mailIdempotencyKey("invoice", 2026815, "reminder", 1)).toBe("invoice:2026815:reminder:1");
  });

  it("never gives the same key for different parts", () => {
    const inputs: (string | number)[][] = [
      ["Müller", 1],
      ["Möller", 1],
      ["M_ller", 1],
      ["a b"],
      ["a/b"],
      ["a:b"],
      ["a", "b"],
      ["a_3ab"],
    ];
    const keys = inputs.map((i) => mailIdempotencyKey(...i));
    expect(new Set(keys).size).toBe(inputs.length);
    for (const k of keys) expect(k).toMatch(/^[A-Za-z0-9._:-]{1,100}$/);
  });

  it("rejects no parts and enforces the length of 100", () => {
    expect(() => mailIdempotencyKey()).toThrow(AuthError);
    expect(mailIdempotencyKey("a".repeat(100))).toHaveLength(100);
    expect(() => mailIdempotencyKey("a".repeat(101))).toThrow(/101/);
  });
});
