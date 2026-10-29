import { describe, expect, it } from "vitest";
import { MAX_EVENT_AGE_SECONDS, parseAccountEvent, securityEvent } from "./events.js";

const NOW = 1_800_000_000;
const base = {
  iat: NOW,
  jti: "j",
  sub: "u",
  toe: NOW - 2,
  env: "production",
  events: { "urn:z40:event:user.disabled": {} },
};

describe("parseAccountEvent", () => {
  it("parses every type of the contract", () => {
    expect(parseAccountEvent("user.email_changed", { email: "a@example.com", emailVerified: false })).toEqual({
      type: "user.email_changed",
      email: "a@example.com",
      emailVerified: false,
    });
    expect(
      parseAccountEvent("user.profile_changed", { changed: ["givenName"], displayName: "E M", givenName: "E", familyName: null }),
    ).toEqual({ type: "user.profile_changed", changed: ["givenName"], displayName: "E M", givenName: "E", familyName: null });
    expect(parseAccountEvent("user.disabled", {})).toEqual({ type: "user.disabled" });
    expect(parseAccountEvent("user.enabled", {})).toEqual({ type: "user.enabled" });
    expect(parseAccountEvent("access.revoked", {})).toEqual({ type: "access.revoked" });
    expect(parseAccountEvent("access.revoked", { reason: "expired" })).toEqual({ type: "access.revoked", reason: "expired" });
    // Unknown or non-string reasons never fail.
    expect(parseAccountEvent("access.revoked", { reason: 1 })).toEqual({ type: "access.revoked" });
    expect(parseAccountEvent("access.revoked", { reason: "policy" })).toEqual({ type: "access.revoked", reason: "policy" });
    expect(parseAccountEvent("access.changed", { roles: ["admin", "editor"], validUntil: "2026-12-31T23:59:59Z", extra: 1 })).toEqual({
      type: "access.changed",
      roles: ["admin", "editor"],
      validUntil: "2026-12-31T23:59:59Z",
    });
    expect(parseAccountEvent("access.changed", { roles: [], validUntil: null })).toEqual({
      type: "access.changed",
      roles: [],
      validUntil: null,
    });
    // Missing or malformed values never fail: empty roles, unlimited.
    expect(parseAccountEvent("access.changed", {})).toEqual({ type: "access.changed", roles: [], validUntil: null });
    expect(parseAccountEvent("access.changed", { roles: "admin", validUntil: 5 })).toEqual({
      type: "access.changed",
      roles: [],
      validUntil: null,
    });
    expect(parseAccountEvent("access.changed", { roles: ["a", 1, null, "b"] })).toEqual({
      type: "access.changed",
      roles: ["a", "b"],
      validUntil: null,
    });
    expect(parseAccountEvent("link.removed", { localId: "7:42" })).toEqual({ type: "link.removed", localId: "7:42" });
    expect(parseAccountEvent("onboarding.accepted", { localId: "7:42", extra: 1 })).toEqual({
      type: "onboarding.accepted",
      localId: "7:42",
    });
    expect(parseAccountEvent("verification", {})).toEqual({ type: "verification" });
  });

  it("keeps unknown types and rejects malformed data", () => {
    expect(parseAccountEvent("user.archived", { a: 1 })).toEqual({ type: "unknown", eventType: "user.archived", data: { a: 1 } });
    expect(parseAccountEvent("link.removed", {})).toBeUndefined();
    expect(parseAccountEvent("user.email_changed", { email: 1, emailVerified: true })).toBeUndefined();
    expect(parseAccountEvent("user.profile_changed", { changed: [1], displayName: "x" })).toBeUndefined();
    expect(parseAccountEvent("link.removed", { localId: "" })).toBeUndefined();
    expect(parseAccountEvent("user.email_changed", { email: "", emailVerified: true })).toBeUndefined();
    expect(parseAccountEvent("user.disabled", "x")).toBeUndefined();
  });
});

describe("securityEvent", () => {
  it("yields the event", () => {
    expect(securityEvent(base, NOW)).toEqual({
      jti: "j",
      sub: "u",
      toe: NOW - 2,
      iat: NOW,
      env: "production",
      event: { type: "user.disabled" },
    });
  });

  it("allows a missing sub only for verification", () => {
    const v = securityEvent({ ...base, sub: undefined, toe: undefined, events: { "urn:z40:event:verification": {} } }, NOW);
    expect(v.sub).toBeUndefined();
    expect(() => securityEvent({ ...base, sub: undefined }, NOW)).toThrow(/sub/);
  });

  it.each([
    ["no events", { ...base, events: undefined }],
    ["two events", { ...base, events: { "urn:z40:event:user.disabled": {}, "urn:z40:event:user.enabled": {} } }],
    ["foreign prefix", { ...base, events: { "urn:other:user.disabled": {} } }],
    ["empty type", { ...base, events: { "urn:z40:event:": {} } }],
    ["malformed data", { ...base, events: { "urn:z40:event:link.removed": {} } }],
    ["too old", { ...base, iat: NOW - MAX_EVENT_AGE_SECONDS - 1 }],
    ["no jti", { ...base, jti: "" }],
    ["unknown env", { ...base, env: "staging" }],
    ["toe not a number", { ...base, toe: "x" }],
  ])("rejects %s", (_n, raw) => {
    expect(() => securityEvent(raw, NOW)).toThrow();
  });
});
