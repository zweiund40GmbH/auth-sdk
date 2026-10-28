import { describe, expect, it } from "vitest";
import { BACKCHANNEL_LOGOUT_EVENT, logoutEvent, logoutTokenFrom, readLimited } from "./backchannel.js";

const base = { jti: "j", sid: "s", events: { [BACKCHANNEL_LOGOUT_EVENT]: {} } };

describe("logoutEvent", () => {
  it("yields sub, sid and jti", () => {
    expect(logoutEvent({ ...base, sub: "u", iat: 1, exp: 2 })).toEqual({ sub: "u", sid: "s", jti: "j", iat: 1, exp: 2 });
    expect(logoutEvent({ ...base, sid: undefined, sub: "u", iat: 1, exp: 2 })).toMatchObject({ sub: "u", sid: undefined });
  });

  it.each([
    ["no events", { jti: "j", sid: "s" }],
    ["other event", { ...base, events: { other: {} } }],
    ["event not an object", { ...base, events: { [BACKCHANNEL_LOGOUT_EVENT]: "x" } }],
    ["events an array", { ...base, events: [] }],
    ["nonce", { ...base, nonce: "n" }],
    ["empty jti", { ...base, jti: "" }],
    ["neither sub nor sid", { ...base, sid: undefined }],
  ])("rejects %s", (_n, raw) => {
    expect(() => logoutEvent(raw)).toThrow();
  });
});

describe("request parsing", () => {
  const req = (body: string, type = "application/x-www-form-urlencoded; charset=utf-8") =>
    new Request("https://app.example.com/auth/backchannel-logout", { method: "POST", headers: { "content-type": type }, body });

  it("takes exactly one logout_token from a form", async () => {
    expect(await logoutTokenFrom(req("logout_token=abc"))).toBe("abc");
    expect(await logoutTokenFrom(req("logout_token=abc", "text/plain"))).toBeUndefined();
    expect(await logoutTokenFrom(req("logout_token="))).toBeUndefined();
    expect(await logoutTokenFrom(req("logout_token=a&logout_token=b"))).toBeUndefined();
  });

  it("limits the body size", async () => {
    expect(await readLimited(req("x".repeat(10)), 10)).toBe("x".repeat(10));
    expect(await readLimited(req("x".repeat(11)), 10)).toBeUndefined();
  });
});
