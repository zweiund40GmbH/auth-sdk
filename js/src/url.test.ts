import { describe, expect, it } from "vitest";
import { isSecureUrl, onOrigin, safeReturnTo } from "./url.js";

describe("safeReturnTo", () => {
  it.each(["/", "/konto", "/a/b?x=1&y=%2F#frag", "/%2F%2Fevil.example"])("keeps %s", (v) => {
    expect(safeReturnTo(v)).toBe(v);
  });

  it.each([
    "https://evil.example/",
    "//evil.example",
    "///evil.example",
    "/\\evil.example",
    "\\\\evil.example",
    "javascript:alert(1)",
    "konto",
    "/\tevil",
    "/\nevil",
    "/x\u0000",
    "",
    "/" + "a".repeat(3000),
  ])("rejects %j", (v) => {
    expect(safeReturnTo(v)).toBe("/");
  });

  it("handles non-strings and a custom fallback", () => {
    expect(safeReturnTo(null)).toBe("/");
    expect(safeReturnTo(undefined, "/start")).toBe("/start");
  });

  it("builds URLs on the given origin only", () => {
    expect(onOrigin("https://app.example.com", "/a?b=1").href).toBe("https://app.example.com/a?b=1");
    expect(onOrigin("https://app.example.com", "//evil.example").href).toBe("https://app.example.com/");
  });
});

describe("isSecureUrl", () => {
  const ok = (u: string, loopback = true) => isSecureUrl(new URL(u), loopback);
  it("allows HTTPS and loopback HTTP in development only", () => {
    expect(ok("https://login.example.com")).toBe(true);
    expect(ok("http://localhost:8400/x") && ok("http://127.0.0.1:1/") && ok("http://[::1]:1/")).toBe(true);
    expect(ok("http://login.example.com/")).toBe(false);
    expect(ok("http://localhost.example.com/")).toBe(false);
    expect(ok("ftp://localhost/")).toBe(false);
    expect(ok("http://localhost/", false)).toBe(false);
  });
});
