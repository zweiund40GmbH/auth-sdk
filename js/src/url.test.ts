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
    // Dot segments that normalize to a protocol-relative URL.
    "/.//evil.example",
    "/a/..//evil.example",
    "/%2e//evil.example",
    "/%2E//evil.example",
    "/..//evil.example/x",
    "/%2e%2e//evil.example",
    "/a/b/../..//evil.example",
    "/././/evil.example",
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

describe("safeReturnTo properties", () => {
  // Building blocks for generated inputs, including the reviewer's examples.
  const parts = ["/", "//", ".", "..", "%2e", "%2E", "%2f", "%5c", "\\", "evil.example", "a", "?x=//y", "#//z", "@", ":", "\t", "%09"];
  /** Deterministic pseudo-random generator (no flaky tests). */
  function* inputs(count: number): Generator<string> {
    let seed = 42;
    const next = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31);
    for (let i = 0; i < count; i++) {
      let v = "/";
      const len = 1 + (next() % 8);
      for (let j = 0; j < len; j++) v += parts[next() % parts.length] ?? "";
      yield v;
    }
  }
  const app = "https://app.example.com";

  it("never yields anything that leaves the origin, and is idempotent", () => {
    for (const v of inputs(5000)) {
      const r = safeReturnTo(v);
      expect(r.startsWith("/") && !r.startsWith("//") && !r.startsWith("/\\"), v).toBe(true);
      expect(new URL(r, app).origin, v).toBe(app);
      expect(safeReturnTo(r), v).toBe(r);
    }
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
