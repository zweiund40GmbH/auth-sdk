import { describe, expect, it } from "vitest";
import { attributes, CHUNK_SIZE, cookieNames, headerSink, MAX_CHUNKS, parseCookieHeader, readChunked, serializeCookie, writeChunked } from "./cookies.js";

describe("cookies", () => {
  it("uses __Host- and Secure on HTTPS only", () => {
    expect(cookieNames("auth", true).session).toBe("__Host-auth.session");
    expect(cookieNames("auth", false).loginPrefix).toBe("auth.login.");
    expect(serializeCookie("n", "v", attributes(true, 10))).toBe("n=v; Path=/; Max-Age=10; HttpOnly; SameSite=Lax; Secure");
    expect(serializeCookie("n", "v", attributes(false, -5))).toBe("n=v; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
  });

  it("parses a Cookie header", () => {
    const c = parseCookieHeader("a=1; b = 2;c=x=y; a=3; broken");
    expect([c.get("a"), c.get("b"), c.get("c"), c.get("broken")]).toEqual(["1", "2", "x=y", undefined]);
    expect(c.names()).toEqual(["a", "b", "c"]);
  });

  it("splits large values and removes stale chunks", () => {
    const big = "x".repeat(CHUNK_SIZE * 2 + 10);
    const sink = headerSink();
    expect(writeChunked(sink, parseCookieHeader(""), "s", big, attributes(false, 60))).toBe(true);
    expect(sink.headers.map((h) => h.split("=")[0])).toEqual(["s", "s.1", "s.2"]);
    const header = sink.headers.map((h) => h.split(";")[0]).join("; ");
    expect(readChunked(parseCookieHeader(header), "s")).toBe(big);
    const shrink = headerSink();
    writeChunked(shrink, parseCookieHeader(header), "s", "small", attributes(false, 60));
    expect(shrink.headers).toEqual([
      "s=small; Path=/; Max-Age=60; HttpOnly; SameSite=Lax",
      "s.1=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
      "s.2=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
    ]);
  });

  it("refuses values beyond the chunk limit", () => {
    const sink = headerSink();
    expect(writeChunked(sink, parseCookieHeader(""), "s", "x".repeat(CHUNK_SIZE * MAX_CHUNKS + 1), attributes(false, 60))).toBe(false);
    expect(sink.headers).toEqual([]);
  });
});
