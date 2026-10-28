import { describe, expect, it, vi } from "vitest";
import { deriveKeyRing, seal, unseal } from "./seal.js";

const secret = "s".repeat(40);
const older = "o".repeat(40);
const now = () => Math.floor(Date.now() / 1000);
const ring = (current = secret, previous: string[] = [], purpose: "session" | "login" = "session") =>
  deriveKeyRing(current, previous, purpose);

describe("seal", () => {
  it("round-trips and hides the content", async () => {
    const keys = await ring();
    const sealed = await seal({ token: "very-secret-token" }, keys, "session", now() + 60);
    expect(sealed.split(".")).toHaveLength(5);
    expect(sealed).not.toContain("very-secret-token");
    expect((await unseal(sealed, keys, "session"))?.["token"]).toBe("very-secret-token");
  });

  it("rejects tampering, other keys and other purposes", async () => {
    const keys = await ring();
    const sealed = await seal({ a: 1 }, keys, "session", now() + 60);
    const parts = sealed.split(".");
    const ct = parts[3] ?? "";
    parts[3] = (ct[0] === "A" ? "B" : "A") + ct.slice(1);
    expect(await unseal(parts.join("."), keys, "session")).toBeUndefined();
    expect(await unseal(sealed, await ring("t".repeat(40)), "session")).toBeUndefined();
    // Same secret, other purpose: other key and other typ.
    expect(await unseal(sealed, await ring(secret, [], "login"), "login")).toBeUndefined();
    expect(await unseal(sealed, keys, "login")).toBeUndefined();
    expect(await unseal("garbage", keys, "session")).toBeUndefined();
  });

  it("decrypts with previous secrets but always encrypts with the current one", async () => {
    const old = await ring(older);
    const fromOld = await seal({ a: 1 }, old, "session", now() + 60);
    const rotated = await ring(secret, ["x".repeat(40), older]);
    expect((await unseal(fromOld, rotated, "session"))?.["a"]).toBe(1);
    const fresh = await seal({ a: 2 }, rotated, "session", now() + 60);
    expect(await unseal(fresh, old, "session")).toBeUndefined();
    expect((await unseal(fresh, await ring(), "session"))?.["a"]).toBe(2);
    // Once the old secret is dropped, its values are gone.
    expect(await unseal(fromOld, await ring(), "session")).toBeUndefined();
  });

  it("expires", async () => {
    const keys = await ring(secret, [older], "login");
    const sealed = await seal({ a: 1 }, keys, "login", now() + 600);
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 601_000);
      expect(await unseal(sealed, keys, "login")).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});
