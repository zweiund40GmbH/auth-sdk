import { describe, expect, it, vi } from "vitest";
import { deriveKey, seal, unseal } from "./seal.js";

const secret = "s".repeat(40);
const now = () => Math.floor(Date.now() / 1000);

describe("seal", () => {
  it("round-trips and hides the content", async () => {
    const key = await deriveKey(secret, "session");
    const sealed = await seal({ token: "very-secret-token" }, key, "session", now() + 60);
    expect(sealed.split(".")).toHaveLength(5);
    expect(sealed).not.toContain("very-secret-token");
    expect((await unseal(sealed, key, "session"))?.["token"]).toBe("very-secret-token");
  });

  it("rejects tampering, other keys and other purposes", async () => {
    const key = await deriveKey(secret, "session");
    const sealed = await seal({ a: 1 }, key, "session", now() + 60);
    const parts = sealed.split(".");
    const ct = parts[3] ?? "";
    parts[3] = (ct[0] === "A" ? "B" : "A") + ct.slice(1);
    expect(await unseal(parts.join("."), key, "session")).toBeUndefined();
    expect(await unseal(sealed, await deriveKey("t".repeat(40), "session"), "session")).toBeUndefined();
    // Same secret, other purpose: other key and other typ.
    expect(await unseal(sealed, await deriveKey(secret, "login"), "login")).toBeUndefined();
    expect(await unseal(sealed, key, "login")).toBeUndefined();
    expect(await unseal("garbage", key, "session")).toBeUndefined();
  });

  it("expires", async () => {
    const key = await deriveKey(secret, "login");
    const sealed = await seal({ a: 1 }, key, "login", now() + 600);
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 601_000);
      expect(await unseal(sealed, key, "login")).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});
