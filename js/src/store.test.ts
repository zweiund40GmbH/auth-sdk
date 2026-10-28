import { describe, expect, it } from "vitest";
import { isRevoked, memorySessionStore, recordLogout } from "./store.js";

describe("revocations", () => {
  it("ends sessions of a sid or of a sub created up to the logout", async () => {
    const store = memorySessionStore();
    await recordLogout(store, { sub: "u", sid: "s1" }, 100, 3600);
    expect(await isRevoked(store, { sub: "u", sid: "s1", createdAt: 100 })).toBe(true);
    expect(await isRevoked(store, { sub: "u", sid: "s2", createdAt: 50 })).toBe(false);
    expect(await isRevoked(store, { sub: "u", sid: "s1", createdAt: 101 })).toBe(false);
    await recordLogout(store, { sub: "u", sid: undefined }, 200, 3600);
    expect(await isRevoked(store, { sub: "u", sid: "s2", createdAt: 150 })).toBe(true);
    expect(await isRevoked(store, { sub: "u", sid: undefined, createdAt: 150 })).toBe(true);
    expect(await isRevoked(store, { sub: "other", sid: undefined, createdAt: 150 })).toBe(false);
  });

  it("keeps the latest logout time and forgets after the TTL", async () => {
    const store = memorySessionStore();
    await recordLogout(store, { sub: undefined, sid: "s" }, 300, 3600);
    await recordLogout(store, { sub: undefined, sid: "s" }, 100, 3600);
    expect(await isRevoked(store, { sub: "u", sid: "s", createdAt: 250 })).toBe(true);
    await store.set("k", "v", 0);
    expect(await store.get("k")).toBeUndefined();
  });
});
