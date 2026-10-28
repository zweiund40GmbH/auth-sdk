import { describe, expect, it } from "vitest";
import { isRevoked, memorySessionStore, recordLogout, type LogoutRecord } from "./store.js";

/** A logout record issued at `iat`. */
const rec = (over: Partial<LogoutRecord>, iat = 100): LogoutRecord => ({
  sub: "u",
  sid: undefined,
  jti: `j-${Math.random()}`,
  iat,
  exp: iat + 120,
  ...over,
});

describe("revocations", () => {
  it("ends sessions of a sid or of a sub created up to the logout", async () => {
    const store = memorySessionStore();
    expect(await recordLogout(store, rec({ sid: "s1" }), 100, 3600, 60)).toBe(true);
    expect(await isRevoked(store, { sub: "u", sid: "s1", createdAt: 100 })).toBe(true);
    expect(await isRevoked(store, { sub: "u", sid: "s2", createdAt: 50 })).toBe(false);
    expect(await isRevoked(store, { sub: "u", sid: "s1", createdAt: 101 })).toBe(false);
    await recordLogout(store, rec({}, 200), 200, 3600, 60);
    expect(await isRevoked(store, { sub: "u", sid: "s2", createdAt: 150 })).toBe(true);
    expect(await isRevoked(store, { sub: "u", sid: undefined, createdAt: 150 })).toBe(true);
    expect(await isRevoked(store, { sub: "other", sid: undefined, createdAt: 150 })).toBe(false);
  });

  it("uses iat as revocation time, bounded by the receipt time", async () => {
    const store = memorySessionStore();
    // Delivered late: sessions created after iat stay valid.
    await recordLogout(store, rec({ sid: "late" }, 100), 160, 3600, 60);
    expect(await isRevoked(store, { sub: "u", sid: "late", createdAt: 100 })).toBe(true);
    expect(await isRevoked(store, { sub: "u", sid: "late", createdAt: 130 })).toBe(false);
    // iat in the future (provider clock ahead): capped at now.
    await recordLogout(store, rec({ sid: "ahead" }, 500), 160, 3600, 60);
    expect(await isRevoked(store, { sub: "u", sid: "ahead", createdAt: 170 })).toBe(false);
  });

  it("rejects a replayed token and does not move the revocation time", async () => {
    const store = memorySessionStore();
    const token = rec({}, 100);
    expect(await recordLogout(store, token, 100, 3600, 60)).toBe(true);
    // A new login after the logout, then the same token again.
    expect(await recordLogout(store, token, 150, 3600, 60)).toBe(false);
    expect(await isRevoked(store, { sub: "u", sid: undefined, createdAt: 140 })).toBe(false);
  });

  it("keeps the latest logout time and forgets after the TTL", async () => {
    const store = memorySessionStore();
    await recordLogout(store, rec({ sid: "s" }, 300), 300, 3600, 60);
    await recordLogout(store, rec({ sid: "s" }, 100), 300, 3600, 60);
    expect(await isRevoked(store, { sub: "u", sid: "s", createdAt: 250 })).toBe(true);
    await store.set("k", "v", 0);
    expect(await store.get("k")).toBeUndefined();
  });
});
