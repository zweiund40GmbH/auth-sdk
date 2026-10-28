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

  it("uses iat plus clock skew as revocation time, bounded by the receipt time", async () => {
    const store = memorySessionStore();
    // Delivered late: sessions created more than the skew after iat stay valid.
    await recordLogout(store, rec({ sid: "late" }, 100), 200, 3600, 60);
    expect(await isRevoked(store, { sub: "u", sid: "late", createdAt: 150 })).toBe(true);
    expect(await isRevoked(store, { sub: "u", sid: "late", createdAt: 170 })).toBe(false);
    // App clock ahead of the provider: a session created just before the logout still ends.
    await recordLogout(store, rec({ sid: "skew" }, 100), 110, 3600, 60);
    expect(await isRevoked(store, { sub: "u", sid: "skew", createdAt: 108 })).toBe(true);
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

  it("does not lose the revocation when the store fails before the jti is written", async () => {
    const inner = memorySessionStore();
    let failNext = true;
    const flaky = {
      get: (k: string) => inner.get(k),
      set: async (k: string, v: string, ttl: number) => {
        if (failNext) {
          failNext = false;
          throw new Error("store down");
        }
        return inner.set(k, v, ttl);
      },
    };
    const token = rec({ sid: "f" }, 100);
    await expect(recordLogout(flaky, token, 100, 3600, 60)).rejects.toThrow();
    // The provider retries the same token: it must still take effect.
    expect(await recordLogout(flaky, token, 101, 3600, 60)).toBe(true);
    expect(await isRevoked(flaky, { sub: "u", sid: "f", createdAt: 100 })).toBe(true);
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
