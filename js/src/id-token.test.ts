import { describe, expect, it } from "vitest";
import { toIdClaims } from "./id-token.js";
import { toSession, type SessionData } from "./session.js";

describe("name claims", () => {
  it("maps given_name and family_name", () => {
    const c = toIdClaims({ sub: "u", given_name: "Erika", family_name: "Mustermann" });
    expect(c.givenName).toBe("Erika");
    expect(c.familyName).toBe("Mustermann");
  });

  it("treats absent and empty values as absent", () => {
    expect(toIdClaims({ sub: "u" }).givenName).toBeUndefined();
    const c = toIdClaims({ sub: "u", given_name: "", family_name: 5 });
    expect(c.givenName).toBeUndefined();
    expect(c.familyName).toBeUndefined();
  });

  it("exposes them on the session user, and omits them for sessions stored by 0.1.0", () => {
    const base = { accessToken: "a", idToken: "i", scope: "openid profile", expiresAt: 9, createdAt: 1 };
    const full = toSession({ ...base, claims: toIdClaims({ sub: "u", given_name: "Erika", family_name: "Mustermann" }) } as SessionData);
    expect(full.user).toMatchObject({ givenName: "Erika", familyName: "Mustermann" });
    // Claims as 0.1.0 wrote them into the cookie: the new fields are simply missing.
    const old = toSession({ ...base, claims: { sub: "u", name: "Erika", amr: [] } } as unknown as SessionData);
    expect(old.user).toEqual({ sub: "u", name: "Erika" });
  });
});
