import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { base64url, createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, UnsecuredJWT, type JWTPayload } from "jose";
import { checkIat, sameTyp, tokenHash, verifyJwt, type Expect } from "./jwt.js";

const expect_: Expect = { typ: "JWT", issuer: "https://login.example.com", audience: "my-app", algs: ["RS256", "ES256"] };
const now = () => Math.floor(Date.now() / 1000);
const claims = (): JWTPayload => ({ iss: expect_.issuer, aud: "my-app", sub: "u", iat: now(), exp: now() + 60 });

async function setup() {
  const rs = await generateKeyPair("RS256");
  const jwks = createLocalJWKSet({ keys: [{ ...(await exportJWK(rs.publicKey)), kid: "k1", alg: "RS256" }] });
  const sign = (header: Record<string, unknown>, payload = claims()) =>
    new SignJWT(payload).setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "k1", ...header }).sign(rs.privateKey);
  /** Signs without jose's header checks (to produce a `crit` header). */
  const signRaw = async (header: Record<string, unknown>) => {
    const enc = (o: unknown) => base64url.encode(JSON.stringify(o));
    const input = `${enc({ alg: "RS256", typ: "JWT", kid: "k1", ...header })}.${enc(claims())}`;
    const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", rs.privateKey, new TextEncoder().encode(input));
    return `${input}.${base64url.encode(new Uint8Array(sig))}`;
  };
  return { jwks, sign, signRaw };
}

describe("verifyJwt", () => {
  it("accepts a valid token and rejects wrong typ, missing kid and crit", async () => {
    const { jwks, sign, signRaw } = await setup();
    await expect(verifyJwt(await sign({}), jwks, expect_)).resolves.toMatchObject({ sub: "u" });
    await expect(verifyJwt(await signRaw({}), jwks, expect_)).resolves.toMatchObject({ sub: "u" });
    await expect(verifyJwt(await sign({ typ: "at+jwt" }), jwks, expect_)).rejects.toThrow(/type/);
    await expect(verifyJwt(await sign({ kid: undefined }), jwks, expect_)).rejects.toThrow(/kid/);
    await expect(verifyJwt(await signRaw({ crit: ["x"], x: 1 }), jwks, expect_)).rejects.toThrow(/verification/);
  });

  it("rejects HS256, none and algorithms the provider does not offer", async () => {
    const { jwks, sign } = await setup();
    const hs = await new SignJWT(claims()).setProtectedHeader({ alg: "HS256", typ: "JWT", kid: "k1" }).sign(new Uint8Array(32));
    await expect(verifyJwt(hs, jwks, expect_)).rejects.toThrow(/algorithm/);
    const none = new UnsecuredJWT(claims()).encode();
    await expect(verifyJwt(none, jwks, expect_)).rejects.toThrow(/algorithm|JWS/);
    await expect(verifyJwt(await sign({}), jwks, { ...expect_, algs: ["ES256"] })).rejects.toThrow(/algorithm/);
  });

  it("checks iss, aud, exp and required claims", async () => {
    const { jwks, sign } = await setup();
    await expect(verifyJwt(await sign({}, { ...claims(), iss: "https://other.example.com" }), jwks, expect_)).rejects.toThrow();
    await expect(verifyJwt(await sign({}, { ...claims(), aud: "other" }), jwks, expect_)).rejects.toThrow();
    await expect(verifyJwt(await sign({}, { ...claims(), exp: now() - 120 }), jwks, expect_)).rejects.toThrow();
    const { iat: _iat, ...noIat } = claims();
    await expect(verifyJwt(await sign({}, noIat), jwks, expect_)).rejects.toThrow();
  });
});

describe("helpers", () => {
  it("compares typ per RFC 7515", () => {
    expect(sameTyp("jwt", "JWT") && sameTyp("application/logout+jwt", "logout+jwt")).toBe(true);
    expect(sameTyp("at+jwt", "JWT") || sameTyp("logout+jwt", "JWT")).toBe(false);
  });

  it("rejects iat in the future beyond the leeway", () => {
    expect(() => { checkIat({ iat: 1060 }, 1000); }).not.toThrow();
    expect(() => { checkIat({ iat: 1061 }, 1000); }).toThrow();
    expect(() => { checkIat({}, 1000); }).toThrow();
  });

  it("computes at_hash as the left half of SHA-256", async () => {
    const token = "jHkWEdUXMU1BwAsC4vtUsZwnUdA0y6g4eCPGXwbAeis";
    const expected = createHash("sha256").update(token).digest().subarray(0, 16).toString("base64url");
    expect(await tokenHash(token)).toBe(expected);
    expect(expected).toHaveLength(22);
  });
});
