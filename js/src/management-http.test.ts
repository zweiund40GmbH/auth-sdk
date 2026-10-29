import { errors } from "jose";
import { describe, expect, it } from "vitest";
import { classify } from "./jwt.js";
import { apiError, validOnBehalfOf } from "./management-http.js";

describe("apiError", () => {
  it("reads the error format and Retry-After", () => {
    const e = apiError(409, JSON.stringify({ error: { code: "conflict", message: "Schon verknüpft." } }), " 12 ");
    expect([e.status, e.apiCode, e.apiMessage, e.retryAfter]).toEqual([409, "conflict", "Schon verknüpft.", 12]);
    expect(e.message).not.toContain("verknüpft");
    const html = apiError(502, "<html>", null);
    expect([html.apiCode, html.apiMessage, html.fields]).toEqual(["unknown", "", {}]);
    expect(apiError(429, "{}", "Wed, 21 Oct 2026 07:28:00 GMT").retryAfter).toBeUndefined();
  });
});

describe("validOnBehalfOf", () => {
  it("allows 1-128 visible ASCII characters", () => {
    expect(validOnBehalfOf("17") && validOnBehalfOf("a:b!~")).toBe(true);
    expect(validOnBehalfOf("") || validOnBehalfOf("a b") || validOnBehalfOf("ä") || validOnBehalfOf("a".repeat(129))).toBe(false);
  });
});

describe("classify", () => {
  it("names the failed check", () => {
    expect(classify(new errors.JWTClaimValidationFailed("x", {}, "iss"))).toBe("issuer");
    expect(classify(new errors.JWTClaimValidationFailed("x", {}, "aud"))).toBe("audience");
    expect(classify(new errors.JWSSignatureVerificationFailed())).toBe("key");
    expect(classify(new errors.JWKSNoMatchingKey())).toBe("key");
    expect(classify(new errors.JWTExpired("x", {}))).toBe("other");
    expect(classify(new TypeError("fetch failed"))).toBe("keys_unavailable");
    expect(classify(new errors.JWKSTimeout())).toBe("keys_unavailable");
  });
});
