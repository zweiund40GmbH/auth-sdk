import { describe, expect, it } from "vitest";
import { authorizeParams, checkRequirements, requirementsFrom } from "./requirements.js";

const NOW = 1_000_000;

describe("requirements", () => {
  it("records max_age, prompt=login and acr_values", () => {
    expect(requirementsFrom({ maxAge: 60, prompt: "login", acrValues: ["urn:z40:mfa", ""] }, NOW)).toEqual({
      maxAge: 60,
      freshLogin: true,
      acrValues: ["urn:z40:mfa"],
      startedAt: NOW,
    });
    expect(requirementsFrom({ prompt: "none", loginHint: "a" }, NOW)).toEqual({ startedAt: NOW });
    expect(() => requirementsFrom({ maxAge: -1 }, NOW)).toThrow();
    expect(() => requirementsFrom({ maxAge: 1.5 }, NOW)).toThrow();
  });

  it("builds the authorize parameters", () => {
    expect(authorizeParams({ prompt: "none", maxAge: 0, acrValues: ["a", "b"], loginHint: "" })).toEqual({
      prompt: "none",
      max_age: "0",
      acr_values: "a b",
    });
  });

  it("checks max_age with leeway", () => {
    const r = requirementsFrom({ maxAge: 60 }, NOW);
    expect(() => { checkRequirements(r, NOW - 30, undefined, NOW); }).not.toThrow();
    expect(() => { checkRequirements(r, NOW - 120, undefined, NOW); }).not.toThrow();
    expect(() => { checkRequirements(r, NOW - 121, undefined, NOW); }).toThrow(/max_age/);
    expect(() => { checkRequirements(r, undefined, undefined, NOW); }).toThrow(/auth_time/);
  });

  it("checks prompt=login against the login start", () => {
    const r = requirementsFrom({ prompt: "login" }, NOW);
    expect(() => { checkRequirements(r, NOW + 5, undefined, NOW + 10); }).not.toThrow();
    expect(() => { checkRequirements(r, NOW - 600, undefined, NOW + 10); }).toThrow(/prompt=login/);
    expect(() => { checkRequirements(requirementsFrom({}, NOW), undefined, undefined, NOW); }).not.toThrow();
  });

  it("checks acr against acr_values", () => {
    const r = requirementsFrom({ acrValues: ["urn:z40:mfa"] }, NOW);
    expect(() => { checkRequirements(r, undefined, "urn:z40:mfa", NOW); }).not.toThrow();
    expect(() => { checkRequirements(r, undefined, "urn:z40:pwd", NOW); }).toThrow(/acr/);
    expect(() => { checkRequirements(r, undefined, undefined, NOW); }).toThrow(/acr/);
  });
});
