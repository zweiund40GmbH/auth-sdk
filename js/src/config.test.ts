import { describe, expect, it } from "vitest";
import { resolveConfig, type AuthOptions } from "./config.js";

const env: Record<string, string> = {
  AUTH_ISSUER: "https://login.example.com",
  AUTH_CLIENT_ID: "my-app",
  AUTH_CLIENT_SECRET: "client-secret-for-tests",
  AUTH_REDIRECT_URI: "https://app.example.com/auth/callback",
  AUTH_POST_LOGOUT_REDIRECT_URI: "https://app.example.com/",
  AUTH_SESSION_SECRET: "x".repeat(32),
  NODE_ENV: "production",
};

/** Resolves with `env` plus `changes` (undefined removes a variable). */
function resolve(changes: Record<string, string | undefined> = {}, options: AuthOptions = {}) {
  const all: Record<string, string | undefined> = { ...env, ...changes };
  return resolveConfig({ lookup: (n) => all[n], logger: { warn: () => undefined }, ...options });
}

describe("resolveConfig", () => {
  it("reads the documented environment variables", () => {
    const cfg = resolve();
    expect(cfg.issuer).toBe("https://login.example.com");
    expect(cfg.clientId).toBe("my-app");
    expect(cfg.appOrigin).toBe("https://app.example.com");
    expect(cfg.secureCookies).toBe(true);
    expect(cfg.allowLoopbackHttp).toBe(false);
    expect(cfg.scopes).toEqual(["openid", "profile", "email", "offline_access"]);
    expect(cfg.basePath).toBe("/auth");
    expect(cfg.sessionMaxAge).toBe(8 * 3600);
  });

  it("lets options override the environment", () => {
    const cfg = resolve({}, { clientId: "other", scopes: ["email"] });
    expect(cfg.clientId).toBe("other");
    expect(cfg.scopes).toEqual(["openid", "email"]);
  });

  it.each([
    ["AUTH_ISSUER", undefined, /AUTH_ISSUER is not set/],
    ["AUTH_CLIENT_SECRET", "  ", /AUTH_CLIENT_SECRET is not set/],
    ["AUTH_SESSION_SECRET", "short", /at least 32/],
    ["AUTH_ISSUER", "http://login.example.com", /HTTPS/],
    ["AUTH_ISSUER", "http://localhost:8400", /HTTPS/],
    ["AUTH_ISSUER", "https://login.example.com?x=1", /query/],
    ["AUTH_REDIRECT_URI", "https://app.example.com/other/callback", /\/auth\/callback/],
    ["AUTH_REDIRECT_URI", "https://app.example.com/auth/callback#x", /fragment/],
    ["AUTH_POST_LOGOUT_REDIRECT_URI", "http://app.example.com/", /HTTPS/],
  ])("fails closed for %s=%j", (name, value, message) => {
    expect(() => resolve({ [name]: value })).toThrow(message);
  });

  it("allows loopback HTTP outside production only", () => {
    const dev = { NODE_ENV: "development", AUTH_ISSUER: "http://localhost:8400", AUTH_REDIRECT_URI: "http://localhost:3000/auth/callback" };
    const cfg = resolve(dev);
    expect(cfg.secureCookies).toBe(false);
    expect(cfg.allowLoopbackHttp).toBe(true);
  });

  it("validates the remaining options", () => {
    expect(() => resolve({}, { sessionMaxAge: 10 })).toThrow(/sessionMaxAge/);
    expect(() => resolve({}, { cookieName: "a;b" })).toThrow(/cookieName/);
    expect(() => resolve({}, { errorPath: "https://evil.example/" })).toThrow(/errorPath/);
    expect(() => resolve({}, { scopes: ["a b"] })).toThrow(/scope/);
    expect(() => resolve({ AUTH_REDIRECT_URI: "https://app.example.com/login/callback" }, { basePath: "/login" })).not.toThrow();
  });
});
