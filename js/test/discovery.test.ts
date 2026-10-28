import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthError } from "../src/errors.js";
import { core, Jar, login } from "./helpers.js";
import { MockProvider } from "./mock-provider.js";

let provider: MockProvider;

beforeAll(async () => {
  provider = await new MockProvider().start();
});
afterAll(async () => {
  await provider.stop();
});
beforeEach(() => {
  provider.discovery = {};
  provider.redirectDiscoveryTo = undefined;
});

/** The error code of connecting with the current discovery document. */
async function connectError(): Promise<string | undefined> {
  const c = await core(provider);
  try {
    await c.provider();
    return undefined;
  } catch (e) {
    return e instanceof AuthError ? e.code : "other";
  }
}

describe("discovery", () => {
  it("accepts the mock provider", async () => {
    expect(await connectError()).toBeUndefined();
  });

  it.each([
    ["an issuer that differs", { issuer: "http://127.0.0.1:1" }],
    ["no PKCE S256", { code_challenge_methods_supported: ["plain"] }],
    ["only HMAC/none algorithms", { id_token_signing_alg_values_supported: ["HS256", "none"] }],
    ["a plain-HTTP endpoint on another host", { token_endpoint: "http://login.example.com/token" }],
  ])("rejects %s", async (_name, override) => {
    provider.discovery = override;
    expect(await connectError()).toBe("discovery");
  });

  it("does not follow redirects", async () => {
    provider.redirectDiscoveryTo = `${provider.issuer}/.well-known/openid-configuration`;
    expect(await connectError()).toBe("discovery");
  });

  it("retries after a failed discovery", async () => {
    const c = await core(provider);
    provider.discovery = { code_challenge_methods_supported: [] };
    await expect(c.provider()).rejects.toThrow(AuthError);
    provider.discovery = {};
    await expect(c.provider()).resolves.toBeDefined();
  });

  it("rejects ES256 ID tokens when the provider only offers RS256", async () => {
    provider.discovery = { id_token_signing_alg_values_supported: ["RS256"] };
    const c = await core(provider);
    expect((await login(c, provider, new Jar(), { tweaks: { key: "es" } })).status).toBe(400);
    expect((await login(c, provider, new Jar())).status).toBe(302);
  });

  it("refuses a loopback HTTP issuer in production", async () => {
    vi.stubEnv("NODE_ENV", "production");
    try {
      await expect(core(provider)).rejects.toThrow(/HTTPS/);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
