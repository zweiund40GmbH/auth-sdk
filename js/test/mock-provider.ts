/**
 * In-process mock OpenID provider for the integration tests: discovery,
 * JWKS (keys generated at start, never stored), token endpoint with
 * authorization code + PKCE and rotating refresh tokens with reuse
 * detection. `authorize()` stands in for the browser round trip.
 */

import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createHash, randomBytes } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT, type JWK, type JWTPayload, type CryptoKey } from "jose";

/** Client credentials the mock accepts. */
export const CLIENT_ID = "my-app";
/** Client secret of the mock client (test value). */
export const CLIENT_SECRET = "test-secret-not-real";

/** How the next ID token should deviate (for negative tests). */
export interface TokenTweaks {
  /** Extra or overriding claims. */
  claims?: Record<string, unknown>;
  /** Header `typ`. */
  typ?: string;
  /** Signing key: `rs` (default), `es`, or `foreign` (not in the JWKS). */
  key?: "rs" | "es" | "foreign";
  /** Leave out the ID token. */
  noIdToken?: boolean;
}

/** Options of a simulated authorization. */
export interface AuthorizeOptions {
  sub?: string;
  sid?: string;
  acr?: string;
  authTime?: number;
  /** `iss` in the callback: default the issuer, `null` = omitted. */
  iss?: string | null;
  /** Answer with this OAuth error instead of a code. */
  error?: string;
  tweaks?: TokenTweaks;
}

interface Grant {
  sub: string;
  sid: string;
  acr: string;
  authTime: number;
  nonce: string;
  challenge: string;
  redirectUri: string;
  scope: string;
  tweaks: TokenTweaks;
}

interface Family {
  grant: Grant;
  current: string;
  revoked: boolean;
}

/** Reads a request body as text. */
export async function body(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

/** Checks `client_secret_basic` (RFC 6749 §2.3.1: both parts form-urlencoded before base64). */
export function basicAuthOk(header: string | undefined): boolean {
  if (header?.startsWith("Basic ") !== true) return false;
  const [id = "", secret = ""] = Buffer.from(header.slice(6), "base64").toString("utf8").split(":");
  return decodeURIComponent(id) === CLIENT_ID && decodeURIComponent(secret) === CLIENT_SECRET;
}

/** The mock provider. */
export class MockProvider {
  issuer = "";
  /** Discovery overrides (for validation tests). */
  discovery: Record<string, unknown> = {};
  /** Count of token endpoint calls per grant type. */
  calls: Record<string, number> = {};
  /** Tweaks applied to the next refresh answer. */
  refreshTweaks: TokenTweaks = {};
  /** Delay of token answers in milliseconds (to test concurrency). */
  delayMs = 0;
  /** `scope` of the last client-credentials request. */
  lastScope: string | undefined;
  /** If set, the discovery endpoint redirects here. */
  redirectDiscoveryTo: string | undefined;
  private server: Server | undefined;
  private rs!: { privateKey: CryptoKey; jwk: JWK };
  private es!: { privateKey: CryptoKey; jwk: JWK };
  private foreign!: { privateKey: CryptoKey };
  private codes = new Map<string, Grant>();
  private families = new Map<string, Family>();

  /** Generates keys and starts listening on a random loopback port. */
  async start(): Promise<this> {
    const make = async (alg: "RS256" | "ES256", kid: string) => {
      const { privateKey, publicKey } = await generateKeyPair(alg);
      return { privateKey, jwk: { ...(await exportJWK(publicKey)), kid, alg, use: "sig" } };
    };
    this.rs = await make("RS256", "rs-1");
    this.es = await make("ES256", "es-1");
    this.foreign = await make("RS256", "rs-1");
    this.server = createServer((req, res) => {
      this.handle(req)
        .then(({ status, json, headers }) => {
          res.writeHead(status, { "content-type": "application/json", ...headers });
          res.end(json === undefined ? "" : JSON.stringify(json));
        })
        .catch(() => {
          res.writeHead(500);
          res.end();
        });
    });
    await new Promise<void>((resolve) => this.server?.listen(0, "127.0.0.1", resolve));
    const { port } = this.server.address() as AddressInfo;
    this.issuer = `http://127.0.0.1:${port}`;
    return this;
  }

  /** Stops the server. */
  async stop(): Promise<void> {
    await new Promise<void>((resolve) => this.server?.close(() => { resolve(); }));
  }

  /** The discovery document. */
  metadata(): Record<string, unknown> {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/oauth2/authorize`,
      token_endpoint: `${this.issuer}/oauth2/token`,
      jwks_uri: `${this.issuer}/.well-known/jwks.json`,
      end_session_endpoint: `${this.issuer}/oauth2/logout`,
      response_types_supported: ["code"],
      id_token_signing_alg_values_supported: ["RS256", "ES256"],
      code_challenge_methods_supported: ["S256"],
      authorization_response_iss_parameter_supported: true,
      backchannel_logout_supported: true,
      ...this.discovery,
    };
  }

  /** Signs a JWT with header `typ` and the chosen key. */
  async sign(claims: JWTPayload, typ: string, key: "rs" | "es" | "foreign" = "rs"): Promise<string> {
    const k = key === "es" ? this.es : key === "foreign" ? this.foreign : this.rs;
    const alg = key === "es" ? "ES256" : "RS256";
    return new SignJWT(claims).setProtectedHeader({ alg, typ, kid: key === "es" ? "es-1" : "rs-1" }).sign(k.privateKey);
  }

  /** A back-channel logout token (valid unless `claims` overrides something). */
  async logoutToken(claims: Record<string, unknown> = {}, typ = "logout+jwt"): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return this.sign(
      {
        iss: this.issuer,
        aud: CLIENT_ID,
        iat: now,
        exp: now + 120,
        jti: randomBytes(8).toString("hex"),
        sid: "sid-1",
        sub: "user-1",
        events: { "http://schemas.openid.net/event/backchannel-logout": {} },
        ...claims,
      },
      typ,
    );
  }

  /** Simulates the browser at the authorize endpoint; returns the callback URL. */
  authorize(authorizeUrl: URL, opts: AuthorizeOptions = {}): URL {
    const p = authorizeUrl.searchParams;
    const callback = new URL(p.get("redirect_uri") ?? "");
    const state = p.get("state") ?? "";
    if (opts.error !== undefined) {
      callback.searchParams.set("error", opts.error);
    } else {
      const code = randomBytes(16).toString("base64url");
      this.codes.set(code, {
        sub: opts.sub ?? "user-1",
        sid: opts.sid ?? "sid-1",
        acr: opts.acr ?? "urn:z40:pwd",
        authTime: opts.authTime ?? Math.floor(Date.now() / 1000),
        nonce: p.get("nonce") ?? "",
        challenge: p.get("code_challenge") ?? "",
        redirectUri: callback.href,
        scope: p.get("scope") ?? "",
        tweaks: opts.tweaks ?? {},
      });
      callback.searchParams.set("code", code);
    }
    callback.searchParams.set("state", state);
    const iss = opts.iss === undefined ? this.issuer : opts.iss;
    if (iss !== null) callback.searchParams.set("iss", iss);
    return callback;
  }

  /** Revokes all refresh tokens (as an SSO logout does). */
  revokeAll(): void {
    for (const f of this.families.values()) f.revoked = true;
  }

  /** Token answer for `grant`; `nonce` only at login. */
  private async tokens(grant: Grant, withNonce: boolean, tweaks: TokenTweaks) {
    const now = Math.floor(Date.now() / 1000);
    const accessToken = randomBytes(24).toString("base64url");
    const atHash = createHash("sha256").update(accessToken).digest().subarray(0, 16).toString("base64url");
    const claims: JWTPayload = {
      iss: this.issuer,
      sub: grant.sub,
      aud: CLIENT_ID,
      iat: now,
      exp: now + 600,
      auth_time: grant.authTime,
      sid: grant.sid,
      acr: grant.acr,
      amr: ["pwd"],
      env: "test",
      name: "Erika Mustermann",
      given_name: "Erika",
      family_name: "Mustermann",
      email: "erika@example.com",
      email_verified: true,
      at_hash: atHash,
      ...(withNonce ? { nonce: grant.nonce } : {}),
      ...tweaks.claims,
    };
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 300,
      scope: grant.scope,
      refresh_token: randomBytes(24).toString("base64url"),
      ...(tweaks.noIdToken === true ? {} : { id_token: await this.sign(claims, tweaks.typ ?? "JWT", tweaks.key) }),
    };
  }

  /** Routes one request. */
  protected async handle(req: IncomingMessage): Promise<{ status: number; json?: unknown; headers?: Record<string, string> }> {
    const url = new URL(req.url ?? "/", this.issuer);
    if (url.pathname === "/.well-known/openid-configuration") {
      if (this.redirectDiscoveryTo !== undefined) return { status: 302, headers: { location: this.redirectDiscoveryTo } };
      return { status: 200, json: this.metadata() };
    }
    if (url.pathname === "/.well-known/jwks.json") return { status: 200, json: { keys: [this.rs.jwk, this.es.jwk] } };
    if (url.pathname !== "/oauth2/token" || req.method !== "POST") return { status: 404 };
    if (!basicAuthOk(req.headers.authorization)) return { status: 401, json: { error: "invalid_client" } };
    const form = new URLSearchParams(await body(req));
    const type = form.get("grant_type") ?? "";
    this.calls[type] = (this.calls[type] ?? 0) + 1;
    if (this.delayMs > 0) await new Promise((r) => setTimeout(r, this.delayMs));
    if (type === "authorization_code") {
      const grant = this.codes.get(form.get("code") ?? "");
      this.codes.delete(form.get("code") ?? "");
      const challenge = createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url");
      if (grant === undefined || grant.challenge !== challenge || grant.redirectUri !== form.get("redirect_uri")) {
        return { status: 400, json: { error: "invalid_grant" } };
      }
      const json = await this.tokens(grant, true, grant.tweaks);
      this.families.set(json.refresh_token, { grant, current: json.refresh_token, revoked: false });
      return { status: 200, json };
    }
    if (type === "refresh_token") {
      const token = form.get("refresh_token") ?? "";
      const family = this.families.get(token);
      if (family === undefined || family.revoked) return { status: 400, json: { error: "invalid_grant" } };
      if (family.current !== token) {
        family.revoked = true;
        return { status: 400, json: { error: "invalid_grant" } };
      }
      const json = await this.tokens(family.grant, false, this.refreshTweaks);
      // Same family: the new token replaces the old one.
      family.current = json.refresh_token;
      this.families.set(json.refresh_token, family);
      return { status: 200, json };
    }
    if (type === "client_credentials") {
      this.lastScope = form.get("scope") ?? undefined;
      return { status: 200, json: { access_token: `cc-${this.calls[type]}`, token_type: "Bearer", expires_in: 300 } };
    }
    return { status: 400, json: { error: "unsupported_grant_type" } };
  }
}
