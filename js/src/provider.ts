/**
 * Connection to the provider: discovery (openid-client), validation of the
 * metadata, the JWKS (jose) and the one fetch used for all provider calls –
 * with a timeout and **without** following redirects (a redirect could
 * carry the client secret, codes or tokens to another host).
 */

import * as oidc from "openid-client";
import { createRemoteJWKSet, customFetch as joseFetch, type JWTVerifyGetKey } from "jose";
import type { ResolvedConfig } from "./config.js";
import { AuthError } from "./errors.js";
import { SUPPORTED_ALGS } from "./jwt.js";
import { LEEWAY_SECONDS } from "./requirements.js";
import { isSecureUrl } from "./url.js";

/** Timeout of every provider call in seconds. */
const TIMEOUT_SECONDS = 10;

/** Everything needed to talk to the provider. */
export interface ProviderContext {
  /** openid-client configuration (grants, URLs). */
  oidc: oidc.Configuration;
  /** Key lookup for JWT verification. */
  jwks: JWTVerifyGetKey;
  /** Allowed signature algorithms (offered by the provider and supported here). */
  algs: string[];
  /** Issuer, exact. */
  issuer: string;
  /** End-session endpoint, if offered. */
  endSessionEndpoint: string | undefined;
}

/** The configuration needed to connect (a subset of `ResolvedConfig`; no secret = public client). */
export type ConnectConfig = Pick<ResolvedConfig, "issuer" | "clientId" | "tokenEndpointAuthMethod" | "allowLoopbackHttp"> & {
  /** Client secret; `undefined` only for receivers that never call the token endpoint. */
  clientSecret: string | undefined;
};

/** fetch with redirects disabled; a redirect answer is returned as is and then fails as non-2xx. */
export function noRedirectFetch(url: string | URL, init?: RequestInit): Promise<Response> {
  return fetch(url, { ...init, redirect: "manual", signal: init?.signal ?? AbortSignal.timeout(TIMEOUT_SECONDS * 1000) });
}

/** Checks the discovery rules (exact issuer, PKCE S256, algorithms, HTTPS endpoints); returns the algorithms. */
export function validateMetadata(meta: oidc.ServerMetadata, cfg: Pick<ResolvedConfig, "issuer" | "allowLoopbackHttp">): string[] {
  if (meta.issuer !== cfg.issuer) throw new AuthError("discovery", "issuer does not match exactly");
  if (!(meta.code_challenge_methods_supported ?? []).includes("S256")) {
    throw new AuthError("discovery", "PKCE S256 not supported");
  }
  const offered = meta.id_token_signing_alg_values_supported ?? [];
  const algs = SUPPORTED_ALGS.filter((a) => offered.includes(a));
  if (algs.length === 0) throw new AuthError("discovery", "no supported signature algorithm");
  const endpoints = [
    meta.authorization_endpoint,
    meta.token_endpoint,
    meta.jwks_uri,
    meta.userinfo_endpoint,
    meta.revocation_endpoint,
    meta.end_session_endpoint,
  ];
  for (const e of endpoints) {
    if (e === undefined) continue;
    let url: URL;
    try {
      url = new URL(e);
    } catch {
      throw new AuthError("discovery", "endpoint is not a URL");
    }
    if (!isSecureUrl(url, cfg.allowLoopbackHttp)) throw new AuthError("discovery", "endpoint is not HTTPS");
  }
  if (meta.authorization_endpoint === undefined || meta.token_endpoint === undefined || meta.jwks_uri === undefined) {
    throw new AuthError("discovery", "authorization, token or JWKS endpoint missing");
  }
  return algs;
}

/** Loads and validates the discovery document and sets up the JWKS. */
async function connect(cfg: ConnectConfig): Promise<ProviderContext> {
  const auth =
    cfg.clientSecret === undefined
      ? oidc.None()
      : cfg.tokenEndpointAuthMethod === "client_secret_post"
        ? oidc.ClientSecretPost(cfg.clientSecret)
        : oidc.ClientSecretBasic(cfg.clientSecret);
  const issuerUrl = new URL(cfg.issuer);
  const insecure = issuerUrl.protocol === "http:";
  let config: oidc.Configuration;
  try {
    // Same clock tolerance for openid-client's own ID token checks as for the package's.
    config = await oidc.discovery(issuerUrl, cfg.clientId, { [oidc.clockTolerance]: LEEWAY_SECONDS }, auth, {
      // openid-client's body type is a subset of BodyInit (typed with a narrower Uint8Array).
      [oidc.customFetch]: (url, init) => noRedirectFetch(url, init as RequestInit),
      timeout: TIMEOUT_SECONDS,
      // Plain HTTP passed the config check, so it is a loopback issuer outside production.
      // eslint-disable-next-line @typescript-eslint/no-deprecated -- needed for loopback development only
      ...(insecure ? { execute: [oidc.allowInsecureRequests] } : {}),
    });
  } catch (cause) {
    throw new AuthError("discovery", "discovery failed", { cause });
  }
  const meta = config.serverMetadata();
  const algs = validateMetadata(meta, cfg);
  const jwks = createRemoteJWKSet(new URL(meta.jwks_uri ?? ""), {
    timeoutDuration: TIMEOUT_SECONDS * 1000,
    cacheMaxAge: 5 * 60 * 1000,
    cooldownDuration: 30 * 1000,
    [joseFetch]: noRedirectFetch,
  });
  return { oidc: config, jwks, algs, issuer: meta.issuer, endSessionEndpoint: meta.end_session_endpoint };
}

/**
 * Lazily connects once and caches the result. A failed attempt is not
 * cached, so the next request retries.
 */
export function lazyProvider(cfg: ConnectConfig): () => Promise<ProviderContext> {
  let pending: Promise<ProviderContext> | undefined;
  return () => {
    pending ??= connect(cfg).catch((e: unknown) => {
      pending = undefined;
      throw e;
    });
    return pending;
  };
}
