/**
 * Configuration of the server-to-server parts (event receiver, management
 * client): only issuer, client ID and – for the management API – the
 * client secret. No session secret or redirect URI is needed, so a service
 * without user login can use them too. Same environment variables and the
 * same fail-closed rules as `createAuth`.
 */

import {
  consoleLogger,
  loopbackAllowed,
  processEnv,
  required,
  resolveIssuer,
  type Logger,
  type TokenEndpointAuthMethod,
} from "./config.js";
import { lazyProvider, type ConnectConfig, type ProviderContext } from "./provider.js";

/** Connection options; unset values are read from the environment variables named in brackets. */
export interface ServiceOptions {
  /** Issuer URL, exactly as in the discovery document (`AUTH_ISSUER`). */
  issuer?: string;
  /** Client ID (`AUTH_CLIENT_ID`). */
  clientId?: string;
  /** Client secret (`AUTH_CLIENT_SECRET`); required for the management API only. */
  clientSecret?: string;
  /** Client authentication at the token endpoint. Default: `client_secret_basic`. */
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
  /** Plain HTTP to loopback hosts, only with `NODE_ENV` set and not `production` (as in `createAuth`). */
  allowInsecureLoopback?: boolean;
  /** Source of the `AUTH_*` environment variables. Default: `process.env`. */
  lookup?: (name: string) => string | undefined;
  /** Receives warnings. Default: `console`. */
  logger?: Logger;
}

/** Validated service configuration. */
export interface ServiceConfig extends ConnectConfig {
  /** Warning sink. */
  logger: Logger;
}

/** Validates `options`; with `needSecret` the client secret is required. Throws `AuthError` (`config`). */
export function resolveServiceConfig(options: ServiceOptions, needSecret: boolean): ServiceConfig {
  const lookup = options.lookup ?? processEnv;
  const allowLoopbackHttp = loopbackAllowed(options.allowInsecureLoopback);
  const issuer = resolveIssuer(options.issuer, lookup, allowLoopbackHttp);
  const clientId = required(options.clientId, lookup, "AUTH_CLIENT_ID");
  const clientSecret = needSecret
    ? required(options.clientSecret, lookup, "AUTH_CLIENT_SECRET")
    : (options.clientSecret ?? lookup("AUTH_CLIENT_SECRET"));
  return {
    issuer,
    clientId,
    clientSecret: clientSecret === undefined || clientSecret.trim() === "" ? undefined : clientSecret.trim(),
    tokenEndpointAuthMethod: options.tokenEndpointAuthMethod ?? "client_secret_basic",
    allowLoopbackHttp,
    logger: options.logger ?? consoleLogger,
  };
}

/** The configuration and a lazy provider connection; a configuration error is raised on every use. */
export interface Service {
  /** Validated configuration. */
  cfg: ServiceConfig;
  /** Provider connection (lazy, cached, retried after a failure). */
  provider: () => Promise<ProviderContext>;
}

/** Memoizes the configuration; the provider is connected on first use (so `next build` works without secrets). */
export function lazyService(options: ServiceOptions, needSecret: boolean): () => Service {
  let service: Service | undefined;
  return () => {
    if (service === undefined) {
      const cfg = resolveServiceConfig(options, needSecret);
      service = { cfg, provider: lazyProvider(cfg) };
    }
    return service;
  };
}
