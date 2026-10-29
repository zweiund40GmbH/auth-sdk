/**
 * Mock provider with a mocked management API: answers come from a queue,
 * requests are recorded. Also signs Security Event Tokens.
 */

import type { IncomingMessage } from "node:http";
import { randomUUID } from "node:crypto";
import { body, CLIENT_ID, MockProvider } from "./mock-provider.js";

/** A recorded management API request. */
export interface SeenRequest {
  method: string;
  /** Path and query. */
  url: string;
  authorization: string | undefined;
  onBehalfOf: string | undefined;
  body: unknown;
}

/** A queued answer. */
export interface Answer {
  status: number;
  json?: unknown;
  headers?: Record<string, string>;
}

/** The mock provider plus management API. */
export class MockManageProvider extends MockProvider {
  /** Answers of the next management API requests. */
  answers: Answer[] = [];
  /** Recorded management API requests. */
  seen: SeenRequest[] = [];
  /** If set, the JWKS endpoint answers this instead of the keys. */
  jwksAnswer: Answer | undefined;

  /** The last recorded request. */
  last(): SeenRequest {
    const r = this.seen.at(-1);
    if (r === undefined) throw new Error("no management request");
    return r;
  }

  /** A Security Event Token (valid unless `claims` overrides something). */
  async eventToken(claims: Record<string, unknown> = {}, typ = "secevent+jwt", key: "rs" | "es" | "foreign" = "es"): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return this.sign(
      {
        iss: this.issuer,
        aud: CLIENT_ID,
        iat: now,
        exp: now + 120,
        jti: randomUUID(),
        sub: "user-1",
        toe: now - 1,
        env: "test",
        events: { "urn:z40:event:user.email_changed": { email: "erika@example.com", emailVerified: true } },
        ...claims,
      },
      typ,
      key,
    );
  }

  /** Routes management API requests to the queue, everything else to the provider. */
  protected override async handle(req: IncomingMessage): Promise<Answer> {
    const url = req.url ?? "/";
    if (url === "/.well-known/jwks.json" && this.jwksAnswer !== undefined) return this.jwksAnswer;
    if (!url.startsWith("/api/v1/manage/")) return super.handle(req);
    const text = await body(req);
    const header = (n: string) => (typeof req.headers[n] === "string" ? req.headers[n] : undefined);
    this.seen.push({
      method: req.method ?? "",
      url,
      authorization: header("authorization"),
      onBehalfOf: header("x-on-behalf-of"),
      body: text === "" ? undefined : (JSON.parse(text) as unknown),
    });
    return this.answers.shift() ?? { status: 500 };
  }
}
