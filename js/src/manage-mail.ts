/**
 * Mail sending for applications (`POST /manage/mail`, `GET /manage/mail/{id}`, scope `manage:mail.send`):
 * the application hands its mails to the login's mail path instead of running its own SMTP.
 *
 * Errors are {@link ManagementError}s: `409` with `apiCode` `mail_disabled` or `idempotency_conflict`,
 * `422` with `fields` (`to`, `to[2]`, `subject`, …), `413` (request over 256 KiB), `429` with `retryAfter`
 * (seconds) and `503`; repeat after `429`/`503`/network failures with the **same** `idempotencyKey`.
 */

import { AuthError, configError } from "./errors.js";
import type { ApiCaller } from "./management-http.js";

/** Longest idempotency key the API accepts. */
const MAX_KEY_LENGTH = 100;
/** Characters the API accepts in an idempotency key. */
const KEY_PATTERN = /^[A-Za-z0-9._:-]{1,100}$/;

/** A mail to send (`POST /manage/mail`). The sender is set by the login, never by the request. */
export interface NewMail {
  /** 1–50 recipients; each one gets an individual mail (recipients do not see each other). */
  to: string[];
  /** 1–200 characters, one line. */
  subject: string;
  /** Plain text, 1–100 000 characters (required). */
  text: string;
  /** Optional HTML (at most 200 000 characters); the server sanitizes it to simple markup. */
  html?: string;
  /** Optional reply address. */
  replyTo?: string;
  /**
   * Key of the operation, 1–100 characters of `[A-Za-z0-9._:-]`, unique per application for 7 days. Derive it
   * from your own ids with {@link mailIdempotencyKey}, not randomly per attempt; never put personal data in it.
   */
  idempotencyKey: string;
}

/** Delivery state of a mail dispatch. */
export type MailStatus = "pending" | "sent" | "failed" | (string & {});

/** Answer of {@link ManagementClient.mail}`.send`. */
export interface MailReceipt {
  /** Id of the dispatch (use it for `mail.status`). */
  id: string;
  /** `pending` for a new dispatch; a repetition reports the current state. */
  status: MailStatus;
  /** Number of recipients (one mail each). */
  recipients: number;
  /** `true` if the key was known and nothing was queued again (answer `200`), `false` for a new dispatch (`202`). */
  repeated: boolean;
}

/** Progress of a dispatch (`GET /manage/mail/{id}`; kept for 30 days, then `404`). */
export interface MailProgress {
  /** Id of the dispatch. */
  id: string;
  /** `pending` (some still open), `sent` (all delivered) or `failed` (none open, at least one failed for good). */
  status: MailStatus;
  /** Number of recipients. */
  recipients: number;
  /** Delivered mails. */
  sent: number;
  /** Finally failed mails. */
  failed: number;
  /** Mails still open. */
  pending: number;
  /** When the dispatch was queued (ISO 8601). */
  createdAt: string;
}

/** The mail part of the management client. */
export interface MailClient {
  /**
   * Queues a mail (scope `manage:mail.send`). The same request under the same key is answered with the
   * existing dispatch (`repeated: true`) and sends nothing again. A key reused for other content is
   * `409 idempotency_conflict`. Invalid input (empty `to`, bad key) is a config error before anything is sent.
   */
  send(mail: NewMail): Promise<MailReceipt>;
  /** The progress of an own dispatch (`404` for unknown, foreign or expired ids). */
  status(id: string): Promise<MailProgress>;
}

/**
 * Builds a stable, collision-free idempotency key from ids of your own, e.g.
 * `mailIdempotencyKey("order", 123)` → `order:123`. The same parts always give the same key, so a retried
 * send is recognised; different parts never give the same key.
 *
 * Encoding (identical in the Rust SDK): each part is converted to text and encoded as UTF-8; the bytes
 * `A–Z a–z 0–9 . -` stay, every other byte (including `_` and `:`) becomes `_` plus two lowercase hex digits
 * (`ü` → `_c3_bc`, `_` → `_5f`, `:` → `_3a`); the parts are joined with `:`. Empty parts are allowed and give
 * empty sections. No parts, an empty result (a single empty part), a part with an unpaired UTF-16 surrogate
 * (it has no UTF-8 form and would collide with other parts), or a result over 100 characters is a config error.
 * Pass ids, never personal data (the server stores the key).
 */
export function mailIdempotencyKey(...parts: (string | number)[]): string {
  if (parts.length === 0) throw configError("idempotency key needs at least one part");
  if (parts.some((p) => /\p{Surrogate}/u.test(String(p)))) {
    throw configError("idempotency key parts must not contain unpaired UTF-16 surrogates");
  }
  const encoder = new TextEncoder();
  const encodePart = (part: string | number): string =>
    Array.from(encoder.encode(String(part)), (byte) => {
      const ch = String.fromCharCode(byte);
      return byte < 0x80 && /[A-Za-z0-9.-]/.test(ch) ? ch : `_${byte.toString(16).padStart(2, "0")}`;
    }).join("");
  const key = parts.map(encodePart).join(":");
  if (key.length === 0) throw configError("idempotency key is empty");
  if (key.length > MAX_KEY_LENGTH) {
    throw configError(`idempotency key is ${key.length} characters long, at most ${MAX_KEY_LENGTH} are allowed`);
  }
  return key;
}

/** Thrown for answers that do not have the contract's form. */
function invalid(): AuthError {
  return new AuthError("provider_error", "invalid management API answer (mail)");
}

/** Checks the request before sending, so mistakes surface locally. */
function checkMail(mail: NewMail): void {
  if (!KEY_PATTERN.test(mail.idempotencyKey)) {
    throw configError(`idempotencyKey must be 1-${MAX_KEY_LENGTH} characters of [A-Za-z0-9._:-]`);
  }
  if (mail.to.length === 0) throw configError("to must contain at least one recipient");
}

/** The mail client on top of `call`. */
export function mailClient(call: ApiCaller): MailClient {
  return {
    send: async (mail) => {
      checkMail(mail);
      let status = 0;
      const body = {
        to: mail.to,
        subject: mail.subject,
        text: mail.text,
        html: mail.html,
        replyTo: mail.replyTo,
        idempotencyKey: mail.idempotencyKey,
      };
      const r = (await call({ method: "POST", path: ["mail"], body, onStatus: (s) => (status = s) })) as
        | Record<string, unknown>
        | undefined;
      if (typeof r?.["id"] !== "string" || typeof r["status"] !== "string" || typeof r["recipients"] !== "number") {
        throw invalid();
      }
      return { id: r["id"], status: r["status"], recipients: r["recipients"], repeated: status === 200 };
    },
    status: async (id) => {
      const r = (await call({ method: "GET", path: ["mail", id] })) as Record<string, unknown> | undefined;
      const numbers = ["recipients", "sent", "failed", "pending"] as const;
      if (
        typeof r?.["id"] !== "string" ||
        typeof r["status"] !== "string" ||
        typeof r["createdAt"] !== "string" ||
        numbers.some((k) => typeof r[k] !== "number")
      ) {
        throw invalid();
      }
      return r as unknown as MailProgress;
    },
  };
}
