/**
 * Revocations for back-channel logout. Session cookies cannot be deleted
 * from the server, so a back-channel logout records "sessions of this
 * `sid` / `sub` created up to time T are over" in a {@link SessionStore}
 * shared by all instances (e.g. Redis or a database table); every session
 * read checks it.
 */

/**
 * Minimal key-value store the application provides. Values are short
 * strings; entries may be dropped after `ttlSeconds`. Must be shared by all
 * instances of the application; must not throw for missing keys.
 */
export interface SessionStore {
  /** Stores `value` under `key` for at least `ttlSeconds` seconds. */
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  /** Returns the value stored under `key`, or `undefined`. */
  get(key: string): Promise<string | undefined>;
}

/** What a session must reveal for the revocation check. */
export interface RevocationSubject {
  /** User id. */
  sub: string;
  /** SSO session id at this client, if the ID token had one. */
  sid: string | undefined;
  /** When the session was created at the application (seconds since the epoch). */
  createdAt: number;
}

/** Key prefix of all entries. */
const PREFIX = "auth-next:revoked:";

/** Store key for a `sid` revocation. */
function sidKey(sid: string): string {
  return `${PREFIX}sid:${sid}`;
}

/** Store key for a `sub` revocation (all sessions of the user). */
function subKey(sub: string): string {
  return `${PREFIX}sub:${sub}`;
}

/** Store key remembering a logout token id (replay protection). */
function jtiKey(jti: string): string {
  return `${PREFIX}jti:${jti}`;
}

/** The parts of a verified logout token {@link recordLogout} needs. */
export interface LogoutRecord {
  /** User. */
  sub: string | undefined;
  /** SSO session id. */
  sid: string | undefined;
  /** Token id. */
  jti: string;
  /** Issue time (seconds). */
  iat: number;
  /** Expiry (seconds). */
  exp: number;
}

/**
 * Records a back-channel logout: with `sid` only that SSO session ends,
 * otherwise all sessions of `sub`. The revocation time is the token's
 * `iat`, bounded by the receipt time `now`, so a later delivery cannot end
 * sessions created after the logout. The `jti` is remembered until the
 * token expires (plus `skew`); a second delivery of the same token returns
 * `false` and changes nothing. Revocations live as long as a session can
 * (`ttlSeconds`).
 */
export async function recordLogout(
  store: SessionStore,
  event: LogoutRecord,
  now: number,
  ttlSeconds: number,
  skew: number,
): Promise<boolean> {
  if ((await store.get(jtiKey(event.jti))) !== undefined) return false;
  await store.set(jtiKey(event.jti), "1", Math.max(1, event.exp - now + skew));
  const key = event.sid !== undefined ? sidKey(event.sid) : event.sub !== undefined ? subKey(event.sub) : undefined;
  if (key === undefined) return true;
  const at = Math.min(event.iat, now);
  const previous = Number(await store.get(key));
  // Keep the latest time: a session created after an earlier logout must still end.
  await store.set(key, String(Math.max(at, Number.isFinite(previous) ? previous : 0)), ttlSeconds);
  return true;
}

/**
 * Whether the session was ended by a back-channel logout: a revocation of
 * its `sid` or its `sub` at or after its creation. Sessions created after
 * the logout (a new login) stay valid.
 */
export async function isRevoked(store: SessionStore, subject: RevocationSubject): Promise<boolean> {
  const [bySid, bySub] = await Promise.all([
    subject.sid !== undefined ? store.get(sidKey(subject.sid)) : Promise.resolve(undefined),
    store.get(subKey(subject.sub)),
  ]);
  return [bySid, bySub].some((v) => v !== undefined && Number(v) >= subject.createdAt);
}

/**
 * In-memory {@link SessionStore} for development, tests and applications
 * with exactly **one** instance. With several instances use a shared store.
 */
export function memorySessionStore(): SessionStore {
  const entries = new Map<string, { value: string; until: number }>();
  return {
    set(key, value, ttlSeconds) {
      const now = Date.now();
      for (const [k, e] of entries) if (e.until <= now) entries.delete(k);
      entries.set(key, { value, until: now + ttlSeconds * 1000 });
      return Promise.resolve();
    },
    get(key) {
      const e = entries.get(key);
      return Promise.resolve(e !== undefined && e.until > Date.now() ? e.value : undefined);
    },
  };
}
