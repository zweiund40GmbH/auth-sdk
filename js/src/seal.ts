/**
 * Cookie encryption: compact JWE with `dir` + `A256GCM` (jose). The key is
 * derived per purpose (session, login state) from the session secret with
 * HKDF-SHA-256, so a sealed value of one kind cannot stand in for another.
 * Expiry is part of the encrypted claims (`exp`), not only of the cookie.
 */

import { EncryptJWT, jwtDecrypt, type JWTPayload } from "jose";

/** What a sealed value is used for (part of the key derivation and of the JWE header). */
export type SealPurpose = "session" | "login";

/** Derives the 256-bit key for `purpose` from `secret`. */
export async function deriveKey(secret: string, purpose: SealPurpose): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(`auth-next ${purpose} v1`),
    },
    base,
    256,
  );
  return new Uint8Array(bits);
}

/** JWE `typ` per purpose. */
function typ(purpose: SealPurpose): string {
  return `auth-next-${purpose}`;
}

/** Encrypts `payload`, valid until `expiresAt` (seconds since the epoch). */
export async function seal(
  payload: JWTPayload,
  key: Uint8Array,
  purpose: SealPurpose,
  expiresAt: number,
): Promise<string> {
  return new EncryptJWT(payload)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM", typ: typ(purpose) })
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .encrypt(key);
}

/**
 * Decrypts a value sealed with {@link seal}. Returns `undefined` for any
 * failure (tampered, wrong key or purpose, expired, malformed) – callers
 * treat all of them as "no value".
 */
export async function unseal(value: string, key: Uint8Array, purpose: SealPurpose): Promise<JWTPayload | undefined> {
  try {
    const { payload } = await jwtDecrypt(value, key, {
      keyManagementAlgorithms: ["dir"],
      contentEncryptionAlgorithms: ["A256GCM"],
      typ: typ(purpose),
      clockTolerance: 0,
    });
    return payload;
  } catch {
    return undefined;
  }
}
