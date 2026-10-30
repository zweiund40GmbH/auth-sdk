//! Idempotency keys for [`Management::mail_send`](crate::Management::mail_send):
//! derived from the application's own operation, never random per attempt,
//! so a retry after a network error is recognised and nothing is sent twice.

use crate::error::{Error, Result};
use serde::Serialize;

/// Longest key the provider accepts.
const MAX_LEN: usize = 100;

/// A valid idempotency key: 1–100 characters of `A–Z a–z 0–9 . _ : -`.
/// The provider keeps it per application for 7 days; the same key with
/// other content is answered with `409 idempotency_conflict`.
///
/// Do not put personal data (e.g. addresses) into it: it is stored.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Uses `key` unchanged; [`Error::Config`] unless it has 1–100
    /// characters of `A–Z a–z 0–9 . _ : -`.
    pub fn new(key: impl Into<String>) -> Result<Self> {
        let key = key.into();
        let allowed = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-');
        if key.is_empty() || key.len() > MAX_LEN || !key.bytes().all(allowed) {
            return Err(Error::Config(
                "idempotency key must be 1-100 characters of A-Z a-z 0-9 . _ : -",
            ));
        }
        Ok(Self(key))
    }

    /// A stable, collision-free key from the parts of an application-owned
    /// id, e.g. `from_parts(&["order", "123"])` → `order:123`.
    ///
    /// Encoding (fixed, identical in all SDKs): each part is taken as UTF-8;
    /// the bytes `A–Z a–z 0–9 . -` stay, every other byte (also `_` and `:`)
    /// becomes `_` plus two lower-case hex digits (`ü` → `_c3_bc`,
    /// `_` → `_5f`, `:` → `_3a`); the parts are joined with `:`. Empty parts
    /// are allowed. No parts, an empty result or more than 100 characters
    /// give [`Error::Config`].
    pub fn from_parts(parts: &[&str]) -> Result<Self> {
        if parts.is_empty() {
            return Err(Error::Config("idempotency key needs at least one part"));
        }
        let encoded: Vec<String> = parts.iter().map(|p| encode_part(p)).collect();
        Self::new(encoded.join(":"))
    }

    /// The key as sent to the provider.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IdempotencyKey {
    /// The key itself (not secret).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Escapes one part: unreserved bytes stay, all others become `_xx`.
fn encode_part(part: &str) -> String {
    let mut out = String::with_capacity(part.len());
    for b in part.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("_{b:02x}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(parts: &[&str]) -> String {
        IdempotencyKey::from_parts(parts).unwrap().to_string()
    }

    #[test]
    fn parts_are_encoded_like_the_other_sdks() {
        assert_eq!(key(&["order", "123"]), "order:123");
        assert_eq!(key(&["Müller", "a_b:c"]), "M_c3_bcller:a_5fb_3ac");
        assert_eq!(key(&["", "x"]), ":x");
        assert_eq!(key(&["a.b-C9"]), "a.b-C9");
    }

    #[test]
    fn different_parts_never_collide() {
        let keys = [
            key(&["Müller"]),
            key(&["Möller"]),
            key(&["M_ller"]),
            key(&["a:b"]),
            key(&["a", "b"]),
            key(&["a_3ab"]),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn length_and_empty_input_are_checked() {
        assert_eq!(key(&[&"a".repeat(100)]).len(), 100);
        assert!(IdempotencyKey::from_parts(&[&"a".repeat(101)]).is_err());
        assert!(IdempotencyKey::from_parts(&["a".repeat(95).as_str(), "ü"]).is_err());
        assert!(IdempotencyKey::from_parts(&[]).is_err());
        assert!(IdempotencyKey::from_parts(&[""]).is_err());
    }

    #[test]
    fn raw_keys_are_validated() {
        assert!(IdempotencyKey::new("rechnung-2026-0815:erinnerung-1").is_ok());
        assert!(IdempotencyKey::new("a_b.c").is_ok());
        assert!(IdempotencyKey::new("").is_err());
        assert!(IdempotencyKey::new("a b").is_err());
        assert!(IdempotencyKey::new("ä").is_err());
        assert!(IdempotencyKey::new("a".repeat(101)).is_err());
    }
}
