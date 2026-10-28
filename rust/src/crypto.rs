//! Small crypto helpers on top of `aws-lc-rs`: random values for `state`,
//! `nonce` and the PKCE verifier, the S256 challenge, `at_hash` and a
//! constant-time comparison.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Random bytes per generated value (256 bit → 43 base64url characters,
/// also a valid PKCE verifier length, RFC 7636 §4.1).
const RANDOM_BYTES: usize = 32;

/// A fresh random value, base64url without padding.
pub(crate) fn random_value() -> Result<String, crate::Error> {
    let mut buf = [0u8; RANDOM_BYTES];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| crate::Error::Config("system random number generator unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// PKCE `code_challenge` for `verifier` with method S256 (RFC 7636 §4.2).
pub(crate) fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()))
}

/// `at_hash` of an access token (OIDC Core §3.1.3.6): left half of the
/// SHA-256 digest. Both allowed algorithms (RS256, ES256) use SHA-256.
pub(crate) fn token_hash(value: &str) -> String {
    let d = digest(&SHA256, value.as_bytes());
    let bytes = d.as_ref();
    URL_SAFE_NO_PAD.encode(&bytes[..bytes.len() / 2])
}

/// Compares two strings in constant time (for `state` and `nonce`).
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a.as_bytes(), b.as_bytes()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_values_are_long_and_distinct() {
        let a = random_value().unwrap();
        let b = random_value().unwrap();
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
    }

    #[test]
    fn pkce_matches_rfc_7636_example() {
        // RFC 7636 Appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn at_hash_matches_oidc_example() {
        // OIDC Core A.3 (RS256, SHA-256).
        assert_eq!(
            token_hash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"),
            "77QmUPtjPfzWtF2AnpK9RQ"
        );
    }

    #[test]
    fn constant_time_eq_compares_content_and_length() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }
}
