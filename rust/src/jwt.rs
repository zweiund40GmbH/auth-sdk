//! Generic JWT verification shared by ID, access and logout tokens.
//!
//! Strict like the provider's own check: the algorithm must be on the
//! allowlist **and** match the key's `alg` (no algorithm confusion; `none`
//! and HMAC never pass), the key is chosen by `kid` from the provider's JWKS
//! only, the header `typ` must be the one expected for the token kind (an
//! access token cannot stand in for an ID token), `crit` headers are rejected
//! (RFC 7515 §4.1.11), and `iss`, `aud`, `exp`, `nbf`, `iat` are checked with
//! [`LEEWAY_SECS`] of clock skew.

use crate::error::{Error, Result, TokenError};
use crate::jwks::JwksCache;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, Validation};
use serde_json::Value;

/// Allowed clock skew in seconds (same as the provider).
pub(crate) const LEEWAY_SECS: u64 = 60;

/// Header `typ` of ID tokens.
pub(crate) const TYP_ID: &str = "JWT";
/// Header `typ` of access tokens (RFC 9068 §2.1).
pub(crate) const TYP_ACCESS: &str = "at+jwt";
/// Header `typ` of back-channel logout tokens (Back-Channel Logout 1.0 §2.4).
pub(crate) const TYP_LOGOUT: &str = "logout+jwt";

/// What a token must look like.
pub(crate) struct Expect<'a> {
    /// Header `typ`.
    pub typ: &'a str,
    /// Expected `iss`.
    pub issuer: &'a str,
    /// Value that `aud` must contain.
    pub audience: &'a str,
    /// Accepted algorithms.
    pub algs: &'a [Algorithm],
}

/// `typ` comparison per RFC 7515 §4.1.9: case-insensitive, `application/` optional.
fn same_typ(actual: &str, expected: &str) -> bool {
    let strip = |s: &str| {
        let lower = s.to_ascii_lowercase();
        lower
            .strip_prefix("application/")
            .map(str::to_owned)
            .unwrap_or(lower)
    };
    strip(actual) == strip(expected)
}

/// Maps `jsonwebtoken` errors to [`TokenError`].
fn map_error(e: jsonwebtoken::errors::Error) -> TokenError {
    match e.into_kind() {
        ErrorKind::InvalidSignature => TokenError::BadSignature,
        ErrorKind::ExpiredSignature => TokenError::Expired,
        ErrorKind::ImmatureSignature => TokenError::NotYetValid,
        ErrorKind::InvalidIssuer => TokenError::WrongIssuer,
        ErrorKind::InvalidAudience => TokenError::WrongAudience,
        ErrorKind::InvalidAlgorithm => TokenError::AlgNotAllowed,
        ErrorKind::MissingRequiredClaim(c) | ErrorKind::InvalidClaimFormat(c) => {
            TokenError::Claim(claim_name(&c))
        }
        _ => TokenError::Malformed,
    }
}

/// Static name of a registered claim (for [`TokenError::Claim`]).
pub(crate) fn claim_name(c: &str) -> &'static str {
    match c {
        "exp" => "exp",
        "iat" => "iat",
        "iss" => "iss",
        "aud" => "aud",
        "nbf" => "nbf",
        "sub" => "sub",
        _ => "unknown",
    }
}

/// Verifies `token` at the current time and returns its claims as JSON.
pub(crate) async fn verify(
    token: &str,
    http: &reqwest::Client,
    jwks: &JwksCache,
    expect: &Expect<'_>,
) -> Result<Value> {
    verify_at(
        token,
        http,
        jwks,
        expect,
        jsonwebtoken::get_current_timestamp(),
    )
    .await
}

/// Verifies `token` as of `at` (seconds since the epoch) and returns its
/// claims as JSON. `exp`, `nbf` and `iat` are judged against `at` instead
/// of the current time – for a check that is caught up later, with `at` =
/// the time the token was received.
pub(crate) async fn verify_at(
    token: &str,
    http: &reqwest::Client,
    jwks: &JwksCache,
    expect: &Expect<'_>,
    at: u64,
) -> Result<Value> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| TokenError::Malformed)?;
    if !expect.algs.contains(&header.alg) {
        return Err(TokenError::AlgNotAllowed.into());
    }
    if header.crit.is_some() {
        return Err(TokenError::Malformed.into());
    }
    if !header
        .typ
        .as_deref()
        .is_some_and(|t| same_typ(t, expect.typ))
    {
        return Err(TokenError::WrongType.into());
    }
    let kid = header.kid.as_deref().ok_or(TokenError::UnknownKey)?;
    let (key_alg, key) = jwks.key(http, kid).await?;
    if key_alg != header.alg {
        return Err(TokenError::AlgNotAllowed.into());
    }
    let mut validation = Validation::new(header.alg);
    // jsonwebtoken only knows the current time: the time claims are checked
    // below against `at` (exp/nbf/iat, see `check_times`).
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.set_issuer(&[expect.issuer]);
    validation.set_audience(&[expect.audience]);
    validation.set_required_spec_claims(&["exp", "iat", "iss", "aud"]);
    let data = jsonwebtoken::decode::<Value>(token, &key, &validation).map_err(map_error)?;
    check_times(&data.claims, at)?;
    Ok(data.claims)
}

/// Time claims as of `now`, each with [`LEEWAY_SECS`]: `exp` (required)
/// not passed, `nbf` (optional) and `iat` (required) not in the future.
fn check_times(claims: &Value, now: u64) -> Result<(), TokenError> {
    let number = |name: &'static str| match claims.get(name) {
        None => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or(TokenError::Claim(name)),
    };
    let exp = number("exp")?.ok_or(TokenError::Claim("exp"))?;
    if exp.saturating_add(LEEWAY_SECS) < now {
        return Err(TokenError::Expired);
    }
    if number("nbf")?.is_some_and(|nbf| nbf > now.saturating_add(LEEWAY_SECS)) {
        return Err(TokenError::NotYetValid);
    }
    check_iat(claims, now)
}

/// `iat` must be a number and not in the future beyond the leeway.
fn check_iat(claims: &Value, now: u64) -> Result<(), TokenError> {
    let iat = claims
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(TokenError::Claim("iat"))?;
    if iat > now.saturating_add(LEEWAY_SECS) {
        return Err(TokenError::NotYetValid);
    }
    Ok(())
}

/// Deserializes verified claims into `T`.
pub(crate) fn into_claims<T: serde::de::DeserializeOwned>(claims: Value) -> Result<T> {
    serde_json::from_value(claims).map_err(|_| Error::Token(TokenError::Claim("unknown")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn typ_comparison_follows_rfc_7515() {
        assert!(same_typ("JWT", "JWT") && same_typ("jwt", "JWT"));
        assert!(same_typ("application/at+jwt", "at+jwt"));
        assert!(!same_typ("at+jwt", "JWT") && !same_typ("logout+jwt", "at+jwt"));
    }

    #[test]
    fn time_claims_are_judged_at_the_given_time() {
        let claims = json!({"exp": 1000, "nbf": 900, "iat": 900});
        assert!(check_times(&claims, 1060).is_ok());
        assert_eq!(check_times(&claims, 1061), Err(TokenError::Expired));
        assert!(check_times(&claims, 840).is_ok());
        assert_eq!(check_times(&claims, 839), Err(TokenError::NotYetValid));
        assert_eq!(
            check_times(&json!({"iat": 900}), 900),
            Err(TokenError::Claim("exp"))
        );
        assert_eq!(
            check_times(&json!({"exp": 1000.5, "iat": 900}), 900),
            Err(TokenError::Claim("exp"))
        );
        assert_eq!(
            check_times(&json!({"exp": 1000, "nbf": "x", "iat": 900}), 900),
            Err(TokenError::Claim("nbf"))
        );
    }

    #[test]
    fn iat_in_the_future_is_rejected() {
        assert!(check_iat(&json!({"iat": 1000}), 1000).is_ok());
        assert!(check_iat(&json!({"iat": 1060}), 1000).is_ok());
        assert_eq!(
            check_iat(&json!({"iat": 1061}), 1000),
            Err(TokenError::NotYetValid)
        );
        assert_eq!(
            check_iat(&json!({"iat": "x"}), 1000),
            Err(TokenError::Claim("iat"))
        );
    }
}
