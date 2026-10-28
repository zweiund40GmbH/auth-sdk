//! Parsing the provider's JWKS (RFC 7517) into verification keys. Only
//! signature keys with `kid` and `alg` RS256 (RSA) or ES256 (P-256) are
//! kept; everything else is skipped, never guessed.

use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;

/// One usable verification key.
#[derive(Clone)]
pub(crate) struct Key {
    /// Key id.
    pub kid: String,
    /// The only algorithm this key verifies.
    pub alg: Algorithm,
    /// The public key.
    pub key: DecodingKey,
}

/// A JWK as published (RFC 7517); members we do not use are ignored.
#[derive(Deserialize)]
pub(crate) struct RawJwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    key_use: Option<String>,
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

/// The JWKS document.
#[derive(Deserialize)]
pub(crate) struct RawJwks {
    /// Published keys.
    pub keys: Vec<RawJwk>,
}

/// Converts a JWK into a key; `None` for keys we cannot or must not use
/// (no `kid`, no or unsupported `alg`, encryption keys, wrong key type).
pub(crate) fn convert(jwk: RawJwk) -> Option<Key> {
    if jwk.key_use.as_deref().is_some_and(|u| u != "sig") {
        return None;
    }
    let alg = match jwk.alg.as_deref()? {
        "RS256" => Algorithm::RS256,
        "ES256" => Algorithm::ES256,
        _ => return None,
    };
    let key = match (alg, jwk.kty.as_str()) {
        (Algorithm::RS256, "RSA") => {
            DecodingKey::from_rsa_components(jwk.n.as_deref()?, jwk.e.as_deref()?).ok()?
        }
        (Algorithm::ES256, "EC") if jwk.crv.as_deref() == Some("P-256") => {
            DecodingKey::from_ec_components(jwk.x.as_deref()?, jwk.y.as_deref()?).ok()?
        }
        _ => return None,
    };
    Some(Key {
        kid: jwk.kid?,
        alg,
        key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn raw(v: serde_json::Value) -> RawJwk {
        serde_json::from_value(v).unwrap()
    }

    // P-256 test point (RFC 7517 Appendix A.1).
    const X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
    const Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

    #[test]
    fn ec_key_is_accepted_with_matching_alg() {
        let k = convert(raw(
            json!({"kty":"EC","crv":"P-256","x":X,"y":Y,"kid":"k","alg":"ES256","use":"sig"}),
        ));
        assert!(k.is_some_and(|k| k.kid == "k" && k.alg == Algorithm::ES256));
    }

    #[test]
    fn unusable_keys_are_skipped() {
        let ec = |extra: serde_json::Value| {
            let mut v = json!({"kty":"EC","crv":"P-256","x":X,"y":Y,"kid":"k","alg":"ES256"});
            v.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            convert(raw(v)).is_none()
        };
        assert!(ec(json!({"use": "enc"})));
        assert!(ec(json!({"alg": "HS256"})));
        assert!(ec(json!({"alg": "RS256"})));
        assert!(ec(json!({"crv": "P-384"})));
        assert!(
            convert(raw(
                json!({"kty":"EC","crv":"P-256","x":X,"y":Y,"alg":"ES256"})
            ))
            .is_none()
        );
        assert!(convert(raw(json!({"kty":"EC","crv":"P-256","x":X,"y":Y,"kid":"k"}))).is_none());
    }
}
