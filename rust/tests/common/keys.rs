//! Locally generated signing keys for tests (no key files: the secret scan
//! would flag them) and helpers to sign test tokens.

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};

/// A private test key with its public JWK.
pub struct TestKey {
    /// Key id.
    pub kid: String,
    /// Algorithm.
    pub alg: Algorithm,
    /// Public JWK as published in the JWKS.
    pub jwk: Value,
    enc: EncodingKey,
}

/// Encodes bytes as base64url without padding.
pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Splits one DER TLV off `input`: `(content, rest)`.
fn tlv(input: &[u8]) -> (&[u8], &[u8]) {
    let first = input[1] as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        let len = input[2..2 + n]
            .iter()
            .fold(0usize, |a, b| (a << 8) | *b as usize);
        (len, 2 + n)
    };
    (&input[header..header + len], &input[header + len..])
}

/// The PKCS#1 key inside a PKCS#8 `PrivateKeyInfo` (jsonwebtoken wants PKCS#1 for RSA).
fn pkcs1_from_pkcs8(pkcs8: &[u8]) -> Vec<u8> {
    let (info, _) = tlv(pkcs8);
    let (_, rest) = tlv(info); // version
    let (_, rest) = tlv(rest); // algorithm identifier
    let (key, _) = tlv(rest); // privateKey OCTET STRING
    key.to_vec()
}

impl TestKey {
    /// A fresh P-256 key.
    pub fn es256(kid: &str) -> Self {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let point = &pair.public_key().as_ref()[1..];
        let (x, y) = point.split_at(32);
        Self {
            kid: kid.into(),
            alg: Algorithm::ES256,
            jwk: json!({"kty":"EC","crv":"P-256","x":b64(x),"y":b64(y),"kid":kid,"alg":"ES256","use":"sig"}),
            enc: EncodingKey::from_ec_der(pkcs8.as_ref()),
        }
    }

    /// A fresh 2048-bit RSA key (smaller than the provider's 3072 bit: faster tests).
    pub fn rs256(kid: &str) -> Self {
        let pair = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let pkcs8 = pair.as_der().unwrap();
        let public = pair.public_key();
        let n = b64(public.modulus().big_endian_without_leading_zero());
        let e = b64(public.exponent().big_endian_without_leading_zero());
        Self {
            kid: kid.into(),
            alg: Algorithm::RS256,
            jwk: json!({"kty":"RSA","n":n,"e":e,"kid":kid,"alg":"RS256","use":"sig"}),
            enc: EncodingKey::from_rsa_der(&pkcs1_from_pkcs8(pkcs8.as_ref())),
        }
    }

    /// Signs `claims` with header `typ` and this key's `kid`.
    pub fn sign(&self, claims: &Value, typ: &str) -> String {
        let mut header = Header::new(self.alg);
        header.typ = Some(typ.into());
        header.kid = Some(self.kid.clone());
        self.sign_with(&header, claims)
    }

    /// Signs `claims` with an explicit header.
    pub fn sign_with(&self, header: &Header, claims: &Value) -> String {
        jsonwebtoken::encode(header, claims, &self.enc).unwrap()
    }
}

/// An unsigned token with `alg: none`.
pub fn unsigned_token(kid: &str, claims: &Value) -> String {
    let header = json!({"alg": "none", "typ": "JWT", "kid": kid});
    format!(
        "{}.{}.",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    )
}
