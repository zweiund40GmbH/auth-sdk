//! ID token checks at the end of the login: every rule gets its own case.

// Test helper functions outside #[test] may panic on setup failures.
#![allow(clippy::unwrap_used)]

mod common;

use common::keys::{TestKey, unsigned_token};
use common::{REDIRECT, client, id_claims, now, start, token_body};
use jsonwebtoken::{Algorithm, Header};
use serde_json::{Value, json};
use z40_auth::{CallbackParams, Client, Error, LoginResult, TokenError};

/// Runs a login whose token endpoint returns the ID token built by `make`
/// from the valid claims (nonce already set).
async fn login_with(
    mock: &common::Mock,
    c: &Client,
    make: impl FnOnce(Value) -> String,
) -> Result<LoginResult, Error> {
    let login = c.begin_login(REDIRECT, &[], &[]).unwrap().state;
    mock.token_ok(token_body(&make(id_claims(mock, Some(&login.nonce)))));
    let params = CallbackParams {
        code: Some("code".into()),
        state: Some(login.state.clone()),
        iss: Some(mock.issuer.clone()),
        ..Default::default()
    };
    c.complete_login(&login, &params).await
}

/// Asserts that the login fails with `expected`.
fn assert_token_error(r: Result<LoginResult, Error>, expected: TokenError) {
    match r {
        Err(Error::Token(e)) => assert_eq!(e, expected),
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

#[tokio::test]
async fn rs256_tokens_are_accepted() {
    let key = TestKey::rs256("rsa-1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let r = login_with(&mock, &c, |claims| key.sign(&claims, "JWT")).await;
    assert_eq!(r.unwrap().claims.sub, "user-1");
}

#[tokio::test]
async fn claim_rules() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let cases: Vec<(&str, Value, TokenError)> = vec![
        (
            "iss",
            json!("https://evil.example.com"),
            TokenError::WrongIssuer,
        ),
        ("aud", json!("other-app"), TokenError::WrongAudience),
        ("nonce", json!("other-nonce"), TokenError::WrongNonce),
        ("exp", json!(now() - 120), TokenError::Expired),
        ("iat", json!(now() + 600), TokenError::NotYetValid),
        ("nbf", json!(now() + 600), TokenError::NotYetValid),
        ("azp", json!("other-app"), TokenError::WrongAzp),
        ("at_hash", json!("wrong-hash"), TokenError::AtHashMismatch),
    ];
    for (claim, value, expected) in cases {
        let r = login_with(&mock, &c, |mut claims| {
            claims[claim] = value;
            key.sign(&claims, "JWT")
        })
        .await;
        assert_token_error(r, expected);
    }
}

#[tokio::test]
async fn missing_nonce_and_several_audiences_without_azp_are_rejected() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let r = login_with(&mock, &c, |mut claims| {
        claims.as_object_mut().unwrap().remove("nonce");
        key.sign(&claims, "JWT")
    })
    .await;
    assert_token_error(r, TokenError::WrongNonce);
    let r = login_with(&mock, &c, |mut claims| {
        claims["aud"] = json!(["app", "other"]);
        key.sign(&claims, "JWT")
    })
    .await;
    assert_token_error(r, TokenError::WrongAzp);
}

#[tokio::test]
async fn small_clock_skew_is_tolerated() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let r = login_with(&mock, &c, |mut claims| {
        claims["exp"] = json!(now() - 10);
        claims["iat"] = json!(now() + 10);
        key.sign(&claims, "JWT")
    })
    .await;
    assert!(r.is_ok());
}

#[tokio::test]
async fn header_rules() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;

    let r = login_with(&mock, &c, |claims| unsigned_token("k1", &claims)).await;
    assert_token_error(r, TokenError::Malformed);

    let r = login_with(&mock, &c, |claims| key.sign(&claims, "at+jwt")).await;
    assert_token_error(r, TokenError::WrongType);

    let r = login_with(&mock, &c, |claims| {
        // No `typ` at all.
        let mut h = Header::new(Algorithm::ES256);
        h.typ = None;
        h.kid = Some("k1".into());
        key.sign_with(&h, &claims)
    })
    .await;
    assert_token_error(r, TokenError::WrongType);

    let r = login_with(&mock, &c, |claims| {
        let mut h = Header::new(Algorithm::ES256);
        h.typ = Some("JWT".into());
        h.kid = Some("k1".into());
        h.crit = Some(vec!["exp".into()]);
        key.sign_with(&h, &claims)
    })
    .await;
    assert_token_error(r, TokenError::Malformed);

    let r = login_with(&mock, &c, |claims| {
        let mut h = Header::new(Algorithm::HS256);
        h.typ = Some("JWT".into());
        h.kid = Some("k1".into());
        let secret = jsonwebtoken::EncodingKey::from_secret(b"guessable");
        jsonwebtoken::encode(&h, &claims, &secret).unwrap()
    })
    .await;
    assert_token_error(r, TokenError::AlgNotAllowed);
}

#[tokio::test]
async fn foreign_signature_under_a_known_kid_is_rejected() {
    let key = TestKey::es256("k1");
    let attacker = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let r = login_with(&mock, &c, |claims| attacker.sign(&claims, "JWT")).await;
    assert_token_error(r, TokenError::BadSignature);
}

#[tokio::test]
async fn key_algorithm_must_match_header() {
    // An RSA key published with alg RS256 must not verify an ES256 header and vice versa.
    let rsa = TestKey::rs256("shared");
    let ec = TestKey::es256("shared");
    let mock = start(&[&rsa]).await;
    let c = client(&mock).await;
    let r = login_with(&mock, &c, |claims| ec.sign(&claims, "JWT")).await;
    assert_token_error(r, TokenError::AlgNotAllowed);
}

#[tokio::test]
async fn missing_id_token_is_rejected() {
    let mock = start(&[]).await;
    let c = client(&mock).await;
    let login = c.begin_login(REDIRECT, &[], &[]).unwrap().state;
    let mut body = token_body("x");
    body.as_object_mut().unwrap().remove("id_token");
    mock.token_ok(body);
    let params = CallbackParams {
        code: Some("code".into()),
        state: Some(login.state.clone()),
        iss: Some(mock.issuer.clone()),
        ..Default::default()
    };
    let r = c.complete_login(&login, &params).await;
    assert_token_error(r, TokenError::Claim("id_token"));
}
