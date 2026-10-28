//! JWKS cache: refetch on unknown `kid` and its rate limit.

mod common;

use common::keys::TestKey;
use common::{CLIENT_ID, client, client_with, now, start};
use serde_json::json;
use std::time::Duration;
use z40_auth::{AuthMethod, Error, TokenError};

/// A valid access token for `issuer`.
fn access_claims(issuer: &str) -> serde_json::Value {
    json!({
        "iss": issuer, "sub": "user-1", "aud": CLIENT_ID, "client_id": CLIENT_ID,
        "scope": "openid", "exp": now() + 300, "iat": now(), "jti": "j1", "env": "test",
    })
}

#[tokio::test]
async fn unknown_kid_triggers_a_refetch() {
    let old = TestKey::es256("old");
    let new = TestKey::es256("new");
    let mock = start(&[&old]).await;
    let c = client(&mock).await;
    let token = old.sign(&access_claims(&mock.issuer), "at+jwt");
    c.verify_access_token(&token, CLIENT_ID).await.unwrap();
    assert_eq!(mock.jwks_hits(), 1);

    // Cached: no second fetch for a known kid.
    c.verify_access_token(&token, CLIENT_ID).await.unwrap();
    assert_eq!(mock.jwks_hits(), 1);

    // Rotation: the new key is only in the refreshed JWKS.
    mock.set_keys(&[&old, &new]);
    let token = new.sign(&access_claims(&mock.issuer), "at+jwt");
    c.verify_access_token(&token, CLIENT_ID).await.unwrap();
    assert_eq!(mock.jwks_hits(), 2);
}

#[tokio::test]
async fn refetches_are_rate_limited() {
    let known = TestKey::es256("known");
    let forged = TestKey::es256("forged");
    let mock = start(&[&known]).await;
    let c = client_with(&mock, AuthMethod::Basic, Duration::from_secs(60)).await;
    let token = forged.sign(&access_claims(&mock.issuer), "at+jwt");
    for _ in 0..5 {
        let r = c.verify_access_token(&token, CLIENT_ID).await;
        assert!(matches!(r, Err(Error::Token(TokenError::UnknownKey))));
    }
    assert_eq!(mock.jwks_hits(), 1);
}

#[tokio::test]
async fn token_without_kid_is_rejected() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("at+jwt".into());
    let token = key.sign_with(&header, &access_claims(&mock.issuer));
    let r = c.verify_access_token(&token, CLIENT_ID).await;
    assert!(matches!(r, Err(Error::Token(TokenError::UnknownKey))));
    assert_eq!(mock.jwks_hits(), 0);
}
