//! `max_age`, `prompt=login` and `acr_values` are enforced at the end of
//! the login, even if the browser dropped them from the authorize URL.

mod common;

use common::keys::TestKey;
use common::{Mock, REDIRECT, client, id_claims, now, start, token_body};
use serde_json::{Value, json};
use z40_auth::{CallbackParams, Client, Error, LoginResult, TokenError};

/// Login with `extra` parameters; `edit` adjusts the ID token claims.
async fn login(
    mock: &Mock,
    c: &Client,
    key: &TestKey,
    extra: &[(&str, &str)],
    edit: impl FnOnce(&mut Value),
) -> Result<LoginResult, Error> {
    let login = c.begin_login(REDIRECT, &[], extra)?.state;
    let mut claims = id_claims(mock, Some(&login.nonce));
    edit(&mut claims);
    mock.token_ok(token_body(&key.sign(&claims, "JWT")));
    let params = CallbackParams {
        code: Some("code".into()),
        state: Some(login.state.clone()),
        iss: Some(mock.issuer.clone()),
        ..Default::default()
    };
    c.complete_login(&login, &params).await
}

/// The token error of `r`.
fn token_error(r: Result<LoginResult, Error>) -> TokenError {
    match r {
        Err(Error::Token(e)) => e,
        other => panic!("expected token error, got {other:?}"),
    }
}

#[tokio::test]
async fn max_age_is_enforced() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let extra = [("max_age", "60")];
    assert!(login(&mock, &c, &key, &extra, |_| {}).await.is_ok());
    let old = login(&mock, &c, &key, &extra, |c| {
        c["auth_time"] = json!(now() - 3600)
    })
    .await;
    assert_eq!(token_error(old), TokenError::AuthTooOld);
    let missing = login(&mock, &c, &key, &extra, |c| {
        c.as_object_mut().unwrap().remove("auth_time");
    })
    .await;
    assert_eq!(token_error(missing), TokenError::Claim("auth_time"));
}

#[tokio::test]
async fn prompt_login_needs_a_new_authentication() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let extra = [("prompt", "login")];
    assert!(login(&mock, &c, &key, &extra, |_| {}).await.is_ok());
    let reused = login(&mock, &c, &key, &extra, |c| {
        c["auth_time"] = json!(now() - 600)
    })
    .await;
    assert_eq!(token_error(reused), TokenError::AuthTooOld);
}

#[tokio::test]
async fn requested_acr_is_enforced() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let extra = [("acr_values", "urn:z40:mfa")];
    let pwd_only = login(&mock, &c, &key, &extra, |_| {}).await;
    assert_eq!(token_error(pwd_only), TokenError::InsufficientAcr);
    let mfa = login(&mock, &c, &key, &extra, |c| c["acr"] = json!("urn:z40:mfa")).await;
    assert_eq!(mfa.unwrap().claims.acr.as_deref(), Some("urn:z40:mfa"));
    // Without acr_values the acr is only reported.
    assert!(login(&mock, &c, &key, &[], |_| {}).await.is_ok());
}

#[tokio::test]
async fn invalid_requirement_parameters_are_rejected() {
    let mock = start(&[]).await;
    let c = client(&mock).await;
    assert!(matches!(
        c.begin_login(REDIRECT, &[], &[("max_age", "soon")]),
        Err(Error::Config(_))
    ));
    let twice = [("acr_values", "a"), ("acr_values", "b")];
    assert!(matches!(
        c.begin_login(REDIRECT, &[], &twice),
        Err(Error::Config(_))
    ));
}
