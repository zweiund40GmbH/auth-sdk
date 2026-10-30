//! Login flow against the mock provider: authorize URL, callback checks
//! (state, iss, error responses) and the token request.

mod common;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::keys::TestKey;
use common::{CLIENT_ID, REDIRECT, SECRET, client, client_with, id_claims, start, token_body};
use std::time::Duration;
use z40_auth::{AuthMethod, CallbackParams, Error, LoginState};

/// Callback query for `login` with the mock's issuer.
fn callback(issuer: &str, login: &LoginState) -> CallbackParams {
    CallbackParams {
        code: Some("the-code".into()),
        state: Some(login.state.clone()),
        iss: Some(issuer.into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn authorize_url_carries_pkce_state_and_nonce() {
    let mock = start(&[]).await;
    let c = client(&mock).await;
    let req = c
        .begin_login(REDIRECT, &["email", "openid"], &[("prompt", "login")])
        .unwrap();
    let q: std::collections::HashMap<_, _> = req.url.query_pairs().into_owned().collect();
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["client_id"], CLIENT_ID);
    assert_eq!(q["redirect_uri"], REDIRECT);
    assert_eq!(q["scope"], "openid email");
    assert_eq!(q["state"], req.state.state);
    assert_eq!(q["nonce"], req.state.nonce);
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["prompt"], "login");
    let digest = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        req.state.pkce_verifier.as_bytes(),
    );
    assert_eq!(q["code_challenge"], URL_SAFE_NO_PAD.encode(digest));
    assert!(
        req.url
            .as_str()
            .starts_with(&format!("{}/oauth2/authorize?", mock.issuer))
    );
    assert_ne!(req.state.state, req.state.nonce);
}

#[tokio::test]
async fn reserved_extra_parameters_are_rejected() {
    let mock = start(&[]).await;
    let c = client(&mock).await;
    for key in [
        "state",
        "nonce",
        "code_challenge_method",
        "redirect_uri",
        "scope",
    ] {
        let r = c.begin_login(REDIRECT, &[], &[(key, "x")]);
        assert!(matches!(r, Err(Error::Config(_))), "{key}");
    }
}

#[tokio::test]
async fn successful_login_with_basic_auth() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let login = c.begin_login(REDIRECT, &["email"], &[]).unwrap().state;
    mock.token_ok(token_body(
        &key.sign(&id_claims(&mock, Some(&login.nonce)), "JWT"),
    ));

    let result = c
        .complete_login(&login, &callback(&mock.issuer, &login))
        .await
        .unwrap();
    assert_eq!(result.claims.sub, "user-1");
    assert_eq!(result.claims.sid.as_deref(), Some("sid-1"));
    assert_eq!(result.claims.email.as_deref(), Some("a@example.com"));
    assert_eq!(result.claims.amr, vec!["pwd"]);
    assert_eq!(
        result
            .tokens
            .refresh_token
            .as_ref()
            .map(|t| t.expose_secret()),
        Some("refresh-1")
    );
    assert!(!format!("{:?}", result.tokens).contains("good-access-token"));

    let (form, auth) = mock.last_form();
    let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(get("grant_type"), Some("authorization_code"));
    assert_eq!(get("code"), Some("the-code"));
    assert_eq!(get("redirect_uri"), Some(REDIRECT));
    assert_eq!(get("code_verifier"), Some(login.pkce_verifier.as_str()));
    assert_eq!(get("client_secret"), None);
    let basic = STANDARD.encode(format!("{CLIENT_ID}:{SECRET}"));
    assert_eq!(auth.as_deref(), Some(format!("Basic {basic}").as_str()));
}

#[tokio::test]
async fn client_secret_post_sends_credentials_in_body() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client_with(&mock, AuthMethod::Post, Duration::ZERO).await;
    let login = c.begin_login(REDIRECT, &[], &[]).unwrap().state;
    mock.token_ok(token_body(
        &key.sign(&id_claims(&mock, Some(&login.nonce)), "JWT"),
    ));
    c.complete_login(&login, &callback(&mock.issuer, &login))
        .await
        .unwrap();
    let (form, auth) = mock.last_form();
    assert!(auth.is_none());
    assert!(form.contains(&("client_id".into(), CLIENT_ID.into())));
    assert!(form.contains(&("client_secret".into(), SECRET.into())));
}

#[tokio::test]
async fn wrong_state_is_rejected_before_the_token_request() {
    let mock = start(&[]).await;
    let c = client(&mock).await;
    let login = c.begin_login(REDIRECT, &[], &[]).unwrap().state;
    let mut params = callback(&mock.issuer, &login);
    params.state = Some("forged".into());
    let r = c.complete_login(&login, &params).await;
    assert!(matches!(r, Err(Error::StateMismatch)));
    params.state = None;
    assert!(matches!(
        c.complete_login(&login, &params).await,
        Err(Error::InvalidCallback)
    ));
    assert!(mock.last_form.lock().unwrap().is_none());
}

#[tokio::test]
async fn missing_or_wrong_iss_is_rejected() {
    let mock = start(&[]).await;
    let c = client(&mock).await;
    let login = c.begin_login(REDIRECT, &[], &[]).unwrap().state;
    let mut params = callback(&mock.issuer, &login);
    params.iss = None;
    assert!(matches!(
        c.complete_login(&login, &params).await,
        Err(Error::IssuerMismatch)
    ));
    params.iss = Some("https://evil.example.com".into());
    assert!(matches!(
        c.complete_login(&login, &params).await,
        Err(Error::IssuerMismatch)
    ));
}

#[tokio::test]
async fn error_response_is_reported_after_state_check() {
    let mock = start(&[]).await;
    let c = client(&mock).await;
    let login = c.begin_login(REDIRECT, &[], &[]).unwrap().state;
    let mut params = callback(&mock.issuer, &login);
    params.code = None;
    params.error = Some("login_required".into());
    match c.complete_login(&login, &params).await {
        Err(Error::Authorization { error, .. }) => assert_eq!(error, "login_required"),
        other => panic!("unexpected {other:?}"),
    }
    params.state = Some("forged".into());
    assert!(matches!(
        c.complete_login(&login, &params).await,
        Err(Error::StateMismatch)
    ));
}

#[tokio::test]
async fn token_endpoint_errors_are_passed_on() {
    let mock = start(&[]).await;
    let c = client(&mock).await;
    let login = c.begin_login(REDIRECT, &[], &[]).unwrap().state;
    *mock.token_response.lock().unwrap() = (400, serde_json::json!({"error": "invalid_grant"}));
    match c
        .complete_login(&login, &callback(&mock.issuer, &login))
        .await
    {
        Err(Error::OAuth { error, .. }) => assert_eq!(error, "invalid_grant"),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn discovery_with_other_issuer_is_rejected() {
    let mock = start(&[]).await;
    *mock.discovery_extra.lock().unwrap() =
        serde_json::json!({"issuer": "https://evil.example.com"});
    let r =
        z40_auth::Client::discover(&mock.issuer, CLIENT_ID, z40_auth::ClientSecret::new(SECRET))
            .await;
    assert!(matches!(r, Err(Error::Discovery(_))));
}
