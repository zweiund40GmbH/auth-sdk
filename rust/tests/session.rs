//! After the login: refresh, userinfo, revoke, logout URL, back-channel
//! logout and access token verification.

mod common;

use common::keys::TestKey;
use common::{CLIENT_ID, client, id_claims, now, start, token_body};
use serde_json::{Value, json};
use z40_auth::{BACKCHANNEL_LOGOUT_EVENT, Error, TokenError};

/// Valid logout token claims for `issuer`.
fn logout_claims(issuer: &str) -> Value {
    json!({
        "iss": issuer, "aud": CLIENT_ID, "iat": now(), "exp": now() + 120, "jti": "jti-1",
        "sub": "user-1", "sid": "sid-1", "events": {BACKCHANNEL_LOGOUT_EVENT: {}}, "env": "test",
    })
}

#[tokio::test]
async fn refresh_verifies_the_new_id_token_without_nonce() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    mock.token_ok(token_body(&key.sign(&id_claims(&mock, None), "JWT")));
    let r = c.refresh("refresh-0", Some("user-1")).await.unwrap();
    assert_eq!(r.claims.unwrap().sub, "user-1");
    assert_eq!(
        r.tokens.refresh_token.as_ref().map(|t| t.expose_secret()),
        Some("refresh-1")
    );
    let (form, _) = mock.last_form();
    assert!(form.contains(&("grant_type".into(), "refresh_token".into())));
    assert!(form.contains(&("refresh_token".into(), "refresh-0".into())));

    mock.token_ok(token_body(&key.sign(&id_claims(&mock, Some("n")), "JWT")));
    let r = c.refresh("refresh-1", None).await;
    assert!(matches!(r, Err(Error::Token(TokenError::WrongNonce))));

    // OIDC Core §12.2: the refreshed ID token must be for the same user.
    mock.token_ok(token_body(&key.sign(&id_claims(&mock, None), "JWT")));
    let r = c.refresh("refresh-1", Some("someone-else")).await;
    assert!(matches!(r, Err(Error::Token(TokenError::WrongSubject))));

    *mock.token_response.lock().unwrap() = (400, json!({"error": "invalid_grant"}));
    assert!(matches!(
        c.refresh("refresh-1", None).await,
        Err(Error::OAuth { .. })
    ));
}

#[tokio::test]
async fn userinfo_and_revoke() {
    let mock = start(&[]).await;
    let c = client(&mock).await;
    let info = c.userinfo("good-access-token").await.unwrap();
    assert_eq!(info.sub, "user-1");
    assert_eq!(info.email_verified, Some(true));
    // Bodies as the real server sends them (401 invalid_token, 403 insufficient_scope).
    assert!(matches!(
        c.userinfo("revoked").await,
        Err(Error::Unauthorized)
    ));
    match c.userinfo("client-token").await {
        Err(Error::OAuth { error, .. }) => assert_eq!(error, "insufficient_scope"),
        other => panic!("unexpected {other:?}"),
    }

    c.revoke("refresh-1").await.unwrap();
    let (form, auth) = mock.last_form();
    assert_eq!(form, vec![("token".to_owned(), "refresh-1".to_owned())]);
    assert!(auth.is_some_and(|a| a.starts_with("Basic ")));
}

#[tokio::test]
async fn logout_url_has_all_parameters() {
    let mock = start(&[]).await;
    let c = client(&mock).await;
    let url = c
        .logout_url(
            Some("id.tok.en"),
            Some("https://app.example.com/bye"),
            Some("st"),
        )
        .unwrap();
    assert!(
        url.as_str()
            .starts_with(&format!("{}/oauth2/logout?", mock.issuer))
    );
    let q: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    assert!(q.contains(&("client_id".into(), CLIENT_ID.into())));
    assert!(q.contains(&("id_token_hint".into(), "id.tok.en".into())));
    assert!(q.contains(&(
        "post_logout_redirect_uri".into(),
        "https://app.example.com/bye".into()
    )));
    assert!(q.contains(&("state".into(), "st".into())));
    let bare = c.logout_url(None, None, None).unwrap();
    assert_eq!(bare.query(), Some("client_id=app"));
}

#[tokio::test]
async fn backchannel_logout_token_is_verified() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let ok = key.sign(&logout_claims(&mock.issuer), "logout+jwt");
    let event = c.verify_backchannel_logout(&ok).await.unwrap();
    assert_eq!(event.sid.as_deref(), Some("sid-1"));
    assert_eq!(event.sub.as_deref(), Some("user-1"));
    assert_eq!(event.jti, "jti-1");

    let reject = |claims: Value, typ: &str| key.sign(&claims, typ);
    let mut cases: Vec<(String, TokenError)> = Vec::new();
    cases.push((reject(id_claims(&mock, None), "JWT"), TokenError::WrongType));
    cases.push((
        reject(logout_claims(&mock.issuer), "JWT"),
        TokenError::WrongType,
    ));
    let mut c2 = logout_claims(&mock.issuer);
    c2["aud"] = json!("other-app");
    cases.push((reject(c2, "logout+jwt"), TokenError::WrongAudience));
    let mut c3 = logout_claims(&mock.issuer);
    c3["nonce"] = json!("n");
    cases.push((reject(c3, "logout+jwt"), TokenError::WrongNonce));
    let mut c4 = logout_claims(&mock.issuer);
    c4.as_object_mut().unwrap().remove("events");
    cases.push((reject(c4, "logout+jwt"), TokenError::Claim("events")));
    let mut c5 = logout_claims(&mock.issuer);
    c5["exp"] = json!(now() - 120);
    cases.push((reject(c5, "logout+jwt"), TokenError::Expired));
    let mut c6 = logout_claims(&mock.issuer);
    c6["iss"] = json!("https://evil.example.com");
    cases.push((reject(c6, "logout+jwt"), TokenError::WrongIssuer));
    for (token, expected) in cases {
        match c.verify_backchannel_logout(&token).await {
            Err(Error::Token(e)) => assert_eq!(e, expected),
            other => panic!("expected {expected:?}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn access_tokens_are_verified_for_resource_servers() {
    let key = TestKey::rs256("r1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let claims = json!({
        "iss": mock.issuer, "sub": "user-1", "aud": CLIENT_ID, "client_id": CLIENT_ID,
        "scope": "openid roles", "exp": now() + 300, "iat": now(), "jti": "j1", "env": "production",
        "roles": ["admin"],
    });
    let token = key.sign(&claims, "at+jwt");
    let at = c.verify_access_token(&token, CLIENT_ID).await.unwrap();
    assert!(at.has_scope("roles") && at.roles == vec!["admin"]);
    let r = c.verify_access_token(&token, "other-api").await;
    assert!(matches!(r, Err(Error::Token(TokenError::WrongAudience))));
    let id_token = key.sign(&id_claims(&mock, None), "JWT");
    let r = c.verify_access_token(&id_token, CLIENT_ID).await;
    assert!(matches!(r, Err(Error::Token(TokenError::WrongType))));
}
