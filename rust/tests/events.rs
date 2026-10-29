//! Account events: verification of pushed Security Event Tokens against
//! the mock provider's JWKS and the RFC 8935 answers of the receiver.

// Test helpers: panicking on unexpected mock state is intended.
#![allow(clippy::unwrap_used)]

mod common;

use common::keys::TestKey;
use common::{CLIENT_ID, client, now, start};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use z40_auth::{AccountEvent, Error, MemoryJtiStore, PushResponse, TokenError};

const CT: Option<&str> = Some("application/secevent+jwt");

/// Valid SET claims for `issuer` with one `user.email_changed` event.
fn set_claims(issuer: &str, jti: &str) -> Value {
    json!({
        "iss": issuer, "aud": CLIENT_ID, "iat": now(), "exp": now() + 120, "jti": jti,
        "sub": "user-1", "toe": now() - 1, "env": "test",
        "events": {"urn:z40:event:user.email_changed": {"email": "a@example.com", "emailVerified": true}},
    })
}

/// `set_claims` with `changes` merged in.
fn claims_with(issuer: &str, changes: Value) -> Value {
    let mut c = set_claims(issuer, "jti-x");
    c.as_object_mut()
        .unwrap()
        .extend(changes.as_object().unwrap().clone());
    c
}

#[tokio::test]
async fn valid_event_is_verified_and_typed() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let token = key.sign(&set_claims(&mock.issuer, "jti-1"), "secevent+jwt");
    let e = c.verify_security_event(&token).await.unwrap();
    assert_eq!(e.jti, "jti-1");
    assert_eq!(e.sub.as_deref(), Some("user-1"));
    assert_eq!(
        e.event,
        AccountEvent::EmailChanged {
            email: "a@example.com".into(),
            email_verified: true
        }
    );
    // RFC 7515: `application/` prefix and case do not matter.
    let token = key.sign(
        &set_claims(&mock.issuer, "jti-2"),
        "application/SecEvent+JWT",
    );
    assert!(c.verify_security_event(&token).await.is_ok());
}

#[tokio::test]
async fn bad_tokens_are_rejected() {
    let key = TestKey::rs256("k1");
    let foreign = TestKey::rs256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let iss = mock.issuer.clone();
    let token_err = |r: Result<_, Error>| match r {
        Err(Error::Token(t)) => t,
        other => panic!("{other:?}"),
    };
    let cases: Vec<(String, TokenError)> = vec![
        (
            key.sign(&set_claims(&iss, "j"), "logout+jwt"),
            TokenError::WrongType,
        ),
        (
            key.sign(&set_claims(&iss, "j"), "JWT"),
            TokenError::WrongType,
        ),
        (
            key.sign(
                &claims_with(&iss, json!({"aud": "other-app"})),
                "secevent+jwt",
            ),
            TokenError::WrongAudience,
        ),
        (
            key.sign(
                &claims_with(&iss, json!({"iss": "https://evil.example.com"})),
                "secevent+jwt",
            ),
            TokenError::WrongIssuer,
        ),
        (
            key.sign(
                &claims_with(&iss, json!({"iat": now() - 600, "exp": now() - 480})),
                "secevent+jwt",
            ),
            TokenError::Expired,
        ),
        (
            foreign.sign(&set_claims(&iss, "j"), "secevent+jwt"),
            TokenError::BadSignature,
        ),
        (
            key.sign(&claims_with(&iss, json!({"events": {}})), "secevent+jwt"),
            TokenError::Claim("events"),
        ),
    ];
    for (token, expected) in cases {
        let got = token_err(c.verify_security_event(&token).await);
        assert_eq!(got, expected);
    }
}

#[tokio::test]
async fn unknown_event_type_is_accepted() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let claims = claims_with(
        &mock.issuer,
        json!({"events": {"urn:z40:event:user.archived": {"since": 1}}}),
    );
    let e = c
        .verify_security_event(&key.sign(&claims, "secevent+jwt"))
        .await
        .unwrap();
    assert!(
        matches!(e.event, AccountEvent::Unknown { ref event_type, .. } if event_type == "user.archived")
    );
}

#[tokio::test]
async fn receiver_answers_per_rfc_8935_and_deduplicates() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let store = MemoryJtiStore::new();
    let calls = AtomicUsize::new(0);
    let handle = |_e| {
        calls.fetch_add(1, Ordering::SeqCst);
        async { Ok::<(), ()>(()) }
    };
    let token = key.sign(&set_claims(&mock.issuer, "jti-r"), "secevent+jwt");

    let r = c.receive_event(CT, token.as_bytes(), &store, handle).await;
    assert_eq!((r.status, r.body.as_deref()), (202, None));
    // Same jti again (provider retry): accepted, not handled twice.
    let r = c.receive_event(CT, token.as_bytes(), &store, handle).await;
    assert_eq!(r.status, 202);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let bad_aud = key.sign(
        &claims_with(&mock.issuer, json!({"aud": "x"})),
        "secevent+jwt",
    );
    let r = c
        .receive_event(CT, bad_aud.as_bytes(), &store, handle)
        .await;
    assert_eq!(
        (r.status, r.err().as_deref()),
        (400, Some("invalid_audience"))
    );
    let r = c
        .receive_event(Some("text/plain"), token.as_bytes(), &store, handle)
        .await;
    assert_eq!(
        (r.status, r.err().as_deref()),
        (400, Some("invalid_request"))
    );
    let foreign = TestKey::es256("other-kid").sign(&set_claims(&mock.issuer, "j"), "secevent+jwt");
    let r = c
        .receive_event(CT, foreign.as_bytes(), &store, handle)
        .await;
    assert_eq!(r.err().as_deref(), Some("invalid_key"));
}

#[tokio::test]
async fn failing_handler_is_retried_by_the_provider() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    let store = MemoryJtiStore::new();
    let token = key.sign(&set_claims(&mock.issuer, "jti-f"), "secevent+jwt");
    let r: PushResponse = c
        .receive_event(CT, token.as_bytes(), &store, |_e| async {
            Err::<(), _>("database down")
        })
        .await;
    assert_eq!(r.status, 500);
    // Not remembered: the retry is handled.
    let r = c
        .receive_event(CT, token.as_bytes(), &store, |_e| async {
            Ok::<(), ()>(())
        })
        .await;
    assert_eq!(r.status, 202);
}

#[tokio::test]
async fn unreachable_keys_ask_for_a_retry() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client(&mock).await;
    mock.jwks_down.store(true, Ordering::SeqCst);
    let token = key.sign(&set_claims(&mock.issuer, "jti-k"), "secevent+jwt");
    let r = c
        .receive_event(CT, token.as_bytes(), &MemoryJtiStore::new(), |_e| async {
            Ok::<(), ()>(())
        })
        .await;
    assert_eq!((r.status, r.body), (503, None));
}
