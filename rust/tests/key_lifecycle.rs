//! JWKS cache over time (test clock): expiry of removed keys, the stale
//! fallback and its end, forced refresh, and that cached keys never wait
//! for a running fetch.

mod common;

use common::keys::TestKey;
use common::{CLIENT_ID, Mock, advance, client_custom, now, start};
use serde_json::json;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use z40_auth::{Client, Error, TokenError};

/// A valid access token signed by `key`.
fn token(mock: &Mock, key: &TestKey) -> String {
    let claims = json!({
        "iss": mock.issuer, "sub": "user-1", "aud": CLIENT_ID, "client_id": CLIENT_ID,
        "scope": "openid", "exp": now() + 300, "iat": now(), "jti": "j1", "env": "test",
    });
    key.sign(&claims, "at+jwt")
}

/// Verifies `token` and returns the error, if any.
async fn check(c: &Client, token: &str) -> Result<(), Error> {
    c.verify_access_token(token, CLIENT_ID).await.map(|_| ())
}

#[tokio::test]
async fn removed_key_stops_working_after_max_age() {
    let key = TestKey::es256("leaked");
    let mock = start(&[&key]).await;
    let c = client_custom(&mock, |o| o.jwks_min_refetch = Duration::ZERO).await;
    let t = token(&mock, &key);
    check(&c, &t).await.unwrap();
    mock.set_keys(&[]);
    advance(Duration::from_secs(200));
    check(&c, &t).await.unwrap(); // still fresh
    advance(Duration::from_secs(101));
    let r = check(&c, &t).await;
    assert!(
        matches!(r, Err(Error::Token(TokenError::UnknownKey))),
        "{r:?}"
    );
}

#[tokio::test]
async fn stale_keys_bridge_an_outage_until_max_stale() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client_custom(&mock, |o| {
        o.jwks_min_refetch = Duration::ZERO;
        o.jwks_max_stale = Duration::from_secs(600);
    })
    .await;
    let t = token(&mock, &key);
    check(&c, &t).await.unwrap();
    mock.jwks_down.store(true, Ordering::SeqCst);
    advance(Duration::from_secs(300 + 599));
    check(&c, &t).await.unwrap();
    advance(Duration::from_secs(1));
    assert!(matches!(check(&c, &t).await, Err(Error::KeysUnavailable)));
    // Back online: works again.
    mock.jwks_down.store(false, Ordering::SeqCst);
    check(&c, &t).await.unwrap();
}

#[tokio::test]
async fn zero_max_stale_fails_closed() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    let c = client_custom(&mock, |o| o.jwks_max_stale = Duration::ZERO).await;
    let t = token(&mock, &key);
    check(&c, &t).await.unwrap();
    mock.jwks_down.store(true, Ordering::SeqCst);
    advance(Duration::from_secs(300));
    assert!(matches!(check(&c, &t).await, Err(Error::KeysUnavailable)));
}

#[tokio::test]
async fn first_fetch_failure_is_keys_unavailable() {
    let key = TestKey::es256("k1");
    let mock = start(&[&key]).await;
    mock.jwks_down.store(true, Ordering::SeqCst);
    let c = client_custom(&mock, |_| {}).await;
    assert!(matches!(
        check(&c, &token(&mock, &key)).await,
        Err(Error::KeysUnavailable)
    ));
}

#[tokio::test]
async fn refresh_keys_drops_revoked_keys_at_once() {
    let leaked = TestKey::es256("leaked");
    let fresh = TestKey::es256("fresh");
    let mock = start(&[&leaked]).await;
    // Large refetch interval: refresh_keys must ignore it.
    let c = client_custom(&mock, |o| o.jwks_min_refetch = Duration::from_secs(3600)).await;
    let t = token(&mock, &leaked);
    check(&c, &t).await.unwrap();
    mock.set_keys(&[&fresh]);
    c.refresh_keys().await.unwrap();
    assert!(matches!(
        check(&c, &t).await,
        Err(Error::Token(TokenError::UnknownKey))
    ));
    check(&c, &token(&mock, &fresh)).await.unwrap();

    // A failed forced refresh drops everything (fail closed).
    mock.jwks_down.store(true, Ordering::SeqCst);
    assert!(c.refresh_keys().await.is_err());
    assert!(matches!(
        check(&c, &token(&mock, &fresh)).await,
        Err(Error::KeysUnavailable)
    ));
}

#[tokio::test]
async fn cached_keys_do_not_wait_for_a_running_fetch() {
    let known = TestKey::es256("known");
    let unknown = TestKey::es256("unknown");
    let mock = start(&[&known]).await;
    let c = client_custom(&mock, |o| o.jwks_min_refetch = Duration::ZERO).await;
    let known_token = token(&mock, &known);
    check(&c, &known_token).await.unwrap();
    *mock.jwks_delay.lock().unwrap() = Duration::from_secs(2);

    let unknown_token = token(&mock, &unknown);
    let slow = check(&c, &unknown_token);
    let fast = async {
        // Let the slow check start its fetch first.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = Instant::now();
        check(&c, &known_token).await.unwrap();
        started.elapsed()
    };
    let (slow_result, fast_elapsed) = tokio::join!(slow, fast);
    assert!(matches!(
        slow_result,
        Err(Error::Token(TokenError::UnknownKey))
    ));
    assert!(
        fast_elapsed < Duration::from_millis(500),
        "{fast_elapsed:?}"
    );
    assert_eq!(mock.jwks_hits(), 2);
}
