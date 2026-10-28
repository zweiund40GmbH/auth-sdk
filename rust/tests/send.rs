//! Compile-time check: all futures are `Send`, so they work in axum
//! handlers and `tokio::spawn` (a non-`Send` value across an `.await` once
//! broke this).

use z40_auth::{CallbackParams, Client, LoginState};

/// Accepts only `Send` values.
fn assert_send<T: Send>(_: T) {}

/// Never called; it only has to compile.
#[allow(dead_code)]
fn futures_are_send(c: &Client, s: &LoginState, p: &CallbackParams) {
    assert_send(c.complete_login(s, p));
    assert_send(c.refresh("t", Some("sub")));
    assert_send(c.userinfo("t"));
    assert_send(c.revoke("t"));
    assert_send(c.verify_backchannel_logout("t"));
    assert_send(c.verify_access_token("t", "aud"));
    assert_send(c.refresh_keys());
    assert_send(Client::discover(
        "https://a",
        "b",
        z40_auth::ClientSecret::new("c"),
    ));
}

#[test]
fn client_is_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<Client>();
}
