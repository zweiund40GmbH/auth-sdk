//! Compile-time check: all futures are `Send`, so they work in axum
//! handlers and `tokio::spawn` (a non-`Send` value across an `.await` once
//! broke this).

use z40_auth::{
    CallbackParams, Client, LoginState, MailRequest, Management, MemoryJtiStore, NewOnboarding,
    Tokens,
};

/// Accepts only `Send` values.
fn assert_send<T: Send>(_: T) {}

/// Never called; it only has to compile.
#[allow(dead_code)]
fn futures_are_send(
    c: &Client,
    s: &LoginState,
    p: &CallbackParams,
    m: &Management,
    store: &MemoryJtiStore,
    mail: &MailRequest,
    tokens: &Tokens,
) {
    assert_send(c.complete_login(s, p));
    assert_send(c.refresh("t", Some("sub")));
    assert_send(c.userinfo("t"));
    assert_send(c.revoke("t"));
    assert_send(c.verify_backchannel_logout("t"));
    assert_send(c.verify_access_token("t", "aud"));
    assert_send(c.refresh_keys());
    assert_send(c.verify_security_event("t"));
    assert_send(c.receive_event(None, b"t", store, |_e| async { Ok::<(), ()>(()) }));
    assert_send(c.client_credentials(&[]));
    assert_send(m.create_onboarding(&NewOnboarding::new("a@example.com", "1")));
    assert_send(m.onboarding("id"));
    assert_send(m.revoke_onboarding("id"));
    assert_send(m.resend_onboarding("id", true));
    assert_send(m.user_links("sub"));
    assert_send(m.report_links(&[]));
    assert_send(m.events(None, None));
    assert_send(m.mail_send(mail));
    assert_send(m.mail_status("id"));
    assert_send(c.verify_refreshed(tokens, None));
    assert_send(c.verify_refreshed_at(tokens, None, 0));
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
    check::<Management>();
    check::<MemoryJtiStore>();
}
