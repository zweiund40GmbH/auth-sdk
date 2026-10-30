//! Mail sending of the management API against the mocked API: new and
//! repeated orders, error codes with status and `Retry-After`, order status.

// Test helpers: panicking on unexpected mock state is intended.
#![allow(clippy::unwrap_used)]

mod common;

use common::manage_api::setup;
use serde_json::json;
use std::time::Duration;
use z40_auth::{Error, IdempotencyKey, MailRequest, MailState};

fn request() -> MailRequest {
    let key = IdempotencyKey::from_parts(&["anfrage", "4711"]).unwrap();
    let mut r = MailRequest::new(
        vec!["anna@example.com".into(), "bert@example.com".into()],
        "Ihre Anfrage ist eingegangen",
        "Hallo,\n\nwir haben Ihre Anfrage erhalten.",
        key,
    );
    r.html = Some("<p>Hallo,</p>".into());
    r
}

/// Error body of the management API.
fn api_error(code: &str) -> serde_json::Value {
    json!({"error": {"code": code, "message": "Nicht möglich."}})
}

#[tokio::test]
async fn new_and_repeated_orders() {
    let (_mock, api, mgmt) = setup().await;
    let order = json!({"id": "m1", "status": "pending", "recipients": 2});
    api.answer(202, order.clone());
    let q = mgmt.mail_send(&request()).await.unwrap();
    assert_eq!(
        (q.id.as_str(), q.status, q.recipients),
        ("m1", MailState::Pending, 2)
    );
    assert!(!q.repeated);
    let seen = api.last();
    assert_eq!(
        (seen.method.as_str(), seen.path_and_query.as_str()),
        ("POST", "/api/v1/manage/mail")
    );
    assert_eq!(
        seen.body.unwrap(),
        json!({"to": ["anna@example.com", "bert@example.com"],
               "subject": "Ihre Anfrage ist eingegangen",
               "text": "Hallo,\n\nwir haben Ihre Anfrage erhalten.",
               "html": "<p>Hallo,</p>", "idempotencyKey": "anfrage:4711"})
    );

    api.answer(200, order);
    let again = mgmt.mail_send(&request()).await.unwrap();
    assert!(again.repeated && again.id == "m1");
}

#[tokio::test]
async fn empty_recipient_list_is_rejected_before_sending() {
    let (_mock, api, mgmt) = setup().await;
    let mut r = request();
    r.to.clear();
    assert!(matches!(mgmt.mail_send(&r).await, Err(Error::Config(_))));
    assert!(api.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn error_codes_keep_status_and_retry_after() {
    let (_mock, api, mgmt) = setup().await;
    for (status, code) in [
        (409, "idempotency_conflict"),
        (409, "mail_disabled"),
        (413, "payload_too_large"),
    ] {
        api.answer(status, api_error(code));
        match mgmt.mail_send(&request()).await {
            Err(Error::Api(e)) => assert_eq!((e.status, e.code.as_str()), (status, code)),
            other => panic!("{other:?}"),
        }
    }

    api.answer(429, api_error("rate_limited"));
    let err = mgmt.mail_send(&request()).await.unwrap_err();
    assert!(err.is_rate_limited());
    assert_eq!(err.retry_after(), Some(Duration::from_secs(7)));

    api.answer(
        422,
        json!({"error": {"code": "validation", "message": "Bitte Eingaben prüfen.",
                         "fields": {"to[1]": "Ungültige E-Mail-Adresse."}}}),
    );
    match mgmt.mail_send(&request()).await {
        Err(Error::Api(e)) => assert!(e.fields.contains_key("to[1]")),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn order_status_is_read() {
    let (_mock, api, mgmt) = setup().await;
    api.answer(
        200,
        json!({"id": "m1", "status": "sent", "recipients": 2, "sent": 2, "failed": 0,
               "pending": 0, "createdAt": "2026-10-30T10:00:00Z"}),
    );
    let s = mgmt.mail_status("m1").await.unwrap();
    assert_eq!((s.status, s.sent, s.pending), (MailState::Sent, 2, 0));
    assert_eq!(s.created_at, "2026-10-30T10:00:00Z");
    assert_eq!(api.last().path_and_query, "/api/v1/manage/mail/m1");
    assert!(matches!(mgmt.mail_status("").await, Err(Error::Config(_))));
}
