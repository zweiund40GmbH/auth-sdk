//! Management API client against a mocked API: client-credentials token
//! cache, request and response bodies of onboarding and links, error
//! mapping and the event catch-up with `gap`.

// Test helpers: panicking on unexpected mock state is intended.
#![allow(clippy::unwrap_used)]

mod common;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use z40_auth::{
    AccountEvent, Error, LinkReport, LinkSource, Management, NewOnboarding, OnboardingState,
};

/// One recorded API request.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path_and_query: String,
    auth: Option<String>,
    on_behalf_of: Option<String>,
    body: Option<Value>,
}

/// Mocked management API: answers from a queue, records requests.
#[derive(Default)]
struct Api {
    answers: Mutex<VecDeque<(u16, Value)>>,
    seen: Mutex<Vec<Seen>>,
}

impl Api {
    fn answer(&self, status: u16, body: Value) {
        self.answers.lock().unwrap().push_back((status, body));
    }

    fn last(&self) -> Seen {
        self.seen.lock().unwrap().last().cloned().unwrap()
    }
}

async fn api(State(api): State<Arc<Api>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let header = |n: &str| parts.headers.get(n).map(|v| v.to_str().unwrap().to_owned());
    let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    api.seen.lock().unwrap().push(Seen {
        method: parts.method.to_string(),
        path_and_query: parts.uri.path_and_query().unwrap().to_string(),
        auth: header("authorization"),
        on_behalf_of: header("x-on-behalf-of"),
        body: serde_json::from_slice(&bytes).ok(),
    });
    let (status, body) = api.answers.lock().unwrap().pop_front().unwrap();
    let status = StatusCode::from_u16(status).unwrap();
    if body.is_null() {
        return status.into_response();
    }
    let headers = [("content-type", "application/json"), ("retry-after", "7")];
    (status, headers, body.to_string()).into_response()
}

/// Mock provider with the mocked API and a management client.
async fn setup() -> (Arc<common::Mock>, Arc<Api>, Management) {
    let state = Arc::new(Api::default());
    let router = Router::new()
        .route("/api/v1/manage/{*rest}", axum::routing::any(api))
        .with_state(state.clone());
    let mock = common::start_with(&[], router).await;
    mock.token_ok(json!({"access_token": "mgmt-1", "token_type": "Bearer", "expires_in": 300}));
    let client = Arc::new(common::client(&mock).await);
    (mock, state, Management::new(client).unwrap())
}

fn onboarding_body(status: &str, url: Option<&str>) -> Value {
    json!({
        "id": "0192-a", "localId": "7:42", "email": "lena@example.com", "appAdmin": false,
        "roles": ["operator"], "validUntil": null, "status": status,
        "createdAt": "2026-10-29T10:00:00Z", "expiresAt": "2026-11-12T10:00:00Z",
        "sentAt": null, "acceptedAt": null, "sub": null, "url": url,
    })
}

#[tokio::test]
async fn onboarding_calls_and_token_cache() {
    let (mock, api, mgmt) = setup().await;
    api.answer(
        201,
        onboarding_body("open", Some("https://login.example.com/x#t=abc")),
    );
    let mut req = NewOnboarding::new("lena@example.com", "7:42");
    req.send_mail = false;
    req.family_name = Some("Berg".into());
    let o = mgmt
        .on_behalf_of("17")
        .unwrap()
        .create_onboarding(&req)
        .await
        .unwrap();
    assert_eq!((o.status, o.url.is_some()), (OnboardingState::Open, true));
    let seen = api.last();
    assert_eq!(
        (seen.method.as_str(), seen.path_and_query.as_str()),
        ("POST", "/api/v1/manage/onboarding")
    );
    assert_eq!(seen.auth.as_deref(), Some("Bearer mgmt-1"));
    assert_eq!(seen.on_behalf_of.as_deref(), Some("17"));
    assert_eq!(
        seen.body.unwrap(),
        json!({"email": "lena@example.com", "localId": "7:42", "familyName": "Berg",
               "appAdmin": false, "sendMail": false})
    );
    let (form, _) = mock.last_form();
    assert!(form.contains(&("grant_type".into(), "client_credentials".into())));
    assert!(!form.iter().any(|(k, _)| k == "scope"));

    api.answer(200, onboarding_body("accepted", None));
    assert_eq!(
        mgmt.onboarding("0192-a").await.unwrap().status,
        OnboardingState::Accepted
    );
    assert_eq!(
        api.last().path_and_query,
        "/api/v1/manage/onboarding/0192-a"
    );
    assert!(api.last().on_behalf_of.is_none());

    api.answer(200, onboarding_body("open", None));
    mgmt.resend_onboarding("0192-a", true).await.unwrap();
    let seen = api.last();
    assert_eq!(
        seen.path_and_query,
        "/api/v1/manage/onboarding/0192-a/resend"
    );
    assert_eq!(seen.body.unwrap(), json!({"sendMail": true}));

    api.answer(204, Value::Null);
    mgmt.revoke_onboarding("0192-a").await.unwrap();
    assert_eq!(api.last().method, "DELETE");
    // One token for all calls.
    assert_eq!(mock.token_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn errors_are_mapped_and_401_renews_the_token() {
    let (mock, api, mgmt) = setup().await;
    api.answer(
        409,
        json!({"error": {"code": "conflict", "message": "Dieser Zugang ist bereits mit einem Konto verknüpft."}}),
    );
    match mgmt
        .create_onboarding(&NewOnboarding::new("a@example.com", "1"))
        .await
    {
        Err(Error::Api(e)) => {
            assert_eq!((e.status, e.code.as_str()), (409, "conflict"));
            assert_eq!(e.retry_after, Some(7));
        }
        other => panic!("{other:?}"),
    }
    api.answer(401, Value::Null);
    api.answer(200, json!({"items": []}));
    assert!(mgmt.user_links("sub-1").await.unwrap().is_empty());
    assert_eq!(mock.token_hits.load(Ordering::SeqCst), 2);
    api.answer(401, Value::Null);
    api.answer(401, Value::Null);
    assert!(matches!(
        mgmt.user_links("sub-1").await,
        Err(Error::Unauthorized)
    ));
    assert!(mgmt.on_behalf_of("a b").is_err());
}

#[tokio::test]
async fn links_are_reported_and_read() {
    let (_mock, api, mgmt) = setup().await;
    api.answer(200, json!({"linked": 1, "ignored": 1}));
    let r = mgmt
        .report_links(&[LinkReport {
            sub: "s".into(),
            local_id: "7:42".into(),
        }])
        .await
        .unwrap();
    assert_eq!((r.linked, r.ignored), (1, 1));
    assert_eq!(
        api.last().body.unwrap(),
        json!({"items": [{"sub": "s", "localId": "7:42"}]})
    );
    api.answer(
        200,
        json!({"items": [{"localId": "7:42", "source": "reported", "linkedAt": "2026-10-29T10:00:00Z"}]}),
    );
    let links = mgmt.user_links("a/b").await.unwrap();
    assert_eq!(links[0].source, LinkSource::Reported);
    // Path segments are encoded.
    assert_eq!(
        api.last().path_and_query,
        "/api/v1/manage/users/a%2Fb/links"
    );
}

fn event(cursor: &str, ty: &str, data: Value) -> Value {
    json!({"cursor": cursor, "jti": format!("j{cursor}"), "type": ty, "sub": "s",
           "occurredAt": "2026-10-29T10:00:00Z", "data": data})
}

#[tokio::test]
async fn catch_up_pages_until_done_and_reports_gap() {
    let (_mock, api, mgmt) = setup().await;
    api.answer(
        200,
        json!({"items": [event("3", "user.disabled", json!({}))], "nextCursor": "3", "hasMore": true, "gap": true}),
    );
    api.answer(
        200,
        json!({"items": [event("9", "user.future", json!({"a": 1}))], "nextCursor": "9", "hasMore": false, "gap": false}),
    );
    let mut pages = mgmt.event_pages(None);
    let first = pages.next().await.unwrap().unwrap();
    assert!(first.gap);
    assert_eq!(first.items[0].event, AccountEvent::UserDisabled);
    assert_eq!(api.last().path_and_query, "/api/v1/manage/events");
    let second = pages.next().await.unwrap().unwrap();
    assert!(!second.gap);
    assert_eq!(second.items[0].event.event_type(), "user.future");
    assert_eq!(api.last().path_and_query, "/api/v1/manage/events?since=3");
    assert!(pages.next().await.unwrap().is_none());
    assert_eq!(pages.cursor(), Some("9"));

    api.answer(
        503,
        json!({"error": {"code": "unavailable", "message": "Bitte gleich erneut versuchen."}}),
    );
    let r = mgmt.events(Some("9"), Some(50)).await;
    assert!(matches!(r, Err(Error::Api(ref e)) if e.code == "unavailable"));
    assert_eq!(
        api.last().path_and_query,
        "/api/v1/manage/events?since=9&limit=50"
    );
}
