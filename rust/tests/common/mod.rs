//! Mock provider for the integration tests: a small axum server on a random
//! loopback port that serves discovery, JWKS, token, userinfo and revoke
//! endpoints from shared, test-controlled state.

// Test-only helpers: panicking on setup failures is intended.
#![allow(dead_code, missing_docs, clippy::unwrap_used, clippy::expect_used)]

pub mod keys;
pub mod manage_api;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use keys::TestKey;
use serde_json::{Value, json};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use z40_auth::{AuthMethod, Client, ClientSecret, Options};

/// Client id used by all tests.
pub const CLIENT_ID: &str = "app";
/// Client secret used by all tests (not a real secret).
pub const SECRET: &str = "test-client-secret";
/// Redirect URI used by all tests.
pub const REDIRECT: &str = "https://app.example.com/callback";

/// Shared state of the mock provider.
pub struct Mock {
    pub issuer: String,
    /// Overrides merged into the discovery document.
    pub discovery_extra: Mutex<Value>,
    pub jwks: Mutex<Value>,
    pub jwks_hits: AtomicUsize,
    /// JWKS answers `503` while set.
    pub jwks_down: AtomicBool,
    /// Delay before the JWKS answer.
    pub jwks_delay: Mutex<Duration>,
    /// Status and JSON body of the next token responses.
    pub token_response: Mutex<(u16, Value)>,
    /// `Retry-After` header of the token responses, if set.
    pub token_retry_after: Mutex<Option<String>>,
    /// Body and `Authorization` header of the last token or revoke request.
    pub last_form: Mutex<Option<(String, Option<String>)>>,
    /// Number of token requests so far.
    pub token_hits: AtomicUsize,
}

impl Mock {
    /// Publishes exactly `keys` in the JWKS.
    pub fn set_keys(&self, keys: &[&TestKey]) {
        *self.jwks.lock().unwrap() =
            json!({"keys": keys.iter().map(|k| k.jwk.clone()).collect::<Vec<_>>()});
    }

    /// Lets the token endpoint answer `200` with `body`.
    pub fn token_ok(&self, body: Value) {
        *self.token_response.lock().unwrap() = (200, body);
    }

    /// The last form body as key/value pairs and the `Authorization` header.
    pub fn last_form(&self) -> (Vec<(String, String)>, Option<String>) {
        let (body, auth) = self
            .last_form
            .lock()
            .unwrap()
            .clone()
            .expect("no form request");
        let pairs = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        (pairs, auth)
    }

    /// Number of JWKS fetches so far.
    pub fn jwks_hits(&self) -> usize {
        self.jwks_hits.load(Ordering::SeqCst)
    }
}

/// JSON response.
fn json_response(status: u16, body: &Value) -> Response {
    let status = StatusCode::from_u16(status).unwrap();
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn discovery(State(m): State<Arc<Mock>>) -> Response {
    let i = &m.issuer;
    let mut doc = json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/oauth2/authorize"),
        "token_endpoint": format!("{i}/oauth2/token"),
        "userinfo_endpoint": format!("{i}/oauth2/userinfo"),
        "jwks_uri": format!("{i}/.well-known/jwks.json"),
        "revocation_endpoint": format!("{i}/oauth2/revoke"),
        "end_session_endpoint": format!("{i}/oauth2/logout"),
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
    });
    let extra = m.discovery_extra.lock().unwrap().clone();
    if let (Some(d), Some(e)) = (doc.as_object_mut(), extra.as_object()) {
        d.extend(e.clone());
    }
    json_response(200, &doc)
}

async fn jwks(State(m): State<Arc<Mock>>) -> Response {
    m.jwks_hits.fetch_add(1, Ordering::SeqCst);
    let delay = *m.jwks_delay.lock().unwrap();
    tokio::time::sleep(delay).await;
    if m.jwks_down.load(Ordering::SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let body = m.jwks.lock().unwrap().clone();
    json_response(200, &body)
}

/// Remembers the form body and `Authorization` header.
fn record(m: &Mock, headers: &HeaderMap, body: String) {
    let auth = headers
        .get(header::AUTHORIZATION)
        .map(|v| v.to_str().unwrap().to_owned());
    *m.last_form.lock().unwrap() = Some((body, auth));
}

async fn token(State(m): State<Arc<Mock>>, headers: HeaderMap, body: String) -> Response {
    m.token_hits.fetch_add(1, Ordering::SeqCst);
    record(&m, &headers, body);
    let (status, body) = m.token_response.lock().unwrap().clone();
    let mut resp = json_response(status, &body);
    if let Some(v) = m.token_retry_after.lock().unwrap().clone() {
        resp.headers_mut()
            .insert(header::RETRY_AFTER, v.parse().unwrap());
    }
    resp
}

async fn revoke(State(m): State<Arc<Mock>>, headers: HeaderMap, body: String) -> Response {
    record(&m, &headers, body);
    StatusCode::OK.into_response()
}

/// Behaves like the provider's UserInfo endpoint:
/// JSON error bodies with `WWW-Authenticate`.
async fn userinfo(headers: HeaderMap) -> Response {
    let challenge = |status: StatusCode, error: &str| {
        let www = format!("Bearer realm=\"auth\", error=\"{error}\"");
        let body = json!({ "error": error }).to_string();
        let h = [
            (header::WWW_AUTHENTICATE, www),
            (header::CONTENT_TYPE, "application/json".into()),
        ];
        (status, h, body).into_response()
    };
    match headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        Some("Bearer good-access-token") => json_response(
            200,
            &json!({"sub": "user-1", "email": "a@example.com", "email_verified": true}),
        ),
        Some("Bearer client-token") => challenge(StatusCode::FORBIDDEN, "insufficient_scope"),
        Some(_) => challenge(StatusCode::UNAUTHORIZED, "invalid_token"),
        None => challenge(StatusCode::UNAUTHORIZED, "invalid_request"),
    }
}

/// Starts a mock provider with `keys` in its JWKS.
pub async fn start(keys: &[&TestKey]) -> Arc<Mock> {
    start_with(keys, Router::new()).await
}

/// Like [`start`], with further routes (e.g. a mocked management API).
pub async fn start_with(keys: &[&TestKey], extra: Router) -> Arc<Mock> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let mock = Arc::new(Mock {
        issuer,
        discovery_extra: Mutex::new(json!({})),
        jwks: Mutex::new(json!({"keys": []})),
        jwks_hits: AtomicUsize::new(0),
        jwks_down: AtomicBool::new(false),
        jwks_delay: Mutex::new(Duration::ZERO),
        token_response: Mutex::new((500, json!({}))),
        token_retry_after: Mutex::new(None),
        last_form: Mutex::new(None),
        token_hits: AtomicUsize::new(0),
    });
    mock.set_keys(keys);
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth2/token", post(token))
        .route("/oauth2/revoke", post(revoke))
        .route("/oauth2/userinfo", get(userinfo))
        .with_state(mock.clone())
        .merge(extra);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    mock
}

/// A client for `mock` that may refetch the JWKS at any time.
pub async fn client(mock: &Mock) -> Client {
    client_with(mock, AuthMethod::Basic, Duration::ZERO).await
}

/// A client with explicit auth method and JWKS refetch interval.
pub async fn client_with(mock: &Mock, auth_method: AuthMethod, min_refetch: Duration) -> Client {
    client_custom(mock, |o| {
        o.auth_method = auth_method;
        o.jwks_min_refetch = min_refetch;
    })
    .await
}

/// A client using the test clock, with options changed by `f`.
pub async fn client_custom(mock: &Mock, f: impl FnOnce(&mut Options)) -> Client {
    let mut options = Options {
        clock: test_clock,
        ..Options::default()
    };
    f(&mut options);
    Client::discover_with(&mock.issuer, CLIENT_ID, ClientSecret::new(SECRET), options)
        .await
        .unwrap()
}

thread_local! {
    static CLOCK_BASE: Instant = Instant::now();
    static CLOCK_OFFSET: Cell<Duration> = const { Cell::new(Duration::ZERO) };
}

/// Test clock of the JWKS cache: per thread, so the (single-threaded) tests
/// do not influence each other.
pub fn test_clock() -> Instant {
    CLOCK_BASE.with(|b| *b) + CLOCK_OFFSET.with(Cell::get)
}

/// Moves the test clock forward.
pub fn advance(by: Duration) {
    CLOCK_OFFSET.with(|o| o.set(o.get() + by));
}

/// Current time in seconds since the epoch.
pub fn now() -> i64 {
    jsonwebtoken::get_current_timestamp() as i64
}

/// Valid ID token claims for `mock` with `nonce`.
pub fn id_claims(mock: &Mock, nonce: Option<&str>) -> Value {
    let mut c = json!({
        "iss": mock.issuer, "sub": "user-1", "aud": CLIENT_ID,
        "exp": now() + 300, "iat": now(), "auth_time": now(),
        "sid": "sid-1", "amr": ["pwd"], "acr": "urn:z40:pwd", "env": "test",
        "email": "a@example.com", "email_verified": true, "name": "Anna",
    });
    if let Some(n) = nonce {
        c["nonce"] = json!(n);
    }
    c
}

/// Token endpoint answer carrying `id_token`.
pub fn token_body(id_token: &str) -> Value {
    json!({
        "access_token": "good-access-token", "token_type": "Bearer", "expires_in": 300,
        "scope": "openid email", "id_token": id_token, "refresh_token": "refresh-1",
    })
}
