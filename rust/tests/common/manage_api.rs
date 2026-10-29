//! Mocked management API on top of the mock provider: answers come from a
//! queue, requests are recorded.

use super::{Mock, client, start_with};
use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use z40_auth::Management;

/// One recorded API request.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path_and_query: String,
    pub auth: Option<String>,
    pub on_behalf_of: Option<String>,
    pub body: Option<Value>,
}

/// Mocked management API: answers from a queue, records requests.
#[derive(Default)]
pub struct Api {
    pub answers: Mutex<VecDeque<(u16, Value)>>,
    pub seen: Mutex<Vec<Seen>>,
}

impl Api {
    pub fn answer(&self, status: u16, body: Value) {
        self.answers.lock().unwrap().push_back((status, body));
    }

    pub fn last(&self) -> Seen {
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
pub async fn setup() -> (Arc<Mock>, Arc<Api>, Management) {
    let state = Arc::new(Api::default());
    let router = Router::new()
        .route("/api/v1/manage/{*rest}", axum::routing::any(api))
        .with_state(state.clone());
    let mock = start_with(&[], router).await;
    mock.token_ok(json!({"access_token": "mgmt-1", "token_type": "Bearer", "expires_in": 300}));
    let client = Arc::new(client(&mock).await);
    (mock, state, Management::new(client).unwrap())
}
