//! Thin `axum` helpers (feature `axum`): extractors for the login callback
//! and the back-channel logout body, and the logout response. Bad input is
//! rejected with `400` before any handler code runs.

use crate::login::CallbackParams;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Largest accepted back-channel logout body (a logout token is ~1 KiB).
const MAX_LOGOUT_BODY: usize = 16 * 1024;

/// Extracts [`CallbackParams`] from the query; repeated parameters → `400`.
#[derive(Debug, Clone)]
pub struct Callback(pub CallbackParams);

impl<S: Send + Sync> FromRequestParts<S> for Callback {
    type Rejection = StatusCode;

    /// Parses the request's query string.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        CallbackParams::from_query(parts.uri.query().unwrap_or(""))
            .map(Callback)
            .map_err(|_| StatusCode::BAD_REQUEST)
    }
}

/// Extracts `logout_token` from an `application/x-www-form-urlencoded` body.
/// Wrong content type, body over 16 KiB, missing, empty or repeated
/// `logout_token` → `400`. `Debug` hides the token.
#[derive(Clone)]
pub struct LogoutToken(pub String);

impl std::fmt::Debug for LogoutToken {
    /// Prints a placeholder.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LogoutToken([redacted])")
    }
}

/// Whether the request declares a form body (parameters such as `charset` allowed).
fn is_form(req: &Request) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| {
            m.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

/// The single non-empty `logout_token` of a form body.
fn logout_token_from_form(body: &[u8]) -> Option<String> {
    let mut found = None;
    for (key, value) in url::form_urlencoded::parse(body) {
        if key == "logout_token" {
            if found.is_some() {
                return None;
            }
            found = Some(value.into_owned());
        }
    }
    found.filter(|t| !t.is_empty())
}

impl<S: Send + Sync> FromRequest<S> for LogoutToken {
    type Rejection = StatusCode;

    /// Reads the size-limited body and picks `logout_token`.
    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        if !is_form(&req) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let body = axum::body::to_bytes(req.into_body(), MAX_LOGOUT_BODY)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        logout_token_from_form(&body)
            .map(LogoutToken)
            .ok_or(StatusCode::BAD_REQUEST)
    }
}

/// Response of the back-channel logout endpoint (§2.8): `200` after the
/// local sessions were ended, else `400`; never cached.
pub fn logout_response(ok: bool) -> Response {
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, [(header::CACHE_CONTROL, "no-store")]).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn form_request(content_type: &str, body: &str) -> Request {
        axum::http::Request::builder()
            .method("POST")
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    #[tokio::test]
    async fn logout_token_is_extracted() {
        let req = form_request(
            "application/x-www-form-urlencoded; charset=utf-8",
            "logout_token=a.b.c",
        );
        let token = LogoutToken::from_request(req, &()).await.unwrap();
        assert_eq!(token.0, "a.b.c");
        assert!(!format!("{token:?}").contains("a.b.c"));
    }

    #[tokio::test]
    async fn bad_logout_bodies_are_rejected() {
        for (ct, body) in [
            ("application/json", "logout_token=a"),
            ("application/x-www-form-urlencoded", "logout_token="),
            (
                "application/x-www-form-urlencoded",
                "logout_token=a&logout_token=b",
            ),
            ("application/x-www-form-urlencoded", "other=a"),
        ] {
            let r = LogoutToken::from_request(form_request(ct, body), &()).await;
            assert_eq!(r.unwrap_err(), StatusCode::BAD_REQUEST, "{ct} {body}");
        }
        let big = format!("logout_token={}", "a".repeat(MAX_LOGOUT_BODY));
        let r =
            LogoutToken::from_request(form_request("application/x-www-form-urlencoded", &big), &())
                .await;
        assert_eq!(r.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn callback_rejects_repeated_parameters() {
        let (mut parts, ()) = axum::http::Request::builder()
            .uri("/cb?code=a&code=b&state=s")
            .body(())
            .unwrap()
            .into_parts();
        let r = Callback::from_request_parts(&mut parts, &()).await;
        assert_eq!(r.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn logout_response_is_not_cached() {
        let r = logout_response(false);
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(logout_response(true).status(), StatusCode::OK);
    }
}
