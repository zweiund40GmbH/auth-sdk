//! The one HTTP layer of the crate: a `reqwest` client with timeouts and
//! without redirects, size-limited bodies, the OAuth error format (RFC 6749
//! §5.2) and bearer requests; form posts with client authentication are in
//! [`form`].

mod form;

pub use form::AuthMethod;
pub(crate) use form::{Credentials, post_form_empty, post_form_json};

use crate::error::{Error, Result};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde::de::DeserializeOwned;
use std::time::Duration;
use url::Url;
use zeroize::Zeroizing;

/// Whole-request timeout.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest response body read (discovery, JWKS and token answers are small).
const MAX_BODY: usize = 256 * 1024;

/// Builds the default HTTP client: rustls with the system's CA store,
/// 10 s timeout, no redirects (the provider never redirects API calls;
/// following one could leak credentials). Proxies from the environment
/// (`HTTP(S)_PROXY`, `NO_PROXY`) are honoured, as reqwest does by default.
pub(crate) fn default_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| Error::Config("HTTP client could not be built"))
}

/// Reads at most [`MAX_BODY`] bytes of `resp`. The buffer is zeroed on
/// drop: token answers carry secrets. It is allocated once from
/// `Content-Length` (or [`MAX_BODY`]), so growing it normally leaves no
/// copies behind. Best effort: the chunks inside reqwest/hyper and the TLS
/// buffers are not reachable and are not zeroed.
async fn read_body(mut resp: reqwest::Response) -> Result<Zeroizing<Vec<u8>>> {
    let hint = resp.content_length().and_then(|n| usize::try_from(n).ok());
    let mut body = Zeroizing::new(Vec::with_capacity(
        hint.map_or(MAX_BODY, |n| n.min(MAX_BODY)),
    ));
    while let Some(chunk) = resp.chunk().await.map_err(Error::transport)? {
        if body.len() + chunk.len() > MAX_BODY {
            return Err(Error::InvalidResponse);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Parses a JSON body.
pub(crate) fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|_| Error::InvalidResponse)
}

/// OAuth error body.
#[derive(serde::Deserialize)]
struct OAuthErrorBody {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Maps a non-success answer of an OAuth endpoint: `429` is always
/// [`Error::RateLimited`] (whatever the body says, nothing was consumed),
/// else the OAuth error body if present, else the status.
pub(crate) fn error_from(resp: &RawResponse) -> Error {
    if resp.status == 429 {
        return Error::RateLimited {
            retry_after: resp.retry_after,
        };
    }
    match serde_json::from_slice::<OAuthErrorBody>(&resp.body) {
        Ok(e) => Error::OAuth {
            error: e.error,
            description: e.error_description,
            status: resp.status,
        },
        Err(_) => Error::Status(resp.status),
    }
}

/// Reads status, `Retry-After` (seconds) and the size-limited body.
pub(crate) async fn read_raw(resp: reqwest::Response) -> Result<RawResponse> {
    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok());
    let body = read_body(resp).await?;
    Ok(RawResponse {
        status,
        retry_after,
        body,
    })
}

/// Turns a response into `T` (2xx with JSON) or an [`Error`].
async fn json_response<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let raw = read_raw(resp).await?;
    if (200..300).contains(&raw.status) {
        parse_json(&raw.body)
    } else {
        Err(error_from(&raw))
    }
}

/// `GET url` expecting JSON, optionally with a bearer token.
pub(crate) async fn get_json<T: DeserializeOwned>(
    http: &reqwest::Client,
    url: &Url,
    bearer: Option<&str>,
) -> Result<T> {
    let mut req = http.get(url.clone()).header(ACCEPT, "application/json");
    if let Some(token) = bearer {
        req = req.header(AUTHORIZATION, sensitive(&format!("Bearer {token}"))?);
    }
    let resp = req.send().await.map_err(Error::transport)?;
    // With a bearer token, `401` always means the token is not (or no
    // longer) valid, whatever the body says (RFC 6750 §3.1).
    if bearer.is_some() && resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(Error::Unauthorized);
    }
    json_response(resp).await
}

/// Header value marked sensitive (kept out of `Debug` output by `http`).
pub(crate) fn sensitive(value: &str) -> Result<HeaderValue> {
    let mut v = HeaderValue::from_str(value).map_err(|_| Error::Config("invalid header value"))?;
    v.set_sensitive(true);
    Ok(v)
}

/// A raw answer: status, `Retry-After` seconds and the size-limited body.
pub(crate) struct RawResponse {
    /// HTTP status.
    pub status: u16,
    /// `Retry-After` in seconds, if sent as a number.
    pub retry_after: Option<u64>,
    /// The body (zeroed on drop).
    pub body: Zeroizing<Vec<u8>>,
}

/// Sends a JSON request with a bearer token (management API) and returns
/// the raw answer; `headers` are extra request headers (e.g. `X-On-Behalf-Of`).
pub(crate) async fn send_bearer(
    http: &reqwest::Client,
    method: reqwest::Method,
    url: &Url,
    bearer: &str,
    body: Option<String>,
    headers: &[(&str, &str)],
) -> Result<RawResponse> {
    let mut req = http
        .request(method, url.clone())
        .header(ACCEPT, "application/json")
        .header(AUTHORIZATION, sensitive(&format!("Bearer {bearer}"))?);
    for (name, value) in headers {
        let value =
            HeaderValue::from_str(value).map_err(|_| Error::Config("invalid header value"))?;
        req = req.header(*name, value);
    }
    if let Some(body) = body {
        req = req.header(CONTENT_TYPE, "application/json").body(body);
    }
    read_raw(req.send().await.map_err(Error::transport)?).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(status: u16, retry_after: Option<u64>, body: &[u8]) -> RawResponse {
        RawResponse {
            status,
            retry_after,
            body: body.to_vec().into(),
        }
    }

    #[test]
    fn error_body_is_mapped_with_status() {
        let e = error_from(&raw(400, None, br#"{"error":"invalid_grant"}"#));
        assert!(
            matches!(e, Error::OAuth { ref error, status: 400, .. } if error == "invalid_grant")
        );
        assert!(matches!(
            error_from(&raw(502, None, b"<html>")),
            Error::Status(502)
        ));
    }

    #[test]
    fn too_many_requests_is_rate_limited_even_with_an_oauth_body() {
        let e = error_from(&raw(429, Some(30), br#"{"error":"invalid_grant"}"#));
        assert!(matches!(
            e,
            Error::RateLimited {
                retry_after: Some(30)
            }
        ));
        assert!(matches!(
            error_from(&raw(429, None, b"")),
            Error::RateLimited { retry_after: None }
        ));
    }
}
