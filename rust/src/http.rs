//! The one HTTP layer of the crate: a `reqwest` client with timeouts and
//! without redirects, size-limited bodies, form posts with client
//! authentication and the OAuth error format (RFC 6749 §5.2).

use crate::error::{Error, Result};
use crate::secret::ClientSecret;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde::de::DeserializeOwned;
use std::time::Duration;
use url::Url;

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

/// How the client authenticates at the token and revocation endpoints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthMethod {
    /// `client_secret_basic`: credentials in the `Authorization` header (default).
    #[default]
    Basic,
    /// `client_secret_post`: credentials in the form body.
    Post,
}

/// Client credentials attached to a form post.
pub(crate) struct Credentials<'a> {
    /// The client id.
    pub client_id: &'a str,
    /// The client secret.
    pub secret: &'a ClientSecret,
    /// How to send them.
    pub method: AuthMethod,
}

/// Reads at most [`MAX_BODY`] bytes of `resp`.
async fn read_body(mut resp: reqwest::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
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

/// Maps a non-success answer: OAuth error body if present, else the status.
fn error_from(status: u16, body: &[u8]) -> Error {
    match serde_json::from_slice::<OAuthErrorBody>(body) {
        Ok(e) => Error::OAuth {
            error: e.error,
            description: e.error_description,
        },
        Err(_) => Error::Status(status),
    }
}

/// Turns a response into `T` (2xx with JSON) or an [`Error`].
async fn json_response<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let status = resp.status();
    let body = read_body(resp).await?;
    if status.is_success() {
        parse_json(&body)
    } else {
        Err(error_from(status.as_u16(), &body))
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
fn sensitive(value: &str) -> Result<HeaderValue> {
    let mut v = HeaderValue::from_str(value).map_err(|_| Error::Config("invalid header value"))?;
    v.set_sensitive(true);
    Ok(v)
}

/// `client_secret_basic` header: id and secret are form-urlencoded before
/// base64 (RFC 6749 §2.3.1), which the provider decodes.
fn basic_header(client_id: &str, secret: &ClientSecret) -> Result<HeaderValue> {
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let raw = format!("{}:{}", enc(client_id), enc(secret.expose_secret()));
    sensitive(&format!("Basic {}", STANDARD.encode(raw)))
}

/// The form body, with the credentials for `client_secret_post`. A plain
/// function on purpose: the serializer is not `Send` and must not live
/// across an `.await` (the futures must stay `Send` for axum/tokio).
fn form_body(fields: &[(&str, &str)], creds: &Credentials<'_>) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.extend_pairs(fields);
    if creds.method == AuthMethod::Post {
        form.append_pair("client_id", creds.client_id);
        form.append_pair("client_secret", creds.secret.expose_secret());
    }
    form.finish()
}

/// Builds and sends a form post with client authentication.
async fn send_form(
    http: &reqwest::Client,
    url: &Url,
    fields: &[(&str, &str)],
    creds: &Credentials<'_>,
) -> Result<reqwest::Response> {
    let mut req = http
        .post(url.clone())
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form_body(fields, creds));
    if creds.method == AuthMethod::Basic {
        req = req.header(AUTHORIZATION, basic_header(creds.client_id, creds.secret)?);
    }
    req.send().await.map_err(Error::transport)
}

/// Form post expecting a JSON answer (token endpoint).
pub(crate) async fn post_form_json<T: DeserializeOwned>(
    http: &reqwest::Client,
    url: &Url,
    fields: &[(&str, &str)],
    creds: &Credentials<'_>,
) -> Result<T> {
    json_response(send_form(http, url, fields, creds).await?).await
}

/// Form post expecting only a success status (revocation endpoint).
pub(crate) async fn post_form_empty(
    http: &reqwest::Client,
    url: &Url,
    fields: &[(&str, &str)],
    creds: &Credentials<'_>,
) -> Result<()> {
    let resp = send_form(http, url, fields, creds).await?;
    let status = resp.status();
    let body = read_body(resp).await?;
    if status.is_success() {
        Ok(())
    } else {
        Err(error_from(status.as_u16(), &body))
    }
}

/// A raw answer: status, `Retry-After` seconds and the size-limited body.
pub(crate) struct RawResponse {
    /// HTTP status.
    pub status: u16,
    /// `Retry-After` in seconds, if sent as a number.
    pub retry_after: Option<u64>,
    /// The body.
    pub body: Vec<u8>,
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
    let resp = req.send().await.map_err(Error::transport)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_header_form_encodes_credentials() {
        let v = basic_header("app:1", &ClientSecret::new("s e/cret")).unwrap();
        assert!(v.is_sensitive());
        let b64 = v.to_str().unwrap().strip_prefix("Basic ").unwrap();
        let raw = String::from_utf8(STANDARD.decode(b64).unwrap()).unwrap();
        assert_eq!(raw, "app%3A1:s+e%2Fcret");
    }

    #[test]
    fn error_body_is_mapped() {
        let e = error_from(400, br#"{"error":"invalid_grant"}"#);
        assert!(matches!(e, Error::OAuth { ref error, .. } if error == "invalid_grant"));
        assert!(matches!(error_from(502, b"<html>"), Error::Status(502)));
    }
}
