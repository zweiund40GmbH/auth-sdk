//! Form posts with client authentication (token and revocation endpoints):
//! `client_secret_basic` or `client_secret_post`, bodies zeroed on drop.

use super::{RawResponse, error_from, parse_json, read_raw, sensitive};
use crate::error::{Error, Result};
use crate::secret::ClientSecret;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde::de::DeserializeOwned;
use url::Url;
use zeroize::Zeroizing;

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

/// `client_secret_basic` header: id and secret are form-urlencoded before
/// base64 (RFC 6749 §2.3.1), which the provider decodes.
fn basic_header(client_id: &str, secret: &ClientSecret) -> Result<HeaderValue> {
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let raw = Zeroizing::new(format!(
        "{}:{}",
        enc(client_id),
        enc(secret.expose_secret())
    ));
    sensitive(&format!("Basic {}", STANDARD.encode(raw.as_bytes())))
}

/// A request body that is zeroed when reqwest drops it (form bodies carry
/// codes, refresh tokens and possibly the client secret).
struct ZeroizedBody(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for ZeroizedBody {
    /// The body bytes.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The form body, with the credentials for `client_secret_post`, zeroed on
/// drop. The buffer is sized for the worst case of percent-encoding, so it
/// is never reallocated (which would leave copies behind). A plain
/// function on purpose: the serializer is not `Send` and must not live
/// across an `.await` (the futures must stay `Send` for axum/tokio).
fn form_body(fields: &[(&str, &str)], creds: &Credentials<'_>) -> bytes::Bytes {
    let post = creds.method == AuthMethod::Post;
    let cred_len = if post {
        creds.client_id.len() + creds.secret.expose_secret().len() + 32
    } else {
        0
    };
    let worst = |(k, v): &(&str, &str)| 3 * (k.len() + v.len()) + 2;
    let capacity = fields.iter().map(worst).sum::<usize>() + 3 * cred_len;
    let mut form = url::form_urlencoded::Serializer::new(String::with_capacity(capacity));
    form.extend_pairs(fields);
    if post {
        form.append_pair("client_id", creds.client_id);
        form.append_pair("client_secret", creds.secret.expose_secret());
    }
    let body = Zeroizing::new(form.finish().into_bytes());
    bytes::Bytes::from_owner(ZeroizedBody(body))
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
    let raw = read_raw(send_form(http, url, fields, creds).await?).await?;
    success(&raw)?;
    parse_json(&raw.body)
}

/// Form post expecting only a success status (revocation endpoint).
pub(crate) async fn post_form_empty(
    http: &reqwest::Client,
    url: &Url,
    fields: &[(&str, &str)],
    creds: &Credentials<'_>,
) -> Result<()> {
    let raw = read_raw(send_form(http, url, fields, creds).await?).await?;
    success(&raw)
}

/// `Ok` for a 2xx answer, else the mapped OAuth error.
fn success(raw: &RawResponse) -> Result<()> {
    if (200..300).contains(&raw.status) {
        Ok(())
    } else {
        Err(error_from(raw))
    }
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
}
