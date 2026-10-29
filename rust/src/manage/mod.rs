//! Client of the management API (`/api/v1/manage/…`): server-to-server
//! calls of the application with a client-credentials token. Everything is
//! limited to the calling application by the provider.
//!
//! - [`Management`] holds the token (fetched on first use, renewed shortly
//!   before it expires or after a `401`) and sends the requests.
//! - Onboarding links ([`onboarding`]), links to local accounts ([`links`])
//!   and the event catch-up ([`catch_up`]) add their calls as `impl` blocks.
//!
//! Error answers become [`Error::Api`] with code, message and field errors
//! of the provider; `401` after a fresh token becomes [`Error::Unauthorized`].

pub mod catch_up;
pub mod links;
pub mod onboarding;
mod token;

use crate::client::Client;
use crate::error::{ApiError, Error, Result};
use crate::http::{self, RawResponse};
use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::sync::Arc;
use token::TokenCache;
use url::Url;

/// Largest length of `X-On-Behalf-Of`.
const MAX_ON_BEHALF_OF: usize = 128;

/// Management API client of one application. Cheap to clone (the token
/// cache is shared); all methods take `&self`.
#[derive(Clone)]
pub struct Management {
    client: Arc<Client>,
    base: Url,
    token: Arc<TokenCache>,
    on_behalf_of: Option<String>,
}

impl std::fmt::Debug for Management {
    /// Prints the base URL only (never the token).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Management")
            .field("base", &self.base.as_str())
            .field("on_behalf_of", &self.on_behalf_of)
            .finish_non_exhaustive()
    }
}

/// Error body of the management API.
#[derive(serde::Deserialize)]
struct ErrorBody {
    error: ErrorDetail,
}

/// `error` object of [`ErrorBody`].
#[derive(serde::Deserialize)]
struct ErrorDetail {
    code: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    fields: BTreeMap<String, String>,
}

/// Maps a non-success answer to [`Error::Api`], or [`Error::Status`] if the
/// body is not the API's error format.
fn api_error(resp: &RawResponse) -> Error {
    match serde_json::from_slice::<ErrorBody>(&resp.body) {
        Ok(b) => Error::Api(ApiError {
            status: resp.status,
            code: b.error.code,
            message: b.error.message,
            fields: b.error.fields,
            retry_after: resp.retry_after,
        }),
        Err(_) => Error::Status(resp.status),
    }
}

/// Whether `value` is a valid `X-On-Behalf-Of`: 1–128 visible ASCII characters.
fn valid_on_behalf_of(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ON_BEHALF_OF
        && value.bytes().all(|b| (b'!'..=b'~').contains(&b))
}

impl Management {
    /// A management client for `client`. The token is requested without
    /// `scope`, i.e. with all `manage:*` scopes registered for the
    /// application; [`Management::with_scopes`] narrows it.
    pub fn new(client: Arc<Client>) -> Result<Self> {
        let base = format!(
            "{}/api/v1/manage/",
            client.metadata().issuer.trim_end_matches('/')
        );
        let base = Url::parse(&base).map_err(|_| Error::Config("issuer is not a URL"))?;
        Ok(Self {
            client,
            base,
            token: Arc::new(TokenCache::new(None)),
            on_behalf_of: None,
        })
    }

    /// Requests tokens with exactly these scopes (e.g. `manage:onboarding`).
    pub fn with_scopes(mut self, scopes: &[&str]) -> Self {
        self.token = Arc::new(TokenCache::new(Some(scopes.join(" "))));
        self
    }

    /// The same client, sending `X-On-Behalf-Of: <local_user_id>` (the
    /// local user who triggered the call; only recorded in the provider's
    /// audit log). 1–128 visible ASCII characters, else [`Error::Config`].
    pub fn on_behalf_of(&self, local_user_id: &str) -> Result<Self> {
        if !valid_on_behalf_of(local_user_id) {
            return Err(Error::Config(
                "X-On-Behalf-Of must be 1-128 visible ASCII characters",
            ));
        }
        let mut copy = self.clone();
        copy.on_behalf_of = Some(local_user_id.to_owned());
        Ok(copy)
    }

    /// URL of the API path `segments` (each percent-encoded) with `query`.
    pub(crate) fn url(&self, segments: &[&str], query: &[(&str, &str)]) -> Result<Url> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| Error::Config("issuer is not a URL"))?
            .pop_if_empty()
            .extend(segments);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        Ok(url)
    }

    /// Sends one request; a `401` is retried once with a fresh token.
    async fn send(&self, method: Method, url: &Url, body: Option<String>) -> Result<RawResponse> {
        let headers: Vec<(&str, &str)> = self
            .on_behalf_of
            .as_deref()
            .map(|v| ("x-on-behalf-of", v))
            .into_iter()
            .collect();
        let mut fresh = false;
        loop {
            let token = self.token.get(&self.client, fresh).await?;
            let resp = http::send_bearer(
                &self.client.http,
                method.clone(),
                url,
                &token,
                body.clone(),
                &headers,
            )
            .await?;
            match resp.status {
                401 if !fresh => fresh = true,
                401 => return Err(Error::Unauthorized),
                200..=299 => return Ok(resp),
                _ => return Err(api_error(&resp)),
            }
        }
    }

    /// Request expecting a JSON answer.
    pub(crate) async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        url: &Url,
        body: Option<&impl Serialize>,
    ) -> Result<T> {
        let resp = self.send(method, url, serialize(body)?).await?;
        http::parse_json(&resp.body)
    }

    /// Request expecting only a success status (`204`).
    pub(crate) async fn empty(&self, method: Method, url: &Url) -> Result<()> {
        self.send(method, url, None).await.map(|_| ())
    }
}

/// Serializes an optional JSON body.
fn serialize(body: Option<&impl Serialize>) -> Result<Option<String>> {
    body.map(serde_json::to_string)
        .transpose()
        .map_err(|_| Error::Config("request body not serializable"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_body_is_mapped() {
        let resp = RawResponse {
            status: 422,
            retry_after: None,
            body: r#"{"error":{"code":"validation","message":"Bitte Eingaben prüfen.","fields":{"localId":"Ungültig."}}}"#
                .as_bytes()
                .to_vec(),
        };
        let Error::Api(e) = api_error(&resp) else {
            panic!("not an API error")
        };
        assert_eq!((e.status, e.code.as_str()), (422, "validation"));
        assert_eq!(e.fields["localId"], "Ungültig.");
        let html = RawResponse {
            status: 502,
            retry_after: None,
            body: b"<html>".to_vec(),
        };
        assert!(matches!(api_error(&html), Error::Status(502)));
    }

    #[test]
    fn on_behalf_of_is_visible_ascii() {
        assert!(valid_on_behalf_of("17") && valid_on_behalf_of("a:b!~"));
        assert!(!valid_on_behalf_of("") && !valid_on_behalf_of("a b"));
        assert!(!valid_on_behalf_of("ä") && !valid_on_behalf_of(&"a".repeat(129)));
    }
}
