//! Client-credentials tokens for the management API and their cache.

use crate::client::Client;
use crate::error::Result;
use crate::http;
use crate::tokens::Tokens;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// A cached token is renewed this long before it expires.
const RENEW_BEFORE: Duration = Duration::from_secs(30);

impl Client {
    /// Requests an access token with `grant_type=client_credentials` for
    /// the management API. Empty `scopes` = all `manage:*` scopes
    /// registered for the application. [`crate::Management`] does this
    /// (and caches the token); call it directly only for own requests.
    pub async fn client_credentials(&self, scopes: &[&str]) -> Result<Tokens> {
        let scope = scopes.join(" ");
        let mut fields = vec![("grant_type", "client_credentials")];
        if !scope.is_empty() {
            fields.push(("scope", scope.as_str()));
        }
        let creds = self.credentials();
        http::post_form_json(&self.http, &self.meta.token_endpoint, &fields, &creds).await
    }
}

/// The current token and when it must be renewed.
struct Cached {
    token: Zeroizing<String>,
    renew_at: Instant,
}

/// Single-flight token cache: at most one token request at a time.
pub(crate) struct TokenCache {
    scope: Option<String>,
    current: tokio::sync::Mutex<Option<Cached>>,
}

impl TokenCache {
    /// An empty cache requesting `scope` (`None` = all registered scopes).
    pub(crate) fn new(scope: Option<String>) -> Self {
        Self {
            scope,
            current: tokio::sync::Mutex::new(None),
        }
    }

    /// A valid token. `rejected` is a token the API answered `401` to: it
    /// is renewed only if it is still the cached one, so concurrent callers
    /// hit by the same `401` share one new token (single flight).
    pub(crate) async fn get(
        &self,
        client: &Client,
        rejected: Option<&str>,
    ) -> Result<Zeroizing<String>> {
        let mut current = self.current.lock().await;
        let now = Instant::now();
        if let Some(c) = current.as_ref().filter(|c| c.renew_at > now)
            && rejected != Some(c.token.as_str())
        {
            return Ok(c.token.clone());
        }
        let scopes: Vec<&str> = self.scope.as_deref().map_or(Vec::new(), |s| vec![s]);
        let tokens = client.client_credentials(&scopes).await?;
        let lifetime = Duration::from_secs(u64::try_from(tokens.expires_in).unwrap_or(0));
        let token = Zeroizing::new(tokens.access_token);
        *current = Some(Cached {
            token: token.clone(),
            renew_at: now + lifetime.saturating_sub(RENEW_BEFORE),
        });
        Ok(token)
    }
}
