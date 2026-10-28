//! The [`Client`]: one confidential OIDC client of the central login, built
//! from the provider's discovery document. Login, token and logout functions
//! live in their own modules as further `impl Client` blocks.

use crate::claims::UserInfo;
use crate::discovery::{self, ProviderMetadata};
use crate::error::{Error, Result};
use crate::http::{self, AuthMethod, Credentials};
use crate::jwks::{Clock, DEFAULT_MAX_STALE, DEFAULT_MIN_REFETCH, JwksCache, Policy};
use crate::secret::ClientSecret;
use jsonwebtoken::Algorithm;
use std::time::Duration;
use url::Url;

/// Settings beyond issuer, client id and secret. `Default` fits most apps.
#[derive(Debug, Clone)]
pub struct Options {
    /// Client authentication at the token and revocation endpoints.
    pub auth_method: AuthMethod,
    /// Minimum time between two JWKS fetches (unknown key ids, failed refreshes).
    pub jwks_min_refetch: Duration,
    /// How long cached signing keys stay usable beyond their 5 minutes while
    /// the JWKS cannot be refreshed. `Duration::ZERO` = fail closed at once.
    pub jwks_max_stale: Duration,
    /// Own HTTP client. **Caution:** the crate's protections then depend on
    /// it: it must not follow redirects (a redirect could carry the client
    /// secret, codes or tokens to another host) and must have timeouts. By
    /// default the crate builds such a client (proxies from `HTTPS_PROXY` /
    /// `NO_PROXY` apply).
    pub http_client: Option<reqwest::Client>,
    /// Clock of the JWKS cache; only tests replace it.
    pub clock: Clock,
}

impl Default for Options {
    /// Basic authentication, JWKS refetch at most every 30 s, old keys at
    /// most 10 min beyond their lifetime, built-in HTTP client, system clock.
    fn default() -> Self {
        Self {
            auth_method: AuthMethod::Basic,
            jwks_min_refetch: DEFAULT_MIN_REFETCH,
            jwks_max_stale: DEFAULT_MAX_STALE,
            http_client: None,
            clock: std::time::Instant::now,
        }
    }
}

/// A confidential client of the central login. Cheap to share behind an
/// `Arc`; all methods take `&self`.
#[derive(Debug)]
pub struct Client {
    pub(crate) meta: ProviderMetadata,
    pub(crate) client_id: String,
    pub(crate) secret: ClientSecret,
    pub(crate) auth_method: AuthMethod,
    pub(crate) http: reqwest::Client,
    pub(crate) jwks: JwksCache,
    pub(crate) algs: Vec<Algorithm>,
}

impl Client {
    /// Loads the discovery document of `issuer` (must match its `issuer`
    /// exactly, e.g. `https://login.example.com`) with default [`Options`].
    pub async fn discover(
        issuer: &str,
        client_id: impl Into<String>,
        secret: ClientSecret,
    ) -> Result<Self> {
        Self::discover_with(issuer, client_id, secret, Options::default()).await
    }

    /// Like [`Client::discover`] with explicit [`Options`].
    pub async fn discover_with(
        issuer: &str,
        client_id: impl Into<String>,
        secret: ClientSecret,
        options: Options,
    ) -> Result<Self> {
        let client_id = client_id.into();
        if client_id.is_empty() {
            return Err(Error::Config("client id is empty"));
        }
        let http = match options.http_client {
            Some(c) => c,
            None => http::default_client()?,
        };
        let meta = discovery::fetch(&http, issuer).await?;
        let algs = meta.allowed_algs();
        let policy = Policy {
            min_refetch: options.jwks_min_refetch,
            max_stale: options.jwks_max_stale,
            clock: options.clock,
        };
        let jwks = JwksCache::new(meta.jwks_uri.clone(), policy);
        Ok(Self {
            meta,
            client_id,
            secret,
            auth_method: options.auth_method,
            http,
            jwks,
            algs,
        })
    }

    /// The validated discovery document.
    pub fn metadata(&self) -> &ProviderMetadata {
        &self.meta
    }

    /// The client id.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Reloads the provider's signing keys now, ignoring the rate limit;
    /// keys no longer published are dropped at once. Emergency path after the
    /// provider revoked a leaked key: call it on every
    /// instance (e.g. via an admin endpoint). If loading fails, **all**
    /// cached keys are dropped (fail closed) and the error is returned.
    pub async fn refresh_keys(&self) -> Result<()> {
        self.jwks.force_refresh(&self.http).await
    }

    /// Credentials for form posts.
    pub(crate) fn credentials(&self) -> Credentials<'_> {
        Credentials {
            client_id: &self.client_id,
            secret: &self.secret,
            method: self.auth_method,
        }
    }

    /// Claims of the user behind `access_token` from the UserInfo endpoint.
    /// An invalid, expired or revoked token (`401`) gives
    /// [`Error::Unauthorized`] – end the local session; a token without
    /// scope `openid` (`403`) gives [`Error::OAuth`] `insufficient_scope`.
    pub async fn userinfo(&self, access_token: &str) -> Result<UserInfo> {
        let url = self
            .meta
            .userinfo_endpoint
            .as_ref()
            .ok_or(Error::Discovery("no userinfo endpoint"))?;
        let info: UserInfo = http::get_json(&self.http, url, Some(access_token)).await?;
        Ok(info)
    }

    /// Revokes a refresh token (the whole token family) or an access token
    /// (RFC 7009). Unknown tokens are not an error.
    pub async fn revoke(&self, token: &str) -> Result<()> {
        let url = self
            .meta
            .revocation_endpoint
            .as_ref()
            .ok_or(Error::Discovery("no revocation endpoint"))?;
        http::post_form_empty(&self.http, url, &[("token", token)], &self.credentials()).await
    }

    /// URL for RP-initiated logout (OIDC RP-Initiated Logout 1.0). Redirect
    /// the browser there after ending the local session. Without a matching
    /// `id_token_hint` the provider asks the user to confirm. The
    /// `post_logout_redirect_uri` must be registered exactly.
    pub fn logout_url(
        &self,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        state: Option<&str>,
    ) -> Result<Url> {
        let mut url = self
            .meta
            .end_session_endpoint
            .clone()
            .ok_or(Error::Discovery("no end_session endpoint"))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("client_id", &self.client_id);
            if let Some(hint) = id_token_hint {
                q.append_pair("id_token_hint", hint);
            }
            if let Some(uri) = post_logout_redirect_uri {
                q.append_pair("post_logout_redirect_uri", uri);
            }
            if let Some(s) = state {
                q.append_pair("state", s);
            }
        }
        Ok(url)
    }
}
