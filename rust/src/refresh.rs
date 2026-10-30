//! Refresh: new tokens for a refresh token, and the check of the new ID
//! token. The provider rotates the refresh token on every use and treats a
//! reused old one as theft (it revokes the whole token family), so new
//! tokens are never dropped: if the new ID token is rejected, they come
//! back inside [`RefreshError::IdToken`].

use crate::claims::IdClaims;
use crate::client::Client;
use crate::error::{Error, TokenError};
use crate::tokens::Tokens;
use thiserror::Error;

/// Result of a refresh.
#[derive(Debug, Clone)]
pub struct Refreshed {
    /// The new tokens (with a new refresh token: replace the old one).
    pub tokens: Tokens,
    /// Verified claims of the new ID token, if one was issued (its `sub` is
    /// checked against `expected_sub` of [`Client::refresh`]).
    pub claims: Option<IdClaims>,
}

/// Why [`Client::refresh`] failed.
///
/// There is deliberately no conversion into [`enum@Error`]: `?` would drop
/// the rotated tokens of [`RefreshError::IdToken`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RefreshError {
    /// The token request failed; no new tokens were issued. With
    /// [`Error::RateLimited`] the old refresh token is still valid (retry
    /// later); `invalid_grant` ([`Error::OAuth`], status `400`) means the
    /// login is over. After [`Error::Transport`] it is unknown whether the
    /// provider rotated the token.
    #[error(transparent)]
    Request(Error),
    /// The provider issued new tokens – the old refresh token is now
    /// **used up** – but the new ID token was rejected (`source`: e.g.
    /// [`Error::KeysUnavailable`] or a [`TokenError`]). Store
    /// `tokens.refresh_token` in place of the old one in any case. Then
    /// either retry the check later with [`Client::verify_refreshed`] or,
    /// with [`TokenError::WrongSubject`] (tokens of another user), revoke
    /// the new refresh token and end the session.
    #[error("refreshed ID token rejected: {source}")]
    IdToken {
        /// The new tokens (unverified ID token).
        tokens: Box<Tokens>,
        /// Why the ID token was rejected.
        #[source]
        source: Error,
    },
}

impl RefreshError {
    /// The error of the request or of the ID token check.
    pub fn error(&self) -> &Error {
        match self {
            RefreshError::Request(e) | RefreshError::IdToken { source: e, .. } => e,
        }
    }

    /// The new tokens, if the provider issued any (see [`RefreshError::IdToken`]).
    pub fn tokens(&self) -> Option<&Tokens> {
        match self {
            RefreshError::IdToken { tokens, .. } => Some(tokens),
            RefreshError::Request(_) => None,
        }
    }
}

impl Client {
    /// Exchanges a refresh token for new tokens and verifies a new ID token
    /// (without `nonce`).
    ///
    /// `expected_sub`: the `sub` of the login. If given, a new ID token for
    /// another user is rejected ([`TokenError::WrongSubject`], OIDC Core
    /// §12.2); pass it whenever the session knows it.
    ///
    /// Errors: see [`RefreshError`] – after [`RefreshError::IdToken`] the
    /// old refresh token is already used up; keep the new one.
    pub async fn refresh(
        &self,
        refresh_token: &str,
        expected_sub: Option<&str>,
    ) -> Result<Refreshed, RefreshError> {
        let fields = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];
        let tokens = self
            .token_request(&fields)
            .await
            .map_err(RefreshError::Request)?;
        match self.verify_refreshed(&tokens, expected_sub).await {
            Ok(claims) => Ok(Refreshed { tokens, claims }),
            Err(source) => Err(RefreshError::IdToken {
                tokens: Box::new(tokens),
                source,
            }),
        }
    }

    /// Verifies the ID token of refreshed `tokens` (`None` if none was
    /// issued): signature, `typ`, `iss`, `aud`, `azp`, `exp`/`iat`, no
    /// `nonce`, `at_hash` and `sub` = `expected_sub`. [`Client::refresh`]
    /// does this; call it directly to retry the check after
    /// [`RefreshError::IdToken`] (e.g. once the keys can be loaded again).
    pub async fn verify_refreshed(
        &self,
        tokens: &Tokens,
        expected_sub: Option<&str>,
    ) -> Result<Option<IdClaims>, Error> {
        let Some(id_token) = &tokens.id_token else {
            return Ok(None);
        };
        let access_token = tokens.access_token.expose_secret();
        let claims = self
            .verify_id_token(id_token.expose_secret(), access_token, None)
            .await?;
        if expected_sub.is_some_and(|sub| claims.sub != sub) {
            return Err(TokenError::WrongSubject.into());
        }
        Ok(Some(claims))
    }
}
