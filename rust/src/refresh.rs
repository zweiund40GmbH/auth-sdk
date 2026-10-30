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
    /// `tokens.refresh_token` in place of the old one in any case. Then,
    /// after [`Error::KeysUnavailable`] (a passing failure), keep the
    /// session and catch the check up later with
    /// [`Client::verify_refreshed_at`] and `received_at`; after any other
    /// error (a verdict on the token, e.g. [`TokenError::WrongSubject`] or a
    /// bad signature), revoke the new refresh token and end the session.
    #[error("refreshed ID token rejected: {source}")]
    IdToken {
        /// The new tokens (unverified ID token).
        tokens: Box<Tokens>,
        /// Why the ID token was rejected.
        #[source]
        source: Error,
        /// When the tokens were received (seconds since the Unix epoch):
        /// a later check judges `exp`/`iat` at this time, so a short-lived
        /// ID token does not expire while the keys are unreachable.
        received_at: i64,
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

    /// When the new tokens were received (seconds since the Unix epoch), if
    /// the provider issued any – the time to pass to
    /// [`Client::verify_refreshed_at`].
    pub fn received_at(&self) -> Option<i64> {
        match self {
            RefreshError::IdToken { received_at, .. } => Some(*received_at),
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
        let received_at = now();
        match self
            .verify_refreshed_at(&tokens, expected_sub, received_at)
            .await
        {
            Ok(claims) => Ok(Refreshed { tokens, claims }),
            Err(source) => Err(RefreshError::IdToken {
                tokens: Box::new(tokens),
                source,
                received_at,
            }),
        }
    }

    /// Verifies the ID token of refreshed `tokens` at the current time; see
    /// [`Client::verify_refreshed_at`]. To catch up a check after
    /// [`RefreshError::IdToken`], use that one with `received_at`: a
    /// short-lived ID token may have expired since.
    pub async fn verify_refreshed(
        &self,
        tokens: &Tokens,
        expected_sub: Option<&str>,
    ) -> Result<Option<IdClaims>, Error> {
        self.verify_refreshed_at(tokens, expected_sub, now()).await
    }

    /// Verifies the ID token of refreshed `tokens` (`None` if none was
    /// issued): signature, `typ`, `iss`, `aud`, `azp`, no `nonce`,
    /// `at_hash`, `sub` = `expected_sub`, and `exp`/`nbf`/`iat` as of
    /// `received_at` (seconds since the Unix epoch, see
    /// [`RefreshError::received_at`]) – the same window as a check right at
    /// receipt, so a token that had already expired then is still rejected.
    /// A `received_at` in the future counts as now. [`Client::refresh`] does
    /// this; call it directly to catch up the check after
    /// [`RefreshError::IdToken`] with [`Error::KeysUnavailable`]. Pass only
    /// the time the application stored itself, never one from a request.
    pub async fn verify_refreshed_at(
        &self,
        tokens: &Tokens,
        expected_sub: Option<&str>,
        received_at: i64,
    ) -> Result<Option<IdClaims>, Error> {
        let Some(id_token) = &tokens.id_token else {
            return Ok(None);
        };
        // Never later than now; before the epoch everything has expired.
        let at = u64::try_from(received_at.min(now())).unwrap_or(0);
        let access_token = tokens.access_token.expose_secret();
        let claims = self
            .verify_id_token(id_token.expose_secret(), access_token, None, at)
            .await?;
        if expected_sub.is_some_and(|sub| claims.sub != sub) {
            return Err(TokenError::WrongSubject.into());
        }
        Ok(Some(claims))
    }
}

/// Current time in seconds since the Unix epoch.
fn now() -> i64 {
    i64::try_from(jsonwebtoken::get_current_timestamp()).unwrap_or(i64::MAX)
}
