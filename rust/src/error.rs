//! The one error type of the crate.
//!
//! Variants say what an application needs to react (retry later, restart the
//! login, show an error page), not how the check failed internally. Messages
//! never contain tokens, secrets or URLs.

use std::collections::BTreeMap;
use thiserror::Error;

/// Result with the crate's [`enum@Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Why a JWT (ID, access or logout token) was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TokenError {
    /// Not a well-formed JWS, unknown header fields or a `crit` header.
    #[error("malformed token")]
    Malformed,
    /// `alg` is not on the allowlist or does not match the key.
    #[error("algorithm not allowed")]
    AlgNotAllowed,
    /// No key with this `kid` in the provider's JWKS (also after a refresh).
    #[error("unknown signing key")]
    UnknownKey,
    /// Header `typ` is not the one expected for this kind of token.
    #[error("unexpected token type")]
    WrongType,
    /// Signature does not verify.
    #[error("invalid signature")]
    BadSignature,
    /// `exp` is in the past (beyond the leeway).
    #[error("token expired")]
    Expired,
    /// `nbf` or `iat` is in the future (beyond the leeway).
    #[error("token not yet valid")]
    NotYetValid,
    /// `iss` is not the provider's issuer.
    #[error("wrong issuer")]
    WrongIssuer,
    /// `aud` does not contain the expected audience.
    #[error("wrong audience")]
    WrongAudience,
    /// `azp` is missing (several audiences) or not this client.
    #[error("wrong authorized party")]
    WrongAzp,
    /// `nonce` does not match the login request (or is present where it must not be).
    #[error("nonce mismatch")]
    WrongNonce,
    /// `auth_time` is older than `max_age` allows or predates a `prompt=login` request.
    #[error("authentication too old")]
    AuthTooOld,
    /// `acr` is not one of the requested `acr_values` (e.g. no second factor).
    #[error("insufficient authentication context")]
    InsufficientAcr,
    /// `sub` of a refreshed ID token is not the user of the login.
    #[error("wrong subject")]
    WrongSubject,
    /// `at_hash` does not match the access token.
    #[error("access token hash mismatch")]
    AtHashMismatch,
    /// A required claim is missing or has the wrong form.
    #[error("missing or invalid claim `{0}`")]
    Claim(&'static str),
}

/// Everything that can go wrong when talking to the provider or checking its answers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The caller passed something unusable (e.g. a reserved authorize parameter).
    #[error("invalid configuration: {0}")]
    Config(&'static str),
    /// The discovery document is unusable (issuer mismatch, no PKCE S256, insecure URL, …).
    #[error("discovery document rejected: {0}")]
    Discovery(&'static str),
    /// The provider could not be reached (network, TLS, timeout).
    #[error("identity provider not reachable")]
    Transport(#[source] reqwest::Error),
    /// The access token was rejected by UserInfo (`401`: invalid, expired or
    /// revoked, RFC 6750 §3.1).
    #[error("access token rejected by the identity provider")]
    Unauthorized,
    /// The provider's signing keys could not be loaded recently enough to
    /// trust them (whatever the cause of the failed fetch).
    #[error("signing keys of the identity provider unavailable")]
    KeysUnavailable,
    /// The provider answered with an unexpected HTTP status.
    #[error("identity provider answered with HTTP {0}")]
    Status(u16),
    /// The provider's answer could not be parsed or was too large.
    #[error("invalid response from the identity provider")]
    InvalidResponse,
    /// Error response of the token or revocation endpoint (RFC 6749 §5.2), e.g.
    /// `invalid_grant` for an expired code or a revoked refresh token, or of
    /// UserInfo with `403` (`insufficient_scope`, RFC 6750 §3.1).
    #[error("identity provider rejected the request: {error}")]
    OAuth {
        /// The `error` code.
        error: String,
        /// The `error_description`, if sent (English, for logs).
        description: Option<String>,
    },
    /// Error response at the callback (RFC 6749 §4.1.2.1), e.g. `login_required`
    /// after `prompt=none`. Only returned after `state` and `iss` were verified.
    #[error("authorization failed: {error}")]
    Authorization {
        /// The `error` code.
        error: String,
        /// The `error_description`, if sent (English, for logs).
        description: Option<String>,
    },
    /// The callback query is not decodable, repeats a parameter or lacks `code`/`state`.
    #[error("invalid callback request")]
    InvalidCallback,
    /// `state` of the callback does not belong to this login.
    #[error("state mismatch")]
    StateMismatch,
    /// `iss` of the callback is missing or not the provider (RFC 9207, mix-up defence).
    #[error("issuer mismatch in the authorization response")]
    IssuerMismatch,
    /// A token was rejected.
    #[error("token rejected: {0}")]
    Token(#[from] TokenError),
    /// Error answer of the management API (`{"error": {"code", "message", "fields"}}`).
    #[error("management API rejected the request: {} (HTTP {})", .0.code, .0.status)]
    Api(ApiError),
}

/// Error answer of the management API.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ApiError {
    /// HTTP status (`403`, `404`, `409`, `422`, `429`, `503`, …).
    pub status: u16,
    /// Machine-readable code: `forbidden`, `not_found`, `conflict`,
    /// `validation`, `rate_limited`, `unavailable`, `internal`, …
    pub code: String,
    /// Message for users (German), safe to show.
    pub message: String,
    /// Field errors (only with `validation`): field name → message.
    pub fields: BTreeMap<String, String>,
    /// Seconds from `Retry-After` (with `429`), if sent.
    pub retry_after: Option<u64>,
}

impl Error {
    /// Wraps a transport error without its URL (keeps logs short and free of query strings).
    pub(crate) fn transport(e: reqwest::Error) -> Self {
        Error::Transport(e.without_url())
    }
}
