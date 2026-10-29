//! Push receiver for Security Event Tokens (RFC 8935): framework-agnostic,
//! takes the request's `Content-Type` and body and returns the response to
//! send. Deduplication goes through a caller-provided [`JtiStore`], because
//! the provider delivers at least once.
//!
//! Responses:
//! - `202` without body: accepted (also for an already processed `jti`, so
//!   the provider stops retrying),
//! - `400` with `{"err", "description"}` (RFC 8935 §2.3): the token was
//!   rejected (`invalid_request`, `invalid_key`, `invalid_issuer`,
//!   `invalid_audience`),
//! - `503` without body: signing keys or the store unavailable (the
//!   provider retries),
//! - `500` without body: the application's handler failed (the provider retries).

use super::{CONTENT_TYPE_SECEVENT, SecurityEvent};
use crate::client::Client;
use crate::error::{Error, TokenError};
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Largest accepted body (a Security Event Token is about 1 KiB).
pub(crate) const MAX_SET_BYTES: usize = 64 * 1024;

/// How long a processed `jti` is remembered. The contract asks for at least
/// 72 hours for the push; the catch-up repeats events of the last 30 days
/// with the same `jti`, so a store shared by both should keep them longer.
pub const JTI_TTL: Duration = Duration::from_secs(31 * 24 * 3600);

/// Error of a [`JtiStore`] implementation.
pub type StoreError = Box<dyn std::error::Error + Send + Sync>;

/// Remembers processed event ids (`jti`). Provided by the application and
/// shared by all its instances (e.g. a database table or Redis).
pub trait JtiStore: Send + Sync {
    /// Whether `jti` was already processed.
    fn seen(&self, jti: &str) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Records `jti` as processed for at least `ttl`.
    fn remember(
        &self,
        jti: &str,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// In-memory [`JtiStore`] for tests and applications with exactly **one**
/// instance; entries are lost on restart.
#[derive(Debug, Default)]
pub struct MemoryJtiStore {
    entries: Mutex<HashMap<String, Instant>>,
}

impl MemoryJtiStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs `f` on the map; a poisoned lock still holds consistent data.
    fn with<T>(&self, f: impl FnOnce(&mut HashMap<String, Instant>) -> T) -> T {
        let mut guard = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut guard)
    }
}

impl JtiStore for MemoryJtiStore {
    /// Whether `jti` is stored and not yet expired.
    fn seen(&self, jti: &str) -> impl Future<Output = Result<bool, StoreError>> + Send {
        let now = Instant::now();
        let seen = self.with(|m| m.get(jti).is_some_and(|until| *until > now));
        std::future::ready(Ok(seen))
    }

    /// Stores `jti` until `ttl` from now and drops expired entries.
    fn remember(
        &self,
        jti: &str,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let now = Instant::now();
        self.with(|m| {
            m.retain(|_, until| *until > now);
            m.insert(jti.to_owned(), now + ttl);
        });
        std::future::ready(Ok(()))
    }
}

/// The response for the provider's push request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushResponse {
    /// HTTP status (`202`, `400`, `500` or `503`).
    pub status: u16,
    /// JSON body (`application/json`, only with `400`).
    pub body: Option<String>,
}

impl PushResponse {
    /// `202 Accepted` without body.
    fn accepted() -> Self {
        Self::bare(202)
    }

    /// A status without body.
    fn bare(status: u16) -> Self {
        Self { status, body: None }
    }

    /// `400` with the RFC 8935 error object.
    fn rejected(err: &str, description: &str) -> Self {
        let body = serde_json::json!({ "err": err, "description": description }).to_string();
        Self {
            status: 400,
            body: Some(body),
        }
    }

    /// The RFC 8935 error code of a `400` response (`invalid_key`, …).
    pub fn err(&self) -> Option<String> {
        let body: serde_json::Value = serde_json::from_str(self.body.as_deref()?).ok()?;
        body.get("err")?.as_str().map(str::to_owned)
    }
}

/// The response for a failed verification.
fn rejection(e: &Error) -> PushResponse {
    match e {
        Error::Token(t) => {
            let err = match t {
                TokenError::WrongIssuer => "invalid_issuer",
                TokenError::WrongAudience => "invalid_audience",
                TokenError::UnknownKey | TokenError::BadSignature | TokenError::AlgNotAllowed => {
                    "invalid_key"
                }
                _ => "invalid_request",
            };
            PushResponse::rejected(err, &t.to_string())
        }
        Error::KeysUnavailable
        | Error::Transport(_)
        | Error::Status(_)
        | Error::InvalidResponse => PushResponse::bare(503),
        _ => PushResponse::rejected("invalid_request", "invalid security event token"),
    }
}

/// Whether the media type is `application/secevent+jwt` (parameters allowed).
fn is_secevent(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case(CONTENT_TYPE_SECEVENT))
}

/// The token in the body: UTF-8, size-limited, surrounding whitespace removed.
fn token_from(body: &[u8]) -> Option<&str> {
    if body.len() > MAX_SET_BYTES {
        return None;
    }
    let token = std::str::from_utf8(body).ok()?.trim();
    (!token.is_empty()).then_some(token)
}

impl Client {
    /// Handles one push request of the provider (RFC 8935): checks the
    /// `Content-Type`, verifies the token ([`Client::verify_security_event`]),
    /// skips an already processed `jti`, runs `handle` and then remembers
    /// the `jti` in `store` for [`JTI_TTL`]. Returns the response to send;
    /// see the module documentation for the status codes.
    ///
    /// `handle` should be idempotent: an event is delivered at least once,
    /// and a store failure after `handle` succeeded leads to a second run.
    pub async fn receive_event<S, F, Fut, E>(
        &self,
        content_type: Option<&str>,
        body: &[u8],
        store: &S,
        handle: F,
    ) -> PushResponse
    where
        S: JtiStore,
        F: FnOnce(SecurityEvent) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        if !is_secevent(content_type) {
            return PushResponse::rejected(
                "invalid_request",
                "content type must be application/secevent+jwt",
            );
        }
        let Some(token) = token_from(body) else {
            return PushResponse::rejected("invalid_request", "empty or oversized body");
        };
        let event = match self.verify_security_event(token).await {
            Ok(event) => event,
            Err(e) => return rejection(&e),
        };
        match store.seen(&event.jti).await {
            Ok(true) => return PushResponse::accepted(),
            Ok(false) => {}
            Err(_) => return PushResponse::bare(503),
        }
        let jti = event.jti.clone();
        if handle(event).await.is_err() {
            return PushResponse::bare(500);
        }
        // Processed: a failing store must not make the provider retry an
        // event that was handled (the next delivery would run it again).
        let _ = store.remember(&jti, JTI_TTL).await;
        PushResponse::accepted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_and_body_checks() {
        assert!(is_secevent(Some("application/secevent+jwt")));
        assert!(is_secevent(Some("Application/SecEvent+JWT; charset=utf-8")));
        assert!(!is_secevent(Some("application/jwt")) && !is_secevent(None));
        assert_eq!(token_from(b" a.b.c\n"), Some("a.b.c"));
        assert_eq!(token_from(b"  "), None);
        assert_eq!(token_from(&[0xff, 0xfe]), None);
        assert_eq!(token_from(&vec![b'a'; MAX_SET_BYTES + 1]), None);
    }

    #[test]
    fn errors_map_to_rfc_8935_codes() {
        let code = |t: TokenError| rejection(&Error::Token(t)).err();
        assert_eq!(
            code(TokenError::WrongIssuer).as_deref(),
            Some("invalid_issuer")
        );
        assert_eq!(
            code(TokenError::WrongAudience).as_deref(),
            Some("invalid_audience")
        );
        assert_eq!(
            code(TokenError::BadSignature).as_deref(),
            Some("invalid_key")
        );
        assert_eq!(
            code(TokenError::Expired).as_deref(),
            Some("invalid_request")
        );
        let r = rejection(&Error::KeysUnavailable);
        assert_eq!((r.status, r.body), (503, None));
    }

    #[tokio::test]
    async fn memory_store_remembers_until_ttl() {
        let s = MemoryJtiStore::new();
        assert!(!s.seen("a").await.unwrap());
        s.remember("a", Duration::from_secs(60)).await.unwrap();
        s.remember("b", Duration::ZERO).await.unwrap();
        assert!(s.seen("a").await.unwrap());
        assert!(!s.seen("b").await.unwrap());
    }
}
