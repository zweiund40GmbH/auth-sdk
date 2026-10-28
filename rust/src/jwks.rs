//! JWKS cache with key rotation.
//!
//! - Keys are fetched lazily and are fresh for [`MAX_AGE`] (the provider
//!   serves the JWKS with `max-age=300`); the next use after that refetches,
//!   so keys the provider removed stop being trusted within minutes.
//! - An unknown `kid` triggers a refetch at most once per `min_refetch`, so
//!   forged `kid`s cannot make us hammer the provider.
//! - If refreshing fails, the old keys stay usable for `max_stale` beyond
//!   [`MAX_AGE`] (`Duration::ZERO` = fail closed); then
//!   [`Error::KeysUnavailable`].
//! - Single flight: at most one fetch runs at a time and the state lock is
//!   never held across it. Callers whose key is cached keep verifying while
//!   a fetch runs; only callers that need the fetch result wait for it.
//! - [`JwksCache::force_refresh`] is the emergency path after a key leak.

use crate::error::{Error, Result, TokenError};
use crate::http;
use crate::jwk::{Key, RawJwks, convert};
use jsonwebtoken::{Algorithm, DecodingKey};
use std::sync::{PoisonError, RwLock};
use std::time::{Duration, Instant};
use url::Url;

/// Age after which the cached keys are refreshed on the next use.
pub(crate) const MAX_AGE: Duration = Duration::from_secs(300);
/// Default use of old keys beyond [`MAX_AGE`] while the provider is unreachable.
pub(crate) const DEFAULT_MAX_STALE: Duration = Duration::from_secs(600);
/// Default minimum time between two fetch attempts.
pub(crate) const DEFAULT_MIN_REFETCH: Duration = Duration::from_secs(30);

/// Source of the current time (injectable for tests).
pub type Clock = fn() -> Instant;

/// Timing rules of the cache.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Policy {
    /// Minimum time between two fetch attempts (except forced ones).
    pub min_refetch: Duration,
    /// Use of old keys beyond [`MAX_AGE`] while refreshing fails.
    pub max_stale: Duration,
    /// The clock.
    pub clock: Clock,
}

/// Cached keys and when they were fetched.
#[derive(Default)]
struct State {
    keys: Vec<Key>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
}

/// What a lookup in the current state says.
enum Lookup {
    /// Key found and fresh: use it.
    Fresh(Algorithm, DecodingKey),
    /// Key found, cache older than [`MAX_AGE`] but still within `max_stale`.
    Stale(Algorithm, DecodingKey),
    /// Fetch needed (unknown key, nothing cached, or cache too old).
    Missing,
}

/// The JWKS of one provider.
pub(crate) struct JwksCache {
    uri: Url,
    policy: Policy,
    state: RwLock<State>,
    /// Single-flight guard: held while a fetch is in progress.
    fetching: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for JwksCache {
    /// Prints the URI only.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksCache")
            .field("uri", &self.uri.as_str())
            .finish_non_exhaustive()
    }
}

impl JwksCache {
    /// A cache for the JWKS at `uri`; nothing is fetched yet.
    pub(crate) fn new(uri: Url, policy: Policy) -> Self {
        Self {
            uri,
            policy,
            state: RwLock::new(State::default()),
            fetching: tokio::sync::Mutex::new(()),
        }
    }

    /// Runs `f` on the state. The lock is only held for `f` (never across
    /// an `.await`); a poisoned lock still holds consistent data.
    fn with_state<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        let mut guard = self.state.write().unwrap_or_else(PoisonError::into_inner);
        f(&mut guard)
    }

    /// Classifies `kid` against the current state.
    fn lookup(&self, kid: &str) -> Lookup {
        let now = (self.policy.clock)();
        self.with_state(|s| {
            let Some(age) = s.fetched_at.map(|t| now.saturating_duration_since(t)) else {
                return Lookup::Missing;
            };
            let found = s.keys.iter().find(|k| k.kid == kid);
            match found {
                Some(k) if age < MAX_AGE => Lookup::Fresh(k.alg, k.key.clone()),
                Some(k) if age < MAX_AGE + self.policy.max_stale => {
                    Lookup::Stale(k.alg, k.key.clone())
                }
                _ => Lookup::Missing,
            }
        })
    }

    /// The final answer after a fetch attempt.
    fn resolve(&self, kid: &str) -> Result<(Algorithm, DecodingKey)> {
        let now = (self.policy.clock)();
        self.with_state(|s| {
            let usable = s.fetched_at.is_some_and(|t| {
                now.saturating_duration_since(t) < MAX_AGE + self.policy.max_stale
            });
            if !usable {
                return Err(Error::KeysUnavailable);
            }
            s.keys
                .iter()
                .find(|k| k.kid == kid)
                .map(|k| (k.alg, k.key.clone()))
                .ok_or(Error::Token(TokenError::UnknownKey))
        })
    }

    /// The verification key for `kid` with its algorithm.
    pub(crate) async fn key(
        &self,
        http: &reqwest::Client,
        kid: &str,
    ) -> Result<(Algorithm, DecodingKey)> {
        match self.lookup(kid) {
            Lookup::Fresh(alg, key) => Ok((alg, key)),
            Lookup::Stale(alg, key) => {
                // Refresh if nobody else is; never wait for another fetch.
                if let Ok(_guard) = self.fetching.try_lock() {
                    self.fetch_if_allowed(http).await;
                    return self.resolve(kid);
                }
                Ok((alg, key))
            }
            Lookup::Missing => {
                let _guard = self.fetching.lock().await;
                // Another task may have fetched while we waited.
                if let Lookup::Fresh(alg, key) = self.lookup(kid) {
                    return Ok((alg, key));
                }
                self.fetch_if_allowed(http).await;
                self.resolve(kid)
            }
        }
    }

    /// Fetches unless the last attempt was less than `min_refetch` ago.
    /// Must be called with the single-flight guard held.
    async fn fetch_if_allowed(&self, http: &reqwest::Client) {
        let now = (self.policy.clock)();
        let allowed = self.with_state(|s| {
            let ok = s
                .last_attempt
                .is_none_or(|t| now.saturating_duration_since(t) >= self.policy.min_refetch);
            if ok {
                s.last_attempt = Some(now);
            }
            ok
        });
        if allowed && let Ok(keys) = self.fetch(http).await {
            self.store(keys);
        }
    }

    /// Replaces the cached keys.
    fn store(&self, keys: Vec<Key>) {
        let now = (self.policy.clock)();
        self.with_state(|s| {
            s.keys = keys;
            s.fetched_at = Some(now);
        });
    }

    /// Refetches now, ignoring the rate limit. On failure all cached keys are
    /// dropped (fail closed) and the error is returned.
    pub(crate) async fn force_refresh(&self, http: &reqwest::Client) -> Result<()> {
        let _guard = self.fetching.lock().await;
        let now = (self.policy.clock)();
        self.with_state(|s| s.last_attempt = Some(now));
        match self.fetch(http).await {
            Ok(keys) => {
                self.store(keys);
                Ok(())
            }
            Err(e) => {
                self.with_state(|s| {
                    s.keys.clear();
                    s.fetched_at = None;
                });
                Err(e)
            }
        }
    }

    /// Fetches and converts the JWKS.
    async fn fetch(&self, http: &reqwest::Client) -> Result<Vec<Key>> {
        let raw: RawJwks = http::get_json(http, &self.uri, None).await?;
        Ok(raw.keys.into_iter().filter_map(convert).collect())
    }
}
