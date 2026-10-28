//! Authentication requirements of a login (`max_age`, `prompt=login`,
//! `acr_values`) and their check against the ID token (OIDC Core §3.1.2.1,
//! §3.1.3.7 items 11–12).
//!
//! The authorize URL passes through the browser, so the user could drop
//! these parameters. [`Client::begin_login`](crate::Client::begin_login)
//! therefore records them in the [`LoginState`](crate::LoginState), and
//! [`Client::complete_login`](crate::Client::complete_login) rejects an ID
//! token that does not fulfil them.

use crate::error::{Error, Result, TokenError};
use crate::jwt::LEEWAY_SECS;
use serde::{Deserialize, Serialize};

/// What the login asked for. Part of [`LoginState`](crate::LoginState);
/// every field defaults, so states stored by older versions still load.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRequirements {
    /// `max_age` sent: the authentication must be at most this many seconds old.
    #[serde(default)]
    pub max_age: Option<u64>,
    /// `acr_values` sent: the ID token's `acr` must be one of them.
    #[serde(default)]
    pub acr_values: Vec<String>,
    /// `prompt=login` sent: the authentication must be newer than the login start.
    #[serde(default)]
    pub fresh_login: bool,
    /// When the login started (seconds since the epoch).
    #[serde(default)]
    pub started_at: i64,
}

impl AuthRequirements {
    /// Reads the requirements from the `extra` authorize parameters. Each of
    /// `max_age`, `acr_values` and `prompt` may appear at most once, and
    /// `max_age` must be a number.
    pub(crate) fn from_extra(extra: &[(&str, &str)], now: i64) -> Result<Self> {
        let single = |name: &str| -> Result<Option<&str>> {
            let mut values = extra.iter().filter(|(k, _)| *k == name).map(|(_, v)| *v);
            let first = values.next();
            if values.next().is_some() {
                return Err(Error::Config("authorize parameter given twice in `extra`"));
            }
            Ok(first)
        };
        let max_age = single("max_age")?
            .map(|v| v.parse::<u64>())
            .transpose()
            .map_err(|_| Error::Config("max_age is not a number of seconds"))?;
        let acr_values = single("acr_values")?
            .map(|v| {
                v.split(' ')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let fresh_login = single("prompt")?.is_some_and(|p| p.split(' ').any(|v| v == "login"));
        Ok(Self {
            max_age,
            acr_values,
            fresh_login,
            started_at: now,
        })
    }

    /// Checks `auth_time` and `acr` of a verified ID token at time `now`.
    pub(crate) fn check(
        &self,
        auth_time: Option<i64>,
        acr: Option<&str>,
        now: i64,
    ) -> Result<(), TokenError> {
        let leeway = LEEWAY_SECS as i64;
        if self.max_age.is_some() || self.fresh_login {
            let auth_time = auth_time.ok_or(TokenError::Claim("auth_time"))?;
            if let Some(max_age) = self.max_age {
                let limit = i64::try_from(max_age)
                    .unwrap_or(i64::MAX)
                    .saturating_add(leeway);
                if now.saturating_sub(auth_time) > limit {
                    return Err(TokenError::AuthTooOld);
                }
            }
            if self.fresh_login && auth_time < self.started_at.saturating_sub(leeway) {
                return Err(TokenError::AuthTooOld);
            }
        }
        if !self.acr_values.is_empty()
            && !acr.is_some_and(|a| self.acr_values.iter().any(|v| v == a))
        {
            return Err(TokenError::InsufficientAcr);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;

    fn req(extra: &[(&str, &str)]) -> AuthRequirements {
        AuthRequirements::from_extra(extra, NOW).unwrap()
    }

    #[test]
    fn parameters_are_recorded() {
        let r = req(&[
            ("max_age", "60"),
            ("acr_values", "urn:z40:mfa"),
            ("prompt", "login"),
        ]);
        assert_eq!(r.max_age, Some(60));
        assert_eq!(r.acr_values, vec!["urn:z40:mfa"]);
        assert!(r.fresh_login && r.started_at == NOW);
        assert_eq!(
            req(&[("login_hint", "a")]),
            AuthRequirements {
                started_at: NOW,
                ..Default::default()
            }
        );
        assert!(AuthRequirements::from_extra(&[("max_age", "x")], NOW).is_err());
        assert!(
            AuthRequirements::from_extra(&[("prompt", "none"), ("prompt", "login")], NOW).is_err()
        );
    }

    #[test]
    fn max_age_needs_recent_auth_time() {
        let r = req(&[("max_age", "60")]);
        assert_eq!(r.check(Some(NOW - 30), None, NOW), Ok(()));
        assert_eq!(r.check(Some(NOW - 120), None, NOW), Ok(()), "within leeway");
        assert_eq!(
            r.check(Some(NOW - 3600), None, NOW),
            Err(TokenError::AuthTooOld)
        );
        assert_eq!(
            r.check(None, None, NOW),
            Err(TokenError::Claim("auth_time"))
        );
    }

    #[test]
    fn prompt_login_needs_auth_after_the_start() {
        let r = req(&[("prompt", "login")]);
        assert_eq!(r.check(Some(NOW + 5), None, NOW + 10), Ok(()));
        assert_eq!(
            r.check(Some(NOW - 600), None, NOW + 10),
            Err(TokenError::AuthTooOld)
        );
        assert_eq!(
            r.check(None, None, NOW),
            Err(TokenError::Claim("auth_time"))
        );
        // Without requirements nothing is checked.
        assert_eq!(req(&[]).check(None, None, NOW), Ok(()));
    }

    #[test]
    fn acr_must_be_one_of_the_requested() {
        let r = req(&[("acr_values", "urn:z40:mfa")]);
        assert_eq!(r.check(None, Some("urn:z40:mfa"), NOW), Ok(()));
        assert_eq!(
            r.check(None, Some("urn:z40:pwd"), NOW),
            Err(TokenError::InsufficientAcr)
        );
        assert_eq!(r.check(None, None, NOW), Err(TokenError::InsufficientAcr));
    }
}
