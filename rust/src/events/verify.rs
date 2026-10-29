//! Verification of a pushed Security Event Token: the generic JWT checks
//! (signature via the JWKS, `typ: secevent+jwt`, `iss`, `aud` = client id,
//! `exp`, `iat`) plus the event rules of the contract.

use super::{AccountEvent, EVENT_URN_PREFIX, SecurityEvent, TYP_SECEVENT};
use crate::claims::TokenEnv;
use crate::client::Client;
use crate::error::{Result, TokenError};
use crate::jwt::{self, Expect, LEEWAY_SECS};
use serde_json::Value;

/// Oldest accepted `iat` relative to now, in seconds. The provider signs
/// every attempt anew with a 2 minute lifetime; with the clock leeway an
/// older token is a replay or a badly skewed clock.
pub(crate) const MAX_AGE_SECS: i64 = 120 + LEEWAY_SECS as i64;

impl Client {
    /// Verifies a pushed Security Event Token (RFC 8417): signature against
    /// the provider's JWKS, header `typ: secevent+jwt`, `iss`, `aud` (this
    /// client id), `exp`, `iat` within a few minutes, `jti`, exactly one
    /// `urn:z40:event:` entry in `events` and `sub` (except for
    /// verification events).
    ///
    /// This does **not** deduplicate: use [`Client::receive_event`] or check
    /// [`SecurityEvent::jti`] against a [`JtiStore`](crate::JtiStore) yourself.
    pub async fn verify_security_event(&self, token: &str) -> Result<SecurityEvent> {
        let expect = Expect {
            typ: TYP_SECEVENT,
            issuer: &self.meta.issuer,
            audience: &self.client_id,
            algs: &self.algs,
        };
        let raw = jwt::verify(token, &self.http, &self.jwks, &expect).await?;
        let now = jsonwebtoken::get_current_timestamp() as i64;
        Ok(security_event(&raw, now)?)
    }
}

/// The SET-specific rules on top of [`jwt::verify`].
pub(crate) fn security_event(raw: &Value, now: i64) -> Result<SecurityEvent, TokenError> {
    let iat = raw
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(TokenError::Claim("iat"))?;
    if iat < now - MAX_AGE_SECS {
        return Err(TokenError::Expired);
    }
    let str_claim = |name: &str| {
        raw.get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let jti = str_claim("jti").ok_or(TokenError::Claim("jti"))?;
    let env: TokenEnv = raw
        .get("env")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or(TokenError::Claim("env"))?;
    let event = single_event(raw.get("events")).ok_or(TokenError::Claim("events"))?;
    let sub = str_claim("sub");
    if sub.is_none() && event != AccountEvent::Verification {
        return Err(TokenError::Claim("sub"));
    }
    let toe = match raw.get("toe") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_i64().ok_or(TokenError::Claim("toe"))?),
    };
    Ok(SecurityEvent {
        jti,
        sub,
        toe,
        iat,
        env,
        event,
    })
}

/// The one event of the `events` claim (exactly one `urn:z40:event:` key
/// with an object value).
fn single_event(events: Option<&Value>) -> Option<AccountEvent> {
    let map = events?.as_object()?;
    if map.len() != 1 {
        return None;
    }
    let (uri, data) = map.iter().next()?;
    let name = uri.strip_prefix(EVENT_URN_PREFIX)?;
    if name.is_empty() {
        return None;
    }
    AccountEvent::from_parts(name, data.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;

    fn token(extra: Value) -> Value {
        let mut v = json!({
            "iat": NOW, "jti": "j", "sub": "u", "toe": NOW - 2, "env": "production",
            "events": {"urn:z40:event:user.disabled": {}},
        });
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        v
    }

    #[test]
    fn valid_token_yields_event() {
        let e = security_event(&token(json!({})), NOW).unwrap();
        assert_eq!(e.event, AccountEvent::UserDisabled);
        assert_eq!((e.jti.as_str(), e.sub.as_deref()), ("j", Some("u")));
        assert_eq!((e.toe, e.env), (Some(NOW - 2), TokenEnv::Production));
    }

    #[test]
    fn verification_needs_no_sub() {
        let v =
            token(json!({"sub": null, "toe": null, "events": {"urn:z40:event:verification": {}}}));
        let e = security_event(&v, NOW).unwrap();
        assert_eq!(
            (e.event, e.sub, e.toe),
            (AccountEvent::Verification, None, None)
        );
        let v = token(json!({"sub": null}));
        assert_eq!(security_event(&v, NOW), Err(TokenError::Claim("sub")));
    }

    #[test]
    fn unknown_type_is_forward_compatible() {
        let v = token(json!({"events": {"urn:z40:event:user.renamed": {"a": 1}}}));
        let e = security_event(&v, NOW).unwrap();
        assert_eq!(e.event.event_type(), "user.renamed");
    }

    #[test]
    fn malformed_events_are_rejected() {
        for events in [
            json!(null),
            json!({}),
            json!([]),
            json!({"urn:z40:event:user.disabled": {}, "urn:z40:event:user.enabled": {}}),
            json!({"urn:other:user.disabled": {}}),
            json!({"urn:z40:event:": {}}),
            json!({"urn:z40:event:user.disabled": "x"}),
            json!({"urn:z40:event:link.removed": {}}),
        ] {
            let v = token(json!({ "events": events }));
            assert_eq!(
                security_event(&v, NOW),
                Err(TokenError::Claim("events")),
                "{events}"
            );
        }
    }

    #[test]
    fn old_iat_missing_jti_env_and_bad_toe_are_rejected() {
        let old = token(json!({"iat": NOW - MAX_AGE_SECS - 1}));
        assert_eq!(security_event(&old, NOW), Err(TokenError::Expired));
        assert!(security_event(&token(json!({"iat": NOW - MAX_AGE_SECS})), NOW).is_ok());
        assert_eq!(
            security_event(&token(json!({"jti": ""})), NOW),
            Err(TokenError::Claim("jti"))
        );
        assert_eq!(
            security_event(&token(json!({"env": "staging"})), NOW),
            Err(TokenError::Claim("env"))
        );
        assert_eq!(
            security_event(&token(json!({"toe": "x"})), NOW),
            Err(TokenError::Claim("toe"))
        );
    }
}
