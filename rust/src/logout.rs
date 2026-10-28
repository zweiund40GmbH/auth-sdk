//! Back-channel logout (OIDC Back-Channel Logout 1.0 §2.6): the provider
//! POSTs a `logout_token` to the application's `backchannel_logout_uri`
//! when an SSO session ends; the application ends its local sessions with
//! the same `sid` (or all sessions of `sub`).

use crate::client::Client;
use crate::error::{Result, TokenError};
use crate::jwt::{self, Expect, TYP_LOGOUT};
use serde_json::Value;

/// Event URI that a logout token must carry in `events`.
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// What a verified logout token asks for. At least one of `sub` and `sid`
/// is set; with `sid`, end only the sessions created with that `sid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutEvent {
    /// The user whose session ended.
    pub sub: Option<String>,
    /// The SSO session id (the `sid` claim of the ID token at login).
    pub sid: Option<String>,
    /// Token id. The provider issues a new token per delivery attempt, so
    /// replays can be detected by remembering `jti` until `exp` if wanted.
    pub jti: String,
}

impl Client {
    /// Verifies a back-channel logout token (signature, `typ: logout+jwt`,
    /// `iss`, `aud`, `iat`, `exp`, `jti`, `events`, `sub`/`sid`, no `nonce`).
    /// On success answer `200`; on any error answer `400` (§2.8).
    pub async fn verify_backchannel_logout(&self, logout_token: &str) -> Result<LogoutEvent> {
        let expect = Expect {
            typ: TYP_LOGOUT,
            issuer: &self.meta.issuer,
            audience: &self.client_id,
            algs: &self.algs,
        };
        let raw = jwt::verify(logout_token, &self.http, &self.jwks, &expect).await?;
        Ok(logout_event(&raw)?)
    }
}

/// The logout-token-specific rules on top of [`jwt::verify`] (§2.6 steps 3–5).
fn logout_event(raw: &Value) -> Result<LogoutEvent, TokenError> {
    let str_claim = |name: &str| {
        raw.get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let event_ok = raw
        .get("events")
        .and_then(Value::as_object)
        .and_then(|e| e.get(BACKCHANNEL_LOGOUT_EVENT))
        .is_some_and(Value::is_object);
    if !event_ok {
        return Err(TokenError::Claim("events"));
    }
    if raw.get("nonce").is_some() {
        return Err(TokenError::WrongNonce);
    }
    let jti = str_claim("jti").ok_or(TokenError::Claim("jti"))?;
    let (sub, sid) = (str_claim("sub"), str_claim("sid"));
    if sub.is_none() && sid.is_none() {
        return Err(TokenError::Claim("sid"));
    }
    Ok(LogoutEvent { sub, sid, jti })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn token(extra: Value) -> Value {
        let mut v = json!({"jti": "j", "sid": "s", "events": {BACKCHANNEL_LOGOUT_EVENT: {}}});
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        v
    }

    #[test]
    fn valid_token_yields_event() {
        let e = logout_event(&token(json!({"sub": "u"}))).unwrap();
        assert_eq!(e.sid.as_deref(), Some("s"));
        assert_eq!(e.sub.as_deref(), Some("u"));
        assert_eq!(e.jti, "j");
    }

    #[test]
    fn event_is_required() {
        let missing = json!({"jti": "j", "sid": "s"});
        assert_eq!(logout_event(&missing), Err(TokenError::Claim("events")));
        let wrong = token(json!({"events": {"other": {}}}));
        assert_eq!(logout_event(&wrong), Err(TokenError::Claim("events")));
        let not_object = token(json!({"events": {BACKCHANNEL_LOGOUT_EVENT: "x"}}));
        assert_eq!(logout_event(&not_object), Err(TokenError::Claim("events")));
    }

    #[test]
    fn nonce_jti_and_subject_rules() {
        assert_eq!(
            logout_event(&token(json!({"nonce": "n"}))),
            Err(TokenError::WrongNonce)
        );
        assert_eq!(
            logout_event(&token(json!({"jti": ""}))),
            Err(TokenError::Claim("jti"))
        );
        assert_eq!(
            logout_event(&token(json!({"sid": null}))),
            Err(TokenError::Claim("sid"))
        );
        assert!(logout_event(&token(json!({"sid": null, "sub": "u"}))).is_ok());
    }
}
