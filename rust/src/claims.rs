//! Claim sets the provider issues, as the application sees
//! them after verification. Unknown claims are ignored; optional claims are
//! `None` or empty when the granted scopes do not include them.

use serde::{Deserialize, Deserializer, Serialize};

/// Deserializes an optional string and maps an empty string to `None`
/// (the provider never sends empty values; this guards against it defensively).
fn non_empty<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.filter(|v| !v.is_empty()))
}

/// `aud`: one string or a list (RFC 7519 §4.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience.
    One(String),
    /// Several audiences.
    Many(Vec<String>),
}

impl Audience {
    /// Whether `aud` contains `value`.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Audience::One(a) => a == value,
            Audience::Many(list) => list.iter().any(|a| a == value),
        }
    }

    /// Whether `aud` names more than one audience.
    pub fn is_multiple(&self) -> bool {
        matches!(self, Audience::Many(list) if list.len() > 1)
    }
}

/// Environment marker `env` the provider puts in every token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenEnv {
    /// Production application.
    Production,
    /// Application in test mode.
    Test,
}

/// Verified claims of an ID token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdClaims {
    /// Issuer.
    pub iss: String,
    /// Stable user id at the provider; link local accounts with this, not the e-mail address.
    pub sub: String,
    /// Audience (contains this client).
    pub aud: Audience,
    /// Expiry (seconds since the epoch).
    pub exp: i64,
    /// Issued at (seconds since the epoch).
    pub iat: i64,
    /// Time of the authentication.
    #[serde(default)]
    pub auth_time: Option<i64>,
    /// SSO session id at this client; keep it to match back-channel logouts.
    #[serde(default)]
    pub sid: Option<String>,
    /// Authentication methods (`pwd`, `otp`).
    #[serde(default)]
    pub amr: Vec<String>,
    /// Authentication context (`urn:z40:pwd` | `urn:z40:mfa`).
    #[serde(default)]
    pub acr: Option<String>,
    /// Production or test application.
    pub env: TokenEnv,
    /// Scope `profile`: display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Scope `profile`: given name (only when set; empty values read as `None`).
    #[serde(default, deserialize_with = "non_empty")]
    pub given_name: Option<String>,
    /// Scope `profile`: family name (only when set; empty values read as `None`).
    #[serde(default, deserialize_with = "non_empty")]
    pub family_name: Option<String>,
    /// Scope `profile`: locale.
    #[serde(default)]
    pub locale: Option<String>,
    /// Scope `email`: address.
    #[serde(default)]
    pub email: Option<String>,
    /// Scope `email`: whether the address is verified.
    #[serde(default)]
    pub email_verified: Option<bool>,
}

/// Verified claims of a JWT access token (RFC 9068).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessClaims {
    /// Issuer.
    pub iss: String,
    /// User id, or the client id for client-credentials tokens.
    pub sub: String,
    /// Audience.
    pub aud: Audience,
    /// Client the token was issued to.
    pub client_id: String,
    /// Granted scopes, space separated.
    pub scope: String,
    /// Expiry.
    pub exp: i64,
    /// Issued at.
    pub iat: i64,
    /// Unique token id.
    pub jti: String,
    /// SSO session id (user tokens).
    #[serde(default)]
    pub sid: Option<String>,
    /// Authentication context (user tokens).
    #[serde(default)]
    pub acr: Option<String>,
    /// Production or test application.
    pub env: TokenEnv,
    /// App roles (scope `roles`).
    #[serde(default)]
    pub roles: Vec<String>,
}

impl AccessClaims {
    /// Whether the token grants `scope`.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.split(' ').any(|s| s == scope)
    }
}

/// Answer of the UserInfo endpoint (fields depend on the granted scopes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    /// User id (same as the ID token's `sub`).
    pub sub: String,
    /// Display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Given name (scope `profile`; only when set, empty values read as `None`).
    #[serde(default, deserialize_with = "non_empty")]
    pub given_name: Option<String>,
    /// Family name (scope `profile`; only when set, empty values read as `None`).
    #[serde(default, deserialize_with = "non_empty")]
    pub family_name: Option<String>,
    /// Locale.
    #[serde(default)]
    pub locale: Option<String>,
    /// E-mail address.
    #[serde(default)]
    pub email: Option<String>,
    /// Whether the address is verified.
    #[serde(default)]
    pub email_verified: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn audience_is_string_or_list() {
        let one: Audience = serde_json::from_value(json!("a")).unwrap();
        let many: Audience = serde_json::from_value(json!(["a", "b"])).unwrap();
        assert!(one.contains("a") && !one.is_multiple());
        assert!(many.contains("b") && !many.contains("c") && many.is_multiple());
        assert!(!Audience::Many(vec!["a".into()]).is_multiple());
    }

    #[test]
    fn access_scope_check_is_exact() {
        let claims: AccessClaims = serde_json::from_value(json!({
            "iss": "i", "sub": "s", "aud": "app", "client_id": "app",
            "scope": "openid profile", "exp": 2, "iat": 1, "jti": "j", "env": "test"
        }))
        .unwrap();
        assert!(claims.has_scope("profile") && !claims.has_scope("prof"));
        assert!(claims.roles.is_empty());
    }

    #[test]
    fn id_token_name_parts_present_absent_and_empty() {
        let base = json!({"iss": "i", "sub": "s", "aud": "app", "exp": 2, "iat": 1, "env": "test"});
        let with = |extra: serde_json::Value| {
            let mut v = base.clone();
            v.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            serde_json::from_value::<IdClaims>(v).unwrap()
        };
        let present = with(json!({"given_name": "Erika", "family_name": "Mustermann"}));
        assert_eq!(present.given_name.as_deref(), Some("Erika"));
        assert_eq!(present.family_name.as_deref(), Some("Mustermann"));
        let absent = with(json!({}));
        assert!(absent.given_name.is_none() && absent.family_name.is_none());
        let empty = with(json!({"given_name": "", "family_name": ""}));
        assert!(empty.given_name.is_none() && empty.family_name.is_none());
    }

    #[test]
    fn userinfo_name_parts_present_absent_and_empty() {
        let present: UserInfo = serde_json::from_value(
            json!({"sub": "s", "given_name": "Erika", "family_name": "Mustermann"}),
        )
        .unwrap();
        assert_eq!(present.given_name.as_deref(), Some("Erika"));
        assert_eq!(present.family_name.as_deref(), Some("Mustermann"));
        let absent: UserInfo = serde_json::from_value(json!({"sub": "s"})).unwrap();
        assert!(absent.given_name.is_none() && absent.family_name.is_none());
        let empty: UserInfo =
            serde_json::from_value(json!({"sub": "s", "given_name": "", "family_name": null}))
                .unwrap();
        assert!(empty.given_name.is_none() && empty.family_name.is_none());
    }
}
