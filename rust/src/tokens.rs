//! Token endpoint: code exchange at the end of the login and the ID token
//! checks of OIDC Core §3.1.3.7 (the refresh is in `refresh.rs`).

use crate::claims::IdClaims;
use crate::client::Client;
use crate::crypto;
use crate::error::{Result, TokenError};
use crate::http;
use crate::jwt::{self, Expect, TYP_ID};
use crate::login::{CallbackParams, LoginState};
use crate::secret::SecretString;
use serde::Deserialize;
use serde_json::Value;

/// Tokens from the token endpoint. Token values are [`SecretString`]s:
/// `Debug` never prints them and they are zeroed on drop. Keep them
/// server-side (BFF) and never log them.
#[derive(Debug, Clone, Deserialize)]
pub struct Tokens {
    /// Access token (JWT, about 5 minutes).
    pub access_token: SecretString,
    /// Always `Bearer`.
    pub token_type: String,
    /// Lifetime of the access token in seconds.
    pub expires_in: i64,
    /// Granted scopes, space separated.
    #[serde(default)]
    pub scope: String,
    /// ID token (scope `openid`); keep it as `id_token_hint` for logout.
    #[serde(default)]
    pub id_token: Option<SecretString>,
    /// Refresh token (scope `offline_access`); rotates on every use.
    #[serde(default)]
    pub refresh_token: Option<SecretString>,
}

/// Result of a completed login.
#[derive(Debug, Clone)]
pub struct LoginResult {
    /// The tokens.
    pub tokens: Tokens,
    /// Verified claims of the ID token.
    pub claims: IdClaims,
}

impl Client {
    /// Completes a login: checks `iss`, `state` and errors of the callback,
    /// exchanges the code (with the PKCE verifier) and verifies the ID token
    /// (signature, `typ`, `iss`, `aud`, `azp`, `exp`/`iat`, `nonce`, `at_hash`).
    pub async fn complete_login(
        &self,
        login: &LoginState,
        params: &CallbackParams,
    ) -> Result<LoginResult> {
        let code = self.check_callback(login, params)?;
        let fields = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", login.redirect_uri.as_str()),
            ("code_verifier", login.pkce_verifier.as_str()),
        ];
        let tokens = self.token_request(&fields).await?;
        let id_token = tokens
            .id_token
            .as_ref()
            .ok_or(TokenError::Claim("id_token"))?;
        let claims = self
            .verify_id_token(
                id_token.expose_secret(),
                tokens.access_token.expose_secret(),
                Some(&login.nonce),
                jsonwebtoken::get_current_timestamp(),
            )
            .await?;
        let now = jsonwebtoken::get_current_timestamp() as i64;
        login
            .requirements
            .check(claims.auth_time, claims.acr.as_deref(), now)?;
        Ok(LoginResult { tokens, claims })
    }

    /// Posts `fields` with client authentication to the token endpoint.
    pub(crate) async fn token_request(&self, fields: &[(&str, &str)]) -> Result<Tokens> {
        let creds = self.credentials();
        http::post_form_json(&self.http, &self.meta.token_endpoint, fields, &creds).await
    }

    /// Verifies an ID token. `nonce`: the expected value at login; `None`
    /// after a refresh, where the token must not carry one. `at`: the time
    /// (seconds since the epoch) the time claims are judged at.
    pub(crate) async fn verify_id_token(
        &self,
        id_token: &str,
        access_token: &str,
        nonce: Option<&str>,
        at: u64,
    ) -> Result<IdClaims> {
        let expect = Expect {
            typ: TYP_ID,
            issuer: &self.meta.issuer,
            audience: &self.client_id,
            algs: &self.algs,
        };
        let raw = jwt::verify_at(id_token, &self.http, &self.jwks, &expect, at).await?;
        check_id_claims(&raw, &self.client_id, nonce, access_token)?;
        jwt::into_claims(raw)
    }
}

/// The ID-token-specific rules on top of [`jwt::verify`].
fn check_id_claims(
    raw: &Value,
    client_id: &str,
    nonce: Option<&str>,
    access_token: &str,
) -> Result<(), TokenError> {
    let str_claim = |name: &str| raw.get(name).and_then(Value::as_str);
    if str_claim("sub").is_none_or(str::is_empty) {
        return Err(TokenError::Claim("sub"));
    }
    // azp: required with several audiences, must be us when present (§3.1.3.7 4–5).
    let several = raw
        .get("aud")
        .and_then(Value::as_array)
        .is_some_and(|a| a.len() > 1);
    match str_claim("azp") {
        Some(azp) if azp != client_id => return Err(TokenError::WrongAzp),
        None if several => return Err(TokenError::WrongAzp),
        _ => {}
    }
    match (nonce, str_claim("nonce")) {
        (Some(expected), Some(got)) if crypto::constant_time_eq(expected, got) => {}
        (None, None) => {}
        _ => return Err(TokenError::WrongNonce),
    }
    if let Some(at_hash) = str_claim("at_hash")
        && at_hash != crypto::token_hash(access_token)
    {
        return Err(TokenError::AtHashMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn debug_of_tokens_contains_no_token_values() {
        let t: Tokens = serde_json::from_value(json!({
            "access_token": "at-secret", "token_type": "Bearer", "expires_in": 300,
            "id_token": "id-secret", "refresh_token": "rt-secret",
        }))
        .unwrap();
        let printed = format!("{t:?}");
        assert!(!printed.contains("secret"), "{printed}");
        assert!(printed.contains("expires_in: 300"));
        assert_eq!(t.refresh_token.unwrap().expose_secret(), "rt-secret");
    }

    #[test]
    fn nonce_must_match_or_be_absent_after_refresh() {
        let c = |v: Value, nonce| check_id_claims(&v, "app", nonce, "at");
        assert!(c(json!({"sub":"u","nonce":"n"}), Some("n")).is_ok());
        assert_eq!(
            c(json!({"sub":"u","nonce":"x"}), Some("n")),
            Err(TokenError::WrongNonce)
        );
        assert_eq!(
            c(json!({"sub":"u"}), Some("n")),
            Err(TokenError::WrongNonce)
        );
        assert!(c(json!({"sub":"u"}), None).is_ok());
        assert_eq!(
            c(json!({"sub":"u","nonce":"n"}), None),
            Err(TokenError::WrongNonce)
        );
    }

    #[test]
    fn azp_rules() {
        let c = |v: Value| check_id_claims(&v, "app", None, "at");
        assert!(c(json!({"sub":"u","aud":"app"})).is_ok());
        assert!(c(json!({"sub":"u","aud":["app","x"],"azp":"app"})).is_ok());
        assert_eq!(
            c(json!({"sub":"u","aud":["app","x"]})),
            Err(TokenError::WrongAzp)
        );
        assert_eq!(
            c(json!({"sub":"u","aud":"app","azp":"x"})),
            Err(TokenError::WrongAzp)
        );
    }

    #[test]
    fn at_hash_and_sub_are_checked() {
        let good = crypto::token_hash("at");
        assert!(check_id_claims(&json!({"sub":"u","at_hash":good}), "app", None, "at").is_ok());
        assert_eq!(
            check_id_claims(&json!({"sub":"u","at_hash":"x"}), "app", None, "at"),
            Err(TokenError::AtHashMismatch)
        );
        assert_eq!(
            check_id_claims(&json!({"sub":""}), "app", None, "at"),
            Err(TokenError::Claim("sub"))
        );
    }
}
