//! Login with Authorization Code + PKCE (S256), `state` and `nonce`
//! (`/oauth2/authorize`).
//!
//! [`Client::begin_login`] returns the authorize URL and a [`LoginState`]
//! that the application keeps until the callback – server-side or in an
//! encrypted, `HttpOnly` cookie; the crate stores nothing. The callback is
//! handled by [`Client::complete_login`] (see the `tokens` module).

use crate::client::Client;
use crate::crypto;
use crate::error::{Error, Result};
use crate::requirements::AuthRequirements;
use serde::{Deserialize, Serialize};
use url::Url;

/// Parameters the crate sets itself; `extra` must not contain them.
const RESERVED: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "response_mode",
    "request",
    "request_uri",
];

/// What has to survive between redirect and callback. Treat it as secret
/// (it contains the PKCE verifier), bind it to the browser, keep it only
/// briefly (e.g. 10 minutes) and use it **once**: delete it when the
/// callback arrives, whatever the outcome. The crate does not check its age.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginState {
    /// `state` sent to the provider.
    pub state: String,
    /// `nonce` sent to the provider, expected in the ID token.
    pub nonce: String,
    /// PKCE `code_verifier`.
    pub pkce_verifier: String,
    /// `redirect_uri` exactly as sent (the token request must repeat it).
    pub redirect_uri: String,
    /// `max_age`, `prompt=login` and `acr_values` of the request, enforced
    /// against the ID token.
    #[serde(default)]
    pub requirements: AuthRequirements,
}

impl std::fmt::Debug for LoginState {
    /// Redacts all values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginState")
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

/// Result of [`Client::begin_login`].
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// Where to redirect the browser (`302`/`303`).
    pub url: Url,
    /// What to keep until the callback.
    pub state: LoginState,
}

/// The query of the callback request (`code`, `state`, `iss` or an error).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct CallbackParams {
    /// Authorization code (success).
    pub code: Option<String>,
    /// Echoed `state`.
    pub state: Option<String>,
    /// Issuer of the response (RFC 9207).
    pub iss: Option<String>,
    /// Error code (failure).
    pub error: Option<String>,
    /// Error description (failure, English).
    pub error_description: Option<String>,
}

impl std::fmt::Debug for CallbackParams {
    /// Redacts the code.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackParams")
            .field("code", &self.code.as_ref().map(|_| "[redacted]"))
            .field("iss", &self.iss)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl CallbackParams {
    /// Parses the raw query string (without `?`). Repeated known parameters
    /// are rejected (RFC 6749 §3.1), also when one of them is empty; empty
    /// values count as absent; unknown parameters are ignored.
    pub fn from_query(query: &str) -> Result<Self> {
        let mut p = Self::default();
        let mut seen = std::collections::HashSet::new();
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            let slot = match key.as_ref() {
                "code" => &mut p.code,
                "state" => &mut p.state,
                "iss" => &mut p.iss,
                "error" => &mut p.error,
                "error_description" => &mut p.error_description,
                _ => continue,
            };
            if !seen.insert(key.clone()) {
                return Err(Error::InvalidCallback);
            }
            if !value.is_empty() {
                *slot = Some(value.into_owned());
            }
        }
        Ok(p)
    }
}

impl Client {
    /// Starts a login: authorize URL plus the [`LoginState`] to keep.
    ///
    /// `scopes` gets `openid` added if missing. `extra` takes optional
    /// parameters such as `prompt`, `max_age`, `acr_values` or `login_hint`;
    /// parameters the crate sets itself are rejected with [`Error::Config`].
    /// `max_age`, `prompt=login` and `acr_values` are recorded in the
    /// [`LoginState`] and enforced by [`Client::complete_login`]
    /// ([`crate::TokenError::AuthTooOld`], [`crate::TokenError::InsufficientAcr`]).
    pub fn begin_login(
        &self,
        redirect_uri: &str,
        scopes: &[&str],
        extra: &[(&str, &str)],
    ) -> Result<AuthorizationRequest> {
        if extra.iter().any(|(k, _)| RESERVED.contains(k)) {
            return Err(Error::Config("reserved authorize parameter in `extra`"));
        }
        Url::parse(redirect_uri).map_err(|_| Error::Config("redirect_uri is not a URL"))?;
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let requirements = AuthRequirements::from_extra(extra, now)?;
        let state = LoginState {
            state: crypto::random_value()?,
            nonce: crypto::random_value()?,
            pkce_verifier: crypto::random_value()?,
            redirect_uri: redirect_uri.to_owned(),
            requirements,
        };
        let mut scope: Vec<&str> = vec!["openid"];
        scope.extend(scopes.iter().copied().filter(|s| *s != "openid"));
        let mut url = self.meta.authorization_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &scope.join(" "))
            .append_pair("state", &state.state)
            .append_pair("nonce", &state.nonce)
            .append_pair(
                "code_challenge",
                &crypto::pkce_challenge(&state.pkce_verifier),
            )
            .append_pair("code_challenge_method", "S256")
            .extend_pairs(extra);
        Ok(AuthorizationRequest { url, state })
    }

    /// Checks `iss` (RFC 9207), `state` and error responses of a callback and
    /// returns the code. Order matters: an error response is only trusted
    /// after `iss` and `state` matched.
    pub(crate) fn check_callback<'a>(
        &self,
        login: &LoginState,
        params: &'a CallbackParams,
    ) -> Result<&'a str> {
        match params.iss.as_deref() {
            Some(iss) if iss == self.meta.issuer => {}
            Some(_) => return Err(Error::IssuerMismatch),
            None if self.meta.authorization_response_iss_parameter_supported => {
                return Err(Error::IssuerMismatch);
            }
            None => {}
        }
        let state = params.state.as_deref().ok_or(Error::InvalidCallback)?;
        if !crypto::constant_time_eq(state, &login.state) {
            return Err(Error::StateMismatch);
        }
        if let Some(error) = &params.error {
            return Err(Error::Authorization {
                error: error.clone(),
                description: params.error_description.clone(),
            });
        }
        params.code.as_deref().ok_or(Error::InvalidCallback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_query_is_parsed() {
        let p = CallbackParams::from_query("code=c%2B1&state=s&iss=https%3A%2F%2Fa&x=1").unwrap();
        assert_eq!(p.code.as_deref(), Some("c+1"));
        assert_eq!(p.iss.as_deref(), Some("https://a"));
        assert!(p.error.is_none());
    }

    #[test]
    fn repeated_parameters_are_rejected() {
        assert!(matches!(
            CallbackParams::from_query("code=a&code=b&state=s"),
            Err(Error::InvalidCallback)
        ));
        assert!(CallbackParams::from_query("x=1&x=2").is_ok());
        assert!(matches!(
            CallbackParams::from_query("code=&code=x&state=s"),
            Err(Error::InvalidCallback)
        ));
        assert!(matches!(
            CallbackParams::from_query("state=&state=s&code=c"),
            Err(Error::InvalidCallback)
        ));
    }

    #[test]
    fn empty_values_count_as_absent_and_debug_hides_code() {
        let p = CallbackParams::from_query("code=secretcode&state=").unwrap();
        assert!(p.state.is_none());
        assert!(!format!("{p:?}").contains("secretcode"));
    }

    #[test]
    fn login_state_round_trips_and_hides_secrets() {
        let s = LoginState {
            state: "st".into(),
            nonce: "no".into(),
            pkce_verifier: "verifier-value".into(),
            redirect_uri: "https://app/cb".into(),
            requirements: AuthRequirements::default(),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<LoginState>(&json).unwrap(), s);
        assert!(!format!("{s:?}").contains("verifier-value"));
    }

    #[test]
    fn login_state_without_requirements_still_loads() {
        let old =
            r#"{"state":"s","nonce":"n","pkce_verifier":"v","redirect_uri":"https://app/cb"}"#;
        let s: LoginState = serde_json::from_str(old).unwrap();
        assert_eq!(s.requirements, AuthRequirements::default());
    }
}
