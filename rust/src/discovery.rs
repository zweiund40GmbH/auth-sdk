//! Loading and checking the discovery document (OIDC Discovery 1.0 §4).
//!
//! The document is only accepted if its `issuer` equals the configured issuer
//! **exactly** (§4.3), PKCE S256 is offered, at least one allowed signature
//! algorithm is offered and every endpoint is HTTPS (plain HTTP only for
//! loopback hosts, i.e. local development).

use crate::error::{Error, Result};
use crate::http;
use jsonwebtoken::Algorithm;
use serde::Deserialize;
use url::{Host, Url};

/// Signature algorithms this library accepts at all (the provider signs with RS256 or ES256).
pub(crate) const SUPPORTED_ALGS: [Algorithm; 2] = [Algorithm::RS256, Algorithm::ES256];

/// The parts of the discovery document this library uses.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    /// Issuer identifier.
    pub issuer: String,
    /// Authorization endpoint.
    pub authorization_endpoint: Url,
    /// Token endpoint.
    pub token_endpoint: Url,
    /// UserInfo endpoint.
    #[serde(default)]
    pub userinfo_endpoint: Option<Url>,
    /// JWKS document.
    pub jwks_uri: Url,
    /// RFC 7009 revocation endpoint.
    #[serde(default)]
    pub revocation_endpoint: Option<Url>,
    /// RP-initiated logout endpoint.
    #[serde(default)]
    pub end_session_endpoint: Option<Url>,
    /// ID token signature algorithms.
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// PKCE methods.
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    /// Whether authorization responses carry `iss` (RFC 9207).
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

impl ProviderMetadata {
    /// Allowed algorithms: offered by the provider and supported here.
    pub(crate) fn allowed_algs(&self) -> Vec<Algorithm> {
        SUPPORTED_ALGS
            .into_iter()
            .filter(|a| {
                self.id_token_signing_alg_values_supported
                    .iter()
                    .any(|s| s == alg_name(*a))
            })
            .collect()
    }

    /// Checks the rules of the module documentation against `expected_issuer`.
    pub(crate) fn validate(&self, expected_issuer: &str) -> Result<()> {
        if self.issuer != expected_issuer {
            return Err(Error::Discovery("issuer does not match"));
        }
        if !self
            .code_challenge_methods_supported
            .iter()
            .any(|m| m == "S256")
        {
            return Err(Error::Discovery("PKCE S256 not supported"));
        }
        if self.allowed_algs().is_empty() {
            return Err(Error::Discovery("no supported signature algorithm"));
        }
        let urls = [
            Some(&self.authorization_endpoint),
            Some(&self.token_endpoint),
            Some(&self.jwks_uri),
            self.userinfo_endpoint.as_ref(),
            self.revocation_endpoint.as_ref(),
            self.end_session_endpoint.as_ref(),
        ];
        if !urls.into_iter().flatten().all(is_secure) {
            return Err(Error::Discovery("endpoint is not HTTPS"));
        }
        Ok(())
    }
}

/// JOSE name of an allowed algorithm.
fn alg_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::ES256 => "ES256",
        _ => "RS256",
    }
}

/// HTTPS, or HTTP to a loopback host (local development only).
pub(crate) fn is_secure(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => match url.host() {
            Some(Host::Domain(d)) => d == "localhost",
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        },
        _ => false,
    }
}

/// URL of the discovery document for `issuer` (OIDC Discovery §4.1).
pub(crate) fn discovery_url(issuer: &str) -> Result<Url> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let url = Url::parse(&url).map_err(|_| Error::Config("issuer is not a URL"))?;
    if !is_secure(&url) {
        return Err(Error::Config("issuer must use HTTPS"));
    }
    Ok(url)
}

/// Fetches and validates the discovery document of `issuer`.
pub(crate) async fn fetch(http: &reqwest::Client, issuer: &str) -> Result<ProviderMetadata> {
    let meta: ProviderMetadata = http::get_json(http, &discovery_url(issuer)?, None).await?;
    meta.validate(issuer)?;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn meta(issuer: &str) -> ProviderMetadata {
        serde_json::from_value(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
            "token_endpoint": format!("{issuer}/oauth2/token"),
            "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
            "code_challenge_methods_supported": ["S256"],
        }))
        .unwrap()
    }

    #[test]
    fn issuer_must_match_exactly() {
        let m = meta("https://login.example.com");
        assert!(m.validate("https://login.example.com").is_ok());
        assert!(m.validate("https://login.example.com/").is_err());
        assert!(m.validate("https://other.example.com").is_err());
    }

    #[test]
    fn only_rs256_and_es256_are_allowed() {
        let m = meta("https://login.example.com");
        assert_eq!(m.allowed_algs(), vec![Algorithm::RS256, Algorithm::ES256]);
        let mut hs_only = m.clone();
        hs_only.id_token_signing_alg_values_supported = vec!["HS256".into(), "none".into()];
        assert!(hs_only.validate("https://login.example.com").is_err());
    }

    #[test]
    fn pkce_s256_is_required() {
        let mut m = meta("https://login.example.com");
        m.code_challenge_methods_supported = vec!["plain".into()];
        assert!(m.validate("https://login.example.com").is_err());
    }

    #[test]
    fn plain_http_only_for_loopback() {
        let ok = |u: &str| is_secure(&Url::parse(u).unwrap());
        assert!(ok("https://login.example.com/x"));
        assert!(
            ok("http://localhost:8400/x") && ok("http://127.0.0.1:1/") && ok("http://[::1]:1/")
        );
        assert!(!ok("http://login.example.com/") && !ok("ftp://localhost/"));
        let m = meta("http://login.example.com");
        assert!(m.validate("http://login.example.com").is_err());
        assert!(discovery_url("http://login.example.com").is_err());
        assert_eq!(
            discovery_url("https://login.example.com/")
                .unwrap()
                .as_str(),
            "https://login.example.com/.well-known/openid-configuration"
        );
    }
}
