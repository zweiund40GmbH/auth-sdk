//! Secret values as their own types: redacted in `Debug`, zeroed on drop,
//! no `Display` or `Serialize`, so they cannot end up in logs by accident.
//!
//! - [`SecretString`]: token values from the provider (access, ID and
//!   refresh tokens).
//! - [`ClientSecret`]: the client secret of the application.
//!
//! Zeroing is best effort and covers only the SDK's own buffers: these
//! types, the read response body, the form body of the token and revocation
//! endpoints and the intermediate values of the `client_secret_basic`
//! header. Copies inside reqwest/hyper and the TLS stack, the scratch
//! buffer of `serde_json` for strings with escapes and the finished
//! `Authorization` header values are out of reach.

use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

/// A secret string (e.g. a token): `Debug` prints a placeholder, the
/// memory is overwritten on drop. Read it only with
/// [`SecretString::expose_secret`], to send or store it; never log it.
#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wraps a secret value.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(Zeroizing::new(secret.into()))
    }

    /// The secret value. Never log it.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    /// Prints only a placeholder.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

impl From<String> for SecretString {
    /// Wraps an owned secret.
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    /// Reads a JSON string.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}

/// Client secret of a confidential client (shown once in the admin UI).
///
/// Load it from an environment variable; never commit or log it.
#[derive(Clone)]
pub struct ClientSecret(SecretString);

impl ClientSecret {
    /// Wraps a secret value.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(SecretString::new(secret))
    }

    /// The secret value, for sending it to the provider. Never log it.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for ClientSecret {
    /// Prints only a placeholder.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientSecret([redacted])")
    }
}

impl From<String> for ClientSecret {
    /// Wraps an owned secret.
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = ClientSecret::new("top-secret-value");
        let printed = format!("{s:?}");
        assert!(!printed.contains("top-secret"));
        assert_eq!(s.expose_secret(), "top-secret-value");
    }

    #[test]
    fn secret_string_is_read_from_json_and_redacted() {
        let s: SecretString = serde_json::from_str(r#""tok-123""#).unwrap();
        assert_eq!(s.expose_secret(), "tok-123");
        assert_eq!(format!("{s:?}"), "[redacted]");
        assert_eq!(format!("{:?}", Some(&s)), "Some([redacted])");
    }
}
