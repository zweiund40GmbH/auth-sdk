//! The client secret as its own type: redacted in `Debug`, zeroed on drop,
//! no `Display` or `Serialize`, so it cannot end up in logs by accident.

use zeroize::Zeroizing;

/// Client secret of a confidential client (shown once in the admin UI).
///
/// Load it from an environment variable; never commit or log it.
#[derive(Clone)]
pub struct ClientSecret(Zeroizing<String>);

impl ClientSecret {
    /// Wraps a secret value.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(Zeroizing::new(secret.into()))
    }

    /// The secret value, for sending it to the provider. Never log it.
    pub fn expose_secret(&self) -> &str {
        &self.0
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
}
