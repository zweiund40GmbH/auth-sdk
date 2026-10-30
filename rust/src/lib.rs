//! # z40-auth
//!
//! Relying-party library for zwei&40 Login, the central login of zwei&40 GmbH (OpenID Connect
//! provider) for **server-side confidential clients** (backend-for-frontend):
//! the application logs the user in via the provider, verifies the ID token
//! and then issues its own session. Tokens stay on the server.
//!
//! What the crate does:
//! - discovery (issuer must match exactly) and a JWKS cache with key rotation,
//! - login with Authorization Code + PKCE S256, `state`, `nonce` and RFC 9207
//!   `iss` check ([`Client::begin_login`], [`Client::complete_login`]),
//! - ID token verification (RS256/ES256 only, `typ`, `iss`, `aud`, `azp`,
//!   `exp`/`iat`, `nonce`, `at_hash`),
//! - [`Client::refresh`], [`Client::userinfo`], [`Client::revoke`],
//!   [`Client::logout_url`],
//! - back-channel logout tokens ([`Client::verify_backchannel_logout`]),
//! - JWT access tokens for resource servers ([`Client::verify_access_token`]),
//! - account events (Security Event Tokens): verification and push receiver
//!   ([`Client::verify_security_event`], [`Client::receive_event`]),
//! - management API ([`Management`]): onboarding links, links to local
//!   accounts and the event catch-up with client-credentials tokens,
//! - feature `axum`: extractors for callback and back-channel logout, and
//!   the response of the event receiver.
//!
//! The crate stores nothing: the [`LoginState`] between redirect and callback
//! is kept by the application (server-side or in an encrypted cookie).
//!
//! ```no_run
//! use z40_auth::{CallbackParams, Client, ClientSecret};
//!
//! # async fn run() -> Result<(), z40_auth::Error> {
//! let client = Client::discover(
//!     "https://login.example.com",
//!     "my-app",
//!     ClientSecret::new(std::env::var("AUTH_CLIENT_SECRET").unwrap_or_default()),
//! )
//! .await?;
//!
//! // 1. Redirect the browser to `req.url`, keep `req.state` for the callback.
//! let req = client.begin_login("https://app.example.com/auth/callback", &["email", "profile"], &[])?;
//!
//! // 2. In the callback handler:
//! let params = CallbackParams::from_query("code=…&state=…&iss=…")?;
//! let login = client.complete_login(&req.state, &params).await?;
//! println!("user {} (session {:?})", login.claims.sub, login.claims.sid);
//!
//! // 3. Back-channel logout endpoint: end local sessions with this sid.
//! let event = client.verify_backchannel_logout("<logout_token>").await?;
//! # let _ = event;
//! # Ok(())
//! # }
//! ```

mod access;
#[cfg(feature = "axum")]
pub mod axum;
mod claims;
mod client;
mod crypto;
mod discovery;
mod error;
pub mod events;
mod http;
mod jwk;
mod jwks;
mod jwt;
mod login;
mod logout;
pub mod manage;
mod requirements;
mod secret;
mod tokens;

pub use claims::{AccessClaims, Audience, IdClaims, TokenEnv, UserInfo};
pub use client::{Client, Options};
pub use discovery::ProviderMetadata;
pub use error::{ApiError, Error, Result, TokenError};
pub use events::{AccountEvent, JtiStore, MemoryJtiStore, PushResponse, SecurityEvent, StoreError};
pub use http::AuthMethod;
pub use jwks::Clock;
pub use login::{AuthorizationRequest, CallbackParams, LoginState};
pub use logout::{BACKCHANNEL_LOGOUT_EVENT, LogoutEvent};
pub use manage::Management;
pub use manage::catch_up::{CaughtUpEvent, EventPage, EventPages};
pub use manage::links::{Link, LinkReport, LinkSource, LinksReported};
pub use manage::onboarding::{NewOnboarding, Onboarding, OnboardingState};
pub use manage::users::{ManagedUser, UserPage, UserStatus, UsersQuery};
pub use requirements::AuthRequirements;
pub use secret::{ClientSecret, SecretString};
pub use tokens::{LoginResult, Refreshed, Tokens};
