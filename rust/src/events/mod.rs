//! Account events (Security Event Tokens, RFC 8417): what the provider
//! tells an application about accounts in its scope between two logins.
//!
//! The same events arrive two ways: pushed to the application's events URI
//! (RFC 8935, [`Client::receive_event`](crate::Client::receive_event)) and
//! fetched from the management API ([`Management::event_pages`](crate::Management::event_pages)).
//! Both carry the same `jti`, so one [`JtiStore`] deduplicates both.
//!
//! Types the SDK does not know yet arrive as [`AccountEvent::Unknown`]
//! (forward compatible: ignore them); unknown fields of known types are
//! ignored as well.

mod receive;
mod verify;

pub use receive::{JTI_TTL, JtiStore, MemoryJtiStore, PushResponse, StoreError};

use crate::claims::TokenEnv;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Prefix of the event type URIs (keys of the `events` claim).
pub const EVENT_URN_PREFIX: &str = "urn:z40:event:";

/// Header `typ` of a Security Event Token (RFC 8417 §2.3).
pub const TYP_SECEVENT: &str = "secevent+jwt";

/// `Content-Type` of a pushed Security Event Token (RFC 8935 §2).
pub const CONTENT_TYPE_SECEVENT: &str = "application/secevent+jwt";

/// One event about an account, with its data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccountEvent {
    /// `user.email_changed`: the address changed or was confirmed.
    EmailChanged {
        /// The current address.
        email: String,
        /// Whether the user confirmed it (`false` after an admin set it).
        email_verified: bool,
    },
    /// `user.profile_changed`: display, given or family name changed.
    ProfileChanged {
        /// Changed fields (`displayName`, `givenName`, `familyName`).
        changed: Vec<String>,
        /// Current display name.
        display_name: String,
        /// Current given name (`None` = not set).
        given_name: Option<String>,
        /// Current family name (`None` = not set).
        family_name: Option<String>,
    },
    /// `user.disabled`: the account was disabled centrally.
    UserDisabled,
    /// `user.enabled`: the disabled account was enabled again.
    UserEnabled,
    /// `access.revoked`: the grant for this application was withdrawn.
    AccessRevoked {
        /// Why, if the provider says so (e.g. `expired` when the grant ran
        /// out). Optional and open: new values may appear, and a missing
        /// or non-string value is `None`.
        reason: Option<String>,
    },
    /// `link.removed`: a link to a local account was removed.
    LinkRemoved {
        /// Id of the local account in the application.
        local_id: String,
    },
    /// `onboarding.accepted`: an onboarding link of this application was accepted.
    OnboardingAccepted {
        /// Id of the local account now linked to the user (`sub`).
        local_id: String,
    },
    /// `verification`: test event from the admin UI (push only, no user).
    Verification,
    /// A type this SDK version does not know; ignore it.
    Unknown {
        /// The type name without prefix.
        event_type: String,
        /// Its data object.
        data: Value,
    },
}

/// Data of `user.email_changed`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailData {
    email: String,
    email_verified: bool,
}

/// Data of `user.profile_changed`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileData {
    changed: Vec<String>,
    display_name: String,
    #[serde(default)]
    given_name: Option<String>,
    #[serde(default)]
    family_name: Option<String>,
}

/// Data of `link.removed` and `onboarding.accepted`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalIdData {
    local_id: String,
}

/// Deserializes event data; `None` if it does not have the contract's form.
fn data<T: DeserializeOwned>(value: &Value) -> Option<T> {
    serde_json::from_value(value.clone()).ok()
}

/// The `localId` of `link.removed` / `onboarding.accepted`; empty = malformed.
fn local_id(value: &Value) -> Option<String> {
    Some(data::<LocalIdData>(value)?.local_id).filter(|id| !id.is_empty())
}

impl AccountEvent {
    /// Builds the event from its type name (without prefix) and data
    /// object. `None` if a known type has malformed data (e.g. an empty
    /// `localId`) or the data is no object.
    pub fn from_parts(event_type: &str, value: Value) -> Option<Self> {
        if !value.is_object() {
            return None;
        }
        let event = match event_type {
            "user.email_changed" => {
                let d: EmailData = data(&value).filter(|d: &EmailData| !d.email.is_empty())?;
                Self::EmailChanged {
                    email: d.email,
                    email_verified: d.email_verified,
                }
            }
            "user.profile_changed" => {
                let d: ProfileData = data(&value)?;
                Self::ProfileChanged {
                    changed: d.changed,
                    display_name: d.display_name,
                    given_name: d.given_name,
                    family_name: d.family_name,
                }
            }
            "user.disabled" => Self::UserDisabled,
            "user.enabled" => Self::UserEnabled,
            // Tolerant on purpose: `reason` is optional and its values are open.
            "access.revoked" => Self::AccessRevoked {
                reason: value
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            },
            "link.removed" => Self::LinkRemoved {
                local_id: local_id(&value)?,
            },
            "onboarding.accepted" => Self::OnboardingAccepted {
                local_id: local_id(&value)?,
            },
            "verification" => Self::Verification,
            other => Self::Unknown {
                event_type: other.to_owned(),
                data: value,
            },
        };
        Some(event)
    }

    /// The type name without prefix (`user.email_changed`, …).
    pub fn event_type(&self) -> &str {
        match self {
            Self::EmailChanged { .. } => "user.email_changed",
            Self::ProfileChanged { .. } => "user.profile_changed",
            Self::UserDisabled => "user.disabled",
            Self::UserEnabled => "user.enabled",
            Self::AccessRevoked { .. } => "access.revoked",
            Self::LinkRemoved { .. } => "link.removed",
            Self::OnboardingAccepted { .. } => "onboarding.accepted",
            Self::Verification => "verification",
            Self::Unknown { event_type, .. } => event_type,
        }
    }
}

/// A verified, pushed Security Event Token.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SecurityEvent {
    /// Event id, the same in every delivery attempt and in the catch-up:
    /// deduplicate on it.
    pub jti: String,
    /// The user (`None` only for [`AccountEvent::Verification`]).
    pub sub: Option<String>,
    /// Time of the change (seconds since the epoch; `None` for verification).
    pub toe: Option<i64>,
    /// Time of this delivery attempt.
    pub iat: i64,
    /// Production or test application, passed through from the token;
    /// compare it with your own environment if a mix-up matters to you.
    pub env: TokenEnv,
    /// The event.
    pub event: AccountEvent,
}

#[cfg(test)]
mod tests;
