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
        /// Optional reason, if the provider sends one (e.g. `expired`).
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

/// Data of `access.revoked`.
#[derive(Deserialize)]
struct RevokedData {
    #[serde(default)]
    reason: Option<String>,
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

impl AccountEvent {
    /// Builds the event from its type name (without prefix) and data
    /// object. `None` if a known type has malformed data or the data is no
    /// object.
    pub fn from_parts(event_type: &str, value: Value) -> Option<Self> {
        if !value.is_object() {
            return None;
        }
        let event = match event_type {
            "user.email_changed" => {
                let d: EmailData = data(&value)?;
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
            "access.revoked" => {
                let d: RevokedData = data(&value)?;
                Self::AccessRevoked { reason: d.reason }
            }
            "link.removed" => Self::LinkRemoved {
                local_id: data::<LocalIdData>(&value)?.local_id,
            },
            "onboarding.accepted" => Self::OnboardingAccepted {
                local_id: data::<LocalIdData>(&value)?.local_id,
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
    /// Production or test application.
    pub env: TokenEnv,
    /// The event.
    pub event: AccountEvent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn all_contract_types_are_parsed() {
        let p = |t: &str, d: Value| AccountEvent::from_parts(t, d).unwrap();
        assert_eq!(
            p(
                "user.email_changed",
                json!({"email": "a@example.com", "emailVerified": false})
            ),
            AccountEvent::EmailChanged {
                email: "a@example.com".into(),
                email_verified: false
            }
        );
        let profile = p(
            "user.profile_changed",
            json!({"changed": ["givenName"], "displayName": "Erika M", "givenName": "Erika", "familyName": null}),
        );
        assert!(
            matches!(profile, AccountEvent::ProfileChanged { ref given_name, ref family_name, .. }
            if given_name.as_deref() == Some("Erika") && family_name.is_none())
        );
        assert_eq!(p("user.disabled", json!({})), AccountEvent::UserDisabled);
        assert_eq!(p("user.enabled", json!({})), AccountEvent::UserEnabled);
        assert_eq!(
            p("access.revoked", json!({})),
            AccountEvent::AccessRevoked { reason: None }
        );
        assert_eq!(
            p("access.revoked", json!({"reason": "expired"})),
            AccountEvent::AccessRevoked {
                reason: Some("expired".into())
            }
        );
        assert_eq!(
            p("link.removed", json!({"localId": "7:42"})),
            AccountEvent::LinkRemoved {
                local_id: "7:42".into()
            }
        );
        assert_eq!(
            p(
                "onboarding.accepted",
                json!({"localId": "7:42", "extra": 1})
            ),
            AccountEvent::OnboardingAccepted {
                local_id: "7:42".into()
            }
        );
        assert_eq!(p("verification", json!({})), AccountEvent::Verification);
    }

    #[test]
    fn unknown_types_are_kept_and_bad_data_rejected() {
        let e = AccountEvent::from_parts("user.deleted", json!({"x": 1})).unwrap();
        assert_eq!(e.event_type(), "user.deleted");
        assert!(matches!(e, AccountEvent::Unknown { ref data, .. } if data["x"] == 1));
        assert!(AccountEvent::from_parts("link.removed", json!({})).is_none());
        assert!(AccountEvent::from_parts("user.email_changed", json!({"email": 1})).is_none());
        assert!(AccountEvent::from_parts("user.disabled", json!("x")).is_none());
    }

    #[test]
    fn type_names_round_trip() {
        for t in [
            "user.email_changed",
            "user.disabled",
            "user.enabled",
            "access.revoked",
            "verification",
        ] {
            let d = if t == "user.email_changed" {
                json!({"email": "a@example.com", "emailVerified": true})
            } else {
                json!({})
            };
            assert_eq!(AccountEvent::from_parts(t, d).unwrap().event_type(), t);
        }
    }
}
