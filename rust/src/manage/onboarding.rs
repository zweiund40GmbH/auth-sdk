//! Onboarding links (scope `manage:onboarding`): the application invites
//! the user of a local account (`localId`) to link it with a central
//! account. The provider mails the link (default) or returns it once.

use super::Management;
use crate::error::Result;
use reqwest::Method;
use serde::{Deserialize, Serialize};

/// Request body of [`Management::create_onboarding`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOnboarding {
    /// Address of the person (the mail goes there).
    pub email: String,
    /// Id of the local account (1–128 visible ASCII characters).
    pub local_id: String,
    /// Suggested display name for a new account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Suggested given name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Suggested family name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// An admin of the application: a second factor becomes mandatory.
    pub app_admin: bool,
    /// Role keys of the grant (`None` = the application's default roles).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// End of a grant created or renewed on acceptance, ISO 8601 UTC
    /// (`2027-03-31T00:00:00Z`); `None` = unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    /// Mail the link (`true`, default) or return it as `url` (`false`).
    pub send_mail: bool,
}

impl NewOnboarding {
    /// A link for `local_id` mailed to `email`, with default roles.
    pub fn new(email: impl Into<String>, local_id: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            local_id: local_id.into(),
            display_name: None,
            given_name: None,
            family_name: None,
            app_admin: false,
            roles: None,
            valid_until: None,
            send_mail: true,
        }
    }
}

/// Status of an onboarding link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum OnboardingState {
    /// Waiting for the user.
    Open,
    /// Accepted: `sub` is set.
    Accepted,
    /// Expired unused.
    Expired,
    /// Revoked by the application (or replaced by a newer link).
    Revoked,
    /// A status this SDK version does not know.
    #[serde(other)]
    Unknown,
}

/// An onboarding link as the application sees it.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Onboarding {
    /// Id (store it with the local account).
    pub id: String,
    /// The local account.
    pub local_id: String,
    /// Requested address.
    pub email: String,
    /// Admin of the application.
    pub app_admin: bool,
    /// Role keys of the grant.
    pub roles: Vec<String>,
    /// End of a grant created on acceptance (`None` = unlimited).
    pub valid_until: Option<String>,
    /// Current status.
    pub status: OnboardingState,
    /// Created (ISO 8601).
    pub created_at: String,
    /// End of the current link (ISO 8601).
    pub expires_at: String,
    /// Last mail (`None` = never mailed).
    pub sent_at: Option<String>,
    /// Accepted (ISO 8601).
    pub accepted_at: Option<String>,
    /// The linked account, only once accepted.
    pub sub: Option<String>,
    /// The link, only with `send_mail: false`. Hand it only to the user it
    /// was made for; never log it (`Debug` hides it).
    #[serde(default)]
    pub url: Option<String>,
}

impl std::fmt::Debug for Onboarding {
    /// All fields except `url`, which is redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Onboarding")
            .field("id", &self.id)
            .field("local_id", &self.local_id)
            .field("email", &self.email)
            .field("app_admin", &self.app_admin)
            .field("roles", &self.roles)
            .field("valid_until", &self.valid_until)
            .field("status", &self.status)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("sent_at", &self.sent_at)
            .field("accepted_at", &self.accepted_at)
            .field("sub", &self.sub)
            .field("url", &self.url.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Body of `POST …/{id}/resend`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Resend {
    send_mail: bool,
}

impl Management {
    /// Requests an onboarding link (`POST /manage/onboarding`). A still
    /// open link of the same `local_id` is replaced. `409`: onboarding is
    /// switched off for the application or `local_id` is already linked.
    pub async fn create_onboarding(&self, request: &NewOnboarding) -> Result<Onboarding> {
        let url = self.url(&["onboarding"], &[])?;
        self.json(Method::POST, &url, Some(request)).await
    }

    /// The status of an own onboarding link (`404` for unknown or deleted ids).
    pub async fn onboarding(&self, id: &str) -> Result<Onboarding> {
        let url = self.url(&["onboarding", id], &[])?;
        self.json(Method::GET, &url, None::<&()>).await
    }

    /// Revokes an open or expired link (idempotent); `409` once accepted.
    pub async fn revoke_onboarding(&self, id: &str) -> Result<()> {
        let url = self.url(&["onboarding", id], &[])?;
        self.empty(Method::DELETE, &url).await
    }

    /// Sends a new link with a new lifetime (the old one stops working):
    /// by mail, or returned as `url` with `send_mail: false`. `409` once
    /// accepted or revoked.
    pub async fn resend_onboarding(&self, id: &str, send_mail: bool) -> Result<Onboarding> {
        let url = self.url(&["onboarding", id, "resend"], &[])?;
        self.json(Method::POST, &url, Some(&Resend { send_mail }))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_uses_contract_names_and_skips_unset_fields() {
        let mut r = NewOnboarding::new("lena@example.com", "7:42");
        r.given_name = Some("Lena".into());
        r.roles = Some(vec!["viewer".into()]);
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({"email": "lena@example.com", "localId": "7:42", "givenName": "Lena",
                   "appAdmin": false, "roles": ["viewer"], "sendMail": true})
        );
    }

    #[test]
    fn status_is_parsed_and_url_redacted() {
        let o: Onboarding = serde_json::from_value(json!({
            "id": "o1", "localId": "7:42", "email": "lena@example.com", "appAdmin": true,
            "roles": [], "validUntil": null, "status": "open", "createdAt": "2026-10-29T10:00:00Z",
            "expiresAt": "2026-11-12T10:00:00Z", "sentAt": null, "acceptedAt": null, "sub": null,
            "url": "https://login.example.com/link#t=secret-token"
        }))
        .unwrap();
        assert_eq!(o.status, OnboardingState::Open);
        assert!(o.url.is_some() && !format!("{o:?}").contains("secret-token"));
        let later: OnboardingState = serde_json::from_value(json!("paused")).unwrap();
        assert_eq!(later, OnboardingState::Unknown);
    }
}
