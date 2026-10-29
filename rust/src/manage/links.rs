//! Links between central accounts (`sub`) and local accounts (`localId`).
//! The provider's links are authoritative; the application keeps a copy.

use super::Management;
use crate::error::Result;
use reqwest::Method;
use serde::{Deserialize, Serialize};

/// A link to report (`POST /manage/links`, scope `manage:users.write`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkReport {
    /// The central account.
    pub sub: String,
    /// Id of the local account (1–128 visible ASCII characters).
    pub local_id: String,
}

/// Result of [`Management::report_links`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct LinksReported {
    /// Stored (or already present) links.
    pub linked: u64,
    /// Skipped: user outside the application's scope, or `localId` already
    /// linked to another account (links are never moved).
    pub ignored: u64,
}

/// Where a link came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum LinkSource {
    /// Reported by the application.
    Reported,
    /// Created by an accepted onboarding link.
    Onboarding,
    /// A source this SDK version does not know.
    #[serde(other)]
    Unknown,
}

/// A link of a user to a local account (`GET /manage/users/{sub}/links`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    /// Id of the local account.
    pub local_id: String,
    /// Origin of the link.
    pub source: LinkSource,
    /// When it was created (ISO 8601).
    pub linked_at: String,
}

/// Body of `POST /manage/links`.
#[derive(Serialize)]
struct Reports<'a> {
    items: &'a [LinkReport],
}

/// Answer of `GET /manage/users/{sub}/links`.
#[derive(Deserialize)]
struct Links {
    items: Vec<Link>,
}

impl Management {
    /// Reports links (1–500 per call, idempotent).
    pub async fn report_links(&self, links: &[LinkReport]) -> Result<LinksReported> {
        let url = self.url(&["links"], &[])?;
        self.json(Method::POST, &url, Some(&Reports { items: links }))
            .await
    }

    /// The links of user `sub`, sorted by `localId` (scope
    /// `manage:users.read`; `404` if the user is outside the scope).
    pub async fn user_links(&self, sub: &str) -> Result<Vec<Link>> {
        let url = self.url(&["users", sub, "links"], &[])?;
        let links: Links = self.json(Method::GET, &url, None::<&()>).await?;
        Ok(links.items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn link_bodies_follow_the_contract() {
        let items = [LinkReport {
            sub: "s".into(),
            local_id: "7:42".into(),
        }];
        assert_eq!(
            serde_json::to_value(Reports { items: &items }).unwrap(),
            json!({"items": [{"sub": "s", "localId": "7:42"}]})
        );
        let links: Links = serde_json::from_value(json!({"items": [
            {"localId": "7:42", "source": "onboarding", "linkedAt": "2026-10-29T10:00:00Z"},
            {"localId": "8:1", "source": "imported", "linkedAt": "2026-10-29T10:00:00Z"}
        ]}))
        .unwrap();
        assert_eq!(links.items[0].source, LinkSource::Onboarding);
        assert_eq!(links.items[1].source, LinkSource::Unknown);
    }
}
