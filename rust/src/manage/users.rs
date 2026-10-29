//! Users with a grant for the application (`GET /manage/users`, scope
//! `manage:users.read`): the full list for a resync, e.g. after a catch-up
//! page with `gap: true`, or a lookup by address.

use super::Management;
use crate::error::Result;
use reqwest::Method;
use serde::Deserialize;

/// Status of a user account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum UserStatus {
    /// Invited, not yet signed in.
    Invited,
    /// Active.
    Active,
    /// Disabled centrally.
    Disabled,
    /// A status this SDK version does not know (e.g. the reserved `locked`).
    #[serde(other)]
    Unknown,
}

/// A user in the application's scope.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ManagedUser {
    /// The central account.
    pub sub: String,
    /// Current address.
    pub email: String,
    /// Display name.
    pub display_name: String,
    /// Given name (`None` = not set).
    #[serde(default)]
    pub given_name: Option<String>,
    /// Family name (`None` = not set).
    #[serde(default)]
    pub family_name: Option<String>,
    /// Account status.
    pub status: UserStatus,
    /// Role keys of this application (sorted).
    pub roles: Vec<String>,
    /// End of the grant (ISO 8601; `None` = unlimited, in the past = expired).
    pub valid_until: Option<String>,
}

/// One page of [`Management::users`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct UserPage {
    /// Users, sorted by address.
    pub items: Vec<ManagedUser>,
    /// Number of matching users over all pages.
    pub total: u64,
}

/// Filter and page of [`Management::users`]; `Default` = first page of all users.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UsersQuery {
    /// Exact address (case-insensitive); `None` = all users.
    pub email: Option<String>,
    /// Page, starting at 1 (provider default 1).
    pub page: Option<u32>,
    /// Page size up to 200 (provider default 50).
    pub page_size: Option<u32>,
}

impl UsersQuery {
    /// Page `page` of all users with `page_size` entries.
    pub fn page(page: u32, page_size: u32) -> Self {
        Self {
            email: None,
            page: Some(page),
            page_size: Some(page_size),
        }
    }
}

impl Management {
    /// One page of the users with a grant for the application (also
    /// expired ones). For a full resync request pages until
    /// `page * page_size >= total`.
    pub async fn users(&self, query: &UsersQuery) -> Result<UserPage> {
        let page = query.page.map(|p| p.to_string());
        let size = query.page_size.map(|p| p.to_string());
        let pairs = [
            ("email", query.email.as_deref()),
            ("page", page.as_deref()),
            ("pageSize", size.as_deref()),
        ];
        let params: Vec<(&str, &str)> = pairs
            .iter()
            .filter_map(|(k, v)| v.map(|v| (*k, v)))
            .collect();
        let url = self.url(&["users"], &params)?;
        self.json(Method::GET, &url, None::<&()>).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn users_follow_the_contract() {
        let page: UserPage = serde_json::from_value(json!({"items": [
            {"sub": "s", "email": "a@example.com", "displayName": "A", "givenName": null,
             "familyName": "B", "status": "locked", "roles": ["operator"], "validUntil": null}
        ], "total": 1}))
        .unwrap();
        assert_eq!(page.items[0].status, UserStatus::Unknown);
        assert_eq!(page.items[0].family_name.as_deref(), Some("B"));
    }
}
