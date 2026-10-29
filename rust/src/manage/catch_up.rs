//! Event catch-up (`GET /manage/events`, scope `manage:events.read`): the
//! events of the last 30 days in cursor order, whether or not the push
//! reached the application. For recovering after an outage or instead of
//! the push.
//!
//! Keep the `next_cursor` of the last processed page. If a page has
//! `gap: true`, events after the cursor were already deleted by the
//! provider's retention: the items of the page are still valid, but the
//! application missed events and must resync its users completely (e.g.
//! via the users endpoints of the management API) before continuing.

use super::Management;
use crate::error::{Error, Result};
use crate::events::AccountEvent;
use reqwest::Method;
use serde::Deserialize;
use serde_json::Value;

/// One event of the catch-up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaughtUpEvent {
    /// Position in the catch-up (opaque).
    pub cursor: String,
    /// Event id, the same as in the pushed token: deduplicate on it.
    pub jti: String,
    /// The user.
    pub sub: String,
    /// Time of the change (ISO 8601).
    pub occurred_at: String,
    /// The event.
    pub event: AccountEvent,
}

/// One page of the catch-up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPage {
    /// Events in cursor order.
    pub items: Vec<CaughtUpEvent>,
    /// Cursor for the next call (store it after processing the items).
    pub next_cursor: String,
    /// More events are ready (call again right away).
    pub has_more: bool,
    /// Events after `since` were deleted before they were fetched: resync
    /// completely (see the module documentation).
    pub gap: bool,
}

/// Wire form of an event.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEvent {
    cursor: String,
    jti: String,
    #[serde(rename = "type")]
    event_type: String,
    sub: String,
    occurred_at: String,
    data: Value,
}

/// Wire form of a page.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPage {
    items: Vec<RawEvent>,
    next_cursor: String,
    has_more: bool,
    gap: bool,
}

/// Converts the wire form; malformed data of a known type → [`Error::InvalidResponse`].
fn page(raw: RawPage) -> Result<EventPage> {
    let items = raw
        .items
        .into_iter()
        .map(|e| {
            let event =
                AccountEvent::from_parts(&e.event_type, e.data).ok_or(Error::InvalidResponse)?;
            Ok(CaughtUpEvent {
                cursor: e.cursor,
                jti: e.jti,
                sub: e.sub,
                occurred_at: e.occurred_at,
                event,
            })
        })
        .collect::<Result<_>>()?;
    Ok(EventPage {
        items,
        next_cursor: raw.next_cursor,
        has_more: raw.has_more,
        gap: raw.gap,
    })
}

impl Management {
    /// One page of events after `since` (`None` = from the oldest kept
    /// event); `limit` 1–500, default 100. A `503` means "try again".
    pub async fn events(&self, since: Option<&str>, limit: Option<u32>) -> Result<EventPage> {
        let limit = limit.map(|l| l.to_string());
        let mut query = Vec::new();
        if let Some(s) = since {
            query.push(("since", s));
        }
        if let Some(l) = limit.as_deref() {
            query.push(("limit", l));
        }
        let url = self.url(&["events"], &query)?;
        let raw: RawPage = self.json(Method::GET, &url, None::<&()>).await?;
        page(raw)
    }

    /// Pages from `since` until the catch-up has no more events:
    ///
    /// ```no_run
    /// # async fn run(mgmt: z40_auth::Management, saved: Option<String>) -> z40_auth::Result<()> {
    /// let mut pages = mgmt.event_pages(saved);
    /// while let Some(page) = pages.next().await? {
    ///     if page.gap { /* resync all users first */ }
    ///     for e in &page.items { /* skip seen e.jti, apply e.event */ }
    ///     // store page.next_cursor
    /// }
    /// # Ok(()) }
    /// ```
    pub fn event_pages(&self, since: Option<String>) -> EventPages<'_> {
        EventPages {
            mgmt: self,
            cursor: since,
            done: false,
        }
    }
}

/// Iterator over catch-up pages, see [`Management::event_pages`].
#[derive(Debug)]
pub struct EventPages<'a> {
    mgmt: &'a Management,
    cursor: Option<String>,
    done: bool,
}

impl EventPages<'_> {
    /// The next page, or `None` once the last page (`has_more: false`) was
    /// returned. After an error the same page is requested again on the
    /// next call.
    pub async fn next(&mut self) -> Result<Option<EventPage>> {
        if self.done {
            return Ok(None);
        }
        let page = self.mgmt.events(self.cursor.as_deref(), None).await?;
        self.cursor = Some(page.next_cursor.clone());
        self.done = !page.has_more;
        Ok(Some(page))
    }

    /// The cursor after the last returned page (`None` before the first).
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pages_are_converted() {
        let raw: RawPage = serde_json::from_value(json!({
            "items": [{"cursor": "5", "jti": "j", "type": "link.removed", "sub": "s",
                       "occurredAt": "2026-10-29T10:00:00Z", "data": {"localId": "7:42"}}],
            "nextCursor": "5", "hasMore": false, "gap": true
        }))
        .unwrap();
        let p = page(raw).unwrap();
        assert!(p.gap && !p.has_more);
        assert_eq!(
            p.items[0].event,
            AccountEvent::LinkRemoved {
                local_id: "7:42".into()
            }
        );
        let bad: RawPage = serde_json::from_value(json!({
            "items": [{"cursor": "5", "jti": "j", "type": "link.removed", "sub": "s",
                       "occurredAt": "x", "data": {}}],
            "nextCursor": "5", "hasMore": false, "gap": false
        }))
        .unwrap();
        assert!(matches!(page(bad), Err(Error::InvalidResponse)));
    }
}
