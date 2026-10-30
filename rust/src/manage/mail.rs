//! Mail sending (scope `manage:mail.send`): the application queues mails
//! with the provider's configured mail transport instead of its own SMTP
//! account. The sender is always set by the provider, never by the request.
//!
//! Errors ([`Error::Api`](crate::Error::Api), `code`):
//! - `409 mail_disabled`: mail sending is not switched on for the application,
//! - `409 idempotency_conflict`: the key was used for another mail,
//! - `413` (`payload_too_large`): request larger than 256 KiB,
//! - `422 validation`: invalid input, field in `fields` (`to`, `to[2]`, `subject`, …),
//! - `429 rate_limited`: hourly or daily limit (counted in recipients), see
//!   [`Error::retry_after`](crate::Error::retry_after); nothing was queued,
//! - `503 unavailable`: retry later.
//!
//! After `429`, `503` or a network error retry with the **same** key.

use super::Management;
use super::idempotency::IdempotencyKey;
use crate::error::Result;
use reqwest::Method;
use serde::{Deserialize, Serialize};

/// Request body of [`Management::mail_send`]. Every recipient gets a mail
/// of their own (recipients do not see each other).
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailRequest {
    /// 1–50 addresses, without duplicates.
    pub to: Vec<String>,
    /// 1–200 characters, one line.
    pub subject: String,
    /// Plain text, 1–100 000 characters.
    pub text: String,
    /// Optional HTML (at most 200 000 characters); the provider keeps only
    /// simple markup. Without it the text is sent as HTML paragraphs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    /// Reply address; `None` = the one configured for the application.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// Key of the application's own operation (see [`IdempotencyKey`]).
    pub idempotency_key: IdempotencyKey,
}

impl MailRequest {
    /// A plain-text mail to `to`, without HTML and reply address.
    pub fn new(
        to: Vec<String>,
        subject: impl Into<String>,
        text: impl Into<String>,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            to,
            subject: subject.into(),
            text: text.into(),
            html: None,
            reply_to: None,
            idempotency_key,
        }
    }
}

impl std::fmt::Debug for MailRequest {
    /// Recipient count, key and sizes only: no addresses or content in logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailRequest")
            .field("recipients", &self.to.len())
            .field("subject_len", &self.subject.len())
            .field("text_len", &self.text.len())
            .field("html_len", &self.html.as_ref().map(String::len))
            .field("has_reply_to", &self.reply_to.is_some())
            .field("idempotency_key", &self.idempotency_key)
            .finish()
    }
}

/// State of a mail order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum MailState {
    /// At least one mail is still open.
    Pending,
    /// All mails were handed over to the mail server.
    Sent,
    /// None open any more, at least one failed for good.
    Failed,
    /// A state this SDK version does not know.
    #[serde(other)]
    Unknown,
}

/// Answer of [`Management::mail_send`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct MailQueued {
    /// Id of the order (for [`Management::mail_status`]).
    pub id: String,
    /// State (`pending` for a new order).
    pub status: MailState,
    /// Number of recipients.
    pub recipients: u32,
    /// `true` if the provider already knew the request (`200`: same key,
    /// same content) and returned the existing order; nothing was sent
    /// again. `false` for a newly queued order (`202`).
    #[serde(skip)]
    pub repeated: bool,
}

/// Answer of [`Management::mail_status`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct MailStatus {
    /// Id of the order.
    pub id: String,
    /// Overall state.
    pub status: MailState,
    /// Number of recipients.
    pub recipients: u32,
    /// Mails handed over.
    pub sent: u32,
    /// Mails failed for good.
    pub failed: u32,
    /// Mails still open.
    pub pending: u32,
    /// When the order was queued (ISO 8601).
    pub created_at: String,
}

impl Management {
    /// Queues a mail (`POST /manage/mail`). Retrying with the same key and
    /// content returns the existing order ([`MailQueued::repeated`]) – also
    /// if sending was switched off or a limit was reached meanwhile. An
    /// empty `to` is rejected with [`Error::Config`](crate::Error::Config)
    /// before sending. Error codes: see the [module documentation](self).
    pub async fn mail_send(&self, request: &MailRequest) -> Result<MailQueued> {
        if request.to.is_empty() {
            return Err(crate::Error::Config("mail needs at least one recipient"));
        }
        let url = self.url(&["mail"], &[])?;
        let (status, mut queued): (u16, MailQueued) =
            self.json_status(Method::POST, &url, Some(request)).await?;
        queued.repeated = status == 200;
        Ok(queued)
    }

    /// The state of an own order (`GET /manage/mail/{id}`); unknown,
    /// foreign or older than 30 days → `404`.
    pub async fn mail_status(&self, id: &str) -> Result<MailStatus> {
        let url = self.url(&["mail", id], &[])?;
        self.json(Method::GET, &url, None::<&()>).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_uses_contract_names_and_debug_hides_content() {
        let key = IdempotencyKey::from_parts(&["anfrage", "4711"]).unwrap();
        let mut r = MailRequest::new(
            vec!["anna@example.com".into()],
            "Ihre Anfrage",
            "Hallo",
            key,
        );
        r.reply_to = Some("team@example.com".into());
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({"to": ["anna@example.com"], "subject": "Ihre Anfrage", "text": "Hallo",
                   "replyTo": "team@example.com", "idempotencyKey": "anfrage:4711"})
        );
        let printed = format!("{r:?}");
        assert!(!printed.contains("anna@") && !printed.contains("Hallo"));
    }

    #[test]
    fn status_is_parsed() {
        let s: MailStatus = serde_json::from_value(json!({
            "id": "m1", "status": "failed", "recipients": 2, "sent": 1, "failed": 1,
            "pending": 0, "createdAt": "2026-10-30T10:00:00Z"
        }))
        .unwrap();
        assert_eq!((s.status, s.sent, s.failed), (MailState::Failed, 1, 1));
        let later: MailState = serde_json::from_value(json!("held")).unwrap();
        assert_eq!(later, MailState::Unknown);
    }
}
