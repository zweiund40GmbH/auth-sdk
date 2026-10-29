//! Unit tests of the event parsing.

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
    // Unknown or non-string reasons never fail.
    assert_eq!(
        p("access.revoked", json!({"reason": 1})),
        AccountEvent::AccessRevoked { reason: None }
    );
    assert_eq!(
        p("access.revoked", json!({"reason": "policy"})),
        AccountEvent::AccessRevoked {
            reason: Some("policy".into())
        }
    );
    assert_eq!(
        p(
            "access.changed",
            json!({"roles": ["admin", "editor"], "validUntil": "2026-12-31T23:59:59Z", "extra": 1})
        ),
        AccountEvent::AccessChanged {
            roles: vec!["admin".into(), "editor".into()],
            valid_until: Some("2026-12-31T23:59:59Z".into())
        }
    );
    assert_eq!(
        p("access.changed", json!({"roles": [], "validUntil": null})),
        AccountEvent::AccessChanged {
            roles: vec![],
            valid_until: None
        }
    );
    // Missing or malformed values never fail: empty roles, unlimited.
    assert_eq!(
        p("access.changed", json!({})),
        AccountEvent::AccessChanged {
            roles: vec![],
            valid_until: None
        }
    );
    assert_eq!(
        p("access.changed", json!({"roles": "admin", "validUntil": 5})),
        AccountEvent::AccessChanged {
            roles: vec![],
            valid_until: None
        }
    );
    assert_eq!(
        p("access.changed", json!({"roles": ["a", 1, null, "b"]})),
        AccountEvent::AccessChanged {
            roles: vec!["a".into(), "b".into()],
            valid_until: None
        }
    );
    // A string end is passed through as is, not checked as a date.
    assert_eq!(
        p("access.changed", json!({"validUntil": "kein-datum"})),
        AccountEvent::AccessChanged {
            roles: vec![],
            valid_until: Some("kein-datum".into())
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
    assert!(AccountEvent::from_parts("link.removed", json!({"localId": ""})).is_none());
    assert!(
        AccountEvent::from_parts(
            "user.email_changed",
            json!({"email": "", "emailVerified": true})
        )
        .is_none()
    );
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
