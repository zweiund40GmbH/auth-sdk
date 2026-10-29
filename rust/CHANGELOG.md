# Changelog

Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionierung nach
[Semantic Versioning](https://semver.org/lang/de/).

## [0.3.0]

### Hinzugefügt
- Kontoereignisse (Security Event Tokens, RFC 8417): `Client::verify_security_event` prüft Signatur, `typ`
  `secevent+jwt`, `iss`, `aud`, `exp`/`iat` und das Ereignis; `AccountEvent` mit allen Typen des Vertrags
  (`user.email_changed`, `user.profile_changed`, `user.disabled`, `user.enabled`, `access.revoked` mit optionalem
  `reason`, `link.removed`, `onboarding.accepted`, `verification`) und `Unknown` für künftige Typen.
- Push-Empfänger nach RFC 8935: `Client::receive_event` mit `JtiStore` (Dublettenprüfung, `MemoryJtiStore`) und
  `PushResponse` (`202`/`400` mit Fehlercode/`500`/`503`); mit Feature `axum` als `IntoResponse`.
- Management-API: `Management` mit Client-Credentials-Token-Cache, `X-On-Behalf-Of`, Umstiegs-Links
  (`create_onboarding`, `onboarding`, `revoke_onboarding`, `resend_onboarding`), Verknüpfungen (`report_links`,
  `user_links`) und Ereignisse nachholen (`events`, `event_pages` mit `gap`).
- `Client::client_credentials` und `Error::Api` (`ApiError`) für Fehler der Management-API.
- `Management::users` (`GET /manage/users`, Typen `ManagedUser`, `UserPage`, `UsersQuery`, `UserStatus`) für den
  vollständigen Abgleich nach `gap: true`.

## [0.2.0]

### Hinzugefügt
- `IdClaims` und `UserInfo` enthalten `given_name` und `family_name` (Scope `profile`, je `Option<String>`).
  Leere Zeichenketten werden defensiv wie fehlende Werte als `None` gelesen.

## [0.1.0]

### Hinzugefügt
- Erste Veröffentlichung: Discovery, JWKS-Cache, Login mit PKCE (S256), ID-Token-Prüfung, Refresh, Logout,
  Back-Channel-Logout, UserInfo und axum-Integration.
