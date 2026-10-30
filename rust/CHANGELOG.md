# Changelog

Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionierung nach
[Semantic Versioning](https://semver.org/lang/de/).

## [0.5.0] – 2026-10-30

### Geändert (inkompatibel)
- `Client::refresh` liefert `Result<Refreshed, RefreshError>`. Wird nur das neue ID-Token abgelehnt, enthält
  `RefreshError::IdToken { tokens, source }` die neuen Tokens: Das alte Refresh-Token ist dann schon verbraucht –
  das neue speichern, sonst widerruft der Provider beim nächsten Versuch die ganze Token-Familie.
  `RefreshError::Request(Error)` heißt: keine neuen Tokens. Es gibt bewusst keine Umwandlung in `Error`, damit `?` die
  Tokens nicht verwirft.
- `429` eines OIDC-Endpunkts (Token, Revoke, UserInfo, Discovery, JWKS) kommt als neue Variante
  `Error::RateLimited { retry_after }` (auch mit `invalid_grant` im Rumpf); am Token-Endpunkt wurde das Token nicht
  verbraucht. `Error::OAuth` hat das neue Feld `status`.
- `Tokens::access_token`, `id_token` und `refresh_token` sind `SecretString` (geschwärztes `Debug`, beim Freigeben
  überschrieben); Wert mit `expose_secret()`.

### Hinzugefügt
- `Client::verify_refreshed` prüft das ID-Token eines Refresh erneut, z. B. nach `RefreshError::IdToken` mit
  `Error::KeysUnavailable`.
- `Error::status()`, `Error::is_rate_limited()` und `Error::retry_after()` für OIDC-Endpunkte und Management-API.
- Mailversand der Management-API (Scope `manage:mail.send`): `Management::mail_send` (`MailRequest` →
  `MailQueued` mit `repeated` für eine erkannte Wiederholung; leeres `to` → `Error::Config` ohne Anfrage) und `Management::mail_status` (`MailStatus`,
  `MailState`).
- `IdempotencyKey::from_parts` (stabile, kollisionsfreie Kodierung wie im TypeScript-SDK) und `IdempotencyKey::new`.

### Sicherheit
- Bestmöglich überschrieben werden nach Gebrauch die SDK-eigenen Puffer: der gelesene Antwortrumpf, der
  Formular-Body von Token- und Revoke-Endpunkt und die Zwischenwerte des `client_secret_basic`-Headers (neue direkte
  Abhängigkeit `bytes`, ohnehin über reqwest enthalten). Nicht erreichbar sind Kopien in reqwest/hyper und den
  TLS-Puffern, der Hilfspuffer von `serde_json` bei Strings mit Escapes und die fertigen `Authorization`-Header.

## [0.4.0] – 2026-10-29

### Hinzugefügt
- Ereignis `access.changed`: `AccountEvent::AccessChanged { roles, valid_until }` meldet, dass sich die Rollen oder das
  Ende der Freigabe für die Anwendung geändert haben (auch bei neu gesetzter oder verlängerter Freigabe). `roles`
  sind die sortierten Rollenschlüssel, `valid_until` der RFC-3339-Zeitstempel (`None` = unbegrenzt). Fehlerhafte
  Werte lassen das Parsen nicht scheitern: kein Array → leere Liste, Nicht-Strings entfallen, ein fehlendes oder nicht
  textuelles `validUntil` → `None` (Zeichenketten werden unverändert durchgereicht, nicht als Datum geprüft).

### Hinweis
- `AccountEvent` ist `#[non_exhaustive]`; ein `match` außerhalb des SDKs hat daher schon einen Auffangzweig und
  kompiliert weiter. Dieser Zweig fängt nun auch `AccessChanged` ab – wer Rollen in der eigenen Sitzung hält, ergänzt
  einen eigenen Zweig.

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
