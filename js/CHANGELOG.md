# Changelog

Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionierung nach
[Semantic Versioning](https://semver.org/lang/de/).

## [0.4.0] – 2026-10-30

### Hinzugefügt
- Mailversand für Anwendungen (Scope `manage:mail.send`): `management.mail.send({ to, subject, text, html?,
  replyTo?, idempotencyKey })` → `{ id, status, recipients, repeated }` (`repeated: true` = Wiederholung mit `200`,
  nichts wurde erneut eingereiht) und `management.mail.status(id)` → `{ id, status, recipients, sent, failed,
  pending, createdAt }`. Fehler wie bei allen Management-Aufrufen als `ManagementError` (`409 mail_disabled`,
  `409 idempotency_conflict`, `413`, `422` mit `fields`, `429` mit `retryAfter`).
- `mailIdempotencyKey(...teile)` bildet aus eigenen Ids einen stabilen, kollisionsfreien Idempotenzschlüssel
  (`[A-Za-z0-9._:-]`, höchstens 100 Zeichen): Teile als UTF-8, die Bytes `A–Z a–z 0–9 . -` bleiben, alle anderen
  werden zu `_` plus zwei Hexziffern, Verbindung mit `:`. Gleiche Teile ergeben immer denselben Schlüssel.

### Geändert
- Token-Refresh verwirft rotierte Tokens nicht mehr, wenn die Signaturschlüssel für die Prüfung des neuen ID-Tokens
  nicht erreichbar sind (Zeitüberschreitung, Netzwerkfehler, `429`, `5xx`): Die Session bekommt die neuen Tokens, das
  ID-Token wartet als `SessionData.pendingIdToken` und wird bei einer späteren Anfrage geprüft (Wiederholung
  frühestens nach 10 Sekunden). Nur ein endgültiges Urteil (anderer `sub`, ungültige Signatur oder Claims) beendet die
  Session. Bis zur Prüfung bleiben `claims` und `idToken` (`id_token_hint`) die des vorherigen ID-Tokens. Die
  nachgeholte Prüfung beurteilt `exp` und `iat` zum Empfangszeitpunkt (`SessionData.pendingIdTokenReceivedAt`), mit
  derselben Toleranz wie eine sofortige Prüfung: Ein kurzlebiges ID-Token (z. B. 60 s bei 300 s Access-Token) läuft
  während des Ausfalls nicht ab, ein schon beim Empfang abgelaufenes bleibt abgelehnt. Passt die Session mit dem
  wartenden ID-Token nicht mehr in die Cookies (6000 Byte), endet sie wie jede zu große Session.
- `mailIdempotencyKey` lehnt ein leeres Ergebnis und Teile mit einzelnen UTF-16-Surrogaten ab (`AuthError`, Code
  `config`), wie das Rust-SDK bzw. weil sie sonst kollidieren würden.
- Release: Veröffentlichung per npm Trusted Publishing (OIDC) statt `NPM_TOKEN`.

### Hinweis
- Keine Brüche der öffentlichen API. `SessionData` (Inhalt des Session-Cookies, nur serverseitig) hat die neuen
  optionalen Felder `pendingIdToken` und `pendingIdTokenReceivedAt`; ältere Cookies bleiben lesbar, ein Cookie mit den neuen Feldern wird von 0.3.0
  gelesen, die Felder dort aber ignoriert (die Prüfung des ID-Tokens entfällt dann).

## [0.3.0] – 2026-10-29

### Hinzugefügt
- Ereignis `access.changed`: `{ type: "access.changed"; roles: string[]; validUntil: string | null }` in
  `AccountEvent` meldet, dass sich die Rollen oder das Ende der Freigabe für die Anwendung geändert haben (auch bei neu
  gesetzter oder verlängerter Freigabe). `roles` sind die sortierten Rollenschlüssel, `validUntil` der
  RFC-3339-Zeitstempel (`null` = unbegrenzt). Fehlerhafte Werte lassen das Parsen nicht scheitern: kein Array →
  `[]`, Nicht-Strings entfallen, ein fehlendes oder nicht textuelles
  `validUntil` → `null` (Zeichenketten werden unverändert durchgereicht, nicht als Datum geprüft).

### Hinweis
- Die Union `AccountEvent` hat ein neues Mitglied; ein `switch` mit `never`-Prüfung im `default` muss es behandeln.

## [0.2.0]

### Hinzugefügt
- `session.user.givenName` und `session.user.familyName` (Scope `profile`, optional) aus dem ID-Token.
  Sie fehlen, wenn der Provider sie nicht sendet oder sie leer sind.
- Kontoereignisse: `createEventsHandler({ onEvent, store })` als Route-Handler für die Ereignis-URI (Security Event
  Tokens nach RFC 8417, Push nach RFC 8935): prüft Signatur, `typ: secevent+jwt`, `iss`, `aud`, `exp`/`iat` und das
  Ereignis, verwirft bereits verarbeitete `jti` und antwortet `202`/`400` (mit RFC-8935-Fehlercode)/`500`/`503`.
  Typen `AccountEvent` (alle Ereignistypen des Vertrags, `access.revoked` mit optionalem `reason`, `unknown` für
  künftige Typen) und `SecurityEvent`.
- Management-API: `createManagementClient()` mit Client-Credentials-Token-Cache, `onBehalfOf`, Umstiegs-Links
  (`createOnboarding`, `getOnboarding`, `revokeOnboarding`, `resendOnboarding`), Verknüpfungen (`reportLinks`,
  `userLinks`), Benutzerliste für den Abgleich nach `gap: true` (`users`) und Ereignisse nachholen (`events`,
  `eventPages` mit `gap`); Fehler als `ManagementError`.
- Bereits ausgestellte Sitzungs-Cookies aus 0.1.0 bleiben gültig (Format unverändert); die neuen Felder fehlen dort
  bis zur nächsten Anmeldung bzw. zum nächsten Refresh.

## [0.1.0]

### Hinzugefügt
- Erste Veröffentlichung: Login mit PKCE (S256), ID-Token-Prüfung, verschlüsselte Cookie-Sitzung, Refresh,
  Logout und Back-Channel-Logout für Next.js.
