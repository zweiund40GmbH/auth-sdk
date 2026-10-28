# Changelog

Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionierung nach
[Semantic Versioning](https://semver.org/lang/de/).

## [0.2.0]

### Hinzugefügt
- `session.user.givenName` und `session.user.familyName` (Scope `profile`, optional) aus dem ID-Token.
  Sie fehlen, wenn der Provider sie nicht sendet oder sie leer sind.
- Bereits ausgestellte Sitzungs-Cookies aus 0.1.0 bleiben gültig (Format unverändert); die neuen Felder fehlen dort
  bis zur nächsten Anmeldung bzw. zum nächsten Refresh.

## [0.1.0]

### Hinzugefügt
- Erste Veröffentlichung: Login mit PKCE (S256), ID-Token-Prüfung, verschlüsselte Cookie-Sitzung, Refresh,
  Logout und Back-Channel-Logout für Next.js.
