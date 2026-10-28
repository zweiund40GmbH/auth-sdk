# Changelog

Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionierung nach
[Semantic Versioning](https://semver.org/lang/de/).

## [0.2.0]

### Hinzugefügt
- `IdClaims` und `UserInfo` enthalten `given_name` und `family_name` (Scope `profile`, je `Option<String>`).
  Leere Zeichenketten werden defensiv wie fehlende Werte als `None` gelesen.

## [0.1.0]

### Hinzugefügt
- Erste Veröffentlichung: Discovery, JWKS-Cache, Login mit PKCE (S256), ID-Token-Prüfung, Refresh, Logout,
  Back-Channel-Logout, UserInfo und axum-Integration.
