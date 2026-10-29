# zwei&40 Login – Client-SDKs

[![CI](https://github.com/zweiund40GmbH/auth-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/zweiund40GmbH/auth-sdk/actions/workflows/ci.yml)
[![Secret Scan](https://github.com/zweiund40GmbH/auth-sdk/actions/workflows/secrets.yml/badge.svg)](https://github.com/zweiund40GmbH/auth-sdk/actions/workflows/secrets.yml)
[![crates.io](https://img.shields.io/crates/v/z40-auth.svg?label=crates.io%20z40-auth)](https://crates.io/crates/z40-auth)
[![docs.rs](https://img.shields.io/docsrs/z40-auth?label=docs.rs)](https://docs.rs/z40-auth)
[![npm](https://img.shields.io/npm/v/@zweiund40gmbh/auth-next.svg?label=npm%20%40zweiund40gmbh%2Fauth-next)](https://www.npmjs.com/package/@zweiund40gmbh/auth-next)
[![Lizenz](https://img.shields.io/badge/Lizenz-MIT%20OR%20Apache--2.0-blue.svg)](#lizenz)

Offizielle Bibliotheken, mit denen Anwendungen sich an **zwei&40 Login** anmelden – dem zentralen Login
(OpenID Connect / OAuth 2.1) der zwei&40 GmbH. Der Login-Server selbst ist nicht Teil dieses Repositorys.

| Sprache | Verzeichnis | Paket | Stand |
|---|---|---|---|
| Rust | [`rust/`](rust/) | [`z40-auth`](https://crates.io/crates/z40-auth) | 0.4 |
| Go | `go/` | `github.com/zweiund40GmbH/auth-sdk/go` | geplant |
| Next.js | [`js/`](js/) | [`@zweiund40gmbh/auth-next`](https://www.npmjs.com/package/@zweiund40gmbh/auth-next) | 0.3 |

Alle SDKs setzen dasselbe um: Discovery, JWKS-Cache mit Schlüsselwechsel, Login mit PKCE (S256), `state`,
`nonce` und `iss`-Prüfung, ID-Token-Prüfung, Refresh, Logout und Back-Channel-Logout. Dazu kommen
Kontoereignisse (Security Event Tokens nach RFC 8417, Push-Empfang nach RFC 8935) und ein Client der Management-API
(Umstiegs-Links, Verknüpfungen, Ereignisse nachholen). Sie speichern serverseitig
nichts selbst (das Next.js-SDK hält die Sitzung in einem verschlüsselten Cookie) und loggen keine Tokens oder
Geheimnisse.

## Versionen und Veröffentlichung

Semantic Versioning je SDK. Veröffentlicht wird ausschließlich per Workflow beim Setzen eines Tags:

| SDK | Tag | Ziel |
|---|---|---|
| Rust | `rust-vX.Y.Z` (= `version` in `rust/Cargo.toml`) | crates.io |
| Go | `go/vX.Y.Z` | Go-Modul-Proxy |
| Next.js | `js-vX.Y.Z` (= `version` in `js/package.json`) | npm |

Ablauf: Version in der Paketdatei erhöhen, committen, auf `main` pushen – der Release-Workflow des SDK
(z. B. „Release Rust“, „Release JS“) prüft, lädt das Paket hoch und setzt danach den Tag.

## Entwicklung

Voraussetzungen: Rust (Version aus `rust/rust-toolchain.toml`), Node.js 24 (`.nvmrc`) mit corepack
(`corepack enable`, danach `yarn install`), [`just`](https://github.com/casey/just).

```bash
just          # alle Rezepte
just check    # Format, Lint, Tests aller SDKs
```

Regeln für Beiträge: [`CONTRIBUTING.md`](CONTRIBUTING.md). Sicherheitslücken bitte nicht als öffentliches Issue melden,
sondern vertraulich über GitHub: Tab **Security → Report a vulnerability** ([`SECURITY.md`](SECURITY.md)).

## Lizenz

Wahlweise [MIT](LICENSE-MIT) oder [Apache-2.0](LICENSE-APACHE), nach Wahl der Nutzerin bzw. des Nutzers.
Beiträge werden, sofern nicht ausdrücklich anders vereinbart, unter denselben beiden Lizenzen angenommen.
