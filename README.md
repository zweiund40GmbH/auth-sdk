# zwei&40 Login – Client-SDKs

[![CI](https://github.com/zweiund40GmbH/auth-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/zweiund40GmbH/auth-sdk/actions/workflows/ci.yml)
[![Secret Scan](https://github.com/zweiund40GmbH/auth-sdk/actions/workflows/secrets.yml/badge.svg)](https://github.com/zweiund40GmbH/auth-sdk/actions/workflows/secrets.yml)
[![crates.io](https://img.shields.io/crates/v/z40-auth.svg)](https://crates.io/crates/z40-auth)

Offizielle Bibliotheken, mit denen Anwendungen sich an **zwei&40 Login** anmelden – dem zentralen Login
(OpenID Connect / OAuth 2.1) der zwei&40 GmbH. Der Login-Server selbst ist nicht Teil dieses Repositorys.

| Sprache | Verzeichnis | Paket | Stand |
|---|---|---|---|
| Rust | [`rust/`](rust/) | [`z40-auth`](https://crates.io/crates/z40-auth) | 0.1 |
| Go | `go/` | `github.com/zweiund40GmbH/auth-sdk/go` | geplant |
| Next.js | `js/` | `@zweiund40gmbh/auth-next` (npm) | geplant |

Alle SDKs setzen dasselbe um: Discovery, JWKS-Cache mit Schlüsselwechsel, Login mit PKCE (S256), `state`,
`nonce` und `iss`-Prüfung, ID-Token-Prüfung, Refresh, Logout und Back-Channel-Logout. Sie speichern nichts
selbst und loggen keine Tokens oder Geheimnisse.

## Versionen und Veröffentlichung

Semantic Versioning je SDK. Veröffentlicht wird ausschließlich per Workflow beim Setzen eines Tags:

| SDK | Tag | Ziel |
|---|---|---|
| Rust | `rust-vX.Y.Z` (= `version` in `rust/Cargo.toml`) | crates.io |
| Go | `go/vX.Y.Z` | Go-Modul-Proxy |
| Next.js | `js-vX.Y.Z` | npm |

Ablauf: Version in der Paketdatei erhöhen, committen, auf `main` pushen – der Release-Workflow des SDK
(z. B. „Release Rust“) prüft, lädt das Paket hoch und setzt danach den Tag.

## Entwicklung

```bash
just          # alle Rezepte
just check    # Format, Lint, Tests aller SDKs
```

Regeln für Beiträge: [`AGENTS.md`](AGENTS.md). Sicherheitslücken bitte nicht als öffentliches Issue melden,
sondern vertraulich über GitHub: Tab **Security → Report a vulnerability** ([`SECURITY.md`](SECURITY.md)).

## Lizenz

Wahlweise [MIT](LICENSE-MIT) oder [Apache-2.0](LICENSE-APACHE), nach Wahl der Nutzerin bzw. des Nutzers.
Beiträge werden, sofern nicht ausdrücklich anders vereinbart, unter denselben beiden Lizenzen angenommen.
