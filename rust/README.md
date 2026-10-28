# z40-auth (Rust-SDK)

[![crates.io](https://img.shields.io/crates/v/z40-auth.svg)](https://crates.io/crates/z40-auth)
[![docs.rs](https://docs.rs/z40-auth/badge.svg)](https://docs.rs/z40-auth)

Bibliothek für Rust-Anwendungen, die sich als **vertraulicher Client** (Server mit Client-Secret,
Backend-for-Frontend) an **zwei&40 Login**, dem zentralen Login der zwei&40 GmbH, anmelden. Die Anwendung leitet zum Login weiter,
prüft das ID-Token und stellt danach ihre **eigene** Session aus; Tokens bleiben auf dem Server.

Enthalten: Discovery, JWKS-Cache mit Schlüsselwechsel, Login mit PKCE S256, `state`, `nonce` und
`iss`-Prüfung (RFC 9207), ID-Token-Prüfung (nur RS256/ES256), Refresh, UserInfo, Revoke, Logout-URL,
Back-Channel-Logout und die Prüfung von Access-Tokens (RFC 9068) für Ressourcen-Server. Feature `axum`:
Extraktoren für Callback und Back-Channel-Logout. Das SDK speichert nichts – den `LoginState` zwischen
Weiterleitung und Callback hält die Anwendung (serverseitig oder in einem verschlüsselten `HttpOnly`-Cookie).

## Einbinden

```bash
cargo add z40-auth --features axum
```

Mindestversion von Rust: 1.94. Client-ID, Client-Secret und Redirect-URIs vergibt die Administration von
zwei&40 Login.

## Beispiel (axum)

```rust,ignore
use axum::{Router, extract::State, http::StatusCode, routing::{get, post}};
use axum::response::{IntoResponse, Redirect, Response};
use std::sync::Arc;
use z40_auth::axum::{Callback, LogoutToken, logout_response};
use z40_auth::{Client, ClientSecret, LoginState};

#[derive(Clone)]
struct App {
    auth: Arc<Client>,
}

const REDIRECT_URI: &str = "https://app.example.com/auth/callback";

/// Startet den Login: LoginState merken (hier nur angedeutet), dann weiterleiten.
async fn login(State(app): State<App>) -> Response {
    let Ok(req) = app.auth.begin_login(REDIRECT_URI, &["profile", "email"], &[]) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    save_login_state(&req.state); // z. B. serverseitig, Schlüssel in einem HttpOnly-Cookie
    Redirect::to(req.url.as_str()).into_response()
}

/// Callback: prüft state, iss, Code-Tausch und ID-Token; danach eigene Session anlegen.
async fn callback(State(app): State<App>, Callback(params): Callback) -> Response {
    let Some(state) = load_login_state() else { return Redirect::to("/login").into_response() };
    match app.auth.complete_login(&state, &params).await {
        Ok(login) => {
            // login.claims.sub = stabile Benutzer-ID, login.claims.sid für den Back-Channel-Logout merken;
            // den LoginState jetzt löschen (einmalig verwendbar)
            create_session(&login.claims.sub, login.claims.sid.as_deref());
            Redirect::to("/").into_response()
        }
        Err(_) => Redirect::to("/login?fehler=1").into_response(),
    }
}

/// Back-Channel-Logout: alle lokalen Sessions mit dieser sid (bzw. dieses sub) beenden.
async fn backchannel(State(app): State<App>, LogoutToken(token): LogoutToken) -> Response {
    match app.auth.verify_backchannel_logout(&token).await {
        Ok(event) => {
            end_sessions(event.sub.as_deref(), event.sid.as_deref());
            logout_response(true)
        }
        Err(_) => logout_response(false),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = ClientSecret::new(std::env::var("AUTH_CLIENT_SECRET")?);
    let auth = Client::discover("https://login.example.com", "my-app", secret).await?;
    let app = Router::new()
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/backchannel-logout", post(backchannel))
        .with_state(App { auth: Arc::new(auth) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

Abmelden: lokale Session beenden, dann zu `client.logout_url(Some(&id_token), Some(post_logout_uri), None)`
weiterleiten (die Rücksprungadresse muss exakt registriert sein).

## Hinweise

- **`LoginState`** nur kurz aufbewahren (z. B. 10 Minuten) und **einmal** verwenden: beim Callback sofort
  löschen, egal wie er ausgeht. Das SDK prüft sein Alter nicht.
- **`max_age`, `prompt=login`, `acr_values`** (als `extra` an `begin_login`) werden im `LoginState` vermerkt und
  von `complete_login` erzwungen – auch wenn der Browser sie aus der URL entfernt: `TokenError::AuthTooOld`
  bzw. `TokenError::InsufficientAcr`. Für eine sensible Aktion mit zweitem Faktor also
  `&[("acr_values", "urn:z40:mfa")]` übergeben und bei `InsufficientAcr` den Zugriff verweigern.
- **Refresh:** `client.refresh(&refresh_token, Some(&sub))` – mit dem `sub` der Anmeldung lehnt das SDK ein
  ID-Token für einen anderen Benutzer ab (`TokenError::WrongSubject`). Das neue Refresh-Token ersetzt das alte.
- **UserInfo:** `Error::Unauthorized` (`401`) heißt: Token ungültig, abgelaufen oder widerrufen – lokale Session
  beenden. `403` kommt als `Error::OAuth { error: "insufficient_scope" }`.
- `Error` ist für Entscheidungen gedacht (`StateMismatch`, `Token(..)`, `OAuth { error: "invalid_grant" }` …),
  nicht zur Anzeige. Benutzer sehen eine deutsche Fehlerseite der Anwendung.
- Tokens und das Client-Secret nie loggen; `Debug` der SDK-Typen schwärzt sie.
- `verify_access_token` sieht keine Widerrufe (Access-Tokens leben etwa 5 Minuten).

### Signaturschlüssel (JWKS)

- Schlüssel gelten 5 Minuten als frisch; danach lädt die nächste Prüfung das JWKS neu, nicht mehr veröffentlichte
  Schlüssel fallen dabei weg. Eine unbekannte `kid` löst einen neuen Abruf aus (höchstens alle 30 s,
  `Options::jwks_min_refetch`). Es läuft immer nur ein Abruf; Prüfungen mit bekanntem Schlüssel warten nicht darauf.
- Ist der Provider nicht erreichbar, bleiben die alten Schlüssel noch **10 Minuten** nutzbar
  (`Options::jwks_max_stale`, `Duration::ZERO` = sofort ablehnen), danach `Error::KeysUnavailable`.
- **Notfall** (der Provider hat einen geleakten Schlüssel zurückgezogen): auf jeder Instanz `client.refresh_keys()`
  aufrufen (z. B. über einen internen Admin-Endpunkt). Das lädt das JWKS sofort neu, ohne Rate-Limit, und verwirft
  widerrufene Schlüssel; schlägt der Abruf fehl, werden **alle** Schlüssel verworfen (Prüfungen schlagen fehl, bis
  das JWKS wieder erreichbar ist). Alternativ den Prozess neu starten.

### Betrieb

- TLS nutzt den CA-Speicher des Systems: das Laufzeit-Image braucht `ca-certificates` (bei `distroless`/`scratch`
  mitliefern).
- Proxys aus `HTTPS_PROXY`/`NO_PROXY` gelten. Weiterleitungen folgt der eingebaute HTTP-Client nicht.
- Eigener `reqwest::Client` über `Options::http_client` nur mit Zeitlimits und **ohne** Weiterleitungen
  (`redirect::Policy::none()`) – eine Weiterleitung könnte Client-Secret, Codes oder Tokens an einen fremden Host
  schicken.

Entwicklung: `just rust-check` im Repository-Wurzelverzeichnis.

## Lizenz

Wahlweise [MIT](LICENSE-MIT) oder [Apache-2.0](LICENSE-APACHE).
