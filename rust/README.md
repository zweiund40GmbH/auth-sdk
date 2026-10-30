# z40-auth (Rust-SDK)

[![crates.io](https://img.shields.io/crates/v/z40-auth.svg)](https://crates.io/crates/z40-auth)
[![docs.rs](https://docs.rs/z40-auth/badge.svg)](https://docs.rs/z40-auth)

Bibliothek für Rust-Anwendungen, die sich als **vertraulicher Client** (Server mit Client-Secret,
Backend-for-Frontend) an **zwei&40 Login**, dem zentralen Login der zwei&40 GmbH, anmelden. Die Anwendung leitet zum Login weiter,
prüft das ID-Token und stellt danach ihre **eigene** Session aus; Tokens bleiben auf dem Server.

Enthalten: Discovery, JWKS-Cache mit Schlüsselwechsel, Login mit PKCE S256, `state`, `nonce` und
`iss`-Prüfung (RFC 9207), ID-Token-Prüfung (nur RS256/ES256), Refresh, UserInfo, Revoke, Logout-URL,
Back-Channel-Logout und die Prüfung von Access-Tokens (RFC 9068) für Ressourcen-Server. Feature `axum`:
Extraktoren für Callback und Back-Channel-Logout. Dazu **Kontoereignisse** (Security Event Tokens nach RFC 8417,
Push nach RFC 8935) und ein Client der **Management-API** (Umstiegs-Links, Verknüpfungen, Ereignisse nachholen).
Das SDK speichert nichts – den `LoginState` zwischen
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
            // Mit Scope `profile`: login.claims.name (Anzeigename) sowie given_name / family_name
            // (Option, nur wenn gepflegt; leere Werte werden zu None)
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

## Kontoereignisse empfangen

Zwischen zwei Anmeldungen erfährt die Anwendung Änderungen an Konten (neue E-Mail-Adresse, Namen, Sperre,
entzogene Freigabe, aufgehobene Verknüpfung, angenommener Umstiegs-Link) als signiertes Ereignis
(`typ: secevent+jwt`), das der Provider per `POST` an die eingetragene Ereignis-URI schickt.
`receive_event` prüft Signatur (JWKS), `typ`, `iss`, `aud` (= Client-ID), `exp`/`iat` und genau ein
`urn:z40:event:`-Ereignis, verwirft bereits verarbeitete `jti` und antwortet nach RFC 8935
(`202`, `400` mit `{"err", "description"}`, `503` bei nicht ladbaren Schlüsseln, `500`, wenn der eigene Handler
scheitert – der Provider wiederholt dann).

```rust,ignore
use axum::{body::Bytes, extract::State, http::{HeaderMap, header}, response::IntoResponse};
use z40_auth::{AccountEvent, MemoryJtiStore, SecurityEvent};

async fn events(State(app): State<App>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    let content_type = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok());
    app.auth
        .receive_event(content_type, &body, &app.jti_store, |e: SecurityEvent| async move {
            match e.event {
                AccountEvent::EmailChanged { email, email_verified } => update_email(e.sub, email, email_verified).await,
                AccountEvent::AccessRevoked { .. } | AccountEvent::UserDisabled => block_user(e.sub).await,
                AccountEvent::LinkRemoved { local_id } => remove_link(e.sub, local_id).await,
                _ => Ok(()), // unbekannte Typen ignorieren
            }
        })
        .await // PushResponse; mit Feature `axum` direkt als Antwort nutzbar
}
```

- Ereignisse kommen **mindestens einmal**. Der `JtiStore` (eigene Implementierung, von allen Instanzen geteilt,
  z. B. Datenbanktabelle oder Redis) merkt sich verarbeitete `jti` für `JTI_TTL` (31 Tage). `MemoryJtiStore`
  nur für Tests und Anwendungen mit genau einer Instanz. Handler idempotent halten.
- Unbekannte Ereignistypen kommen als `AccountEvent::Unknown` an und werden ignoriert, unbekannte Felder ebenso.
- `access.revoked` trägt optional `reason` (z. B. `expired`, wenn die Freigabe abgelaufen ist); weitere Werte können
  hinzukommen, daher als `Option<String>` und nicht als festes Enum.
- `access.changed` kommt, wenn sich die Rollen oder das Ende der Freigabe für die Anwendung ändern (auch bei neu
  gesetzter oder verlängerter Freigabe). `AccountEvent::AccessChanged { roles, valid_until }` trägt die aktuellen
  Werte: `roles` sind die sortierten Rollenschlüssel der Anwendung, `valid_until` ist der Zeitstempel (RFC 3339)
  unverändert als `Option<String>`, `None` = unbegrenzt. Das SDK ist hier tolerant: fehlt `roles` oder ist es kein
  Array, ist die Liste leer, Einträge, die keine Strings sind, entfallen; ein fehlendes, auf `null` gesetztes oder
  nicht textuelles `validUntil` ergibt `None`. Entfernt die Änderung Rollen, beendet der Provider zusätzlich die Sitzungen
  des Benutzers in der Anwendung per Back-Channel-Logout; wer Rollen in der eigenen Sitzung hält, aktualisiert sie
  bei `access.changed`.
- `SecurityEvent::env` (`production` oder `test`) reicht das SDK nur durch; wer Test- und Produktivereignisse
  sicher trennen will, vergleicht es mit der eigenen Umgebung.
- Nur prüfen ohne Dublettenprüfung: `client.verify_security_event(&token)`.

## Management-API

`Management` holt per Client Credentials ein Token (ohne `scope` = alle für die Anwendung freigeschalteten
`manage:*`-Scopes; `with_scopes` schränkt ein), hält es bis kurz vor Ablauf und erneuert es nach einem `401`.
Fehler kommen als `Error::Api(ApiError { status, code, message, fields, retry_after })`.

```rust,ignore
use std::sync::Arc;
use z40_auth::{LinkReport, Management, NewOnboarding};

let mgmt = Management::new(Arc::clone(&auth))?;

// Umstiegs-Link anfordern (Scope manage:onboarding); X-On-Behalf-Of nur fürs Audit.
let mut req = NewOnboarding::new("lena@example.com", "4711");
req.given_name = Some("Lena".into());
let link = mgmt.on_behalf_of("17")?.create_onboarding(&req).await?;
save_onboarding_id("4711", &link.id);

// Stand abfragen, erneut senden, zurückziehen
let state = mgmt.onboarding(&link.id).await?; // state.status, state.sub nach dem Annehmen
mgmt.resend_onboarding(&link.id, true).await?;
mgmt.revoke_onboarding(&link.id).await?;

// Verknüpfungen lesen (maßgeblich) und bestehende melden (1–500 je Aufruf, idempotent)
let links = mgmt.user_links(&sub).await?;
let reported = mgmt
    .report_links(&[LinkReport { sub: sub.clone(), local_id: "4711".into() }])
    .await?; // reported.linked, reported.ignored
```

Ids (`localId`, Onboarding-Id, `sub`) dürfen nicht leer, `.` oder `..` sein – sonst `Error::Config`, ohne Anfrage.

Mit `send_mail = false` enthält die Antwort `url` – nur an den Benutzer weitergeben, für den der Link angefordert
wurde, und nie loggen (`Debug` schwärzt sie).

**Ereignisse nachholen** (Scope `manage:events.read`, z. B. nach einem Ausfall oder statt Push):

```rust,ignore
let mut pages = mgmt.event_pages(load_cursor());
while let Some(page) = pages.next().await? {
    if page.gap {
        // Ereignisse wurden schon gelöscht (Aufbewahrung 30 Tage): Benutzer vollständig abgleichen.
        full_resync(&mgmt).await?;
    }
    for e in &page.items {
        if !jti_store.seen(&e.jti).await? {
            apply(&e.sub, &e.event).await?;
            jti_store.remember(&e.jti, z40_auth::events::JTI_TTL).await?;
        }
    }
    save_cursor(&page.next_cursor);
}
```

Push und Nachholen liefern dasselbe Ereignis mit derselben `jti`; ein gemeinsamer `JtiStore` verhindert doppelte
Verarbeitung. Ein Ereignis bekannten Typs mit unlesbaren Daten kommt beim Nachholen als `AccountEvent::Unknown` mit den
Rohdaten an, statt das Nachholen dauerhaft zu blockieren. Meldet der Provider `hasMore` ohne neuen Cursor, endet
`next()` mit `Error::InvalidResponse`.

**Nach `gap: true` vollständig abgleichen** über `users` (Scope `manage:users.read`, alle Benutzer mit Freigabe,
auch abgelaufener, sortiert nach E-Mail-Adresse):

```rust,ignore
use z40_auth::UsersQuery;

async fn full_resync(mgmt: &z40_auth::Management) -> z40_auth::Result<()> {
    let mut page_no = 1;
    loop {
        let page = mgmt.users(&UsersQuery::page(page_no, 200)).await?;
        for user in &page.items {
            sync_user(user); // sub, email, Namen, status, roles, valid_until
        }
        if u64::from(page_no) * 200 >= page.total { return Ok(()); }
        page_no += 1;
    }
}
```

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
  beenden. `403` kommt als `Error::OAuth { error: "insufficient_scope", status: 403, .. }`.
- **Zu viele Anfragen:** `429` des Token-, Revoke- oder UserInfo-Endpunkts kommt immer als
  `Error::RateLimited { retry_after }` (Sekunden aus `Retry-After`), auch wenn der Rumpf `invalid_grant` nennt. Das
  Token wurde dabei nicht verbraucht: Sitzung behalten und später erneut versuchen. Nur `Error::OAuth` mit
  `error: "invalid_grant"` (Status `400`) heißt: Anmeldung beendet. `Error::status()`, `Error::is_rate_limited()`
  und `Error::retry_after()` gelten für OIDC-Endpunkte und Management-API gleichermaßen.
- `Error` ist für Entscheidungen gedacht (`StateMismatch`, `Token(..)`, `OAuth { error: "invalid_grant", .. }` …),
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
