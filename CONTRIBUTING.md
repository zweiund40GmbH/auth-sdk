# Beiträge – zwei&40 Login, Client-SDKs

Regeln für alle Beiträge zu diesem Repository. Es ist **öffentlich**; der Login-Server ist es nicht.

## 1. Öffentlich heißt: nichts Internes

- Keine Interna: keine internen Hostnamen, Server-IPs, Kunden- oder Projektnamen, Personennamen, E-Mail-Adressen,
  Pfade oder Befehle des Servers, Verweise auf private Repositories oder interne Dokumente.
- Beispiele nur mit `example.com` (`login.example.com`, `app.example.com`, Client-ID `my-app`).
- Keine Geheimnisse, Tokens oder echten Schlüssel – auch nicht in Tests (Testschlüssel werden zur Laufzeit erzeugt).
- Das SDK beschreibt nur das öffentliche Protokoll (OIDC Discovery, JWKS, die dokumentierten Endpunkte).

## 2. Code

- Kommentare und API-Doku englisch; README und Anleitungen deutsch mit Umlauten (ä, ö, ü, ß – nie ae/oe/ue).
- Kleine Dateien (< ~300 Zeilen), jede öffentliche Funktion dokumentiert, neue Logik mit Tests.
- Sicherheit: nur PKCE S256, `state`/`nonce`/`iss` immer prüfen, nur RS256/ES256, HTTPS (Ausnahme Loopback),
  keine Weiterleitungen beim HTTP-Client, Tokens und Secrets nie loggen, `Debug` schwärzt sie.
- Rust (`rust/`): kein `unwrap`/`expect` außerhalb von Tests, `missing_docs` = Fehler, `thiserror`,
  `clippy -D warnings`, `cargo-deny`, Toolchain fest in `rust-toolchain.toml`, `Cargo.lock` committen.
- Neue Abhängigkeit nur mit Begründung im Commit; nur permissive Lizenzen (siehe `rust/deny.toml`).

## 3. Git und Veröffentlichung

- `main` ist der Standard-Branch. Commit-Nachrichten deutsch, Imperativ, eine logische Änderung je Commit.
- Commits im Namen der verantwortlichen Person, ohne Werkzeug-Hinweise oder zusätzliche Trailer in der Nachricht.
- Veröffentlicht wird nur per Workflow (Tag aus der Paketversion, siehe README). Nie von Hand `cargo publish`/
  `npm publish`. Feste Tags werden nie bewegt; ein Fehler wird mit einer neuen Patch-Version behoben.
- Keine destruktiven Git-Operationen ohne ausdrücklichen Auftrag.

## 4. Qualitätstor

```bash
just check   # = rust-check (fmt, clippy -D warnings mit allen Features, Tests) + lines
```

CI ruft dieselben Rezepte auf; dazu `cargo-deny` und ein Secret-Scan (gitleaks).
