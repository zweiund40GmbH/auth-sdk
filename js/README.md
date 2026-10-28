# @zweiund40gmbh/auth-next (Next.js-SDK)

[![npm](https://img.shields.io/npm/v/@zweiund40gmbh/auth-next.svg)](https://www.npmjs.com/package/@zweiund40gmbh/auth-next)

Bibliothek für Next.js-Anwendungen (App Router), die sich als **vertraulicher Client** (Server mit Client-Secret,
Backend-for-Frontend) an **zwei&40 Login**, dem zentralen Login der zwei&40 GmbH, anmelden. Die Anwendung leitet
zum Login weiter, prüft das ID-Token und hält die Sitzung in einem **verschlüsselten `HttpOnly`-Cookie**. Tokens
bleiben auf dem Server – der Browser sieht sie nie.

Enthalten: Route-Handler für Login, Callback, Logout (RP-initiated) und Back-Channel-Logout, `getSession()` und
`getAccessToken()` für Server Components, Route Handler und Server Actions, ein Proxy (Middleware) für
Token-Refresh und geschützte Pfade sowie `withAuth()` für API-Routen. Grundlage sind
[`openid-client`](https://github.com/panva/openid-client) 6 und [`jose`](https://github.com/panva/jose) 6.

## Einbinden

```bash
yarn add @zweiund40gmbh/auth-next   # oder: npm install @zweiund40gmbh/auth-next
```

Voraussetzungen: Next.js ab 15 (getestet mit 16), Node.js ab 20.19. Client-ID, Client-Secret und Redirect-URIs
vergibt die Administration von zwei&40 Login. Zu registrieren sind:

| Was | Wert (Beispiel) |
|---|---|
| Redirect-URI | `https://app.example.com/auth/callback` |
| Post-Logout-Redirect-URI | `https://app.example.com/` |
| Back-Channel-Logout-URI | `https://app.example.com/auth/backchannel-logout` |

## Konfiguration

Umgebungsvariablen (Optionen von `createAuth` haben Vorrang):

| Variable | Pflicht | Bedeutung |
|---|---|---|
| `AUTH_ISSUER` | ja | Issuer, exakt wie im Discovery-Dokument, z. B. `https://login.example.com` |
| `AUTH_CLIENT_ID` | ja | Client-ID, z. B. `my-app` |
| `AUTH_CLIENT_SECRET` | ja | Client-Secret |
| `AUTH_REDIRECT_URI` | ja | Registrierte Redirect-URI; muss auf `<basePath>/callback` zeigen (Standard `/auth/callback`) |
| `AUTH_POST_LOGOUT_REDIRECT_URI` | nein | Registrierte Rücksprungadresse nach dem Logout |
| `AUTH_SESSION_SECRET` | ja | Schlüsselmaterial für die Cookie-Verschlüsselung, mindestens 32 Zeichen, z. B. `openssl rand -base64 32` |
| `AUTH_SESSION_SECRET_PREVIOUS` | nein | Frühere Werte von `AUTH_SESSION_SECRET`, kommagetrennt, je mindestens 32 Zeichen; nur zum Entschlüsseln |

Weitere Optionen (nur im Code): `scopes` (Standard `openid profile email offline_access`), `basePath`
(`/auth`), `cookieName` (`auth`), `sessionMaxAge` (Sekunden, Standard 8 Stunden), `tokenEndpointAuthMethod`
(`client_secret_basic` oder `client_secret_post`), `sessionStore`, `errorPath`, `logger`, `allowInsecureLoopback`.

Geprüft wird beim ersten Aufruf und bei `auth.validate()`; eine ungültige Konfiguration lässt **jeden** Aufruf
scheitern (fail closed). Issuer und Redirect-URIs müssen HTTPS nutzen. Klartext-HTTP zu Loopback-Hosts
(`localhost`, `127.0.0.1`, `[::1]`) für die lokale Entwicklung erlaubt nur die Option
`allowInsecureLoopback: true`, und auch dann nur, wenn `NODE_ENV` in der Prozessumgebung gesetzt und nicht
`production` ist:

```ts
export const auth = createAuth({ allowInsecureLoopback: process.env.NODE_ENV === "development" });
```

## Beispiel

```ts
// lib/auth.ts
import { createAuth } from "@zweiund40gmbh/auth-next";
import { redisSessionStore } from "./session-store";

export const auth = createAuth({ sessionStore: redisSessionStore, errorPath: "/anmeldung-fehlgeschlagen" });
```

```ts
// app/auth/[action]/route.ts – login, callback, logout, backchannel-logout
import { auth } from "@/lib/auth";

export const { GET, POST } = auth.handlers;
```

```ts
// proxy.ts (Next.js 16; bis Next.js 15: middleware.ts mit `export default`)
import { auth } from "@/lib/auth";

export default auth.proxy({ protect: ["/konto", "/admin"] }); // ohne protect: alle Pfade
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
```

```ts
// instrumentation.ts – Konfiguration und Provider beim Start prüfen
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { auth } = await import("@/lib/auth");
    await auth.validate();
  }
}
```

```tsx
// app/konto/page.tsx (Server Component)
import { auth } from "@/lib/auth";
import { redirect } from "next/navigation";

export default async function Konto() {
  const session = await auth.getSession();
  if (!session) redirect(auth.loginUrl("/konto"));
  return (
    <>
      <p>Angemeldet als {session.user.name}</p>
      <form method="post" action="/auth/logout">
        <button>Abmelden</button>
      </form>
    </>
  );
}
```

```ts
// app/api/daten/route.ts – API-Route mit Session, Access-Token für einen nachgelagerten Dienst
import { auth } from "@/lib/auth";

export const GET = auth.withAuth(async (_request, _context, session) => {
  const token = await auth.getAccessToken();
  return Response.json({ sub: session.user.sub, hasToken: token !== null });
});
```

- **Login:** Link auf `auth.loginUrl("/ziel")` (= `/auth/login?returnTo=%2Fziel`). `returnTo` wird nur als
  relativer Pfad auf dem eigenen Origin angenommen; alles andere (`https://…`, `//host`, `/\host`,
  Steuerzeichen) führt auf `/`.
- **Logout** nur per `POST` aus einem Formular der Anwendung: `Origin` muss der Origin der Anwendung sein, ohne
  `Origin` muss `Sec-Fetch-Site: same-origin` vorliegen; sonst `403` (auch wenn beide Header fehlen, etwa bei sehr
  alten Browsern), `GET` → `405`. Das SDK
  löscht die Session und leitet mit `id_token_hint` zum End-Session-Endpunkt des Providers weiter.
- **Erhöhte Anmeldung** (zweiter Faktor, frische Anmeldung) über einen eigenen Route Handler:

  ```ts
  // app/auth/stufe-2/route.ts
  export const GET = (request: Request) =>
    auth.login(request, { acrValues: ["urn:z40:mfa"], returnTo: "/admin" });
  ```

  `prompt: "login"`, `maxAge` und `acrValues` werden im verschlüsselten Login-State vermerkt und beim Callback
  gegen `auth_time` bzw. `acr` des ID-Tokens **erzwungen**, auch wenn der Browser sie aus der URL entfernt. Für
  die sensible Aktion trotzdem `session.acr` prüfen.

## Sitzung und Cookies

- **Session-Cookie** `__Host-auth.session` (bei HTTP-Loopback ohne Präfix): JWE mit `dir` + `A256GCM`, Schlüssel per
  HKDF-SHA-256 aus `AUTH_SESSION_SECRET` abgeleitet; `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`. Enthält ID-,
  Access- und Refresh-Token sowie die geprüften Claims. Laufzeit absolut `sessionMaxAge`, auch im verschlüsselten
  Inhalt geprüft. Ab 3000 Byte verteilt das SDK es auf zwei Cookies (`.1`); mehr als 6000 Byte nimmt es nicht an,
  damit der `Cookie`-Header deutlich unter 8 KiB bleibt. Eine größere Session lässt den Login mit
  `session_too_large` scheitern (mit Warnung im Log) – dann weniger Scopes anfordern.
- **Login-State** `__Host-auth.login.<state>`: eigenes verschlüsseltes Cookie je laufender Anmeldung (mehrere Tabs
  stören sich nicht), 10 Minuten gültig, beim Callback in jedem Fall gelöscht (einmalig verwendbar). Es
  enthält `state`, `nonce`, PKCE-Verifier, `returnTo` und die Anforderungen. Mehr als drei offene Anmeldungen
  verwerfen alle offenen.
- **Secret wechseln:** neues Secret in `AUTH_SESSION_SECRET`, das alte in `AUTH_SESSION_SECRET_PREVIOUS`. Das SDK
  entschlüsselt erst mit dem neuen, dann mit den alten Secrets und verschlüsselt immer mit dem neuen; Sessions
  werden beim nächsten Schreiben (Refresh) umgeschlüsselt. Das alte Secret nach `sessionMaxAge` entfernen – danach
  sind noch damit verschlüsselte Cookies ungültig. Bei einem kompromittierten Secret **nicht** als vorheriges
  Secret eintragen, sondern alle Benutzer abmelden lassen.
- `SameSite=Lax` ist nötig, weil der Rücksprung vom Provider eine seitenübergreifende Navigation ist.
- `getSession()` liefert ein `Session`-Objekt **ohne Tokens** (Benutzer, `sid`, `acr`, `amr`, `authTime`, `env`,
  Scopes, Ablauf) – es darf an Client Components weitergegeben werden. `getAccessToken()` gibt das Access-Token nur
  serverseitig heraus; nie an den Browser geben.

## Token-Refresh

Ein Access-Token, das in weniger als 60 Sekunden abläuft, wird mit dem Refresh-Token erneuert (Scope
`offline_access`). Das Refresh-Token rotiert; ein neues ID-Token muss denselben `sub` tragen und darf kein
`nonce` haben, sonst endet die Session.

Wie ein gescheiterter Refresh wirkt:

| Antwort des Token-Endpunkts | Folge |
|---|---|
| `400` mit `error=invalid_grant` (Refresh-Token widerrufen, abgelaufen, wiederverwendet) | Session endet, Cookie wird gelöscht |
| Antwort gültig, aber ID-Token ungültig oder für einen anderen `sub` | Session endet |
| Zeitüberschreitung (10 s), Netzwerkfehler, `429`, `5xx`, HTML oder sonstige Nicht-OAuth-Antwort, andere OAuth-Fehler | Session bleibt unverändert; nächster Versuch frühestens nach 10 Sekunden |

Bleibt die Session nach einer Störung bestehen, gilt sie weiter bis `sessionMaxAge`; `getSession()` liefert sie,
`getAccessToken()` aber `null`, sobald das Access-Token tatsächlich abgelaufen ist. Mit dem nächsten
erfolgreichen Refresh ist alles wieder normal.

- Erneuert wird nur, wo Cookies geschrieben werden können: im **Proxy**, in Route Handlern und Server Actions.
  In Server Components sind Cookies schreibgeschützt; dort liefert `getSession()` die Session unverändert und
  `getAccessToken()` bei abgelaufenem Token `null`. Deshalb den Proxy für alle Seiten einbinden – er erneuert vor
  dem Rendern und reicht die neuen Cookies an dieselbe Anfrage weiter.
- Gleichzeitige Anfragen derselben Session teilen sich innerhalb eines Prozesses einen Refresh; das Ergebnis gilt
  noch 30 Sekunden für Anfragen mit dem alten Cookie. Über **mehrere Instanzen** hinweg ist das nicht abgesichert:
  ein paralleler Refresh auf zwei Instanzen kann die Wiederverwendungserkennung des Providers auslösen (dann endet
  die Session und der Benutzer meldet sich neu an).

## Back-Channel-Logout

Der Provider sendet beim Ende einer SSO-Session ein `logout_token` per `POST` an `/auth/backchannel-logout`. Das SDK
prüft es (Signatur, `typ: logout+jwt`, `iss`, `aud`, `iat`, `exp`, `jti`, Event, `sub`/`sid`, kein `nonce`) und
antwortet `200` (Logout vermerkt), `400` (Token ungültig oder schon einmal zugestellt), `500` (Store nicht
erreichbar, der Provider wiederholt) bzw. `501` (kein Store konfiguriert); immer mit `Cache-Control: no-store`,
Body höchstens 16 KiB.

Ein Cookie lässt sich vom Server aus nicht löschen. Damit der Logout wirkt, braucht die Anwendung einen
**`SessionStore`**, den alle Instanzen teilen. Das SDK vermerkt dort „Sessions dieser `sid` (bzw. ohne `sid`: dieses
`sub`), angelegt bis Zeitpunkt T, sind beendet“ und prüft das bei jedem Lesen der Session. T ist das `iat` des
Logout-Tokens (höchstens die Empfangszeit), eine neue Anmeldung danach bleibt also gültig. Die `jti` merkt sich
das SDK bis zum Ablauf des Tokens und lehnt eine zweite Zustellung ab. Ist der Store nicht erreichbar, gilt die
Anfrage als abgemeldet (fail closed).

```ts
// lib/session-store.ts – Beispiel mit node-redis
import type { SessionStore } from "@zweiund40gmbh/auth-next";
import { createClient } from "redis";

const redis = await createClient({ url: process.env.REDIS_URL }).connect();

export const redisSessionStore: SessionStore = {
  set: async (key, value, ttlSeconds) => {
    await redis.set(key, value, { EX: ttlSeconds });
  },
  get: async (key) => (await redis.get(key)) ?? undefined,
};
```

`memorySessionStore()` genügt für Entwicklung, Tests und Anwendungen mit genau **einer** Instanz.

**Ohne `sessionStore`** wird der Logout zwar geprüft, beendet aber keine Session: Das SDK antwortet `501`, damit
der Provider die Zustellung als gescheitert verbucht, und loggt beim Start und bei jedem Logout eine Warnung. Die Session endet dann erst beim nächsten Token-Refresh (der Provider widerruft beim Logout die
Refresh-Tokens, also nach höchstens einer Access-Token-Laufzeit, etwa 5 Minuten) bzw. ohne Refresh-Token erst mit
Ablauf von `sessionMaxAge`. In diesem Fall `sessionMaxAge` kurz wählen.

Läuft der Proxy in der Edge-Runtime (Middleware bis Next.js 15), muss auch der Store dort funktionieren
(z. B. ein Redis mit HTTP-Schnittstelle).

## Sicherheit

- Nur Authorization Code mit PKCE (S256); `state`, `nonce` und `iss` (RFC 9207) werden immer geprüft. Kündigt der
  Provider `iss` an, ist es Pflicht. Fehlerantworten werden erst nach passender `iss`- und `state`-Prüfung beachtet.
- Discovery: `issuer` muss exakt dem konfigurierten Wert entsprechen, PKCE S256 muss angeboten werden, alle
  Endpunkte HTTPS (Ausnahme Loopback in der Entwicklung).
- ID-Token: nur RS256/ES256 (und nur, was der Provider anbietet), `kid` aus dem JWKS, Header `typ: JWT`,
  `crit` abgelehnt, `iss`, `aud`, `azp`, `exp`, `iat` (nicht in der Zukunft), `nonce`, `at_hash`, 60 Sekunden
  Toleranz.
- Kein HTTP-Aufruf an den Provider folgt Weiterleitungen (sie könnten Client-Secret, Codes oder Tokens an einen
  fremden Host tragen); Zeitlimit 10 Sekunden.
- Alle Weiterleitungen gehen auf den Origin von `AUTH_REDIRECT_URI`, nie auf den `Host`-Header der Anfrage.
- Tokens, Codes und Secrets werden nie geloggt; Fehlermeldungen enthalten keine Token-Werte.
- Das Paket ist nur für Server-Code gedacht; nicht aus Client Components importieren.

Fehler: Der Callback antwortet ohne `errorPath` mit einer schlichten deutschen Fehlerseite (`400`), mit `errorPath`
per Weiterleitung auf `errorPath?error=<code>`. `code` ist der OAuth-Fehler des Providers (z. B. `access_denied`,
`login_required`) oder einer von `login_state_missing`, `session_too_large`, `invalid_callback` (Callback oder Token-Antwort
abgelehnt), `invalid_token`, `auth_too_old`, `insufficient_acr`, `invalid_grant`, `provider_error`.
Zur Anzeige eigene deutsche Texte verwenden.

## Grenzen (0.1)

- Der JWKS-Cache (jose) lädt Schlüssel nach 5 Minuten bzw. bei unbekannter `kid` neu (höchstens alle 30 Sekunden).
  Anders als das Rust-SDK nutzt er bei nicht erreichbarem Provider keine veralteten Schlüssel weiter.
- UserInfo, Token-Widerruf und die Prüfung von Access-Tokens für Ressourcen-Server sind nicht enthalten.

Entwicklung: `just js-check` im Repository-Wurzelverzeichnis (Lint, Typprüfung, Tests gegen einen
In-Process-Mock-Provider, Build, Paketinhalt).

## Lizenz

Wahlweise MIT oder Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
