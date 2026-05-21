# Client-Side Security Deep Dive

Wird geladen, wenn Frontend-Code erkannt wird: `.js`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.svelte`, Static-HTML, oder Server-Side-Code, der HTML/JS rendert.

## Prototype Pollution

### Was

JavaScript-Objekte haben einen `__proto__`-Pointer auf `Object.prototype`. Modifikationen daran propagieren auf ALLE Objekte. User-kontrollierte Property-Namen wie `__proto__`, `constructor.prototype` können Code-Execution oder Auth-Bypass triggern.

### Client-Side Pattern

```
rg "Object\.assign\([^,]+,\s*JSON\.parse" --type js --type ts
rg "Object\.assign\([^,]+,\s*req\." --type js --type ts
rg "_\.merge\(|lodash\.merge\(" --type js
rg "for\s*\(.*in.*\)" --type js -A 3   # ohne hasOwnProperty
```

### Server-Side Pattern (Node.js)

```
rg "Object\.assign\([^,]+,\s*req\.body" --type js
rg "qs\.parse\(.*allowPrototypes" --type js   # express defaults!
rg "express\.urlencoded.*extended:\s*true" --type js
```

**Anti-Pattern:**
```javascript
// User-Body: {"__proto__": {"isAdmin": true}}
const user = {};
Object.assign(user, req.body);  // Pollution!
// Jetzt hat JEDES Objekt isAdmin=true (default-Wert), wenn nicht explicit gesetzt
```

**Sicher:**
- `Object.create(null)` für untrusted-Objekte → kein `__proto__`
- Whitelist erlaubter Felder
- `Map` statt `Object` für key-value-Strukturen
- Tools: `protect-against-prototype-pollution`, `safe-regex`, `safe-stable-stringify`

### Bekannte Sinks

Wenn Prototype Pollution möglich ist, kann der Effekt durch folgende Sinks zu RCE eskalieren:
- `child_process.exec` mit Properties wie `shell`, `env`
- Lodash `_.template`
- AJV (JSON Schema validation) mit `additionalProperties`
- Express-View-Rendering

**Schwere:** Critical bei Eskalation zu RCE, High bei Logic-Bypass.

## DOM Clobbering

### Was

HTML-Elemente mit `id` oder `name` werden als globale JS-Variablen exponiert (legacy behavior). Angreifer mit HTML-Injection (auch ohne XSS) kann existierende JS-Variablen "clobbern".

### Beispiel

```html
<!-- Angreifer injiziert: -->
<form id="config"><input name="api" value="https://evil.com"></form>
```
```javascript
// Existierender Code:
fetch(config.api + "/data")  // Jetzt zeigt config.api auf evil.com
```

### Patterns

```
rg "window\.[a-zA-Z_]+\s*&&|globalThis\.[a-zA-Z_]+" --type js
rg "var\s+config\s*=\s*config\s*\|\|\s*\{\}" --type js
```

**Mitigation:**
- Strikte CSP, die HTML-Injection-Pfade blockiert
- `Object.freeze` auf Konfigurationsobjekten
- Trusted Types API (Chrome/Edge)
- Niemals globale Variablen-Namen aus DOM lesen

## postMessage-Schwachstellen

```
rg "addEventListener\([\"']message[\"']" --type js --type ts -A 5
rg "window\.addEventListener\([\"']message" --type js -A 5
rg "\.postMessage\(" --type js
```

### Anti-Patterns

```javascript
// Empfangsseite:
window.addEventListener("message", (e) => {
  // KEINE origin-Prüfung!
  eval(e.data);  // RCE via postMessage
});
```

**Pflichten:**
1. **Origin-Check**: `if (e.origin !== "https://trusted.example.com") return;`
2. **Source-Check**: bei Multi-Frame-Setups prüfen, woher das Event kommt
3. **Schema-Validation**: erwartetes Format prüfen, dann handeln
4. **Niemals eval()/Function()/innerHTML** auf empfangenen Daten

### Sender-Seite

```javascript
// Anti-Pattern:
iframe.contentWindow.postMessage(data, "*");  // Wildcard!

// Sicher:
iframe.contentWindow.postMessage(data, "https://trusted.example.com");
```

## Subdomain Takeover

### Was

CNAME oder NS-Record zeigt auf einen Service (S3, Heroku, Azure CDN, GitHub Pages, ...), aber die Ressource dort existiert nicht (mehr). Angreifer registriert dort eine eigene Ressource → kontrolliert die Subdomain.

### Detection im Repo

```
rg "subdomains|subdomain.*=|\.example\.com" -i --type yaml --type tf
rg "cname|CNAME" --type tf -A 2
rg "azureedge|cloudfront\.net|elasticbeanstalk|herokuapp|github\.io|s3\.amazonaws" --type yaml --type tf
```

**Anti-Patterns:**
- DNS-Records (z. B. in Terraform), die auf nicht mehr existierende Services zeigen
- Wildcard-CNAMEs auf externe Services
- Fehlende Monitoring-Workflow für DNS-Records → bei Decommissioning bleibt CNAME

**Mitigation:** Asset-Inventory pflegen, DNS-Records bei Service-Decommission entfernen, automatisches Scanning (z. B. Subjack, Subzy, Aquatone).

**Schwere:** Critical wenn Auth-Tokens / Session-Cookies mit Domain-Scope `*.example.com` gesetzt werden (Cookie-Diebstahl möglich).

## Subresource Integrity (SRI)

```
rg "<script\s+src=" --type html
rg "<link\s+rel=[\"']stylesheet[\"']" --type html
```

Externe Scripts/Stylesheets ohne `integrity=`-Attribut → wenn CDN kompromittiert wird, läuft beliebiges JS auf der Seite.

**Sicher:**
```html
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-..."
        crossorigin="anonymous"></script>
```

## Content Security Policy (CSP)

```
rg "Content-Security-Policy" -i --type py --type js --type java --type yaml
rg "unsafe-inline|unsafe-eval" --type py --type js
```

**Anti-Patterns:**
- Keine CSP gesetzt (vorhandener XSS wird voll exploitable)
- CSP mit `unsafe-inline` für `script-src` → die meisten XSS-Pfade bleiben offen
- CSP mit `unsafe-eval` → eval-basierte Payloads
- `default-src *` oder `script-src https:` → kein Origin-Limit
- Nonce-basierte CSP, aber Nonce ist statisch / wiederverwendet

**Sicher:** Strikte CSP mit `'nonce-<random>'` (pro-Request-Nonce) oder Hash-basiert. `script-src 'self' 'nonce-XXX'`, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`.

## Other Security Headers

```
rg "X-Content-Type-Options|nosniff" --type py --type js
rg "Strict-Transport-Security|HSTS" --type py --type js
rg "X-Frame-Options|frame-ancestors" --type py --type js
rg "Referrer-Policy" --type py --type js
rg "Permissions-Policy|Feature-Policy" --type py --type js
```

**Pflicht-Header für moderne Apps:**
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `Referrer-Policy: strict-origin-when-cross-origin` (oder restriktiver)
- `Permissions-Policy: ...` (alte Bezeichnung: `Feature-Policy`)
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp` (für SharedArrayBuffer)
- `Cross-Origin-Resource-Policy: same-site` oder `same-origin`

## DOM-XSS-Spezifisch

Source → Sink Tracking in Frontend:

**Sources** (user-kontrolliert):
- `location.search`, `location.hash`, `location.pathname`
- `document.referrer`, `document.cookie`
- `window.name`
- `postMessage`-Empfang
- `localStorage`/`sessionStorage` (wenn gefüllt von User)

**Sinks** (gefährlich):
- `innerHTML`, `outerHTML`, `document.write`, `document.writeln`
- `eval`, `Function`, `setTimeout("string")`, `setInterval("string")`
- `location = ...`, `location.href = ...`
- `<script>.src = ...`, `<iframe>.src = ...`
- jQuery `$()`, `html()`
- React `dangerouslySetInnerHTML`
- Vue `v-html`
- Angular: bypass-functions

**Sicher:**
- DOM-XSS-safe APIs: `textContent`, `setAttribute` (für nicht-JS-relevante Attribute), `classList.add/remove`
- Sanitizer-API (DOMPurify, sanitize-html)
- Trusted Types (browser-native, Chrome/Edge)

## CSRF — Modern Considerations

```
rg "@app\.(post|put|delete|patch)" --type py -A 5 | rg -v "csrf"
rg "SameSite" --type py --type js
rg "@csrf_exempt|@csrf.exempt|exempt_when" --type py
```

Beyond classic CSRF tokens:
- **SameSite=Lax** als Default-Schutz (aber: GET-Endpoints, die State ändern, sind weiter anfällig)
- **SameSite=Strict** für sensitive Operationen
- **Custom-Header-Token** (`X-CSRF-Token`) für AJAX
- **Double-Submit-Cookie** als state-less Variante
- **Origin-/Referer-Header-Check** als Defense-in-Depth

## Cross-Origin Window/iframe Attacks

### Tabnabbing

```
rg "target=[\"']_blank" --type html --type jsx -A 2
rg "window\.open\(" --type js -A 2
```

`<a target="_blank">` ohne `rel="noopener noreferrer"` → das geöffnete Fenster kann `window.opener.location` setzen → Origin-Tab wird auf Phishing-Site geleitet.

**Sicher:** `rel="noopener noreferrer"` (moderne Browser default ab 2021, aber zur Sicherheit explizit).

### Clickjacking

Fehlende `X-Frame-Options: DENY` oder `frame-ancestors 'none'` → Seite kann in iframe versteckt + überlagert werden.

Login-Endpunkte, Approval-Buttons, Coupon-Einlösungen sind klassische Ziele.

## Service Worker / PWA Risiken

```
rg "navigator\.serviceWorker\.register|self\.addEventListener.*fetch" --type js -A 5
```

**Anti-Patterns:**
- Service Worker mit Scope, das größer ist als Owner-Path
- Service Worker, der `fetch`-Events manipuliert → permanente "Persistence" für XSS
- Update-Mechanismus: HTTP-Cache-Header für SW selbst nicht restriktiv (`max-age=0`)

## Web Storage Security

```
rg "localStorage\.|sessionStorage\." --type js -A 1
```

- **localStorage**: XSS-anfällig (jeder JS auf Origin liest)
- **sessionStorage**: Tab-isoliert, aber XSS-anfällig
- **IndexedDB**: gleiche Probleme bei sensitiven Daten
- **HttpOnly Cookies** sind für Auth-Tokens deutlich sicherer

## Befund-Beispiel

```
[CLIENT-01] postMessage-Listener ohne Origin-Check
Severity:    High (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N = 8.1)
Exploitability: External-Unauth (über User-Visit auf Angreifer-Seite)
CWE:         CWE-346 Origin Validation Error

Evidence:
src/components/PaymentFrame.jsx:42:
  window.addEventListener("message", (e) => {
    const { type, payload } = e.data;
    if (type === "PAYMENT_TOKEN") {
      submitPayment(payload);  // Keine origin-Prüfung!
    }
  });

Eine vom Opfer besuchte Angreifer-Seite kann postMessage an unsere Origin
schicken, sobald unser Frame eingebettet wird → unautorisierte Zahlungen.

Action:
const ALLOWED = "https://payments.example.com";
window.addEventListener("message", (e) => {
  if (e.origin !== ALLOWED) return;
  // ...
});
```

## Mappings

- CWE-79 XSS
- CWE-1321 Prototype Pollution
- CWE-346 Origin Validation Error (postMessage)
- CWE-352 CSRF
- CWE-601 Open Redirect
- CWE-1021 Improper Restriction of Rendered UI Layers (Clickjacking)
- A03 Injection, A05 Misconfig, A07 Auth
