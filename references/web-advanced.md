# Moderne Web-Angriffe — Tiefenanalyse

Diese Referenz deckt fortgeschrittene Web-Angriffe ab, die in den OWASP Top 10 nicht explizit gelistet sind, in modernen Audits aber sehr oft auftauchen. Geladen bei Web-Apps, JS-Frameworks, Reverse-Proxies, CDN-Konfigurationen.

## 1. Server-Side Template Injection (SSTI)

**Was:** User-Input wird in eine Template-Engine eingespeist und als Code ausgeführt — RCE.

**Engines mit Risiko:**
- Python: Jinja2, Mako, Django-Templates (mit `mark_safe`)
- Java: Velocity, Freemarker, Thymeleaf (mit `[#unsafe]`)
- JS: Pug (mit `!{...}`), Handlebars (mit `{{{...}}}`), EJS (`<%- %>`)
- PHP: Smarty, Twig
- Ruby: ERB, Slim

### Detection
```
rg "Template\([^)]*request|Template\(.*user_input" --type py
rg "render_template_string\(" --type py  # gefährlich wenn User-Input
rg "FreeMarkerTemplate" --type java -A 5
rg "Velocity\.evaluate" --type java
rg "compile\(.*\+.*req\." --type js  # Template-Engine compile
```

### Beispiel-Exploits

**Jinja2:**
```
{{ ''.__class__.__mro__[1].__subclasses__()[XXX]("id", shell=True, stdout=-1).communicate()[0] }}
```

**Freemarker:**
```
<#assign x="freemarker.template.utility.Execute"?new()>${ x("id") }
```

**Twig:**
```
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
```

### Mitigation
- User-Input NIE in Template-Strings einbauen — als Parameter binden
- Sandbox-Mode der Engine nutzen (z. B. Jinja2 `SandboxedEnvironment`)
- Allowlist statt Blocklist für Filter

**Schwere:** Critical, External-Unauth möglich → RCE.

---

## 2. Prototype Pollution

**Was:** JavaScript-Eigenheit. `__proto__`-Manipulation propagiert auf alle Objekte → DoS, Auth-Bypass, RCE bei späterem `eval`.

### Detection
```
rg "JSON\.parse\(.*req\." --type js --type ts
rg "Object\.assign\(\s*\{\}?\s*,\s*req\." --type js
rg "_\.merge\(|_\.defaultsDeep\(|_\.assignWith" --type js  # lodash, oft betroffen
rg "Object\.setPrototypeOf|__proto__" --type js
rg "set\(.*req\.body\.|hoek\.applyToDefaults" --type js
```

### Unsicher
```js
function merge(target, src) {
  for (let key in src) {
    if (typeof src[key] === 'object') {
      merge(target[key] = target[key] || {}, src[key]);
    } else {
      target[key] = src[key];
    }
  }
}
merge({}, JSON.parse(req.body));  // body: {"__proto__": {"isAdmin": true}}
```

### Mitigation
- `Object.create(null)` als sicherer Container
- Use Maps statt Objects für User-Daten
- Allowlist erlaubter Keys
- `--disallow-proto` in modernen Node-Versionen (Node 22+)
- `JSON.parse` mit Reviver-Function, die `__proto__`/`constructor`/`prototype` filtert
- Libraries: `lodash.merge` ist anfällig — `lodash >= 4.17.21` patcht es

### Folge-Angriffe

Polluted Prototype + `child_process.spawn(... { shell: true })` → RCE
Polluted Prototype + Templating-Engine Options → SSTI
Polluted Prototype + ACL-Check (`if (user.isAdmin)`) → Auth Bypass

**Schwere:** High–Critical.

---

## 3. HTTP Request Smuggling

**Was:** Frontend (Reverse Proxy/CDN) und Backend (App-Server) parsen HTTP-Request-Boundaries unterschiedlich. Angreifer schmuggelt zwei Requests in einem, beeinflusst nachfolgende User-Sessions.

### Varianten
- **CL.TE**: Frontend nutzt `Content-Length`, Backend nutzt `Transfer-Encoding`
- **TE.CL**: umgekehrt
- **TE.TE**: beide nutzen TE, aber unterschiedlich (Obfuscation)
- **CL.0**: H2.0 → HTTP/1.1 Downgrade-Smuggling

### Detection (statisch schwer, aber Hinweise)
- Reverse Proxies / Load Balancer im Stack? (NGINX, HAProxy, AWS ALB, Cloudflare)
- Backend-Server, der Transfer-Encoding nicht streng prüft?
- Eigene HTTP-Parser?

```
rg "Transfer-Encoding|Content-Length" --type go --type py --type js  # eigene Parser?
```

### Mitigation
- Frontend MUSS Requests normalisieren, bevor weitergeleitet
- HTTP/2 End-to-End (kein HTTP/1.1-Downgrade)
- Apache/NGINX neu (haben Patches)
- Backend: strikte HTTP-Parser

**Schwere:** Critical (Session-Hijacking, Cache-Poisoning, Cred-Theft).

---

## 4. Web Cache Poisoning

**Was:** Angreifer manipuliert Cache (CDN, Reverse Proxy) so, dass schädliche Antworten an andere User ausgeliefert werden.

### Vektoren
- Unkeyed Headers: Header, die in der Cache-Key nicht enthalten sind, aber die Response beeinflussen (z. B. `X-Forwarded-Host`, `X-Original-URL`)
- Unkeyed Query-Params: gleicher Effekt
- Fat-GET-Requests: GET mit Body
- Parameter-Pollution: `?lang=en&lang=de` — wer gewinnt?
- Cache Deception: `/account.php/nonexistent.css` → Cache cached als CSS

### Detection
```
rg "X-Forwarded-(Host|Server|Scheme)" -A 3 --type py --type js --type java
rg "X-Original-URL|X-Rewrite-URL" -A 3
rg "Cache-Control" --type py --type js
rg "Vary:" --type py --type js  # falls fehlt: Header-Differenzierung schwach
```

### Mitigation
- Vary-Header für relevante Request-Header
- Strikte Cache-Key-Definition
- Unkeyed Inputs identifizieren und ihre Reflexion vermeiden
- Tools wie `Param Miner` (Burp) für Audit

**Schwere:** High (Mass Defacement, Cred-Theft).

---

## 5. DOM Clobbering

**Was:** HTML-Elemente mit IDs / Names überschreiben JS-Variablen mit demselben Namen.

### Beispiel
```html
<form id="config"><input name="apiKey" value="LEAK"></form>
<script>
if (window.config && window.config.apiKey) { /* config kommt vom HTML, nicht JS */ }
</script>
```

### Detection
```
rg "innerHTML|outerHTML|insertAdjacentHTML" --type js --type ts -B 2
rg "DOMParser|parseFromString" --type js
rg "document\.getElementById\(.*\)\.appendChild" --type js
```

### Mitigation
- DOMPurify (mit `SANITIZE_NAMED_PROPS: true` für DOM-Clobbering-Schutz)
- Strict Mode in JS
- TypeScript mit strikten Typen
- Niemals user-controlled HTML in DOM injizieren

---

## 6. PostMessage-Schwachstellen

**Was:** `window.postMessage`-API für Cross-Origin-Communication. Falsche `origin`-Prüfung oder fehlende Validation → Datenleck, XSS.

### Detection
```
rg "addEventListener\(['\"]message['\"]" --type js -A 10
rg "window\.postMessage|parent\.postMessage" --type js
```

### Pflicht-Checks
- `event.origin` gegen Allowlist prüfen — NICHT mit `startsWith` (`evil.example.com.evil.com`)
- `event.source` validieren
- Payload-Schema validieren
- Sender-Seite: Target-Origin spezifisch (kein `*`)

**Unsicher:**
```js
window.addEventListener("message", e => {
  document.getElementById("output").innerHTML = e.data.html;  // XSS!
});
```

---

## 7. Server-Side Request Forgery — vertieft

Basis in `owasp-top10.md` A10. Tiefe:

### Bypass-Techniken (gegen die zu härten ist)
- **DNS Rebinding**: erste Auflösung trusted, zweite → `127.0.0.1`
- **IPv6**: `::1`, `::ffff:127.0.0.1` (IPv4-mapped)
- **Decimal IP**: `2130706433` = `127.0.0.1`
- **URL-Encoding**: `http://0177.0.0.1` (octal)
- **DNS-Wildcards**: `127.0.0.1.nip.io`
- **CRLF Injection in URL**: `http://localhost%0d%0aHost:%20evil`
- **Open Redirect** als Bypass: Allowed-Hosts erlaubt `safe.com`, das auf interne URL weiterleitet

### Mitigation
- IP-Auflösung im Code, gegen private Ranges filtern (RFC 1918, IPv6 ULA, link-local)
- Resolve einmal, übergebe IP — Schutz vor DNS Rebinding
- HTTP Library: keine automatischen Redirects auf andere Hosts
- Egress-Filter auf Netzwerk-Ebene als Defense-in-Depth

---

## 8. CORS-Misconfigurations

### Schwerwiegende Konfigurationsfehler
- `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` (Browser blocked → aber andere CORS-Lib akzeptiert?)
- Origin gegen `null` erlaubt (sandboxed iframes können das senden)
- Reflektierte Origin: Server sendet exakt `Origin`-Header-Wert zurück, ohne Whitelist
- Suffix-Match: Allowed: `api.example.com`, Origin: `evil.api.example.com.attacker.com`
- Prefix-Match: Allowed: `https://example.com`, Origin: `https://example.com.evil.com`

### Detection
```
rg "Access-Control-Allow-Origin.*\*" -B 2 -A 2
rg "cors\(\)" --type js -A 5
rg "origin\s*[:=]\s*['\"](true|\\*)['\"]" --type js
rg "origin.*request\.headers\." --type py  # reflektiert?
```

### Mitigation
- Statische Allowlist erlaubter Origins
- Exakter Match, kein Substring
- `Vary: Origin` Header setzen
- Nur Methods/Headers erlauben, die tatsächlich benötigt werden

---

## 9. Open Redirect

**Was:** App leitet User zu URL aus User-Input weiter.

### Detection
```
rg "redirect\(.*request\.|res\.redirect\(.*req\." --type py --type js
rg "Location\s*:\s*request\." --type py --type java
rg "window\.location\s*=\s*.*request" --type js
```

### Beispiele
- `/login?next=https://evil.com` → nach Login redirect
- `/oauth/callback?redirect_uri=https://evil.com`

### Mitigation
- Allowlist erlaubter Redirect-Ziele
- Nur relative Pfade akzeptieren (`/dashboard`, nicht `//evil.com`)
- Protocol-Relative (`//evil.com`) sind tricky

**Schwere:** Low–Medium allein, High in Verbindung mit OAuth, Reset-Tokens, etc.

---

## 10. HTTP Header Injection / CRLF Injection

**Was:** `\r\n` in User-Input wird in Response-Header eingebaut → Header-Splitting, Response-Splitting.

### Detection
```
rg "set_header\(.*request|setHeader\(.*req" --type py --type js
rg "response\.headers\[.*\]\s*=\s*request" --type py
```

### Mitigation
- Library, die `\r\n` filtert (modernes Express, Flask) — meistens schon
- Bei eigenem HTTP-Code: zwingend filtern
- Encoding: User-Input nie roh in Header

---

## 11. Content Security Policy (CSP)

CSP ist mächtig, aber komplex. Auch leicht falsch zu konfigurieren.

### Schlechte CSP-Konfigurationen
- `unsafe-inline` ohne Nonce/Hash (Standard-XSS-Schutz futsch)
- `unsafe-eval` (verhindert Eval-Mitigation)
- `*` als Source (jeder Origin)
- `data:` für Scripts (Base64-XSS)
- Fehlende `default-src`-Direktive
- Fehlendes `report-uri` / `report-to`

### Detection
```
rg "Content-Security-Policy" --type py --type js -A 3
rg "unsafe-(inline|eval)" --type py --type js --type yaml
```

### Empfohlene CSP
```
default-src 'self';
script-src 'self' 'nonce-{random}' 'strict-dynamic';
style-src 'self' 'nonce-{random}';
img-src 'self' data: https:;
connect-src 'self' https://api.example.com;
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
report-uri https://csp-report.example.com/;
```

---

## 12. Sub-Resource Integrity (SRI)

**Was:** `<script src="https://cdn.../jquery.js">` ohne `integrity=` Attribut → wenn CDN kompromittiert, läuft fremder Code.

### Detection
```
rg "<script.*src=\"https?://" --type html --type tsx --type vue | rg -v "integrity="
rg "<link.*rel=.stylesheet.*href=\"https?://" --type html | rg -v "integrity="
```

### Mitigation
- `integrity="sha384-..."` Attribut
- Self-hosting kritischer Assets statt CDN

---

## 13. Subdomain-Takeover

**Was:** DNS-Eintrag verweist auf eine externe Plattform (Heroku, AWS S3, Azure), aber die Ressource dort wurde gelöscht. Angreifer kann sie übernehmen.

**Statisch nicht direkt erkennbar**, aber Hinweise:
- DNS-Configs im Repo mit `CNAME` zu `*.s3-website-...amazonaws.com` etc.
- Terraform mit S3-Bucket-Created, aber später entfernt — alte DNS-Einträge?

Eher Operational-Befund — aber im Bericht als Hinweis nennen.

---

## 14. WebSocket-Sicherheit

Wenn das Projekt WebSockets nutzt:

- **Origin-Check fehlt**: jede Website kann WebSocket öffnen → Cross-Site WebSocket Hijacking (CSWH)
- **Authentication**: WebSocket nach Upgrade ohne erneute Auth-Prüfung
- **Authorization per Message**: nicht nur bei Upgrade, sondern auch pro Message prüfen
- **Rate Limiting**: WebSocket-Connections oft ungezählt → DoS

### Detection
```
rg "WebSocket|ws://|wss://|socket\.io" --type py --type js -A 5
rg "on\(['\"]connection['\"]" --type js -A 10
```

---

## 15. GraphQL — vertieft

Basis in `owasp-api-top10.md`. Tiefe:

- **Introspection in Production**: `__schema`, `__type` exponieren Schema → kein direkter Exploit, aber Recon
- **Depth & Complexity Limits fehlen**: rekursive Queries → DoS
- **Batching**: 1000 Queries in einem Request → BOLA-Multiplier
- **Aliases**: gleicher Field 100x via Aliases → DoS, Rate-Limit-Bypass
- **Persisted Queries**: Allowlist statt arbitrary Queries

### Detection
```
rg "introspection.*true|GraphiQLOptions" --type py --type js
rg "depth_limit|complexity_limit|max_depth" --type py --type js  # gut wenn vorhanden
rg "expressGraphql|apollo-server" --type js -A 5
```

---

## 16. WebView / Embedded Browsers (Mobile)

Wenn Mobile-App WebView nutzt — siehe auch `mobile-top10.md`:

- `JavaScriptInterface` ohne `@JavascriptInterface`-Annotation (vor Android 4.2 RCE)
- `setAllowFileAccess(true)` + `setAllowUniversalAccessFromFileURLs(true)` = lokales File-Read via `file://`
- Load von HTTP-URLs in WebView (nicht HTTPS)
- Kein `WebViewClient` mit `shouldOverrideUrlLoading` → Phishing-Risiko

---

## Mapping

- OWASP A03 (Injection — inkl. XSS, SSTI), A04 (Insecure Design), A07 (Auth — inkl. CSRF), A10 (SSRF)
- CWE-79 XSS, CWE-94 Code Injection, CWE-352 CSRF, CWE-444 Request Smuggling, CWE-1275 Sensitive Cookie, CWE-942 Permissive Cross-Domain Policy, CWE-601 Open Redirect, CWE-93 CRLF Injection
- PortSwigger Web Security Academy als Referenz für tiefere Tests
