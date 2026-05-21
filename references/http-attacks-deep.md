# HTTP-Attacks Deep Dive

Wird geladen, wenn HTTP-Code erkannt wird: Routing, Header-Manipulation, Caching, Proxying, Template-Rendering.

## HTTP Request Smuggling (Desync)

**Was:** Front- und Backend-Server interpretieren Request-Boundaries unterschiedlich (Content-Length vs Transfer-Encoding) → Angreifer kann Request "schmuggeln", der vom Backend einem anderen User zugeordnet wird.

### Varianten

- **CL.TE**: Frontend nutzt Content-Length, Backend nutzt Transfer-Encoding
- **TE.CL**: Umgekehrt
- **TE.TE**: Beide nutzen TE, aber unterschiedliche Parsing-Logik (obfuscation)
- **CL.CL**: Beide nutzen CL, aber unterschiedliche Interpretation bei Doppel-Header

### Single-Packet Attacks (James Kettle, 2023)

Race-Conditions via HTTP/2 — zwei Requests, beide im selben TCP-Paket, treffen das Backend praktisch gleichzeitig. Bypass von Per-User-Rate-Limits und Race-Conditions in Business-Logic.

### Detection im Code (statisch nicht trivial)

```
# Reverse-Proxy-Konfiguration prüfen
rg "Transfer-Encoding|Content-Length" nginx.conf haproxy.cfg
rg "proxy_pass" nginx.conf -A 3
rg "uwsgi|gunicorn|hypercorn" --type py    # bekannt für CL.TE-Anfälligkeit in bestimmten Versionen
```

**Anti-Patterns:**
- Custom Header-Parsing zwischen Proxies
- HTTP/1.1-only Frontend + HTTP/2 Backend (oder umgekehrt)
- Multiple unbekannte Proxies in Chain
- `proxy_read_timeout 0;` ohne weitere Schutzmaßnahmen

**Mitigation:** Frontend und Backend mit identischem HTTP-Parser (z. B. beide HAProxy oder beide HTTP/2-strict). Reject ambiguous requests (`Connection: keep-alive` + `Transfer-Encoding` + `Content-Length`).

**Schwere:** Critical bei externen Endpoints (Session-Hijacking, Cache Poisoning, Auth-Bypass).

## Web Cache Poisoning

### Klassisch (Reflected)

Header (z. B. `X-Forwarded-Host`, `X-Original-URL`, `X-Forwarded-Scheme`) werden in Cache-Key NICHT, in Response aber schon einbezogen → Angreifer kann via vergiftetem Header eine Response cachen lassen, die andere User bekommen.

**Patterns:**
```
rg "X-Forwarded-Host|X-Forwarded-Scheme|X-Original-URL|X-Original-Host" --type py --type js
rg "request\.headers\[.host.\]|req\.get\(.host.\)" --type py --type js
rg "url_for\(.*_external.*True" --type py    # generiert URL inkl. Host
```

**Anti-Pattern:** `request.host`, `request.url` direkt im Response-Body verwendet (Angreifer kontrolliert Host-Header).

### Cache Keys

```
rg "Vary:" --type yaml --type conf
rg "cacheable|max-age" --type yaml --type conf
```

**Anti-Patterns:**
- Cache-Key enthält nur URL, nicht relevante Header (z. B. `Accept-Language`)
- Cache TTL zu lang für vergiftbare Responses
- Cookies werden ignoriert in Cache-Key, aber session-spezifische Daten in Response

### Cache Deception

URLs wie `/account.php/style.css` werden vom Backend als `/account.php` (mit Session-Context) bedient, aber vom Frontend-Cache als `.css` (öffentlich cacheable) klassifiziert → Session-Inhalt landet im öffentlichen Cache.

**Mitigation:** Path-Normalization auf Frontend, strikte Content-Type-Checks für Cache-Eligibility.

## Server-Side Template Injection (SSTI)

### Jinja2 (Python)

```
rg "Template\([^)]+request\." --type py
rg "render_template_string\([^)]+request\." --type py
rg "from_string\([^)]+request\." --type py
```

**Klassische Payloads:**
- `{{ 7*7 }}` → 49 (Detection)
- `{{ ''.__class__.__mro__[1].__subclasses__() }}` → RCE-Pfad
- `{{ config }}` → komplette Config exposed
- `{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}`

### Twig (PHP), Velocity / Freemarker (Java)

```
rg "Twig_Environment.*render\(" --type php
rg "VelocityEngine|Template\.merge" --type java
rg "FreeMarker" --type java
```

**Java SSTI:**
- Freemarker: `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}`
- Velocity: `#set($x=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))`

### ERB (Ruby)

```
rg "ERB\.new\(.*request" --type ruby
rg "render\s+inline:\s*params" --type ruby
```

### Express + EJS / Pug

```
rg "render\(.*req\.|render\(.*params\." --type js
```

EJS spezifisch: `<%- ... %>` ist unsafe; `<%= ... %>` ist escaped.

### Generelle Mitigation

- Never `Template.render(user_input)` mit User-Input als Template-Source
- Wenn User Daten in Template einbringen darf: als Kontext-Variable (`render(template, data=user_input)`), nicht als Template-String
- Sandboxed Template-Engines verwenden, wenn User-Templates erlaubt sein müssen

**Schwere:** Critical (RCE-Pfad), External-Unauth wenn Endpunkt offen.

## Open Redirect

```
rg "redirect\([^)]*request\." --type py --type js
rg "res\.redirect\([^)]*req\." --type js
rg "Location.*request\." --type java
rg "next\?" --type py --type js   # ?next=URL ist klassisch
```

**Anti-Patterns:**
- `redirect(request.args["next"])` ohne Allowlist
- Naive Prefix-Check: `next.startswith("/")` → Angreifer nutzt `//evil.com`
- URL-Parser ohne Schema-Check: `urlparse(next).hostname` → akzeptiert `javascript:` (außer im Browser-Kontext)
- `referrer`-basierter Redirect ohne Validation

**Sicher:**
```python
from urllib.parse import urlparse

def safe_redirect(target):
    p = urlparse(target)
    if p.netloc and p.netloc != ALLOWED_HOST:
        return abort(400)
    if not p.scheme in ("", "https"):
        return abort(400)
    return redirect(target)
```

**Schwere:** Medium (Phishing-Vector), aber kritischer Bestandteil von OAuth-Token-Diebstahl, Account-Takeover-Chains.

## SSRF Deep — Bypass-Techniken

Aufbauend auf A10 / API7, hier die fortgeschrittenen Patterns:

### Filter-Bypass

- **DNS-Rebinding**: Erste Auflösung von `evil.com` → öffentliche IP (passes filter), zweite Auflösung im HTTP-Request → 127.0.0.1
- **Redirect**: Filter prüft Ziel-URL, aber dann redirected die Ziel-URL auf intern. Wenn der Code `follow_redirects=True` hat: SSRF
- **URL-Parser-Verwirrung**: `http://expected.com#@internal.example` (verschiedene Parser interpretieren das anders)
- **Underflow**: `http://0` → `http://0.0.0.0`, `http://[::]` → IPv6 localhost
- **Decimal/Hex IPs**: `http://2130706433/` → 127.0.0.1
- **IPv6-Notation**: `http://[::ffff:127.0.0.1]/`

### Protokoll-Smuggling

- `gopher://` → kann beliebige TCP-Payloads bauen (Redis, Memcached, SMTP)
- `file://` → lokale Datei-Lesung
- `dict://`, `ldap://`, `ftp://` → diverse Internal-Service-Angriffe

```
rg "ALLOWED_PROTOCOLS|allow_schemes|allowed_schemes" --type py --type js
rg "follow_redirects\s*=\s*True" --type py
rg "maxRedirects" --type js
```

### IMDS-Spezifisch (Cloud)

- AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- GCP: `http://metadata.google.internal/`
- Azure: `http://169.254.169.254/metadata/instance?api-version=...`

**Sicher:** Allowlist für Ziele (Hostnames, IP-Ranges), `follow_redirects=False`, oder Sandboxing über Proxy mit Whitelist.

## CRLF / Header Injection

```
rg "request\..*headers\|.*\\r|\\n" --type py
rg "set_header.*request" --type py --type js
rg "Response\.AddHeader\(.*\+" --type cs
```

**Klassiker:**
- User-Input in Set-Cookie: `Set-Cookie: name=<input>` mit `<input> = "x; \r\nSet-Cookie: session=evil"`
- Location-Header: `Location: <user_input>` → mit `\r\n` zusätzlichen Header injizieren
- Logging-Pfade: User-Input mit `\n` injiziert Log-Zeilen

**Sicher:** Header-Library, die `\r`/`\n` strippt (moderne Frameworks tun das per Default — aber `request.headers.add(name, value)` mit Raw-Bytes umgeht das oft).

## Host-Header-Injection

```
rg "request\.host|request\.headers\.host" --type py --type js
rg "_external.*True" --type py     # url_for(_external=True) nutzt Host-Header
```

**Angriffe:**
- Password-Reset-Email enthält Reset-Link mit Host aus Request-Header → Angreifer sendet Request mit `Host: evil.com`, Opfer klickt Reset-Link, Token landet bei Angreifer
- Cache Poisoning (siehe oben)
- Routing zu anderen Backends

**Sicher:** `ALLOWED_HOSTS` strikt konfigurieren; in URL-Generation explizit den korrekten Host setzen.

## HTTP Parameter Pollution (HPP)

Same parameter twice in request: `?role=user&role=admin`. Different frameworks/servers handle differently:
- PHP: Last value wins
- Java Servlet: First value wins (or array)
- ASP.NET: comma-joined

→ Backend liest `user`, Authorization-Layer liest `admin` (oder umgekehrt) → Bypass.

```
rg "request\.args\.get\(|getParameter\(" --type py --type java
rg "request\.args\.getlist|getParameterValues" --type py --type java  # gut wenn explizit Array gehandhabt
```

## Path Normalization Differentials

Frontend und Backend normalisieren Pfade unterschiedlich:
- `/admin/../public/page` → manche Server resolven das, manche nicht
- `/admin%2f..%2fpublic` (URL-encoded slashes) → einige Proxies decoden, einige nicht

→ Auth-Filter auf `/admin/*` matched nicht, aber Handler wird trotzdem aufgerufen.

```
rg "merge_slashes" nginx.conf
rg "AllowEncodedSlashes" .htaccess httpd.conf
```

## CORS-Misconfiguration

```
rg "Access-Control-Allow-Origin.*request" --type py --type js
rg "Access-Control-Allow-Origin.*\*"
rg "allow_credentials\s*=\s*True"  --type py
```

**Anti-Patterns:**
- `Access-Control-Allow-Origin` wird per-Request aus dem `Origin`-Header reflektiert + `Allow-Credentials: true` → effective trust für jeden
- Naive Prefix-Match: `Origin.startsWith("https://example.com")` → `https://example.com.attacker.com`
- Null-Origin akzeptiert: `Access-Control-Allow-Origin: null` → Sandboxed iframes haben Origin `null` und können requests senden

## Race-Condition-Bewusstsein

Bei Authentication-Endpoints, Wallet-Endpoints, Coupon-Einlösungen → **siehe `race-conditions.md`**.

## Befund-Beispiel

```
[HTTP-01] SSTI in Email-Template-Renderer
Severity:    Critical (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8)
Exploitability: External-Auth (regulärer User-Account reicht)
CWE:         CWE-94 Code Injection (Server-Side Template Injection)

Evidence:
src/email/render.py:42:    template = Template(user_provided_template)
                       43:    return template.render(user=current_user)

User können ihr Profil-Template anpassen ("Hi {{ first_name }}!"). Mit
Payload `{{ ''.__class__.__mro__[1].__subclasses__()[X]() }}` ist RCE
auf dem Email-Worker möglich.

Action:
1. Templates ausschließlich serverseitig vorhalten (keine User-Templates).
2. Falls Customization nötig: Mustache/Handlebars (logikfrei) statt Jinja2.
3. Sandboxed Jinja2 Environment (SandboxedEnvironment) als Notlösung.
```

## Mappings

- CWE-444 Inconsistent Interpretation of HTTP Requests (Smuggling)
- CWE-94 Code Injection (SSTI)
- CWE-918 SSRF
- CWE-601 Open Redirect
- CWE-93 CRLF Injection
- CWE-444, CWE-352
- A03 Injection, A10 SSRF, A05 Misconfig
