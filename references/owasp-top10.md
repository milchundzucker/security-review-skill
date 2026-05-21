# OWASP Top 10 — Detection Reference

Diese Referenz enthält Detection-Patterns für die OWASP Top 10 (2021, mit Updates aus dem 2025-Entwurf). Jede Kategorie hat: Beschreibung, was zu suchen ist, sichere vs. unsichere Beispiele, CWE-Mapping, typische Schwere.

## A01:2021 — Broken Access Control

**Was:** Fehlende oder fehlerhafte Autorisierungsprüfung. Häufigste Schwachstelle 2021.

**Suchen nach:**
- Routen ohne Auth-Decorator: `@app.route(...)` ohne `@login_required`, `@require_auth`, Middleware-Check
- Direkte Objekt-Referenzen ohne Owner-Check: `User.objects.get(id=request.GET['id'])` — kein Vergleich mit `request.user.id`
- Force-Browsing-Pfade: Admin-Routen, die nur per URL versteckt sind
- Client-seitige Rollenprüfung: `if (user.role === 'admin')` im Frontend, aber nicht im Backend
- CORS mit `Access-Control-Allow-Origin: *` UND `Allow-Credentials: true`
- JWT mit `alg: none` oder schwacher Verifikation
- Path Traversal: `open(user_input)`, `send_file(request.args['file'])`

**Patterns (grep/rg):**
```
rg "request\.(args|GET|POST|json)\[.*id.*\]" --type py
rg "Object\.get\(id=" --type py
rg "@app\.route|@router\.(get|post|put|delete)" -A 3 | rg -v "login_required|require_auth|Depends\("
rg "params\[:id\]|params\.id" --type ruby
rg "\.\./" # Path traversal
```

**Unsicher (Python/Flask):**
```python
@app.route("/api/invoice/<int:id>")
def get_invoice(id):
    return Invoice.query.get(id).to_dict()  # Kein Owner-Check!
```

**Sicher:**
```python
@app.route("/api/invoice/<int:id>")
@login_required
def get_invoice(id):
    inv = Invoice.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    return inv.to_dict()
```

**CWE:** CWE-284, CWE-285, CWE-639 (IDOR), CWE-862, CWE-863, CWE-22 (Path Traversal)
**Typische Schwere:** High–Critical, oft External-Unauth oder External-Auth.

---

## A02:2021 — Cryptographic Failures

**Was:** Schwache oder fehlende Kryptografie für sensible Daten.

**Suchen nach:**
- MD5, SHA1 zur Passwort-/Token-Speicherung
- Eigene Krypto-Implementierungen (eigenes XOR, eigene Hash-Funktion)
- `hashlib.md5/sha1` für Passwörter
- ECB-Modus: `Cipher.getInstance("AES")` ohne Modus, `MODE_ECB`
- Hardcoded IVs oder Schlüssel
- HTTP statt HTTPS für sensible Endpoints
- Cookies ohne `Secure`/`HttpOnly`/`SameSite`
- TLS-Validierung deaktiviert: `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`
- Schwache Zufallsquelle: `Math.random()`, `random.random()` für Tokens (statt `secrets`, `crypto.randomBytes`)

**Patterns:**
```
rg "md5|sha1" -i --type py | rg -v "test"
rg "verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify"
rg "Math\.random\(\)|random\.random\(\)" -A 2
rg "Cipher\.getInstance\(\"AES\"\)|MODE_ECB"
rg "set-cookie" -i | rg -v "Secure|HttpOnly"
```

**Unsicher:**
```python
import hashlib
pwd_hash = hashlib.md5(password.encode()).hexdigest()  # MD5 für Passwörter!
```

**Sicher:**
```python
from argon2 import PasswordHasher
ph = PasswordHasher()
pwd_hash = ph.hash(password)
```

**CWE:** CWE-327, CWE-328, CWE-330, CWE-326, CWE-319, CWE-798
**Typische Schwere:** High, Ausnutzbarkeit hängt vom Datenfluss ab.

---

## A03:2021 — Injection

**Was:** Nicht-validierte Eingaben werden in Interpreter-Aufrufe (SQL, NoSQL, OS, LDAP, XPath, ORM) eingebaut. In OWASP 2025 absorbiert auch XSS.

**Suchen nach:**

### SQL Injection
- String-Konkatenation oder f-Strings in SQL: `f"SELECT * FROM x WHERE id={id}"`, `"... WHERE id=" + id`
- `cursor.execute(query % vars)`, `cursor.execute(query.format(...))`
- ORM-Raw-Queries: `session.execute(text(f"..."))`, `db.raw(...)`
- JDBC: `Statement` (statt `PreparedStatement`) + Konkatenation

```
rg "execute\s*\(\s*[\"'`].*\$\{|execute\s*\(\s*f[\"']|execute\s*\(.*%\s|\.format\(" --type py
rg "Statement\(\)|\.createStatement\(\)" --type java
rg "\.query\(.*\+|\.query\(.*\$\{" --type js
```

### Command Injection
- `os.system`, `subprocess.run(..., shell=True)`, `subprocess.call(..., shell=True)`
- `exec`, `eval` mit User-Input
- `child_process.exec(...)`, `Runtime.getRuntime().exec(cmd)` mit String-Konkat

```
rg "shell\s*=\s*True" --type py
rg "exec\(|eval\(" --type py
rg "child_process\.(exec|execSync)" --type js
rg "Runtime\.getRuntime\(\)\.exec" --type java
```

### NoSQL Injection
- MongoDB: `db.users.find({username: req.body.username})` — wenn `req.body.username` ein Objekt `{"$ne": null}` sein kann
- Fehlende Type-Validation auf User-Input bei MongoDB-Filtern

### XSS (in OWASP 2025 unter Injection)
- `innerHTML = userInput`, `document.write(userInput)`
- Template-Engines mit deaktiviertem Auto-Escaping: `{% autoescape off %}`, `{!! ... !!}`, `v-html`
- React `dangerouslySetInnerHTML` mit User-Input

```
rg "innerHTML\s*=|document\.write" --type js
rg "dangerouslySetInnerHTML"
rg "autoescape\s+off|\{!!|v-html"
```

**Unsicher (SQL):**
```python
@app.get("/users")
def search(name: str):
    return db.execute(f"SELECT * FROM users WHERE name LIKE '%{name}%'")
```

**Sicher:**
```python
@app.get("/users")
def search(name: str):
    return db.execute("SELECT * FROM users WHERE name LIKE :n", {"n": f"%{name}%"})
```

**CWE:** CWE-89, CWE-77, CWE-78, CWE-79, CWE-94, CWE-943
**Typische Schwere:** Critical bei SQLi/CMDi mit External-Unauth.

---

## A04:2021 — Insecure Design

**Was:** Architektonische Schwächen, nicht einzelne Code-Bugs. Schwer per grep zu finden — eher konzeptionell.

**Suchen nach:**
- Fehlende Rate Limits auf Login/Reset/OTP
- Fehlende CSRF-Token bei State-changing Operationen
- Business-Logic-Flows ohne Idempotenz / ohne Server-seitige Validation (z. B. Preis aus Frontend-Request übernommen)
- Selbst gebaute Auth-Flows (statt etablierter OAuth/OIDC-Libs)

**Patterns:**
```
rg "@app\.(post|put)" -A 5 | rg -v "csrf|CSRFProtect"
rg "price.*request\.|amount.*request\.|total.*req\." --type py --type js  # Preis aus Request!
```

**CWE:** CWE-209, CWE-256, CWE-501, CWE-522, CWE-799, CWE-840
**Typische Schwere:** Variabel, oft erst bei Business-Logic-Tests sichtbar.

---

## A05:2021 — Security Misconfiguration

**Was:** Defaults, offene Verwaltungs-Endpoints, ausführliche Fehlermeldungen, fehlende Hardening-Header.

**Suchen nach:**
- `DEBUG = True` / `app.debug = True` im Produktionscode
- `ALLOWED_HOSTS = ["*"]`
- Default-Credentials: `admin/admin`, `root/root` in Configs
- Fehlende Security-Header: CSP, HSTS, X-Content-Type-Options, X-Frame-Options
- Verbose Stack Traces in Error-Responses (`traceback.format_exc()` in API-Antwort)
- Offene Management-Endpoints (`/actuator/**` ohne Auth, `/admin` ohne Auth)
- Docker-Container als `root`, `USER root` oder fehlendes `USER`

**Patterns:**
```
rg "DEBUG\s*=\s*True|app\.debug\s*=\s*True"
rg "ALLOWED_HOSTS.*\*"
rg "traceback\.format_exc\(\).*return|jsonify.*str\(e\)"
rg "^USER\s" Dockerfile  # fehlend = Problem
```

**CWE:** CWE-16, CWE-260, CWE-315, CWE-732
**Typische Schwere:** Medium–High.

---

## A06:2021 — Vulnerable and Outdated Components

**Was:** Bekannt verwundbare Dependencies. → Siehe `references/secrets-and-deps.md`.

**CWE:** CWE-1104, CWE-937
**Typische Schwere:** Hängt von CVSS des CVEs ab.

---

## A07:2021 — Identification and Authentication Failures

**Was:** Schwache Login-Mechanismen, fehlerhafte Session-Verwaltung.

**Suchen nach:**
- Fehlende Rate Limits / Brute-Force-Schutz auf Login
- Sessions ohne `HttpOnly`/`Secure`/kurze Lifetime
- Session-IDs in URLs
- Fehlende MFA-Optionen für Admin-Accounts
- Passwort-Komplexität / Min-Länge zu schwach (`len(pw) >= 6`)
- Plain-Text-Passwörter in Storage (siehe A02)
- "Remember me"-Tokens ohne Rotation
- JWT mit `alg: none` akzeptiert, JWT ohne Expiry, Secret hardcoded

**Patterns:**
```
rg "jwt\.decode\(.*verify\s*=\s*False"
rg "algorithms\s*=\s*\[.*none"
rg "session\[.*=\s*request"
rg "len\(password\)\s*[<>=]+\s*[1-7]\b"
```

**CWE:** CWE-287, CWE-294, CWE-307, CWE-384, CWE-521, CWE-613
**Typische Schwere:** High–Critical bei External-Unauth.

---

## A08:2021 — Software and Data Integrity Failures

**Was:** Vertrauen in Daten / Updates ohne Integritätsprüfung. Deserialization gehört hierher.

**Suchen nach:**
- `pickle.loads(user_input)`, `yaml.load(...)` ohne `SafeLoader`, `Marshal.load`, Java `ObjectInputStream`
- PHP `unserialize($_POST[...])`
- Auto-Update-Mechanismen ohne Signaturprüfung
- CI/CD-Pipelines ohne Pinning (`actions/checkout@main` statt `@v4` mit SHA)
- Fehlende Subresource Integrity (`<script src>` ohne `integrity=`)

**Patterns:**
```
rg "pickle\.loads?\("
rg "yaml\.load\(" | rg -v "SafeLoader|safe_load"
rg "ObjectInputStream" --type java
rg "unserialize\(\\\$_" --type php
rg "uses:.*@(main|master)" .github/workflows/
```

**CWE:** CWE-502, CWE-345, CWE-494, CWE-829
**Typische Schwere:** Critical bei Deserialization mit User-Input.

---

## A09:2021 — Security Logging and Monitoring Failures

**Was:** Fehlende Logs für sicherheitsrelevante Events, Logs ohne Schutz, sensible Daten in Logs.

**Suchen nach:**
- Fehlende Logs bei Login-Fehlversuchen, Zugriffsverweigerung, kritischen Transaktionen
- `log.info(f"User pw: {password}")` — sensible Daten in Logs
- Logs ohne zentrale Aggregation (Print-Statements statt Logger)
- Exceptions, die geschluckt werden: `except: pass`, `catch (Exception) {}`

**Patterns:**
```
rg "log.*password|log.*token|log.*secret" -i
rg "except.*:\s*pass" --type py
rg "catch\s*\(\s*Exception.*\)\s*\{\s*\}" --type java --type js
```

**CWE:** CWE-117, CWE-223, CWE-532, CWE-778
**Typische Schwere:** Low–Medium (Defense-in-Depth), aber kritisch für Incident Response.

---

## A10:2021 — Server-Side Request Forgery (SSRF)

**Was:** Server macht HTTP-Request mit User-kontrollierter URL → Zugriff auf interne Services, Cloud-Metadata-Endpoints.

**Suchen nach:**
- `requests.get(user_input)`, `urllib.request.urlopen(user_input)`, `axios.get(user_input)`
- Image-/PDF-/URL-Preview-Funktionen
- Webhook-Aufrufe, deren Ziel-URL aus User-Input stammt
- Fehlende Allowlist für Ziele, fehlende Blockierung von `169.254.169.254`, `127.0.0.1`, `localhost`, `metadata.google.internal`

**Patterns:**
```
rg "requests\.(get|post)\(.*request\." --type py
rg "urllib\.(request\.)?urlopen" --type py
rg "axios\.(get|post)\(.*req\.(body|query|params)" --type js
rg "fetch\(.*req\.(body|query|params)" --type js
```

**Unsicher:**
```python
@app.get("/fetch")
def fetch(url: str):
    return requests.get(url).text  # SSRF!
```

**Sicher:**
```python
ALLOWED = {"api.partner.com", "cdn.example.com"}
@app.get("/fetch")
def fetch(url: str):
    host = urlparse(url).hostname
    if host not in ALLOWED:
        abort(400)
    return requests.get(url, timeout=5).text
```

**CWE:** CWE-918
**Typische Schwere:** High–Critical bei Cloud-Deployments (IMDS-Zugriff).

---

## OWASP 2025-Updates (Draft-Stand)

In der 2025er-Liste haben sich folgende Schwerpunkte verschoben — bei Befunden ist es OK, beide IDs zu nennen:

- **A03:2025 Software Supply Chain Failures** — neu, absorbiert Teile von A06 und A08 (siehe `references/secrets-and-deps.md`).
- **A05:2025 Injection** — XSS ist jetzt explizit unter Injection.
- **A10:2025 Mishandling of Exceptional Conditions** — neu, oft Logik-Bugs in Fehler-Pfaden.

Bei Berichten kann `A03:2021 / A05:2025` als kombiniertes Mapping angegeben werden.
