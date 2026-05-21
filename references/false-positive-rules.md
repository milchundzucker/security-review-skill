# False-Positive-Regeln — Wann ein Befund NICHT gemeldet wird

Diese Referenz ist die wichtigste für das Kernprinzip "keine erfundenen Schwachstellen". Sie listet typische Fälle auf, in denen ein Detection-Pattern matcht, der Code aber NICHT verwundbar ist.

## Goldene Regel

**Ein Pattern-Match ist ein Anfangsverdacht, kein Befund.** Bevor ein Befund in den Bericht aufgenommen wird, müssen drei Fragen mit "ja" beantwortet sein:

1. **Source-Frage:** Kommt der relevante Input tatsächlich aus einer untrusted-Quelle (HTTP-Request, externe API, Datei aus User-Upload, DB-Inhalt der von Users geschrieben wird)?
2. **Sink-Frage:** Erreicht der Input einen echten gefährlichen Sink (SQL-Execution, OS-Command, eval, Filesystem-Write, etc.)?
3. **Mitigation-Frage:** Ist der Pfad zwischen Source und Sink frei von wirksamen Mitigationen (Validation, Escaping, Parametrisierung, Sandboxing)?

Wenn auch nur eine Frage mit "nein" oder "unklar" beantwortet wird → kein Befund, sondern Eintrag in "Hinweise zur weiteren Untersuchung".

---

## Häufige False Positives nach Kategorie

### SQL — wann String-Konkatenation OK ist

- **Konstante Strings**: `db.execute("SELECT 1")` — kein Input, kein Problem.
- **ORM-Builder mit gebundenen Parametern**:
  ```python
  Order.query.filter(Order.status == request.args["s"])  # SQLAlchemy bindet das
  ```
  Hier wird `request.args["s"]` als Parameter gebunden, nicht als String konkateniert.
- **Validierte Whitelist**: `if column in ALLOWED_COLUMNS: f"ORDER BY {column}"` — wenn die Liste statisch ist, ist das sicher.
- **Server-seitig generierte IDs**: `f"SELECT * FROM t WHERE id={uuid_gen()}"` — kein User-Input, kein Problem.

**Vorgehen:** Wenn `execute()` mit String aufgerufen wird, IMMER prüfen, ob der String aus statischen Quellen + Parametern oder aus User-Input zusammengesetzt ist. F-String mit User-Input → Befund. F-String mit konstanten Werten → kein Befund.

### XSS — wann `innerHTML` / `dangerouslySetInnerHTML` OK ist

- Content kommt aus einem CMS / Editor, der bereits HTML-sanitisiert hat (DOMPurify, sanitize-html, Bleach)
- Content ist aus einer Trusted-Source (z. B. Markdown vom selben Author, durch sanitizer gelaufen)
- Framework escaped automatisch (React JSX-Text, Vue text bindings) — Pattern matcht nur in expliziten `dangerouslySetInnerHTML`-Stellen

**Vorgehen:** Prüfen, ob vor dem `innerHTML`-Assignment ein Sanitizer-Aufruf steht.

### Path Traversal — wann `open(user_input)` OK ist

- `secure_filename()` (Werkzeug) wurde vorher aufgerufen
- `os.path.realpath()` wird gegen erlaubte Wurzel geprüft
- User-Input ist ein Lookup-Key, nicht der Pfad selbst:
  ```python
  ALLOWED = {"profile": "/data/profile.json", "logs": "/data/logs.json"}
  open(ALLOWED[request.args["type"]])  # Indirektion, sicher
  ```

### Command Injection — wann `subprocess` mit User-Input OK ist

- `subprocess.run([cmd, arg1, arg2], shell=False)` — Liste mit `shell=False`. Args werden NICHT durch eine Shell interpretiert.
- `shlex.quote()` wurde auf User-Input angewendet
- Input ist gegen Allowlist validiert (z. B. nur ein Enum: "start"/"stop"/"status")

**Achtung:** `shell=True` + Liste ist NICHT sicher — die Shell interpretiert trotzdem.

### Deserialization — wann `pickle.loads` OK ist

- Inhalt kommt nachweisbar aus interner Quelle (Cache des eigenen Services, signed)
- HMAC-Signatur wird vor dem Load verifiziert
- Pickle nur in lokalen Skripten / Tests, nicht in API-Pfaden

### Hardcoded Secrets — wann das kein Secret ist

- Test-/Dev-Fixtures: `password = "test123"` in `/tests/` oder `/fixtures/`
- Beispiel-Werte in Docs: `API_KEY = "your-key-here"`
- Public Keys (sind absichtlich öffentlich)
- Werte, die offensichtlich Platzhalter sind: `"changeme"`, `"REPLACE_ME"`, `"<your-secret>"`

**Vorgehen:** Wert + Pfad + Entropie prüfen. Hoch-Entropie-String in Production-Code → Befund. Niedrig-Entropie-Wort in Test-Code → kein Befund.

### CSRF — wann fehlender Token OK ist

- Endpoint ist eine pure JSON-API, die NUR Bearer-Token aus dem `Authorization`-Header akzeptiert (kein Session-Cookie verwendet). Dann ist CSRF strukturell nicht möglich.
- Endpoint ist `GET`/`HEAD`/`OPTIONS` (idempotent, sollte ohnehin keine State-Changes machen)
- Framework macht es automatisch: Django's `CsrfViewMiddleware` ist global aktiv, einzelne Views ohne explizites `csrf_exempt` sind geschützt

### CORS — wann `*` OK ist

- Public API, die keine Cookies / keine Authentication verwendet (z. B. öffentliche Read-APIs)
- `Access-Control-Allow-Credentials` ist NICHT gleichzeitig auf `true` gesetzt

### Authentication — wann fehlende Auth OK ist

- Health-Endpoints (`/health`, `/ready`) — bewusst öffentlich
- Public-Login-/Registrierungs-Endpoint (paradoxerweise: der MUSS unauthentifiziert sein)
- Webhook-Empfänger mit signaturbasierter Verifikation (HMAC im Header)

### Rate Limiting — wann es OK ist, dass keins im Code steht

- Wird auf Infrastructure-Layer gemacht (NGINX, Cloudflare, AWS WAF) — prüfen, ob `nginx.conf` / Terraform / K8s-Ingress entsprechende Rules hat
- Wird durch API-Gateway gemacht (AWS API Gateway, Kong)

**Vorgehen:** Wenn im Code kein Rate-Limit zu finden ist, vor dem Befund prüfen, ob Infra-Konfig existiert. Sonst: als "Hinweis zur weiteren Untersuchung" markieren.

---

## Framework-spezifische Mitigationen

### Django
- **CSRF**: `CsrfViewMiddleware` ist Default-aktiv → Forms-basierte Endpoints sind geschützt.
- **SQL**: ORM-Querysets sind parametrisiert. Nur `.raw()` und `.extra()` sind gefährlich.
- **XSS**: Template-Engine autoescaped per Default.
- **Mass Assignment**: nicht direkt — Forms/Serializers haben Field-Allowlists.

### Flask + SQLAlchemy
- ORM-Queries sind parametrisiert.
- Jinja2 autoescape ist per Default an für `.html`-Files.
- `flask-wtf` CSRF-Schutz ist OPT-IN, muss aktiviert sein.

### FastAPI + Pydantic
- Pydantic-Models validieren Input — Type-Coercion + Constraint-Validation schon vor dem Handler.
- ORM (SQLAlchemy/SQLModel) wie oben.
- KEIN automatischer CSRF — aber Bearer-Token-Auth macht CSRF strukturell unmöglich.

### Spring Boot
- `@Valid` + Bean Validation: wenn vorhanden, ist Input-Validation gegeben.
- Spring Security: wenn `SecurityFilterChain` konfiguriert ist, geltende Auth-Regel prüfen.
- JPA: Repository-Methoden sind parametrisiert; nur `@Query` mit Konkatenation gefährlich.

### Rails
- ActiveRecord ist parametrisiert.
- ERB autoescaped per Default; `raw()` und `html_safe` sind die Gefahrenstellen.
- CSRF ist global aktiv (`protect_from_forgery`).
- Strong Parameters schützen vor Mass Assignment, WENN sie verwendet werden.

### Express.js (Node)
- KEIN Auto-Escape in Templates standardmäßig — abhängig von Engine (Pug, EJS, Handlebars autoescaped per Default; EJS mit `<%- %>` nicht).
- KEIN Default-CSRF — `csurf` muss explizit eingebunden sein.
- Prüfen, welche Middleware geladen ist: `helmet`, `express-rate-limit`, `express-validator`.

### React / Vue
- JSX-Text-Children und `{{ }}` Mustache sind autoescaped.
- `dangerouslySetInnerHTML` und `v-html` umgehen Escaping — IMMER Befund-Kandidat.

---

## Wann der Befund in "Hinweise zur weiteren Untersuchung" gehört

Statt eines Befunds wird ein Hinweis erstellt, wenn:
- Pattern matcht, aber Source/Sink-Verbindung nicht belegbar ist
- Mitigation könnte greifen, ist aber nicht klar (z. B. WAF könnte Pattern blocken)
- Code ist nicht in einem produktiven Pfad (Tests, Migrations, Tooling)
- Es einen Datenfluss gibt, der menschliche Validierung braucht (Business-Logic)

Format eines Hinweises:
```
- src/handlers/upload.py:78 — `request.files['f'].save(filename)`:
  Filename wird durch `secure_filename` gefiltert (Zeile 76), aber Ziel-Verzeichnis
  ist `/var/www/uploads/` — bitte verifizieren, ob das webserver-reachable & executable ist.
  Nicht als Befund klassifiziert, da Infra-Kontext fehlt.
```

---

## Wenn Unsicherheit bleibt

Das ehrlichste Vorgehen: in den Bericht aufnehmen mit `Konfidenz: Possible` UND mit einer expliziten "What I checked / What I couldn't check"-Notiz. Der menschliche Reviewer entscheidet dann, ob der Befund weiter verfolgt wird.

**Was es nicht heißt:** Konfidenz "Possible" ist KEIN Freischein für Spekulation. Wenn nach dem Mitigation-Check kein konkreter Verdacht mehr besteht, gehört der Punkt NICHT in den Bericht.
