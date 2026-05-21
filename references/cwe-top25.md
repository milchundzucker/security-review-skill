# CWE Top 25 — Most Dangerous Software Weaknesses (2024)

Diese Referenz fokussiert auf CWE-IDs, die in der MITRE CWE Top 25 stehen und im OWASP Top 10 nicht oder nur am Rand abgedeckt sind. Es gibt Überlappungen — in dem Fall verweisen wir auf `owasp-top10.md`.

## Stack-Ranking 2024 (vereinfacht)

| Rang | CWE-ID  | Name                                          | Abdeckung                  |
|------|---------|-----------------------------------------------|----------------------------|
| 1    | CWE-79  | Cross-Site Scripting (XSS)                    | → `owasp-top10.md` A03     |
| 2    | CWE-787 | Out-of-bounds Write                           | hier                       |
| 3    | CWE-89  | SQL Injection                                 | → A03                      |
| 4    | CWE-352 | Cross-Site Request Forgery (CSRF)             | hier                       |
| 5    | CWE-22  | Path Traversal                                | hier (Detail)              |
| 6    | CWE-125 | Out-of-bounds Read                            | hier                       |
| 7    | CWE-78  | OS Command Injection                          | → A03                      |
| 8    | CWE-416 | Use After Free                                | hier                       |
| 9    | CWE-862 | Missing Authorization                         | → A01                      |
| 10   | CWE-434 | Unrestricted Upload of File with Dangerous Type | hier                     |
| 11   | CWE-94  | Code Injection                                | hier (Detail eval/Template) |
| 12   | CWE-20  | Improper Input Validation                     | hier                       |
| 13   | CWE-77  | Command Injection                             | → A03                      |
| 14   | CWE-287 | Improper Authentication                       | → A07                      |
| 15   | CWE-269 | Improper Privilege Management                 | hier                       |
| 16   | CWE-502 | Deserialization of Untrusted Data             | → A08                      |
| 17   | CWE-200 | Exposure of Sensitive Information             | hier                       |
| 18   | CWE-863 | Incorrect Authorization                       | → A01                      |
| 19   | CWE-918 | SSRF                                          | → A10                      |
| 20   | CWE-119 | Improper Restriction of Memory Buffer         | hier                       |
| 21   | CWE-476 | NULL Pointer Dereference                      | hier                       |
| 22   | CWE-798 | Use of Hard-coded Credentials                 | → `secrets-and-deps.md`    |
| 23   | CWE-190 | Integer Overflow or Wraparound                | hier                       |
| 24   | CWE-400 | Uncontrolled Resource Consumption             | hier                       |
| 25   | CWE-306 | Missing Authentication for Critical Function  | → A07                      |

Im Folgenden werden die Punkte mit "hier" detailliert.

---

## CWE-787 / CWE-125 / CWE-119 / CWE-416 — Memory Safety (C/C++/Rust unsafe)

**Relevant bei:** C, C++, Rust `unsafe`-Blöcke, Cython, alte Embedded-Codebases.

**Suchen nach:**
- `strcpy`, `strcat`, `sprintf`, `gets` — klassisch unsicher
- `memcpy` mit User-kontrollierter Länge
- Manuelles Pointer-Arithmetic ohne Bounds-Check
- `unsafe { ... }` in Rust mit externen Inputs
- Fehlende Null-Checks vor Dereferenzierung

**Patterns:**
```
rg "\b(strcpy|strcat|sprintf|gets)\b" --type c --type cpp
rg "unsafe\s*\{" --type rust
```

**Mitigation:** `strncpy_s`, `snprintf` mit Größencheck, `std::string` statt `char*`, Rust ohne `unsafe`.

**Typische Schwere:** High–Critical bei Network-facing C/C++.

---

## CWE-352 — Cross-Site Request Forgery (CSRF)

**Was:** Authentifizierter User wird unbewusst dazu gebracht, einen State-changing Request auszuführen.

**Suchen nach:**
- `@app.post`, `@app.put`, `@app.delete` ohne CSRF-Schutz
- Form-Submits ohne CSRF-Token
- SameSite-Cookie nicht auf `Lax`/`Strict`
- CSRF-Schutz deaktiviert: `WTF_CSRF_ENABLED = False`, `csrf_exempt`, `@csrf.exempt`

**Patterns:**
```
rg "csrf_exempt|CSRF_ENABLED\s*=\s*False"
rg "SameSite\s*=\s*None|sameSite\s*:\s*['\"]none"
rg "@app\.(post|put|delete)" -A 5 | rg -v "csrf_token|CSRFProtect"
```

**Mitigation:** CSRF-Token (Synchronizer Pattern, Double-Submit), `SameSite=Lax/Strict`, für reine APIs: `Bearer`-Token aus `Authorization`-Header (nicht aus Cookies).

**Schwere:** Medium–High, External-Auth.

---

## CWE-22 — Path Traversal (Detailbetrachtung)

**Was:** User-Input wird ohne Validierung in einen Dateipfad eingebaut.

**Suchen nach:**
- `open(base + user_input)`, `Path(base) / user_input`
- `send_file(user_input)`, `StaticFiles` mit User-Pfad
- Archiv-Entpackung ohne Zip-Slip-Schutz (`ZipFile.extractall()` ohne Pfadvalidierung)

**Patterns:**
```
rg "open\(.*request\." --type py
rg "send_file\(.*request\." --type py
rg "extractall\(" --type py
rg "fs\.(readFile|createReadStream)\(.*req\." --type js
```

**Sicher:** Pfad normalisieren (`os.path.realpath`, `path.resolve`) und prüfen, dass er innerhalb des erlaubten Wurzelverzeichnisses liegt.

**Schwere:** High, oft External-Auth.

---

## CWE-434 — Unrestricted File Upload

**Was:** Datei-Upload ohne Validierung von Typ/Größe/Inhalt.

**Suchen nach:**
- `request.files['...']` ohne Validierung
- `file.save(filename)` mit `filename` direkt aus Request
- Fehlende MIME-Type-Prüfung (nur Endung geprüft)
- Upload-Verzeichnis ist webserver-reachable + executable (z. B. `public/uploads/` für `.php`)

**Patterns:**
```
rg "request\.files|req\.files" --type py --type js
rg "secure_filename" --type py  # gut, wenn vorhanden
rg "multer\(\)" --type js -A 5
```

**Mitigation:** `werkzeug.utils.secure_filename`, Whitelist erlaubter MIME-Types (per Magic Bytes, nicht nur Endung), Speicherort außerhalb des Webroots, Größenlimit.

**Schwere:** Critical bei RCE-Pfad (Upload → Execution).

---

## CWE-94 — Code Injection (eval / Template / Expression)

**Was:** Beyond OS-Command-Injection: dynamische Auswertung von User-Input als Code.

**Suchen nach:**
- `eval(user_input)`, `exec(user_input)`, `compile(user_input)`
- Server-Side Template Injection (SSTI): Jinja2 `Template(user_input).render()`, Velocity, Freemarker, Twig mit User-Input
- Expression-Languages: SpEL, OGNL (Struts!), MVEL
- `Function('"use strict"; ' + user)` in JS

**Patterns:**
```
rg "Template\([^\)]+request" --type py
rg "new\s+Function\(" --type js
rg "\.eval\(|\.evaluate\(" --type java
rg "\#\{.*request" --type java  # SpEL/OGNL
```

**Schwere:** Critical, fast immer External-Unauth wenn Endpoint exponiert.

---

## CWE-20 — Improper Input Validation

**Was:** Sammelkategorie. Hier vor allem: Type-Confusion, fehlende Range-/Format-Checks.

**Suchen nach:**
- Fehlende Pydantic-Models / JSON-Schema-Validation an API-Eingängen
- `int(request.args['x'])` ohne Range-Check
- Mass Assignment: `User(**request.json)` ohne Allowlist
- Polyglot-Akzeptanz: Endpoint akzeptiert JSON und XML — XML wird mit unsicherem Parser geparst

**Patterns:**
```
rg "User\(\*\*request" --type py
rg "Object\.assign\(.*req\.body" --type js
rg "setProperty\(.*request" --type java  # mass assignment
```

**Schwere:** Medium–High, abhängig vom Sink.

---

## CWE-269 — Improper Privilege Management

**Was:** Privilege Escalation durch fehlerhafte Rechtevergabe.

**Suchen nach:**
- `chmod 777`, `setuid`, `runas root` in Skripten
- Container mit `--privileged`, K8s-PodSpec mit `privileged: true`, `runAsUser: 0`, fehlendes `securityContext`
- AWS-IAM-Policies mit `"Action": "*", "Resource": "*"`
- Sudo-Konfigurationen mit `NOPASSWD: ALL`

**Patterns:**
```
rg "chmod\s+777"
rg "privileged:\s*true" --type yaml
rg "runAsUser:\s*0" --type yaml
rg "\"Action\":\s*\"\*\"" --type json
```

**Schwere:** High–Critical.

---

## CWE-200 — Exposure of Sensitive Information

**Was:** Sensible Daten landen unbeabsichtigt in Responses / Logs / Error Messages.

**Suchen nach:**
- `return jsonify(user.__dict__)` — alle Felder, inkl. Hash
- Stack Traces in API-Responses (siehe A05)
- Auflistung interner Pfade, DB-Schema in Fehlermeldungen
- Debug-Endpoints in Produktion (`/_debug/`, `/health` mit zu viel Detail, `phpinfo()`)
- Git-Verzeichnis (`.git/`) im Webroot
- Source Maps in Produktion

**Patterns:**
```
rg "jsonify\(.*__dict__\)" --type py
rg "to_dict\(\)" --type py  # prüfen, ob Felder gefiltert werden
rg "phpinfo\(\)" --type php
```

**Schwere:** Medium, kontextabhängig High.

---

## CWE-190 — Integer Overflow

**Relevant bei:** C/C++, Rust ohne Checked Arithmetic, Solidity (vor 0.8), kritische Berechnungen in Finanz-/Krypto-Code.

**Suchen nach:**
- Arithmetik auf User-Input ohne Bounds-Check
- Solidity < 0.8 ohne SafeMath
- `size_t` Berechnungen, die in Allokationen fließen

**Patterns:**
```
rg "pragma solidity \^0\.[0-7]"
rg "SafeMath" --type sol  # gut, wenn vorhanden in alten Versionen
```

**Schwere:** Variabel, bei DeFi-Smart-Contracts Critical.

---

## CWE-400 — Uncontrolled Resource Consumption (DoS)

**Was:** Server kann durch teure Operationen erschöpft werden.

**Suchen nach:**
- Regex-Patterns mit Catastrophic Backtracking (ReDoS): `(a+)+`, `(a|a)*`, `(.*)*`
- Unbeschränkte Loops über User-Input-Größe
- Datei-Upload ohne Größenlimit
- Zip-Bomb-Anfälligkeit: rekursives Entpacken ohne Limit
- LLM-Token-Limits fehlen (siehe `owasp-llm-top10.md`)
- Pagination fehlt — User kann `limit=999999999` setzen

**Patterns:**
```
rg "\(\.\*\)\*|\(\.\+\)\+|\([^)]+\+\)\+"  # mögliches ReDoS
rg "MAX_CONTENT_LENGTH" --type py  # gut, wenn vorhanden
rg "limit\s*=\s*request" --type py  # potentiell unbeschränkt
```

**Schwere:** Medium, bei kritischen Pfaden High.

---

## CWE-476 — NULL Pointer Dereference

**Relevant bei:** C/C++, Go (nil-Pointer), Java (NPE als Crash-Vektor).

**Suchen nach:**
- Rückgabewerte von `malloc`, `calloc` ohne NULL-Check
- Go: Pointer-Dereferenzierung direkt nach Funktion ohne Error-Check
- Java: Optional.get() ohne isPresent()

**Schwere:** Low (Crash), Medium wenn DoS-Vektor.

---

## Hinweise zur Anwendung

- Bei jedem Befund **CWE-ID** und **OWASP-Kategorie** angeben (Doppel-Mapping).
- CWE-Beschreibungen sind oft generisch — im Bericht den konkreten Code-Pfad zitieren, nicht die CWE-Definition kopieren.
- Bei Sprachen mit Memory Safety (Python, Go, JS, Java, C#, Rust safe) sind CWE-787/125/416/476 meist nicht anwendbar — explizit als "nicht zutreffend" markieren, statt zu erfinden.
