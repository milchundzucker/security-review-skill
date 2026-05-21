# Language-spezifische Schwachstellen-Patterns

Ergänzung zu OWASP/CWE: sprachspezifische Fallen, die in den generischen Listen oft zu kurz kommen.

## Python

**Sprachfallen:**
- `pickle`, `shelve`, `marshal` — niemals mit Untrusted Input
- `yaml.load()` ohne `SafeLoader` — Code-Execution via `!!python/object/apply`
- `eval()` / `exec()` / `compile()` — niemals mit User-Input
- `assert` für Security-Checks — wird mit `python -O` entfernt!
- f-Strings mit User-Input in SQL/Shell-Kontexten
- `tempfile.mktemp()` ist deprecated und race-anfällig — `mkstemp()` verwenden
- `xml.etree`, `lxml`, `xml.sax` — anfällig für XXE/Billion Laughs, `defusedxml` verwenden
- `requests` ohne `timeout` → SSRF/DoS-Propagation
- `subprocess.run(..., shell=True)` mit Konkat → CMD-Injection

**Frameworks:**
- Flask: `send_file(user_input)` → Path Traversal; `request.args.get('next')` als Redirect → Open Redirect
- Django: `.raw()`, `.extra()` SQL; `mark_safe()` umgeht XSS-Schutz; `eval()` in Templates (nicht möglich, aber Custom-Tags können es)
- FastAPI: Mass Assignment durch `User(**dict)`; fehlende Pydantic-Validation auf nested-Objects

**Patterns:**
```
rg "pickle\.loads?\(|yaml\.load\([^,)]*\)|marshal\.loads" --type py
rg "assert\s+.*request\." --type py
rg "xml\.etree\.|xml\.sax\.|lxml\.etree" --type py | rg -v "defusedxml"
rg "tempfile\.mktemp"
```

## JavaScript / TypeScript

**Sprachfallen:**
- Prototype Pollution: `Object.assign(target, JSON.parse(userInput))`, `_.merge(obj, userObj)` (lodash < 4.17.21)
- `eval()`, `new Function()`, `setTimeout("...string...")`, `setInterval("...string...")`
- `child_process.exec(cmd)` mit Konkat → CMD-Injection; `execFile`/`spawn` mit Array ist sicher
- `vm` module ist KEINE Sandbox — verwenden, dass es Trust-Boundary-tight ist, ist falsch
- `JSON.parse` auf nicht-validierten Input → Memory-DoS bei riesigen Strings
- `==` vs `===` bei Auth-Vergleichen (Type-Confusion)

**Frameworks:**
- Express: `app.use(bodyParser)` ohne Limit; `res.redirect(req.query.next)` → Open Redirect; fehlende Helmet-Middleware
- Next.js: `getServerSideProps` mit `cookies` ohne Verification; API-Routes ohne CSRF
- React: `dangerouslySetInnerHTML`, `href={userUrl}` (`javascript:`-URL-Injection)
- Vue: `v-html`, `:href="user"`

**Patterns:**
```
rg "eval\(|new Function\(|setTimeout\(['\"]" --type js --type ts
rg "child_process\.(exec|execSync)\(.*\+" --type js
rg "Object\.assign\(.*JSON\.parse|_\.merge\(.*req" --type js
rg "dangerouslySetInnerHTML"
rg "href=\{.*req\.|href=\{.*user" --type tsx
```

## Java

**Sprachfallen:**
- `ObjectInputStream.readObject()` mit Untrusted Input → RCE (ysoserial-Klasse)
- `Runtime.getRuntime().exec(cmd)` mit String — Shell wird genutzt; `exec(String[])` ist sicherer
- `XMLDecoder.readObject()` — RCE-Vektor
- SnakeYAML `Yaml.load()` — `SafeConstructor` verwenden
- `MessageDigest.getInstance("MD5")`, `Cipher.getInstance("DES")` — schwache Krypto
- `String.equals()` für Passwort-Vergleich — Timing-Angriff, `MessageDigest.isEqual` verwenden
- `Class.forName(userString)` — Reflection mit User-Input

**Frameworks:**
- Spring: `@RequestParam` ohne Validation; SpEL-Injection in `@Value`-Ausdrücken; Actuator-Endpoints ohne Auth
- Struts: berüchtigt für OGNL-Injection (siehe Equifax)
- Hibernate: `createQuery(userString)` — HQL-Injection; `createSQLQuery` mit Konkat — SQLi
- Jackson: `enableDefaultTyping()` + ungefilterte Polymorphic-Types → RCE

**Patterns:**
```
rg "ObjectInputStream|XMLDecoder|enableDefaultTyping" --type java
rg "Runtime\.getRuntime\(\)\.exec\(" --type java
rg "createQuery\(.*\+|createSQLQuery\(.*\+" --type java
rg "MessageDigest\.getInstance\(\"(MD5|SHA-?1)\"\)" --type java
```

## Go

**Sprachfallen:**
- `template.HTML(userInput)` — umgeht Auto-Escape von html/template
- `text/template` statt `html/template` für Web-Content
- `exec.Command("sh", "-c", userInput)` — CMD-Injection
- `database/sql` mit `fmt.Sprintf` statt Parameter — SQLi
- `gob.NewDecoder().Decode()` mit Untrusted Input
- Race-Conditions: Map-Zugriff ohne Mutex
- Fehlendes Context-Timeout bei HTTP-Calls
- Nil-Pointer-Dereference nach Error-Ignore

**Frameworks:**
- gin/echo: fehlende Middleware-Konfiguration für CSRF, Rate-Limit
- gorilla/mux: ähnlich

**Patterns:**
```
rg "template\.HTML\(" --type go
rg "exec\.Command\(\"sh\"" --type go
rg "fmt\.Sprintf\(.*WHERE|fmt\.Sprintf\(.*SELECT" --type go
rg "gob\.NewDecoder" --type go
```

## C / C++

**Sprachfallen:**
- Klassiker: `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s", ...)` — Buffer Overflow
- Integer Overflow vor Allokation: `malloc(n * sizeof(x))` ohne Check
- Use-After-Free: `free(p)` ohne `p = NULL`
- Format String: `printf(user_input)` statt `printf("%s", user_input)`
- Off-by-One in Schleifen
- `memcpy(dst, src, user_size)` ohne Größencheck
- TOCTOU bei Datei-Operationen

**Patterns:**
```
rg "\b(strcpy|strcat|sprintf|gets|scanf)\s*\(" --type c --type cpp
rg "printf\s*\(\s*[a-z_]+\s*\)" --type c  # Format-String
rg "memcpy\(.*,.*,.*request" --type c
```

## Rust

**Sprachfallen:**
- `unsafe`-Blöcke mit externen Inputs
- `unwrap()` auf User-Input → Panic-DoS
- `serde_yaml::from_str` ohne Limit (Billion Laughs)
- Embedded JS-Eval via `boa`/`v8` ohne Sandboxing
- FFI-Boundary ohne Validation

**Patterns:**
```
rg "unsafe\s*\{" --type rust -A 5
rg "\.unwrap\(\)" --type rust  # massenhaft → potentiell Panic-DoS
```

## PHP

**Sprachfallen:**
- `unserialize($_POST[...])` — RCE via Magic Methods
- `eval($input)`, `assert($input)`, `create_function`
- `include $_GET['page']` → LFI/RFI
- `extract($_POST)` — Variable Hijacking
- `mysql_*` Funktionen (deprecated und unsicher)
- `==` Type Juggling: `"0e123" == "0e456"` ist `true`!

**Frameworks:**
- WordPress: Plugin-Quellen oft anfällig, `wpdb->query()` ohne Prepare
- Laravel: `DB::raw()`, `eval()` in Blade

**Patterns:**
```
rg "unserialize\(\\\$_(POST|GET|REQUEST|COOKIE)"  --type php
rg "eval\(\\\$|assert\(\\\$" --type php
rg "include\s*[\(]?\\\$_" --type php
```

## C# / .NET

**Sprachfallen:**
- `BinaryFormatter.Deserialize` — RCE-Vektor (Microsoft empfiehlt offiziell Migration)
- `Process.Start(cmd)` mit User-Input
- `SqlCommand` mit Konkat statt `Parameters.Add`
- `XmlReader` ohne `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit` — XXE
- `Razor.Parse(userInput)` — SSTI
- `Type.GetType(userString)` — Reflection-Injection

**Frameworks:**
- ASP.NET: `[ValidateAntiForgeryToken]` fehlt; `Request.QueryString` ungefiltert in HTML
- Entity Framework: `FromSqlRaw` mit Konkat

**Patterns:**
```
rg "BinaryFormatter|LosFormatter|NetDataContractSerializer" --type cs
rg "FromSqlRaw\(\$|FromSqlRaw\(.*\+" --type cs
rg "Process\.Start\(.*\+" --type cs
```

## Ruby

**Sprachfallen:**
- `eval`, `instance_eval`, `class_eval`, `send` mit User-Input
- `Marshal.load` (Untrusted) — RCE
- `YAML.load` (Untrusted, vor Ruby 3.1) — Class-Injection
- `Open3.popen3` mit String → Shell-Interpretation
- Mass Assignment ohne `strong_parameters`

**Frameworks:**
- Rails: `find_by_sql` mit Konkat; `params.permit!` (ohne Allowlist); `raw`/`html_safe` in Views

**Patterns:**
```
rg "eval\(|instance_eval\(|class_eval\(" --type ruby
rg "Marshal\.load" --type ruby
rg "params\.permit!" --type ruby
```

---

## Infrastructure as Code (IaC)

### Terraform
- `acl = "public-read"` auf S3-Buckets
- Security Groups mit `0.0.0.0/0` auf sensiblen Ports (22, 3389, 3306, 5432)
- IAM Policies mit `"Action": "*"` und `"Resource": "*"`
- Fehlende Verschlüsselung: `encrypted = false`, fehlendes `server_side_encryption_configuration`
- Hardcoded Provider-Credentials

### Kubernetes
- `privileged: true`
- `hostNetwork: true`, `hostPID: true`
- `runAsUser: 0`, fehlendes `runAsNonRoot: true`
- `allowPrivilegeEscalation: true`
- Fehlende `NetworkPolicy`
- Secrets als Environment-Variablen (besser: als File-Mount mit limited RBAC)

### Dockerfile
- `USER root` oder fehlendes `USER`
- `ADD <url>` statt `COPY` (führt Download zur Buildzeit aus)
- `--privileged` in docker-compose.yml
- Secrets in Build-Args (landen in History)

### GitHub Actions
- Actions ohne SHA-Pinning: `uses: actions/checkout@main`
- `pull_request_target` mit Code-Checkout des PRs (klassischer RCE-Vektor in OSS)
- `secrets.GITHUB_TOKEN` mit zu breiten Permissions (default ist write-all)
- Script-Injection via `${{ github.event.pull_request.title }}` in Shell-Commands

**Patterns:**
```
rg "uses:.*@(main|master|v\d)" .github/workflows/
rg "pull_request_target" .github/workflows/
rg "\${{\s*github\.event\." .github/workflows/  # potentiell Injection
```

---

## Hinweise zur Anwendung

- Wenn die Sprache eines Projekts unklar ist, in Phase 1 zuerst klären. Nicht "auf Verdacht" alle Sprachen prüfen.
- Bei polyglotten Projekten (z. B. Python-Backend + React-Frontend): beide Abschnitte konsultieren.
- Wenn die Sprache hier nicht aufgeführt ist (z. B. Kotlin, Swift, Scala, Elixir): die nächstliegende konsultieren (Kotlin ≈ Java, Swift ≈ ObjC/C, Scala ≈ Java) und sprachspezifische Eigenheiten im Bericht als "ungeprüft" markieren statt zu erfinden.
