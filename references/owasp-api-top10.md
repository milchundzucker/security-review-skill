# OWASP API Security Top 10 (2023)

Diese Referenz wird geladen, wenn das Projekt eine API ist (REST, GraphQL, gRPC). Sie ergänzt `owasp-top10.md` um API-spezifische Schwachstellen, die in der Web-Liste fehlen oder anders gewichtet sind.

## API1:2023 — Broken Object Level Authorization (BOLA / IDOR)

**Was:** Endpoint operiert auf Objekt-ID aus dem Request, prüft aber nicht, ob der aufrufende User Eigentümer/Berechtigter ist. **Die häufigste API-Schwachstelle überhaupt.**

**Suchen nach:**
- Endpunkte mit ID im Pfad oder Body: `/api/orders/{id}`, `/api/users/{id}/profile`, `{"order_id": ...}`
- Datenbankzugriff per ID OHNE WHERE-Klausel auf Owner: `Order.objects.get(id=...)` statt `Order.objects.get(id=..., user=request.user)`
- GraphQL-Resolver, die ein Objekt zurückgeben ohne Owner-Check
- Hashed/UUID-IDs sind KEIN Schutz — security through obscurity zählt nicht

**Patterns:**
```
rg "objects\.get\(id\s*=|findById\(|findOne\(\{.*id" --type py --type js --type java
rg "@PathVariable.*[Ii]d\b" --type java -A 10  # Spring
rg "@app\.(get|put|delete).*<.*id" --type py -A 10
```

**Unsicher (FastAPI):**
```python
@router.get("/orders/{order_id}")
def get_order(order_id: int, db: Session = Depends(get_db)):
    return db.query(Order).filter(Order.id == order_id).first()
```

**Sicher:**
```python
@router.get("/orders/{order_id}")
def get_order(order_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    order = db.query(Order).filter(Order.id == order_id, Order.user_id == user.id).first()
    if not order:
        raise HTTPException(404)
    return order
```

**Schwere:** Critical bis High, fast immer External-Auth (manchmal External-Unauth, wenn auch Auth fehlt).

---

## API2:2023 — Broken Authentication

**Was:** API-spezifisch oft schlimmer als Web, weil viele APIs eigene Token-Mechanismen bauen.

**Suchen nach:**
- JWT ohne `aud`/`iss`/`exp`-Validation: `jwt.decode(token, key, options={"verify_aud": False})`
- JWT mit `alg: none`: `algorithms=[None]` oder `["HS256", "none"]`
- JWT-Secret hardcoded oder im Repo
- API-Keys ohne Rotation, ohne Scope, im Querystring (`?api_key=...`)
- Refresh-Token ohne Revocation-Mechanismus
- Fehlendes Rate-Limit auf Login/OTP

**Patterns:**
```
rg "jwt\.decode\(" -A 3
rg "algorithms\s*=\s*\[" --type py
rg "api[_-]?key" -i --type yaml --type env
rg "Bearer\s+[A-Za-z0-9._-]{20,}"  # Token-Leaks
```

**Schwere:** Critical, External-Unauth.

---

## API3:2023 — Broken Object Property Level Authorization (BOPLA)

**Was:** Kombiniert die alten "Mass Assignment" (API3:2019) und "Excessive Data Exposure" (API6:2019). Endpoint exponiert oder akzeptiert Felder, die der User nicht ändern/sehen darf.

**Suchen nach:**
- `User(**request.json)`, `user.update(request.json)` — kein Allowlist
- `serializers.ModelSerializer` mit `fields = '__all__'` und ohne `read_only_fields` für sensitive Felder
- API-Responses, die `password_hash`, `mfa_secret`, internal flags zurückgeben
- GraphQL-Schemas, die zu viele Felder per Default exposen

**Patterns:**
```
rg "fields\s*=\s*['\"]__all__['\"]" --type py
rg "\*\*request\.(json|data|body)" --type py
rg "Object\.assign\(.*req\.body" --type js
rg "@RequestBody.*User\s" --type java  # Whole entity binding
```

**Unsicher (Django REST):**
```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # Inkl. is_admin, password_hash!
```

**Sicher:**
```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name']
        read_only_fields = ['id']
```

**Schwere:** High–Critical, External-Auth.

---

## API4:2023 — Unrestricted Resource Consumption

**Was:** DoS-Vektor speziell für APIs. Auch Cost-DoS (jede API-Aufruf kostet $$ in der Cloud).

**Suchen nach:**
- Endpoints ohne Rate-Limit
- Pagination-Parameter ohne Maximum: `limit=999999`
- Bulk-Endpoints ohne Größenlimit: `POST /api/users/bulk` akzeptiert 100k Einträge
- Datei-Upload ohne Größenlimit
- Endpoints, die externe APIs/LLMs aufrufen, ohne User-Quota
- Image-Resize / PDF-Generation per User-Input ohne Limit

**Patterns:**
```
rg "RateLimit|rate_limit|Throttle" -i  # gut, wenn vorhanden
rg "MAX_CONTENT_LENGTH|client_max_body_size"
rg "limit\s*=\s*int\(request" --type py  # potentiell unbeschränkt
```

**Schwere:** Medium–High, External-Unauth oder External-Auth.

---

## API5:2023 — Broken Function Level Authorization (BFLA)

**Was:** Privilegierte Funktionen (Admin-Endpoints) sind erreichbar ohne Admin-Rolle.

**Suchen nach:**
- Admin-Routen, die nur per Pfad unterscheiden (`/api/admin/...`), aber im Handler keine Rollenprüfung haben
- Rollenprüfung im Frontend, fehlend im Backend
- HTTP-Methoden-Verwechslung: `GET /admin/users` ist geschützt, `POST /admin/users` nicht
- Fehlende `@require_role('admin')`-Decorators auf einzelnen Endpoints in einer ansonsten geschützten Klasse

**Patterns:**
```
rg "/admin" -A 5 | rg -v "require_role|is_admin|hasRole|@PreAuthorize"
rg "@router\.(get|post|put|delete).*admin" --type py
```

**Schwere:** Critical, External-Auth.

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

**Was:** Business-Flows (Ticketkauf, Reservierung, Promo-Code-Einlösung) ohne Anti-Automation-Schutz.

**Suchen nach:**
- Endpoints ohne CAPTCHA/Rate-Limit/Behavior-Analysis bei kritischen Aktionen
- Promo-Code-Einlösung ohne Per-User-Limit
- Ticket-/Slot-Reservierung ohne Bot-Schutz
- Multi-Account-Anmeldung ohne Device-Fingerprinting

**Schwere:** Medium–High, business-impact-driven.

---

## API7:2023 — Server Side Request Forgery (SSRF)

→ Siehe `owasp-top10.md` A10. In APIs besonders relevant bei: Webhook-Konfiguration durch User, URL-zu-PDF / URL-zu-Image-Funktionen, Avatar-Import per URL.

---

## API8:2023 — Security Misconfiguration

**Was:** API-spezifisch: CORS, fehlende Security-Header auf API-Responses, ungenutzte HTTP-Methoden offen, ausführliche Error-Responses.

**Suchen nach:**
- CORS-Konfig mit `*` + Credentials: `cors_origins=["*"], allow_credentials=True`
- `Access-Control-Allow-Methods: *`
- Default-Endpoints offen: `/debug`, `/api/docs` in Produktion (manchmal OK, manchmal nicht)
- Fehlende Header: `X-Content-Type-Options`, `Content-Security-Policy`, `Strict-Transport-Security`
- API gibt verbose Errors: `{"error": "psycopg2.errors.UniqueViolation: ..."}`

**Patterns:**
```
rg "allow_origins\s*=\s*\[?['\"]\*"
rg "cors\(\)" --type js -A 3
```

**Schwere:** Medium.

---

## API9:2023 — Improper Inventory Management

**Was:** Veraltete API-Versionen weiter erreichbar, undokumentierte Endpoints (Shadow-APIs), unterschiedlich gehärtete Versionen.

**Suchen nach:**
- `/api/v1/...` Routen, obwohl v2 aktuell ist — sind sie noch erreichbar?
- Endpoints, die im OpenAPI-Spec fehlen
- Staging-/Dev-APIs, die produktiv erreichbar sind
- Fehlende API-Versionierung insgesamt

**Schwere:** Medium, kontextabhängig.

---

## API10:2023 — Unsafe Consumption of APIs

**Was:** Eigener Code vertraut den Antworten externer APIs blind.

**Suchen nach:**
- `response.json()` von externer API direkt in DB geschrieben oder als HTML gerendert
- Fehlende Validation von Webhook-Payloads (kein Signature-Check bei Stripe-/GitHub-Webhooks)
- Open-Redirect-Pattern: externer Service liefert URL, eigener Code redirected ungeprüft
- Fehlende Timeouts / fehlendes Circuit-Breaker für externe Calls (führt zu DoS-Propagation)

**Patterns:**
```
rg "stripe\.Webhook\.construct_event"  # gut, wenn vorhanden
rg "X-Hub-Signature|stripe-signature" -i  # gut bei Webhooks
rg "requests\.(get|post)\(" --type py | rg -v "timeout"
```

**Schwere:** Medium–High, vor allem bei Webhook-Endpoints (External-Unauth).

---

## GraphQL-spezifische Hinweise

Wenn das Projekt GraphQL verwendet, zusätzlich prüfen:

- **Introspection in Produktion aktiv?** → Information Disclosure
- **Query-Depth-/Komplexitäts-Limit?** → DoS via nested queries
- **Batching-Limits?** → 1000 Queries in einem Request möglich → BOLA-Verstärkung
- **Field-Level-Authorization** statt nur Top-Level-Resolver-Auth

**Patterns:**
```
rg "introspection\s*[:=]\s*True|GraphQLPlayground" --type py --type js
rg "max_depth|depth_limit|complexity_limit" -i  # gut, wenn vorhanden
```

---

## gRPC-spezifische Hinweise

- Reflection-API in Produktion (`grpc_reflection`) — Information Disclosure
- TLS-Validierung deaktiviert in Client-Code
- Fehlende Interceptors für Auth
- Streams ohne Größen-/Zeit-Limit
