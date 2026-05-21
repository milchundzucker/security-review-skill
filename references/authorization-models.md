# Authorization Models — RBAC, ABAC, ReBAC

Diese Referenz behandelt komplexe Autorisierungs-Schwachstellen jenseits einfacher "User ist Owner"-Checks. Wichtig für jede Anwendung mit Mehr-Rollen-Modell, Multi-Tenancy oder Resource-Sharing.

## 1. RBAC (Role-Based Access Control)

**Konzept:** User → Rolle → Permissions

**Typische Schwachstellen:**
- Rollen-Inflation: zu viele Rollen, fast jeder wird "Admin" oder "Manager"
- Rollen-Hierarchie nicht erzwungen (Manager kann mehr als Senior, aber Code prüft separat)
- Role-Caching nicht invalidiert nach Rolle-Wechsel
- Rolle als String hardcoded statt Enum

**Patterns:**
```bash
rg "is_admin|isAdmin|isStaff|hasRole" --type py --type js --type java
rg "if\s+user\.role\s*==\s*['\"]" --type py --type js
rg "@PreAuthorize\(['\"]hasRole" --type java
rg "@requires_role\(|@role_required" --type py
```

**Anti-Pattern:** Rolle als String-Vergleich an vielen Stellen statt zentralisierte Permission-Checks:
```python
# UNSICHER — verteilt:
if user.role == "admin" or user.role == "superadmin":
    ...
# Was passiert, wenn neue Rolle "owner" eingeführt wird, die auch admin können soll?

# BESSER:
if user.has_permission("manage_users"):
    ...
```

## 2. ABAC (Attribute-Based Access Control)

**Konzept:** Policy bewertet User-Attribute, Resource-Attribute, Environment.

Beispiel:
```
ALLOW IF user.department == resource.department
       AND time.hour BETWEEN 9 AND 17
       AND user.clearance >= resource.classification
```

**Typische Schwachstellen:**
- Attribute aus User-kontrollierter Quelle (z. B. JWT-Claim, nicht aus DB)
- Policy-Engine fällt bei Fehler auf "DENY" zurück, aber Default ist "ALLOW"
- Time-Based-Conditions ohne Server-Zeit (Client-Zeit als Source)
- Policy-Sprache (OPA Rego, Cedar) erlaubt komplexe Bugs

**Patterns:**
```bash
rg "casbin|opa|cedar|spicedb|openfga" -i
rg "@PolicyEnforcement|@Policy\(" --type java
rg "rego" -g "*.rego"
```

**Audit-Frage:**
- Werden Attribute aus verifizierten Quellen geladen (DB nach Auth) oder aus dem Token (kann veraltet sein)?
- Wenn aus Token: was passiert nach Role-Revoke, bis Token abläuft?

## 3. ReBAC (Relationship-Based Access Control)

**Konzept:** Zugriff über Beziehungen — Google Docs Sharing-Model. Implementiert durch Zanzibar/Spice DB/OpenFGA.

**Typische Schwachstellen:**
- Beziehungs-Updates nicht atomar (Add+Remove in zwei Steps)
- Cache-Inkohärenz (User sieht alte Permissions)
- Predicate-Logic mit Lücken (z. B. "Editor IF user is Owner OR user is in team that has Editor role")
- N+1-Performance-Probleme bei tiefen Hierarchien → DoS

**Patterns:**
```bash
rg "openfga|spicedb|zanzibar|zed-client" -i
rg "writeRelationship|check_relationship" -i
```

## 4. Multi-Tenancy-Isolation

**Pattern:** Mehrere Tenants in einer DB, Trennung per `tenant_id` / `org_id`.

**Klassischer Bug:** WHERE-Klausel ohne Tenant-ID:
```python
# UNSICHER:
@app.get("/api/users/{id}")
def get_user(id: int, current_user: User):
    return db.query(User).get(id)
# User aus Tenant A kann User aus Tenant B sehen.
```

**Patterns:**
```bash
rg "\.objects\.get\(id=|\.query.*get\(.*id\)" --type py | rg -v "tenant|org"
rg "findById\(" --type java -B 5 | rg -v "tenantId|orgId"
```

**Robust:** ORM-Schicht mit automatischem Tenant-Filter:
- Django: Manager mit `get_queryset()` Override
- SQLAlchemy: Event-Listener / Session-Factory pro Tenant
- Hibernate: `@Filter` mit `@FilterDef`
- Row-Level Security (Postgres RLS) — DB-seitige Garantie

```bash
rg "row\s+level\s+security|ENABLE\s+ROW\s+LEVEL\s+SECURITY" -i
rg "CREATE\s+POLICY" --type sql
```

## 5. OAuth / OIDC

### Common Bugs

**Authorization Code Injection:**
- Auth-Code wird ohne PKCE übergeben → kann abgefangen werden (insbesondere Mobile)
- Fehlende `state`-Parameter-Validation → CSRF auf OAuth-Flow

**Token-Audience-Verwechslung:**
- Access-Token für Service A wird gegen Service B verwendet
- ID-Token statt Access-Token verwendet (oder umgekehrt)

**Scope-Overreach:**
- `scope=*` oder zu breite Scopes
- Tokens mit `admin`-Scope für nicht-admin Operationen verwendet

**Patterns:**
```bash
rg "code_challenge\|code_verifier|pkce" -i   # gut, PKCE vorhanden
rg "state\s*=" --type py --type js -B 2 -A 2 | rg "oauth|auth_code"
rg "scope\s*=\s*['\"]\*|scope\s*:\s*['\"]\*" --type py --type js
```

### Open Redirect via OAuth

Wenn `redirect_uri` nicht streng validiert wird:
```
https://auth.example.com/oauth/authorize?client_id=...&redirect_uri=https://evil.com/...
```

```bash
rg "redirect_uri\s*=\s*request" --type py
rg "validate_redirect_uri" --type py  # gut
```

### Implicit Flow (deprecated)

`response_type=token` → Token landet im URL-Fragment → in History, Referer, JS-Leaks. OAuth 2.1 verbietet implicit flow.

```bash
rg "response_type\s*=\s*['\"]token" --type py --type js
```

## 6. SAML-Sicherheit

SAML wird oft in Enterprise-Setups verwendet. Häufige Bugs:

- **Signature Wrapping:** XML-Manipulation mit dupliziertem Element vor Signatur-Element
- **XSW (XML Signature Wrapping)**
- **Comment-Injection:** Email mit `<!---->` darin → manche Parser trennen
- **XXE in SAML-Response** (siehe `web-attacks-advanced.md`)
- **Schwache Signatur-Algorithmen** (SHA1, RSA-PKCS1 v1.5)

**Patterns:**
```bash
rg "python-saml|onelogin\.saml" --type py
rg "OpenSAML" --type java
# Versionen prüfen — viele SAML-Libs hatten CVEs
```

## 7. JWT für Authorization

Wenn JWT-Claims für Authorization verwendet werden:
- **Claim-Mutation nicht erkannt:** User wechselt Rolle, alte JWTs gelten weiter
- **Refresh-Token ohne Permission-Re-Eval**
- **Claim-Storage in JWT statt DB**: bei DB-Updates wird JWT veraltet

**Best Practice:**
- Kurze Access-Token-Lifetime (5-15 min)
- Refresh-Token mit Rotation
- Sensitive Operationen erfordern frische Auth (Re-Auth in den letzten N Minuten)

## 8. Zero Trust / mTLS

Bei Microservice-Architekturen:
- Service A vertraut Service B, weil "ist im selben Netzwerk" → klassisch falsch
- Service-to-Service-Auth über mTLS (jeder Service hat Cert), JWT, oder SPIFFE/SPIRE

**Indikatoren:**
- Service-Mesh konfiguriert (Istio, Linkerd, Consul-Connect)
- mTLS in Service-Configs
- SPIFFE/SPIRE deployed

```bash
rg "mtls|mTLS|client_cert|peer_authentication" -i
rg "spiffe|spire" -i
```

## 9. Anti-Pattern: "Security by Obscurity"

Häufige falsche Annahmen:
- "UUIDs sind unraten" → können trotzdem von berechtigten Usern an unberechtigte weitergegeben werden
- "Endpoint ist nicht dokumentiert" → curl-able, wenn auch nur über Reverse-Engineering
- "Admin-Endpoint ist auf einem anderen Port" → Port-Scan und Vorbei

## 10. Resource-Owner-Trennung

Bei Apps mit "Inhaber" + "Geteilte Nutzer":
- Owner kann Resource löschen, geteilte User nur lesen → korrekt prüfen
- Ownership-Transfer-Flow: was passiert mit alten Sharing-Permissions?
- Soft-Delete: geteilte User sehen gelöschte Resource noch?

## 11. Authorization-Caching

**Falle:**
```python
@cached(ttl=300)
def get_user_permissions(user_id):
    return db.query_permissions(user_id)
```

Nach Permission-Revoke wartet User 5 Minuten auf Wirksamkeit. Bei kritischen Operationen problematisch.

**Mitigation:**
- Cache-Invalidation auf Permission-Change-Events
- Kein Caching für hochsensitive Operationen
- Versionierte Permissions (Cache-Key inkludiert Version, bei Change steigt Version)

---

## Audit-Vorgehen

1. **Authorization-Modell identifizieren** (RBAC / ABAC / ReBAC / Mix?)
2. **Zentrale Authorization-Stellen finden** — Decorators, Middleware, Policy-Engine
3. **Tenant-Isolation prüfen** — alle Queries auf User-/Tenant-Daten haben Filter?
4. **JWT-/Token-Lifecycle prüfen** — Lifetime, Rotation, Revocation
5. **Cross-Tenant-Tests** im Bericht als Audit-Empfehlung
6. **Permissions-Inventur**: welche Rolle hat welche Permissions? — als Anhang

**Im Deep-Audit-Bericht:**
- Sektion "Authorization Model Summary"
- Liste aller Rollen und ihrer Permissions
- Auflistung der Authorization-Defizite
- Empfehlung für Authorization-Tests (mit zwei Test-Accounts)
