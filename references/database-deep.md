# Datenbank-Sicherheit pro Engine

**Wird geladen, wenn** Datenbank-spezifische Treiber/SDKs erkannt werden: `psycopg`, `pg`, `mysql2`, `mysql-connector`, `pymongo`, `mongoose`, `redis`, `ioredis`, `elasticsearch`, `opensearch`, `clickhouse`, `dynamodb`, `cassandra-driver`, `neo4j-driver`, `aerospike`.

Jede Engine hat eigene Injection-Klassen, Auth-Pattern und Defaults. Dieses Modul ergänzt `owasp-top10.md` (A03 Injection) um Engine-spezifische Tiefe.

## 1. PostgreSQL — Row Level Security (RLS)

**CWE-863** — Multi-Tenancy ohne RLS in Postgres ist Standard, aber stark unter-genutzt.

**Detection:**
```bash
rg -n "CREATE POLICY|ENABLE ROW LEVEL SECURITY|FORCE ROW LEVEL SECURITY" --type=sql
rg -n "SET app\\.current_tenant|SET LOCAL" --type=sql --type=py --type=ts
```

**Pattern — RLS richtig anwenden:**
```sql
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;  -- gilt auch für Table-Owner

CREATE POLICY tenant_isolation ON documents
  USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- Im App-Code pro Request:
SET LOCAL app.current_tenant = 'abc-123';  -- LOCAL = nur in Transaction
```

**Anti-Pattern:** RLS aktiv, aber App-User ist `SUPERUSER` oder `BYPASSRLS` → RLS bypassed.

```sql
-- Prüfen:
SELECT rolname, rolsuper, rolbypassrls FROM pg_roles;
```

**Connection-Pooling-Falle:** Bei PgBouncer/Transaction-Pooling überleben `SET LOCAL` nicht zwischen Statements im selben Transaction? → Doch, aber `SET` ohne `LOCAL` leakt zwischen Connections. Immer `SET LOCAL` oder Session-Pool.

## 2. PostgreSQL — Functions / Triggers als SQL-Injection-Vektor

**CWE-89** — `SECURITY DEFINER`-Functions laufen mit Owner-Rechten → privilege escalation.

**Detection:**
```bash
rg -n "SECURITY DEFINER" --type=sql
rg -n "EXECUTE.*\\|\\||EXECUTE format\\(.*%s" --type=sql
```

**Unsafe:**
```sql
CREATE FUNCTION search(q text) RETURNS SETOF docs AS $$
BEGIN
  RETURN QUERY EXECUTE 'SELECT * FROM docs WHERE name LIKE ''%' || q || '%''';
END $$ LANGUAGE plpgsql SECURITY DEFINER;  -- ⚠️ Injection + Privilege Escalation
```

**Safe:**
```sql
CREATE FUNCTION search(q text) RETURNS SETOF docs AS $$
BEGIN
  RETURN QUERY EXECUTE 'SELECT * FROM docs WHERE name LIKE $1' USING '%' || q || '%';
END $$ LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, public;  -- gegen search_path-Hijacking
```

## 3. PostgreSQL — `search_path`-Hijacking

**CWE-427** — Wenn `search_path` `$user, public` ist und ein User eine Schema mit Funktion namens `length()` erstellt → Hijacking.

→ In SECURITY DEFINER Functions IMMER `SET search_path = pg_catalog, public`.

## 4. PostgreSQL — `lo_import` / `lo_export` / `COPY ... TO PROGRAM`

**CWE-78** — Eskalation zu OS-Command-Execution, wenn DB-User die Rechte hat.

**Detection:**
```bash
rg -n "COPY.*FROM PROGRAM|COPY.*TO PROGRAM" --type=sql --type=py --type=ts
rg -n "lo_import|lo_export" --type=sql --type=py
```

**Mitigation:** App-User darf KEIN `SUPERUSER` oder `pg_read_server_files`/`pg_write_server_files` haben.

## 5. PostgreSQL — `current_setting()` als Auth-Layer

Beliebt, aber: `current_setting('app.user_id')` ist ein **String** und prüft KEIN Typ. App muss casten und validieren.

```sql
-- Unsicher
USING (user_id = current_setting('app.user_id'))  -- String-Vergleich, anfällig wenn user_id UUID ist

-- Sicher
USING (user_id = current_setting('app.user_id')::uuid)  -- wirft bei Fehler
```

## 6. MySQL — `LOAD DATA INFILE` / `INTO OUTFILE`

**CWE-78 / CWE-22** — Wenn `FILE`-Privilege beim App-User → File-Read/Write auf DB-Host.

**Detection:**
```bash
rg -n "LOAD DATA|INTO OUTFILE|INTO DUMPFILE" --type=sql --type=py --type=ts
```

**Mitigation:**
- `--local-infile=0` (Server- und Client-seitig)
- App-User nicht `FILE`-privilegiert
- `secure_file_priv` setzen

## 7. MySQL — `sql_mode` & Strict-Mode

**CWE-1284** — Ohne `STRICT_TRANS_TABLES` werden Daten silent truncated. → Auth-Tokens, Hashes, Sicherheits-relevante Felder werden verstümmelt.

```sql
SET GLOBAL sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';
```

## 8. MySQL — Latin1-Collation + Multi-Byte-Bypass

**Klassiker:** `utf8` in MySQL ist nur 3-Byte-UTF-8 → 4-Byte-Zeichen werden truncated. Filter wie `name NOT LIKE '%admin%'` umgangen durch 4-Byte-Zeichen.

```sql
-- Immer:
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
```

## 9. NoSQL — MongoDB Operator Injection

**CWE-943** — JSON-Bodies enthalten Mongo-Operatoren.

**Detection:**
```bash
rg -n "find\\(req\\.body|find\\(req\\.query|find\\(params" --type=ts --type=js
rg -n "\\$where|\\$function|\\$expr" --type=ts --type=js --type=py
```

**Unsafe:**
```javascript
app.post('/login', async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password,  // ⚠️ {$ne: null} bypassed
  });
});
```

**Angriff:**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
```

**Safe — Strict Typing + Sanitization:**
```javascript
import { z } from 'zod';
const LoginSchema = z.object({
  username: z.string().min(3).max(64),
  password: z.string().min(8).max(256),
});
const { username, password } = LoginSchema.parse(req.body);  // wirft bei Objekten

// Zusätzlich: express-mongo-sanitize entfernt $-Keys
app.use(mongoSanitize({ replaceWith: '_' }));
```

## 10. MongoDB — `$where` / `$function` / `$expr` als JS-Injection

**CWE-94** — `$where` führt JavaScript im DB-Prozess aus.

```javascript
// Unsafe
db.users.find({ $where: `this.name == '${userInput}'` });  // RCE in der DB

// Safe — niemals $where mit User-Input. Wenn möglich, ganz deaktivieren:
// mongod --setParameter scriptingEnabled=false
```

## 11. MongoDB — Aggregation-Pipeline Injection

**CWE-943** — `$lookup`, `$out`, `$merge` aus User-Input → schreiben in andere Collections.

**Detection:**
```bash
rg -n "aggregate\\(.*req\\.|aggregate\\(.*body|aggregate\\(.*params" --type=ts --type=js --type=py
```

## 12. MongoDB — Default-Auth

**CWE-1188** — MongoDB Default ist `--noauth` historisch (≤3.x). Auch heute oft falsch konfiguriert.

```bash
# Check:
db.runCommand({usersInfo: 1})
db.adminCommand({getCmdLineOpts: 1})
```

Prüfen:
- `security.authorization: enabled`
- Keine `--bind_ip 0.0.0.0` ohne `--auth`
- Keine User mit `root`-Rolle für App-Use

## 13. Redis — Command Injection

**CWE-94** — Wenn User-Input in Redis-Commands landet:

```javascript
// Unsafe
redis.eval(req.body.script, 0);  // Lua-RCE in Redis

// Unsafe (CRLF-Injection bei Raw-Protocol)
redis.send_command(`SET key${userInput}`);
```

**Safe:** Nur ioredis/node-redis-API verwenden (escaped automatisch), `EVAL` nie mit User-Input.

## 14. Redis — Unsichere Defaults

**CWE-1188** — Redis hat historisch keine Auth. Selbst heute oft fehlkonfiguriert.

**Detection:**
```bash
rg -n "bind 0\\.0\\.0\\.0|protected-mode no|requirepass" -g "redis.conf"
```

**Prüfen:**
- `bind 127.0.0.1 ::1` (nicht `0.0.0.0`)
- `protected-mode yes`
- `requirepass <strong-pw>` ODER ACL-basiert (`user default off`)
- `rename-command FLUSHALL ""`, `CONFIG ""`, `EVAL ""` falls nicht benötigt
- TLS aktiv (`tls-port`)

**Berühmte Exploits:**
- `CONFIG SET dir /var/spool/cron/` + `SAVE` → Cron-RCE
- `MODULE LOAD` → arbiträre Module-RCE

## 15. Redis — Lua-Sandbox-Bypass

**CWE-693** — `EVAL` mit User-Input + Lua-Tricks → siehe Punkt 13. Auch ohne User-Input: einige Redis-Versionen hatten Sandbox-Escapes.

## 16. Elasticsearch / OpenSearch — Query DSL Injection

**CWE-943** — JSON-Query aus User-Input.

**Unsafe:**
```javascript
const result = await es.search({
  index: 'docs',
  body: { query: req.body.query },  // ⚠️ Angreifer kontrolliert komplettes Query
});
// → kann _id-Range, _source-Filter, script_fields setzen
```

**Safe:**
```javascript
const result = await es.search({
  index: 'docs',
  body: {
    query: {
      bool: {
        must: [
          { match: { text: req.body.q } },
          { term: { tenant_id: user.tenantId } },  // erzwungener Tenant-Filter
        ],
      },
    },
  },
});
```

## 17. Elasticsearch — Script-Query als RCE-Vektor

**CWE-94** — `script_score`, `script_fields`, `script` mit User-Input → Java-Code-Execution (Painless).

**Detection:**
```bash
rg -n "script_score|script_fields|\"script\":" --type=ts --type=js --type=py --type=json
```

**Mitigation:** `script.allowed_types: none` oder `inline` deaktivieren, `stored` Scripts mit Allowlist.

## 18. Elasticsearch — `dynamic: true` Mapping → Type-Confusion

**CWE-1284** — Felder werden dynamisch typisiert. Angreifer schickt erstmals `{"price": "free"}` → Mapping wird zu Text → spätere numerische Queries failen oder werden umgangen.

```json
{"mappings": {"dynamic": "strict"}}  // oder "false"
```

## 19. ClickHouse — SQL Injection mit speziellen Funktionen

ClickHouse hat `url()`, `file()`, `s3()` als Tabellen-Functions → SSRF/File-Read via SQL.

**Detection:**
```bash
rg -n "url\\(|file\\(|s3\\(|remote\\(" --type=sql -g "*clickhouse*"
```

**Mitigation:**
- `format_alter_operations_with_parentheses`
- `allow_url_table_function`, `allow_file_table_function` = 0
- User-Profile mit restricted Functions

## 20. DynamoDB — `FilterExpression` ist KEIN Auth

**CWE-863** — `FilterExpression` läuft NACH dem Lesen und nach Capacity-Verbrauch. Wenn AuthZ nur per FilterExpression → Daten werden gelesen, aber nicht ausgegeben. → Internal-Logs / Side-Channels möglich.

```python
# Unsicher (für AuthZ)
table.query(
  KeyConditionExpression=Key('pk').eq('tenant_X'),
  FilterExpression=Attr('owner').eq(user.id),  # ⚠️ filtert, schützt nicht
)

# Sicher: Tenant-Discriminator im PK
table.query(
  KeyConditionExpression=Key('pk').eq(f'tenant_{user.tenant_id}'),
)
```

## 21. DynamoDB — `Scan` ohne Limit

**CWE-770** — Vollscan auf Multi-Million-Row-Table → DoS + hohe Kosten.

```python
# Schlecht
table.scan()

# Besser
table.scan(Limit=100, ExclusiveStartKey=...)
# Noch besser: gar kein Scan, nutze GSI
```

## 22. Cassandra — `ALLOW FILTERING` als Versteckter Performance-Killer

`ALLOW FILTERING` ist ein Code-Smell mit Sicherheitsimplikation: ermöglicht DoS via teure Queries.

```bash
rg -n "ALLOW FILTERING" --type=sql --type=py --type=ts
```

## 23. Neo4j — Cypher Injection

**CWE-943** — Cypher hat eigene Injection-Klasse.

**Unsafe:**
```python
session.run(f"MATCH (u:User {{name: '{name}'}}) RETURN u")
```

**Safe:**
```python
session.run("MATCH (u:User {name: $name}) RETURN u", name=name)
```

## 24. SQLite — `ATTACH DATABASE` / Loadable Extensions

**CWE-829** — `ATTACH DATABASE` mit Pfad aus User-Input → File-Existence-Check. Loadable Extensions → RCE.

```sql
-- Mitigation: SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION = 0
```

## 25. Database Backups als Angriffsoberfläche

**CWE-552** — Backups in S3 ohne Encryption, ohne Bucket-Policy, mit langem History → primärer Datendiebstahl-Vektor.

→ siehe `cloud-security.md` für Bucket-Policies.

## 26. Connection-String-Leaks

**CWE-798** — Connection-String mit Password in Env-Var, Config, oder commit'ed in Repo.

**Detection:**
```bash
rg -n "postgres://[^/]+:[^@]+@|mysql://[^/]+:[^@]+@|mongodb(\\+srv)?://[^/]+:[^@]+@" --type=py --type=ts --type=js --type=yaml
```

→ siehe `secrets-and-deps.md` und `secrets-management-deep.md`.

## 27. TLS für DB-Connections

**CWE-319** — DB-Connection ohne TLS = Klartext auf dem Netz.

**Detection (Postgres):**
```bash
rg -n "sslmode=disable|sslmode=allow|ssl: false" --type=py --type=ts --type=js --type=yaml
```

`sslmode=verify-full` ist die einzig sichere Wahl bei Postgres (verifiziert auch Hostname). `require` verifiziert nicht!

## 28. Read-Replica / Eventual Consistency als Auth-Risiko

**CWE-820** — Auth-Token wird auf Master invalidiert, Read-Replica lagt 100 ms → kurzes Fenster, in dem token noch akzeptiert wird.

**Mitigation:** Auth-Lookups gegen Primary, oder Cache mit kürzerer TTL als Replication-Lag-SLA.

## Severity-Heuristik

| Befund | Default-Severity | Eskalation |
|--------|------------------|------------|
| Mongo `$where` / `$function` mit Input | Critical | confirmed Exploit |
| SQL-Injection via String-Concat | Critical | + öffentlich erreichbar |
| `SECURITY DEFINER` ohne search_path | High | + Admin-Funktion → Critical |
| Redis ohne Auth + offen | Critical |  |
| `COPY FROM PROGRAM` möglich | Critical |  |
| Multi-Tenant ohne RLS/PK-Tenant | High | + Confidential Data → Critical |
| `FilterExpression` als AuthZ | High |  |
| sslmode=require oder schwächer | Medium | + cross-DC → High |
| Connection-String im Repo | Critical | öffentliches Repo |
| `ALLOW FILTERING` öffentlich erreichbar | Medium |  |
| MongoDB ohne Auth + bind 0.0.0.0 | Critical |  |
| ES Script-Query mit Input | Critical |  |
| ClickHouse URL/file/s3 Functions enabled | High |  |
| Cypher Injection | Critical |  |
| Default Latin1 oder utf8 (nicht utf8mb4) | Low | + User-Daten → Medium |

## Referenzen

- CWE-89 (SQL Injection), CWE-943 (NoSQL Injection), CWE-94, CWE-78, CWE-863, CWE-552, CWE-319
- OWASP Database Security Cheat Sheet
- PostgreSQL Security Doc, MySQL Security Doc, MongoDB Security Checklist
- Redis Security Guide, Elasticsearch Security Best Practices
- DynamoDB Best Practices, AWS Well-Architected Security Pillar
