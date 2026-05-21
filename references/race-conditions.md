# Race Conditions & Concurrency Security

Wird geladen, wenn Concurrency-Code erkannt wird: Threads, Async, Locks, Datenbank-Transaktionen, oder Endpunkte mit klassischen Race-Risiken (Wallet, Coupon, Auth, Reservierung).

## TOCTOU (Time-of-Check vs. Time-of-Use)

### Klassisch (Filesystem)

```python
# Anti-Pattern
if not os.path.exists(target):       # CHECK
    with open(target, 'w') as f:     # USE
        f.write(data)
# Zwischen Check und Use kann ein Angreifer die Datei erstellt haben (Symlink-Angriff)
```

**Patterns:**
```
rg "os\.path\.exists.*open\(" --type py
rg "stat.*then.*open" --type py
rg "if\s+exists.*write" --type py --type js
```

**Sicher:** Atomic-Operations: `O_CREAT | O_EXCL` für File-Creation, `link()`-based atomic moves, oder Race-frei mit `tempfile.mkstemp()`.

### TOCTOU in DB

```python
# Anti-Pattern
user = User.query.filter_by(email=email).first()
if user is None:
    db.add(User(email=email))  # zwei parallele Requests → Duplicate
    db.commit()
```

**Sicher:** DB-Unique-Constraints + Exception-Handling, oder `INSERT ... ON CONFLICT` / `INSERT IGNORE`.

## HTTP-Request-Race-Conditions

### Single-Packet Attacks (James Kettle, 2023)

HTTP/2 erlaubt es, mehrere Requests in einem TCP-Paket zu bundle → Backend verarbeitet diese praktisch gleichzeitig, was klassische "ms-Window"-Annahmen unterläuft.

**Klassische Targets:**
- Login mit Rate-Limit (100 Requests in einem Paket umgehen "Max 5 Versuche / min")
- 2FA-Validation (gleiche OTP-Code wird mit verschiedenen Sessions verifiziert)
- Coupon-/Voucher-Einlösung (gleicher Code wird N mal eingelöst)
- Wallet-Withdrawal (Saldo wird negativ)
- Friend-Request-Limits (mehr Friend-Requests gleichzeitig senden)

### Detection im Code

```
rg "rate_limit|Throttle|slowapi|RateLimit" --type py --type js
rg "@app\.(post|put)" --type py -A 10  # Sind kritische Operationen idempotent?
rg "balance|wallet|credit|coupon|voucher" --type py --type js -A 5
```

**Anti-Patterns:**
- Check-then-Act ohne Lock: `if balance >= amount: balance -= amount`
- Rate-Limit als Memory-Counter ohne Atomic-Increment
- "Used"-Flag wird gesetzt NACH der Action statt VOR
- Idempotency-Key fehlt bei kritischen Operationen

### Sicher

Drei Ansätze:

1. **DB-Level (Pessimistic Locking):**
```sql
SELECT balance FROM wallets WHERE user_id=? FOR UPDATE;
-- ... check & update in derselben Transaktion
```

2. **DB-Level (Optimistic Locking mit Version):**
```sql
UPDATE wallets SET balance=?, version=version+1
WHERE user_id=? AND version=? AND balance >= ?;
-- 0 affected rows = Race detected, retry oder Fehler
```

3. **Application-Level Distributed Lock (Redis/Etcd):**
```python
with redlock(user_id, timeout=5):
    # critical section
```

4. **Idempotency-Keys:**
```python
@app.post("/withdraw")
def withdraw(idempotency_key: str):
    if seen_idempotency_key(idempotency_key):
        return previous_result(idempotency_key)
    # process
```

## Authentication Races

### MFA-Bypass via Race

Wenn der Server in einem ersten Schritt "Login OK, MFA pending" markiert und in einem zweiten Schritt MFA validiert — und beide Schritte in separaten Endpunkten sind:
- Angreifer kann ggf. zwischen Schritt 1 und 2 einen anderen Endpoint aufrufen, der bereits "logged in" annimmt
- "MFA-Bypass via Login-Race" — siehe HackerOne-Reports zu prominenten Bug Bounties

### TOTP-Replay

```
rg "totp.*verify|otp.*verify" --type py --type js -A 5
```

Wenn der gleiche OTP-Code mehrmals akzeptiert wird (kein Used-Tracking), kann ein Angreifer einen geleakten Code wiederverwenden.

**Sicher:** Used-Codes in Redis/DB cachen (mit TTL = OTP-Window).

### Session-Creation-Race

Wenn ein User parallel zwei Login-Versuche macht, sollten beide entweder eine gemeinsame Session bekommen, oder die alte invalidiert werden. Bug-Pattern: zwei Sessions, beide gültig, mit unterschiedlichen Permissions (z. B. wenn dazwischen ein Role-Change passierte).

## Workflow-State-Race

```python
# Anti-Pattern: Order kann doppelt fulfilled werden
order = Order.get(id)
if order.status == "paid":
    fulfill(order)
    order.status = "fulfilled"
    order.save()
```

Bei zwei parallel laufenden Worker-Threads ist `fulfill()` zweimal aufgerufen.

**Sicher:**
```python
result = db.execute(
    "UPDATE orders SET status='fulfilling' WHERE id=? AND status='paid'",
    [id]
)
if result.rowcount == 1:
    fulfill_and_complete(id)
```

(State-Transition als atomare DB-Operation.)

## Datenbank-Isolation-Level

Standard-Isolation-Levels und ihre Race-Anfälligkeit:

| Level             | Dirty Read | Non-Repeatable Read | Phantom Read | Race-resistent |
|-------------------|------------|---------------------|--------------|----------------|
| Read Uncommitted  | ✗          | ✗                   | ✗            | nein           |
| Read Committed    | ✓          | ✗                   | ✗            | mäßig          |
| Repeatable Read   | ✓          | ✓                   | ✗            | mittel         |
| Serializable      | ✓          | ✓                   | ✓            | ja             |

Postgres-Default: Read Committed. MySQL/InnoDB-Default: Repeatable Read.

**Pattern:** kritische Geschäftslogik-Transaktionen sollten explizit `SET TRANSACTION ISOLATION LEVEL SERIALIZABLE` setzen oder explizite Locks verwenden.

## Caching-Race

Cache-Stampede: 1000 parallel Requests treffen einen abgelaufenen Cache-Eintrag, alle 1000 bauen das teure Resultat neu.

**Mitigation:** Single-Flight (`golang.org/x/sync/singleflight`, `python-cachetools.lru_cache` thread-safe), oder probabilistic-early-expiration.

## Filesystem-Races (Linux-spezifisch)

### Symlink-Angriffe

```
rg "open\(.*tmp" --type py --type c
rg "tempfile\.mktemp" --type py    # deprecated, RACE-anfällig
```

Klassisch: `/tmp/somefile` wird vom Angreifer durch Symlink auf `/etc/passwd` ersetzt, Service schreibt drauf.

**Sicher:** `O_NOFOLLOW`, `tempfile.mkstemp()` (atomisch).

### Race-on-chmod / chown

```
# Anti-Pattern
touch /var/tmp/secret
chmod 600 /var/tmp/secret    # Zwischen touch und chmod: world-readable
```

**Sicher:** `umask 077` setzen, oder Open mit explizitem Mode (`open(path, O_CREAT|O_EXCL, 0o600)`).

## Async/Concurrency in Programmiersprachen

### Python

```
rg "asyncio|aiohttp|trio" --type py
rg "threading\.Thread|multiprocessing" --type py
rg "lock\(\)|Lock\(\)" --type py -A 3
```

**Patterns:**
- Geteilter State zwischen Tasks ohne Lock
- `dict` als globaler Cache ohne Lock (CPython: meist OK durch GIL, aber kein Garantie)
- async-Code, der sync-blocking I/O macht (DoS, nicht Race, aber wichtig)

### Go

```
rg "go func\(" --type go
rg "sync\.Mutex|sync\.RWMutex|sync\.Map|sync\.WaitGroup" --type go
rg "channel|<-" --type go
```

**Patterns:**
- Race auf map ohne Mutex → `panic: concurrent map writes`
- Closed channel send → panic
- WaitGroup mit `Add()` nach `Go()` start

Test-Pattern: `go test -race ./...` läuft race detector.

### Java

```
rg "synchronized|ReentrantLock|ConcurrentHashMap|AtomicInteger" --type java
rg "@Async|CompletableFuture" --type java
```

- Static Mutable State ohne Lock
- `Vector`/`Hashtable` (slow) vs `Collections.synchronizedList` vs `ConcurrentHashMap`
- Double-Checked-Locking ohne `volatile` (bekannter Bug)

### Rust

Rust verhindert die meisten Races zur Compile-Time. Aber:
- `unsafe`-Blöcke
- FFI-Boundaries
- Cyclic Reference Counts → Memory Leak (kein Race, aber Resource-Leak)

## Logical-Time vs Wall-Clock

```
rg "datetime\.now\(\)|time\.time\(\)|Date\.now\(\)" --type py --type js
```

**Pattern:** Auth-Token-Validation mit Wall-Clock:
```python
if datetime.now() > token.expires_at:
    deny()
```

Wenn die Server-Uhr zurückgestellt wird (NTP-Manipulation, falscher Container-Start), sind alte Tokens wieder gültig.

**Sicher:** Monotonic Clock für relative Zeitmessungen, signed timestamps in tokens.

## Befund-Beispiel

```
[RACE-01] Race Condition in Wallet-Withdrawal
Severity:    High (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N = 6.0)
Exploitability: External-Auth (regulärer User-Account)
CWE:         CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization (TOCTOU)

Evidence:
src/api/wallet.py:42:
  @router.post("/withdraw")
  def withdraw(amount: int, user: User = Depends(current_user)):
      if user.balance < amount:
          raise HTTPException(400)
      user.balance -= amount  # Race window!
      db.commit()
      payout(user, amount)

Angreifer sendet 100 Withdrawal-Requests gleichzeitig (HTTP/2 Single-Packet),
alle prüfen balance==100, alle ziehen 100 ab → 10000 ausgezahlt, balance=-9900.

Action:
@router.post("/withdraw")
def withdraw(amount: int, user: User = Depends(current_user)):
    result = db.execute(
        "UPDATE wallets SET balance = balance - :amt "
        "WHERE user_id = :uid AND balance >= :amt RETURNING balance",
        {"amt": amount, "uid": user.id}
    ).fetchone()
    if not result:
        raise HTTPException(400, "Insufficient balance")
    payout(user, amount)
```

## Mappings

- CWE-362 Concurrent Execution / Race Condition
- CWE-367 TOCTOU
- CWE-364 Signal Handler Race Condition
- CWE-366 Race Condition within a Thread
- CWE-413 Improper Resource Locking
- A04 Insecure Design
- API4 / API6 (für Business-Flow-Races)

## Tooling-Empfehlungen (im Bericht erwähnen)

- Go: `-race` Flag im Test
- Java: Thread Sanitizer, FindBugs, IntelliJ Concurrency-Inspections
- Python: `threading.Lock`, kein direkter Race-Detector, aber `pyflakes`/`mypy` für Type-Confusion
- Rust: Compiler-Garantien
- Allgemein: PortSwigger Lab "HTTP Request Smuggling" + "Single-Packet Attack"
