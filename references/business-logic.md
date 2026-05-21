# Business Logic & Race Conditions

Diese Referenz fokussiert auf Schwachstellen, die NICHT durch Pattern-Matching gefunden werden können — sie erfordern Verständnis der Domain-Logik. Sie sind aber häufig die kritischsten Befunde, weil sie automatisierte Scanner unterlaufen.

## 1. Klassen von Business-Logic-Flaws

### Insufficient Workflow Validation

**Was:** Mehrstufiger Prozess (z. B. Bestellung → Zahlung → Versand) kann an einer Stelle übersprungen werden.

**Suchen nach:**
- Endpoints, die State-Transitions durchführen, ohne den Vor-State zu prüfen
- "Confirm Order" ohne vorherigen "Place Order" Check
- "Mark as Paid" Endpoint, der vom User aufrufbar ist
- Race zwischen "Reserve" und "Confirm"

**Beispiele:**
- `POST /orders/{id}/ship` ohne Check, ob `status == 'paid'`
- `POST /tickets/{id}/refund` ohne Check, ob `status == 'paid' AND age < 30 days`
- `POST /accounts/{id}/upgrade-tier` ohne Payment-Verification

### Price / Amount Manipulation

**Was:** Preise / Beträge / Mengen aus dem Client-Request übernommen statt server-seitig berechnet.

**Patterns:**
```
rg "price.*request\.|amount.*request\.|total.*req\." --type py --type js
rg "@RequestBody.*price|@RequestBody.*amount" --type java
rg "user_price|client_price|cart\.total\s*=\s*request" -i
```

**Beispiel:**
```python
@router.post("/checkout")
def checkout(items: list[dict]):
    total = sum(item["price"] * item["quantity"] for item in items)
    # ⚠️ "price" kommt vom Client! Angreifer setzt price=0.01
    return charge_card(total)
```

**Sicher:**
```python
@router.post("/checkout")
def checkout(items: list[ItemRequest]):
    # Preis aus DB lookup, nicht aus Request
    total = sum(get_product(i.product_id).price * i.quantity for i in items)
    return charge_card(total)
```

### Quota / Limit Bypass

**Was:** Limits werden nicht auf allen Pfaden enforced.

**Beispiele:**
- Free-Tier-User: max 5 Projekte. Aber `/api/v2/projects/import-bulk` hat keine Check.
- Tageslimit für Abhebungen: 1.000€. Aber `/api/legacy/transfer` hat das Limit nicht.
- Promo-Code: einmal pro User. Aber durch Multi-Account / Race nutzbar mehrmals.

### Sequence-Number-Bypass

**Was:** Aktionen müssen in Reihenfolge erfolgen, Reihenfolge nicht enforced.

**Beispiele:**
- 2FA-Setup: erst Secret generieren, dann verifizieren. Wenn Verify ohne Generate aufrufbar: leeres MFA-Setup, das ohne Code valide ist.
- Password-Reset: Token generiert, dann verwendet. Wenn `verify-token`-Step übersprungen wird, ist `reset-password` direkt aufrufbar.

### Account-Funktions-Missbrauch

**Was:** Features funktionieren technisch korrekt, werden aber außerhalb der Intention genutzt.

**Beispiele:**
- "Refer a friend"-Bonus: User refert sich selbst über Zweit-Account
- "Free trial" pro Email: Wegwerf-Emails / `+alias@`-Tricks
- Loyalty Points: per "Cancel and Reorder" beliebig Punkte sammeln
- Gift-Card-Erstellung mit anschließendem Refund auf Original-Karte (Geld-Verdoppelung)

### Negative Numbers / Edge Cases

```python
@router.post("/transfer")
def transfer(amount: int, to_account: int):
    # Was passiert bei amount = -100? "Transfer" wird umgekehrt!
    debit(current_user.id, amount)
    credit(to_account, amount)
```

**Suchen nach:**
- Numerische Inputs ohne Range-Check
- Integer-Overflow-anfällige Berechnungen
- Float-Rundungsfehler bei Geldbeträgen (immer Decimal verwenden, nie Float!)

```
rg "amount|price|total|quantity" --type py -A 1 | rg "int\(|float\("
rg "BigDecimal|Decimal" --type py --type java  # gut, wenn vorhanden für Geld
```

---

## 2. Race Conditions / TOCTOU

### Klassische Patterns

**TOCTOU (Time-of-Check vs. Time-of-Use):**
```python
def withdraw(user_id, amount):
    balance = get_balance(user_id)        # Time of Check
    if balance >= amount:
        # Race-Window
        deduct_balance(user_id, amount)    # Time of Use
        send_money(user_id, amount)
```

Angreifer sendet 100x parallel `withdraw(user, 100€)` → wenn die Race-Window groß genug ist, gehen alle 100 Requests durch, obwohl nur einmal 100€ Balance da war.

### Suchen nach
```
rg "check.*then.*update|select.*then.*update" -i --type py
rg "if.*balance|if.*quota" --type py -A 5
rg "exists\(\).*\.save\(\)" --type py
```

### Realistische Exploitation
Tools wie `Turbo Intruder` (Burp) können Single-Packet-Attacks senden — alle Requests in einem TCP-Paket → praktisch gleichzeitige Server-Verarbeitung.

### Mitigation

#### Database-Level
- **Optimistic Locking**: `version`-Column, UPDATE-WHERE-version
- **Pessimistic Locking**: `SELECT ... FOR UPDATE` in Transaktion
- **Atomic Operations**: `UPDATE balance = balance - ?` (Datenbank rechnet, nicht Code)
- **Constraints**: `CHECK (balance >= 0)` in DB-Schema

```sql
-- Sicher: atomic
UPDATE accounts SET balance = balance - 100 WHERE user_id = ? AND balance >= 100
-- Wenn 0 rows affected → kein Geld da
```

#### Application-Level
- Distributed Locks (Redis-based: redlock)
- Idempotency Keys (Stripe-Style)
- Queue-basierte Verarbeitung (eine pro User)

### Detection
```
rg "SELECT FOR UPDATE|FOR\s+UPDATE" --type sql --type py
rg "with_for_update|lock_mode" --type py
rg "redlock|redis.*lock" --type py --type js
rg "@Transactional" --type java -A 3
```

---

## 3. Klassische Klassen unentdeckter Race-Conditions

### Login Race

User-Erstellung mit derselben Email parallel → zwei User mit gleicher Email, einer überschreibt.

### Coupon-Race
Coupon mit `usage_count`. Race: zwei parallele Requests sehen `count = 0`, beide erhöhen auf `1`. Aber Coupon eigentlich nur einmal nutzbar.

### File-Upload-Race
Upload-Slot mit `count < 5` Limit. Race: parallel 10 Uploads → alle gehen durch.

### Friend-Request-Race
Sender klickt "Send" zweimal schnell → zwei Friend-Requests in DB.

### Inventory Race
"Last item" Race: zwei Kunden kaufen gleichzeitig, beide bekommen das letzte Stück.

### Password-Reset-Race
Zwei Reset-Tokens parallel angefordert → einer gestohlen ist noch valide.

### MFA-Bypass via Race
MFA-Step und Action-Step parallel: in Race-Window kann Action ohne MFA durchlaufen.

---

## 4. Idempotency

Critical-State-changing Operations brauchen Idempotency-Mechanism:

- `Idempotency-Key`-Header (Stripe-Style)
- DB-Constraint auf Transaction-ID
- Hash der Anfrage als Key

### Detection
```
rg "Idempotency-Key|idempotency_key" --type py --type js -A 3
rg "@Idempotent" --type java
```

### Implementation-Pattern
```python
@router.post("/charge")
def charge(req: ChargeReq, idempotency_key: str = Header(...)):
    cached = redis.get(f"idem:{idempotency_key}")
    if cached:
        return cached  # gleicher Key → gleiche Antwort
    result = process_charge(req)
    redis.setex(f"idem:{idempotency_key}", 86400, result)
    return result
```

---

## 5. Finanztransaktions-spezifische Pitfalls

- **Float für Geldbeträge** — IMMER ein Befund. Decimal / fixed-point verwenden.
- **Negative Transactions** ohne Check (siehe oben)
- **Rounding-Errors aggregierbar**: `+0.001` * 10.000 Aktionen = +10€
- **Currency-Conversion** mit hartcodiertem Kurs
- **Zeitzone-Bugs** bei "Pro Tag"-Limits (UTC vs. lokal — User in UTC-12 hat 36h "pro Tag")
- **DST-Bugs** bei Recurring Charges

```
rg "float\(.*amount|float\(.*price" --type py
rg "Number\(.*amount" --type js
```

---

## 6. State-Machine-Analyse

Wenn die App komplexe Workflows hat:

1. **State-Diagramm extrahieren**: alle möglichen States des Hauptobjekts (Order, Booking, Account).
2. **Transitions identifizieren**: welche Endpoints triggern welche Transitions?
3. **Forbidden Transitions identifizieren**: welche dürfen nicht passieren? (Refund auf nicht-paid Order, Cancel auf shipped Order)
4. **Code-Check**: ist jede Transition serverseitig validiert?

Beispiel Order-State-Machine:
```
draft → submitted → paid → shipped → delivered
                          ↓
                       refunded (nur aus paid)
                          ↓
                      cancelled (nur aus submitted, paid)
```

Forbidden:
- `shipped → cancelled` (Ware schon raus)
- `refunded → paid` (Geld schon zurück)

Im Bericht: State-Diagramm als Tabelle, "Validated"/"Not Validated" pro Transition.

---

## 7. Time-Based Vulnerabilities

### Timing-Side-Channels in Auth
- Passwort-Vergleich mit `==` → siehe `crypto-deep-dive.md`
- "User exists" vs. "User doesn't exist": gleiche Response-Zeit anstreben

### Race-Condition durch Wait
- `time.sleep(1)` in Auth-Code → Race-Window vergrößert sich
- `setTimeout` in Async-Handlers ähnlich

### Cache-Race
- `if not cache.get(key): cache.set(key, compute())` — zwei parallele Threads computieren beide, einer überschreibt.
- Lösung: Lock um Compute.

---

## 8. Distributed-System-Pitfalls

### Eventually Consistent Reads
- Nach `INSERT`: read-after-write nicht garantiert in DBs wie DynamoDB, MongoDB (eventually consistent)
- Auth-relevante Reads brauchen `strong consistency`

### Saga / Transaction Failures
- Multi-Service-Transaktion fehlschlägt mittendrin → Compensating Actions korrekt?
- Refund kommt nicht zurück, weil Service down

### Message-Queues
- "At-least-once delivery": Idempotency nötig
- "At-most-once delivery": Verlust-Risiko
- Dead-Letter-Queues mit sensitive Daten?

---

## 9. Wie man das im Bericht macht

Business-Logic- und Race-Befunde sind oft `Likely` oder `Possible` Konfidenz, weil sie kontextuelles Wissen erfordern. Format:

```
[BL-01] Race Condition in Refund-Endpoint
Severity:    High
Exploitability: External-Auth
Confidence:  Likely
Pattern:     Check-Then-Act ohne Lock

Code-Pfad: src/api/refunds.py:42-58
   if order.status == "paid":      # Check
       process_refund(order)         # Act
       order.status = "refunded"
       db.commit()

Race-Szenario:
1. Angreifer ruft `POST /refund/123` 10x parallel auf
2. Alle 10 Requests lesen `status="paid"` → alle 10 passieren Check
3. Alle 10 verarbeiten Refund
4. Order erhält 10x Refund
   
Mitigation:
- Atomare DB-Operation: UPDATE WHERE status='paid' RETURNING id
- Oder pessimistic lock: SELECT FOR UPDATE
- Plus Idempotency-Key-Pattern
```

Mit konkreter Code-Stelle und konkreter Mitigation — nicht abstrakt.

---

## Mapping

- OWASP A04 (Insecure Design) — primär
- OWASP API6 (Sensitive Business Flows)
- CWE-362 Race Condition, CWE-367 TOCTOU, CWE-840 Business Logic Errors, CWE-841 Improper Enforcement of Behavioral Workflow
- Empfohlene Lektüre: PortSwigger Web Security Academy → "Business logic vulnerabilities" und "Race conditions"
- James Kettle: "Smashing the state machine"
