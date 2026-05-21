# Webhooks & Callbacks — Sicherheit

**Wird geladen, wenn** Webhook-Empfänger oder -Sender erkannt werden: `/webhook`, `/callback`, `Stripe-Signature`, `X-Hub-Signature`, `X-Signature`, `svix`, `Standard Webhooks`, `eventsub`, `incoming-webhook`, `slack/events`.

Webhooks haben spezifische Angriffsklassen: Signaturen müssen verifiziert werden, Replays unterbunden, und ausgehende Webhooks sind SSRF-Vektoren.

## 1. Fehlende Signatur-Verifikation

**CWE-345 / CWE-347** — Critical. Endpoint nimmt jeden POST entgegen → Spoofing.

**Detection:**
```bash
rg -n "app\\.post.*webhook|app\\.post.*callback" --type=ts --type=js --type=py -A 15
rg -n "Stripe-Signature|X-Hub-Signature|X-Signature|X-Webhook-Signature" --type=ts --type=js --type=py
rg -n "constructEvent|verify_webhook|verify_signature" --type=ts --type=js --type=py
```

**Unsafe:**
```typescript
app.post('/webhook/stripe', (req, res) => {
  const event = req.body;  // ⚠️ Body unverifiziert
  if (event.type === 'invoice.paid') {
    grantAccess(event.data.customer);
  }
  res.send('OK');
});
```

**Safe (Stripe-Style mit HMAC-SHA256):**
```typescript
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_KEY!);

app.post('/webhook/stripe',
  express.raw({ type: 'application/json' }),    // raw body, nicht JSON-geparsed!
  (req, res) => {
    const sig = req.headers['stripe-signature'] as string;
    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
    } catch {
      return res.status(400).send('invalid signature');
    }
    handle(event);
    res.send('OK');
  }
);
```

**Generic HMAC-Pattern:**
```typescript
import { createHmac, timingSafeEqual } from 'crypto';

function verifyWebhook(body: Buffer, signature: string, secret: string): boolean {
  const expected = createHmac('sha256', secret).update(body).digest('hex');
  const sigBuf = Buffer.from(signature.replace(/^sha256=/, ''), 'hex');
  const expBuf = Buffer.from(expected, 'hex');
  if (sigBuf.length !== expBuf.length) return false;
  return timingSafeEqual(sigBuf, expBuf);  // konstante Zeit
}
```

**Wichtig:** Body als RAW lesen, NICHT vorher zu JSON parsen. Express `bodyParser.json()` ÄNDERT den Body (key-order, whitespace) → Signatur passt nicht.

## 2. String-Vergleich der Signatur (Timing-Attack)

**CWE-208** — `===` oder `==` für Signatur-Vergleich → Timing-Leak (theoretisch); wichtiger: kein Verteidiger sollte das nutzen müssen, weil `timingSafeEqual`/`hmac.compare_digest` Standard ist.

**Detection:**
```bash
rg -n "signature\\s*===|signature\\s*==|hash\\s*==\\s*expected" --type=ts --type=js --type=py
```

**Safe:**
- Node: `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))`
- Python: `hmac.compare_digest(a, b)`
- Go: `subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1`

## 3. Algorithmus-Confusion / Algorithm-Stripping

**CWE-345** — Manche Webhook-Specs erlauben mehrere Algorithmen (`sha1`, `sha256`, `ed25519`). Wenn Empfänger den Header `X-Signature-Alg` vertraut:

```javascript
// Unsafe
const alg = req.headers['x-signature-alg'];
const hmac = createHmac(alg, secret).update(body).digest('hex');
// Angreifer setzt alg=md4 → kollidierbar
```

**Safe:** Algorithmus serverseitig fest verdrahten.

## 4. Replay-Schutz fehlt

**CWE-294** — Selbst mit Signatur: Angreifer kann valide Webhook-Nachricht replay-en (z.B. „payment.succeeded" mehrfach → mehrfacher Service-Grant).

**Mitigationen:**

**(a) Timestamp + Toleranzfenster:**
```typescript
const ts = parseInt(parsedHeader.timestamp);
if (Math.abs(Date.now() / 1000 - ts) > 300) {  // 5 min Toleranz
  return res.status(400).send('stale');
}
```

**(b) Idempotenz-Key tracken:**
```typescript
const eventId = event.id;  // Stripe gibt evt_xxx
const existing = await db.webhookEvents.findUnique({ where: { id: eventId } });
if (existing) return res.send('already processed');

await db.$transaction(async (tx) => {
  await tx.webhookEvents.create({ data: { id: eventId, type: event.type } });
  await applyEffect(event);
});
```

**(c) Bei state-changing-Webhooks:** Datenbank-Constraint (UNIQUE auf event_id) erzwingen.

## 5. Raw Body vs Re-Serialized Body

**CWE-345** — Framework parsed JSON → mutiert key-order / whitespace → HMAC schlägt fehl ODER (schlimmer) Workaround: man hasht den re-serialisierten Body und vertraut darauf.

**Korrekt:** Raw Body sichern (`bodyParser.raw`), HMAC darauf, ERST DANN parsen.

## 6. SSRF via Ausgehende Webhooks

**CWE-918** — User registriert `webhook_url` → unser Server POSTet dorthin → User gibt `http://169.254.169.254/...` oder `http://localhost:6379/` an.

**Detection:**
```bash
rg -n "webhook_url|callback_url|destination_url" --type=py --type=ts --type=js -A 10
```

**Mitigationen — gestaffelt:**

**(a) URL-Allowlist auf Scheme + Hostname:**
```typescript
function validateWebhookUrl(url: string) {
  const u = new URL(url);
  if (!['https:'].includes(u.protocol)) throw 'https only';
  if (u.username || u.password) throw 'no credentials';
  if (u.port && !['', '443', '8443'].includes(u.port)) throw 'invalid port';
  return u;
}
```

**(b) DNS-Resolution + IP-Range-Check + DNS-Pinning:**
```typescript
import dns from 'node:dns/promises';
import ipaddr from 'ipaddr.js';

async function safeWebhookFetch(url: string, body: any) {
  const u = validateWebhookUrl(url);
  const addrs = await dns.resolve4(u.hostname);
  const validAddrs = addrs.filter(a => ipaddr.parse(a).range() === 'unicast');
  if (validAddrs.length === 0) throw 'no public IP';

  // DNS-Pinning: zur gerade resolvten IP connecten, Host-Header setzen
  return fetch(`https://${validAddrs[0]}${u.pathname}`, {
    method: 'POST',
    headers: { 'host': u.hostname, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}
```

**(c) Egress-Proxy:** Webhook-Sendung über einen separaten Proxy (z.B. `smokescreen` von Stripe), der serverseitig nur Public-IPs erlaubt und Redirects verbietet.

**(d) Redirects verbieten oder revalidieren:**
```typescript
fetch(url, { redirect: 'manual' });
// oder bei Redirect erneuten Range-Check
```

**(e) Im VPC-Setup:** Egress-Security-Group, die nur `0.0.0.0/0` minus RFC1918 minus IMDS erlaubt.

## 7. Webhook-URL als Open-Redirect-Vektor

**CWE-601** — User registriert eigene Webhook-URL und nutzt unseren Server als Reflektor (mit unserer IP) → IP-Whitelisting bei Dritten aushebeln.

**Mitigation:** Webhooks signieren (HMAC mit Server-Identifier) → der Empfänger kann unseren Webhook von Forgeries unterscheiden.

## 8. Long-Running Webhooks → DoS

**CWE-400** — Empfänger antwortet sehr langsam → unser Egress-Pool ist voll.

**Mitigation:**
- Timeout (z.B. 10 s)
- Async-Queue für Webhook-Delivery (nicht synchron)
- Retry mit Exponential Backoff + Jitter + Max-Retries
- Circuit-Breaker pro Webhook-Destination

```typescript
const ctrl = new AbortController();
const t = setTimeout(() => ctrl.abort(), 10_000);
const res = await fetch(url, { signal: ctrl.signal, ... });
clearTimeout(t);
```

## 9. Webhook-Secrets-Rotation

**CWE-321** — Webhook-Secret nie rotiert. Bei Leak → Angreifer kann ewig spoofen.

**Pattern — Dual-Secret-Rotation:**
```typescript
function verifyWithAnySecret(body: Buffer, sig: string, secrets: string[]): boolean {
  return secrets.some(s => verifyWebhook(body, sig, s));
}
// Während Rotation: alte + neue gültig. Nach 24h: alte entfernen.
```

## 10. Signed-Payload-Verification — fehlende Felder

**CWE-345** — Signatur deckt nur ein Teil des Payloads ab (z.B. nur den Body, nicht den Header). Angreifer manipuliert Header.

**Stripe-Pattern:** Signiert wird `<timestamp>.<body>` → Timestamp ist Teil der Signatur. Empfänger MUSS Timestamp-Toleranz prüfen, sonst ist der Timestamp-Schutz wertlos.

## 11. Webhook-Receiver Information Disclosure

**CWE-209** — Bei Signatur-Fehler differenzierte Fehlermeldungen → Oracle für Angreifer.

```typescript
// Unsafe
if (!hasSignature) return res.status(400).send('missing signature');
if (!validAlg) return res.status(400).send('invalid algorithm');
if (!validSig) return res.status(401).send('signature mismatch');

// Safe — uniforme Fehlerantwort
if (!verify(...)) return res.status(400).send('bad request');
```

## 12. Webhook-Storms / Retry-Amplification

**CWE-770** — Wenn unser Webhook-Sender bei jedem Fehler wiederholt, ohne Backoff → Empfänger ist down → wir DoSen ihn weiter.

**Mitigation:** Exponential Backoff + Dead Letter Queue + Alarm.

## 13. Standard Webhooks Spec Compliance

[Standard Webhooks](https://www.standardwebhooks.com/) definiert Best-Practice-Signatur (`webhook-id`, `webhook-timestamp`, `webhook-signature`).

```typescript
import { Webhook } from 'svix';

const wh = new Webhook(secret);
try {
  const event = wh.verify(req.body, req.headers);
} catch {
  return res.status(400).send();
}
```

**Vorteile:** Replay-Schutz inkludiert, Multi-Algorithm-Support, Multi-Key-Rotation.

## 14. GitHub-Webhook-Spezifika

**Header:** `X-Hub-Signature-256` (HMAC-SHA256), `X-GitHub-Event`, `X-GitHub-Delivery`.

```python
import hmac, hashlib

def verify_github(body: bytes, signature_header: str, secret: str) -> bool:
    if not signature_header or not signature_header.startswith('sha256='):
        return False
    expected = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)
```

## 15. Slack-Webhook-Spezifika

**Header:** `X-Slack-Signature` + `X-Slack-Request-Timestamp`.

```python
import hmac, hashlib, time

def verify_slack(body: bytes, ts: str, sig: str, secret: str) -> bool:
    if abs(time.time() - int(ts)) > 60 * 5:
        return False
    base = f'v0:{ts}:{body.decode()}'
    expected = 'v0=' + hmac.new(secret.encode(), base.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)
```

## 16. Twilio / Square / Shopify — eigene Schemas

Jeder Anbieter nutzt eigenes Format. Wichtige Regel: **Anbieter-eigene SDK-Verifikation nutzen**, nicht selbst nachbauen.

## 17. Inbound Webhooks ohne CSRF-Protection

Webhook-Endpoints sind public, akzeptieren POST mit JSON. Wenn ein Browser dorthin POSTed (Form mit `application/x-www-form-urlencoded` → SimpleRequest):
- Verifikation schlägt fehl (Body-Format unterschiedlich)
- Aber: Logging-DoS, oder bei laxer Implementation: doch verarbeitet

**Mitigation:** Content-Type `application/json` erzwingen.

## 18. Webhook-Endpoints als Reconnaissance-Vektor

**CWE-209** — `/webhook/stripe` → 200 OK (Signature fail still 200) leakt Existenz von Stripe-Integration. Eher unkritisch, aber:

**Empfehlung:** Nicht-existente Webhook-Pfade dasselbe Verhalten zeigen lassen wie existente (uniformer 400er).

## 19. Webhook-Logs — PII / Secret-Leak

**CWE-532** — Webhook-Bodies oft mit PII oder Credit-Card-Token. Werden 1:1 geloggt → Compliance-Verstoß.

**Mitigation:** Redaction-Layer im Logger (siehe `logging-monitoring.md`).

## 20. Webhook-Endpoint-Inventarisierung

**Audit-Anforderung:** Welche Webhooks sind aktiv? Welche Secrets? Wer hat Zugriff?

→ Webhook-Registry (zentrales Audit-Logging).

## Severity-Heuristik

| Befund | Default-Severity | Eskalation |
|--------|------------------|------------|
| Keine Signatur-Verifikation | Critical | + auth/payment-Effekt |
| String-Equal statt timingSafe | Low | theoretisch, oft mit dem nächsten Befund kombiniert |
| Replay-Schutz fehlt | High | + idempotenz-kritisch (Geld!) → Critical |
| SSRF-Sink via Webhook-URL | Critical |  |
| Raw-Body nicht verwendet | High |  |
| Algorithm-Confusion möglich | High |  |
| Open-Redirect via Webhook | Medium | + IP-Whitelisting umgehbar → High |
| Secret nicht rotierbar | Medium |  |
| Webhook-Body geloggt mit PII | Medium | + PII/PCI → High |
| Kein Timeout / DoS-Risk | Medium |  |
| Webhook-Storm-Risk (kein Backoff) | Low | + öffentlich → Medium |

## Referenzen

- CWE-345 (Insufficient Verification of Data Authenticity)
- CWE-347 (Improper Verification of Cryptographic Signature)
- CWE-294 (Authentication Bypass by Capture-replay)
- CWE-918 (SSRF), CWE-601 (Open Redirect)
- Standard Webhooks Spec (https://www.standardwebhooks.com/)
- Stripe / GitHub / Slack / Twilio Webhook-Security-Docs
- OWASP API Security Top 10 (API3:2023 — Broken Authentication)
