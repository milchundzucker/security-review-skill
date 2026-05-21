# E-Mail- und DNS-Sicherheit

**Wird geladen, wenn** Email-Versand-Code, DNS-Configuration oder Sub-Domain-Setups erkannt werden: `nodemailer`, `smtplib`, `sendgrid`, `ses`, `mailgun`, `postmark`, `resend`, `aws-sdk/client-route-53`, `cloudflare`, `dnspython`, `*.tf` mit DNS-Records.

E-Mail- und DNS-Schwachstellen werden oft übersehen, sind aber Hauptvektor für Phishing, Domain-Hijacking und Account-Takeover-Ketten.

## 1. SPF Record Missing or Misconfigured

**CWE-290** — Domain ohne SPF erlaubt jedem Mail-Server, in deinem Namen zu senden.

**Detection:**
```bash
dig +short TXT example.com | grep -i spf
# Erwartet: "v=spf1 include:_spf.google.com -all"
```

**Häufige Fehler:**
- Kein SPF (Domain offen für Spoofing)
- `+all` (akzeptiert ALLES) — Critical
- `?all` (neutral) — keine Schutzwirkung
- `~all` (softfail) — geringer Schutz; `-all` (hardfail) empfohlen
- DNS-Lookup-Limit überschritten (max. 10 nested lookups) → SPF wird PERMERROR → Mails landen im Spam ODER werden akzeptiert (je nach Empfänger)

**Beispiel (sicher):**
```
example.com. TXT "v=spf1 include:_spf.google.com include:mailgun.org -all"
```

## 2. DKIM Missing, Weak Key, or Replay-Anfällig

**CWE-347** — Ohne DKIM kann Mail nicht authentifiziert werden. Schlüssel < 2048 Bit ist veraltet.

**Detection:**
```bash
dig +short TXT selector1._domainkey.example.com
```

**Häufige Fehler:**
- 1024-Bit-Schlüssel (heute zu schwach)
- Alter Key nie rotiert
- Mehrere Selektoren, alte nicht entfernt → Replay-Risk
- Body-Hash deckt nicht `l=` (Length-Tag) ab → DKIM-Replay-Angriff

**Best Practice:**
- 2048-Bit RSA oder Ed25519
- Jährliche Key-Rotation
- Mehrere Selektoren mit Rolling-Updates
- `l=` Tag NICHT verwenden (sonst kann Inhalt angehängt werden ohne Signature-Break)

## 3. DMARC Fehlt oder Auf `p=none`

**CWE-290** — DMARC verbindet SPF/DKIM mit Empfänger-Policy. Ohne DMARC = keine Empfänger-seitige Enforcement.

**Detection:**
```bash
dig +short TXT _dmarc.example.com
```

**Stufen:**
- `p=none` — nur monitoring, kein Schutz (Startpunkt)
- `p=quarantine` — verdächtige Mails in Spam
- `p=reject` — Ziel-Zustand: Spoofed Mails werden abgelehnt

**Best-Practice-DMARC-Record:**
```
_dmarc.example.com. TXT "v=DMARC1; p=reject; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com; pct=100; adkim=s; aspf=s; fo=1"
```

`adkim=s` und `aspf=s` (Strict-Alignment) sind sicherer als `r` (Relaxed).

## 4. Sub-Domain Without DMARC (`sp=`)

**CWE-290** — Hauptdomain hat DMARC, aber `sp=` (Sub-Policy) fehlt → Sub-Domains spoofbar.

```
v=DMARC1; p=reject; sp=reject; ...
```

## 5. MTA-STS und TLS-RPT Missing

**CWE-319** — MTA-STS erzwingt TLS zwischen Mailservern, TLS-RPT meldet Probleme.

**Detection:**
```bash
dig +short TXT _mta-sts.example.com
curl https://mta-sts.example.com/.well-known/mta-sts.txt
dig +short TXT _smtp._tls.example.com
```

**Beispiel `mta-sts.txt`:**
```
version: STSv1
mode: enforce
mx: mx1.example.com
mx: mx2.example.com
max_age: 604800
```

## 6. BIMI (Brand Indicators) — Vorteil bei DMARC=reject

Nice-to-have, signalisiert Empfängern Authenticity:
```
default._bimi.example.com. TXT "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
```

## 7. Email-Header-Injection in App-Code

**CWE-93 / CWE-93 (CRLF)** — User-Input direkt in Email-Header.

**Detection:**
```bash
rg -n "setHeader|set_header|headers\\[" --type=py --type=ts --type=js -A 3 | rg -B 1 "req\\."
rg -n "sendmail\\(.*req|send_mail\\(.*req|mail\\(.*\\$_" --type=php
```

**Unsafe:**
```python
def send_reset(email):
    msg['Subject'] = f'Reset for {email}'  # ⚠️ email enthält \r\nBcc: angreifer@evil.tld
    msg['To'] = email
    smtp.send_message(msg)
```

**Safe:**
```python
import re
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')

def send_reset(email):
    if not EMAIL_RE.match(email):
        raise ValueError('invalid email')
    if '\r' in email or '\n' in email:
        raise ValueError('header injection attempt')
    msg['Subject'] = f'Reset for {email}'
    msg['To'] = email
    smtp.send_message(msg)
```

## 8. HTML Email — XSS / Clickjacking im Email-Client

**CWE-79** — Manche Mail-Clients (Webmail) rendern HTML. Wenn unverified User-Content in HTML:
- `<script>` (meist gestrippt, aber Bypass möglich)
- `<style>` Injection
- `<base>`-Tag-Hijacking ändert relative URLs

**Safe:** HTML-Sanitization vor Versand (`DOMPurify` serverseitig, `bleach` in Python).

## 9. Email Address Enumeration

**CWE-204** — Login / Forgot-Password leakt, ob Email registriert ist.

**Symptome:**
- "User exists" vs "user not found"
- Unterschiedliche Response-Zeiten
- Unterschiedliche Status-Codes

**Mitigation:**
```python
async def request_reset(email):
    user = await find_user(email)
    if user:
        await send_reset_link(user)
    # IMMER dieselbe Response, IMMER ähnliche Zeit (artificial delay):
    await asyncio.sleep(random.uniform(0.5, 1.5))
    return {'message': 'If account exists, reset email sent'}
```

## 10. Reset-Link-Token Im Klartext-Mail

**CWE-319** — Mail ist Plain-Text-Protokoll. Token mit hoher Entropie & kurzer Lebensdauer ist Pflicht. Außerdem: nicht in `?token=` in der URL (Referer-Leak — siehe `web-advanced.md`), sondern in POST-Form ODER mit Token-Confirmation-Schritt.

## 11. SPF-Lookup-Limit Überschritten

**CWE-1284** — Mehr als 10 DNS-Lookups in SPF → PERMERROR. Manche Empfänger behandeln das als „kein SPF" → wieder spoofbar.

**Detection:** SPF-Checker (`https://www.dmarcanalyzer.com/spf/checker/`).

**Mitigation:**
- SPF-Flattening (mit Vorsicht — bricht bei Anbieter-IP-Wechsel)
- Macros vermeiden
- Unnötige `include:` entfernen

## 12. Sub-Domain Takeover

**CWE-345** — DNS-CNAME zeigt auf nicht mehr existierenden Cloud-Service → Angreifer registriert den Service → kontrolliert Sub-Domain → Cookies (`Domain=.example.com`), SAML-ACS-URL, etc.

**Detection:**
```bash
# Pro Sub-Domain CNAME prüfen
dig +short cdn.example.com
# Wenn CNAME auf z.B. s3-website-... und Bucket nicht existiert → Takeover möglich
```

**Klassische verwundbare Provider:** GitHub Pages, S3, Azure CDN, Heroku, Fastly, Cloud Run, Netlify, AWS Elastic Beanstalk, Shopify.

**Mitigation:**
- DNS-Records mit Lifecycle-Management koppeln
- Regelmäßiges Audit (z.B. mit `nuclei`, `subjack`)
- IaC: DNS-Records mit Resource-State koppeln (Terraform Output → Route53)

## 13. Dangling NS / DNSSEC-Misconfig

**CWE-345** — NS-Records zeigen auf abgelaufene Domain → Domain-Hijack.

**DNSSEC:**
- Signiert DNS-Antworten → Schutz gegen DNS-Spoofing
- KSK / ZSK Key-Rotation
- DS-Records am Registrar
- Empfehlung: aktiv, wenn Mail/DNS sicherheitskritisch

## 14. DNS-Rebinding

**CWE-350** — Web-Browser cached DNS kurz; Server-Side-Fetch resolved jedes Mal neu. Angreifer setzt TTL=0 und wechselt zwischen Public-IP und 169.254.169.254 → Bypass von Host-Allowlist.

**Mitigation:**
- DNS-Pinning serverseitig
- Egress-Proxy (Smokescreen)
- siehe `webhooks-callbacks.md` Punkt 6 und `web-advanced.md`

## 15. CAA Records — Certificate Authority Authorization

**CWE-295** — CAA-Records bestimmen, welche CAs Zertifikate für die Domain ausstellen dürfen. Ohne CAA = jede CA darf.

```
example.com. CAA 0 issue "letsencrypt.org"
example.com. CAA 0 issue "amazon.com"
example.com. CAA 0 iodef "mailto:security@example.com"
```

## 16. NS / SOA — Information Disclosure & Hardening

**CWE-200** — SOA-Records zeigen Email des DNS-Admins; NS-Records zeigen Provider; AXFR (Zone-Transfer) → ggf. komplette Sub-Domain-Liste.

**Hardening:**
- AXFR auf bekannte IPs beschränken (oder ganz aus)
- Generische Admin-Email (`dnsadmin@`)

## 17. Open Resolver / Open Recursor

Wenn DNS-Server intern erreichbar → DNS-Amplification-Vektor. Eigene Recursive-Resolver nur intern erreichbar machen.

## 18. SMTP-Open-Relay

**CWE-285** — SMTP-Server akzeptiert Mail von jedem an jeden → Spam-Schleuder.

**Detection:**
```bash
swaks --to test@external.com --from foo@your.com --server your-smtp-server:25
```

Antwort 250 von externem `to` ohne Auth = offen.

**Mitigation:** Postfix `mynetworks`, Sendmail `RELAYHOSTS`, Mail-Cluster mit auth-required.

## 19. Inbound Mail Filter — DMARC Enforcement & ARC

Wenn DU Mail empfängst:
- DMARC verifizieren
- SPF/DKIM prüfen
- ARC für Forwarder-Chains
- Whitelist KEINER speziellen Absender ohne starke Auth

## 20. Mail-Templates mit Variable-Injection

**CWE-1336** — Templating-Sprache mit User-Input → SSTI in Email-Template.

**Detection:**
```bash
rg -n "Jinja2|Liquid|Handlebars|mustache" --type=py --type=ts --type=js -A 3 | rg "email|template"
```

→ siehe `web-advanced.md` SSTI-Section, gilt analog.

## 21. Test-Mode-Mail-Versand

**CWE-1188** — Dev-Code sendet Test-Mails an Production-Empfänger.

**Detection:**
```bash
rg -n "test@example.com|noreply@.*localhost" --type=py --type=ts --type=js
```

## 22. AWS SES Sandbox-Bypass-Risiko

**CWE-1188** — SES im Sandbox-Modus erlaubt nur verifizierte Empfänger. Production-Move: Anti-Bounce-Mechanismus implementieren, sonst Reputation-Schaden.

## 23. Bounce-Mail-Verarbeitung

**CWE-94** — Bounce-Mail enthält Headers vom Empfänger, oft mit URL → Phishing-Vektor in Reply-Logs.

## 24. From / Reply-To / Sender Header-Verwirrung

Nutzer sehen oft nur `From`. Angreifer kann Sub-Header so setzen, dass `From` legitim aussieht, aber Reply geht woanders hin.

→ Im App-Code: nur `From` auf eigene Domain, kein User-Eingabewert.

## Severity-Heuristik

| Befund | Default-Severity | Eskalation |
|--------|------------------|------------|
| Kein SPF | High | Marketing-Domain → Critical |
| SPF `+all` | Critical |  |
| Kein DMARC | High | + Kunden-Email → Critical |
| DMARC `p=none` lang aktiv | Medium | + Phishing-Indikatoren → High |
| `sp=` fehlt | Medium |  |
| DKIM 1024 Bit | Medium |  |
| Email-Header-Injection | High | + Bcc-Möglich → Critical |
| Sub-Domain Takeover (CNAME dangling) | Critical | + Cookie-Domain `.example.com` → Critical |
| Dangling NS | Critical |  |
| Address Enumeration | Medium | + Brute-Force-möglich → High |
| MTA-STS fehlt | Low |  |
| CAA fehlt | Low | + EV-Cert → Medium |
| Open Relay | Critical |  |
| DNS AXFR offen | Medium |  |
| Test-Mail in Prod-Code | Low | + PII im Body → Medium |

## Referenzen

- RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 8461 (MTA-STS), RFC 8460 (TLS-RPT)
- RFC 8657 (CAA), RFC 4033ff (DNSSEC)
- M3AAWG Sender Best Common Practices
- "Subdomain Takeover" — EdOverflow / HackerOne reports
- CWE-93, CWE-290, CWE-345, CWE-350, CWE-204
