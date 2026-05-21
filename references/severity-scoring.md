# Severity Scoring & External Exploitability

Diese Referenz definiert die Bewertungs-Logik für Phase 4 des Workflows. Ziel ist Reproduzierbarkeit: gleiche Schwachstelle → gleicher Score, unabhängig vom prüfenden Lauf.

## Achse 1 — Schweregrad (CVSS 3.1 orientiert)

Wir folgen den CVSS-3.1-Stufen, weil sie das de-facto-Standardvokabular sind:

| Stufe        | Score        | Was bedeutet das?                                                              |
|--------------|--------------|---------------------------------------------------------------------------------|
| **Critical** | 9.0 – 10.0   | Komplette Kompromittierung möglich (RCE, Auth Bypass, Datenbank-Vollzugriff)   |
| **High**     | 7.0 – 8.9    | Schwerer Impact: Datenleck, Privilege Escalation, schwerer DoS                  |
| **Medium**   | 4.0 – 6.9    | Begrenzter Impact oder erschwerte Ausnutzung                                    |
| **Low**      | 0.1 – 3.9    | Geringer Impact, oft Defense-in-Depth                                           |
| **Info**     | 0.0          | Hardening-Empfehlung, kein direktes Risiko                                      |

### CVSS-Vektor angeben

Wenn möglich, den CVSS-3.1-Vektor angeben. Beispiel SQL-Injection in öffentlicher API:
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  → Score 9.8 (Critical)
```

Komponenten:
- **AV** Attack Vector: `N`etwork / `A`djacent / `L`ocal / `P`hysical
- **AC** Attack Complexity: `L`ow / `H`igh
- **PR** Privileges Required: `N`one / `L`ow / `H`igh
- **UI** User Interaction: `N`one / `R`equired
- **S** Scope: `U`nchanged / `C`hanged
- **C/I/A** Confidentiality/Integrity/Availability Impact: `N`one / `L`ow / `H`igh

### Heuristik bei Unsicherheit

Wenn die genaue CVSS-Berechnung nicht möglich ist, nach Beispiel-Schwachstellen kalibrieren:

| Beispiel-Schwachstelle                                                | Stufe    | Begründung                                  |
|-----------------------------------------------------------------------|----------|---------------------------------------------|
| SQLi mit DB-Vollzugriff, kein Auth nötig                              | Critical | RCE/Datenleak-Pfad, External-Unauth         |
| Command Injection, root-Kontext                                       | Critical | RCE                                         |
| Auth Bypass / Account Takeover                                        | Critical | Vollständiger Kontroll-Verlust              |
| IDOR auf sensitive User-Daten (External-Auth)                         | High     | Daten anderer User abrufbar                 |
| Stored XSS in Admin-Bereich                                           | High     | Admin-Session-Hijack                        |
| SSRF mit Cloud-IMDS-Zugriff                                           | High     | AWS-Credentials abgreifbar                  |
| Reflected XSS                                                         | Medium   | Social-Engineering-Vektor                   |
| Missing Security Headers, kein direkter Exploit                       | Low      | Defense-in-Depth                            |
| Verbose Error Messages                                                | Low      | Information Disclosure                      |
| Veraltetes Logging-Format                                             | Info     | Best-Practice-Hinweis                       |

### Wann hoch- / runter-stufen?

**Hochstufen, wenn:**
- Endpoint ist unauthentifiziert erreichbar (`PR:N`)
- Keine User-Interaction nötig (`UI:N`)
- Auswirkung betrifft viele Nutzer / Tenants (`S:C`, "Scope Changed")
- Daten enthalten PII, Zahlungsdaten, Gesundheitsdaten

**Runter-stufen, wenn:**
- Ausnutzung erfordert mehrere unwahrscheinliche Voraussetzungen
- Framework-Mitigation greift teilweise (z. B. CSP würde XSS einschränken)
- Code-Pfad nur in nicht-produktivem Kontext (Dev-Endpoint mit `if DEBUG:`)

---

## Achse 2 — Externe Ausnutzbarkeit

Diese Achse ist **orthogonal zur Schwere** und für die Priorisierung mindestens genauso wichtig. Ein "Critical / Local" priorisiert man anders als "Medium / External-Unauth".

| Stufe                  | Bedeutung                                                                  | Beispiel                                                |
|------------------------|----------------------------------------------------------------------------|---------------------------------------------------------|
| **External-Unauth**    | Aus dem Internet ohne Credentials ausnutzbar                               | SQLi auf öffentlicher Such-API                          |
| **External-Auth**      | Aus dem Internet mit gültigen Credentials einer regulären Rolle           | IDOR auf `/api/orders/{id}` für eingeloggte User        |
| **Internal-Network**   | Nur aus internem Netz/VPN/Service-Mesh erreichbar                          | SSRF gegen interne Admin-API                            |
| **Local**              | Lokale Code-Ausführung / Filesystem-Zugriff erforderlich                   | Insecure deserialization einer lokalen Config-Datei     |
| **Supply-Chain**       | Erfordert Kompromittierung der Build-/Dependency-Pipeline                  | `trust_remote_code=True` mit fremden HF-Modellen        |

### Bestimmung der Ausnutzbarkeit

Frage in dieser Reihenfolge:

1. **Ist der verwundbare Code-Pfad an einen externen Entry Point gebunden?** (HTTP-Route, Public Webhook, öffentlicher Webhook-Empfänger, Mailbox)
2. Wenn ja: **Erfordert er Auth?**
   - Nein → `External-Unauth`
   - Ja → `External-Auth` (mit Hinweis auf benötigte Rolle, z. B. "External-Auth (Standard-User)" vs. "External-Auth (Admin)")
3. Wenn nein: **Ist der Code-Pfad aus internem Netz erreichbar?** → `Internal-Network`
4. Wenn nur lokal (Konfig, Crontab, Service-Account): → `Local`
5. Wenn nur über kompromittierte Dependency / Build → `Supply-Chain`

### Priorisierungs-Matrix (für TODO-Liste)

| Schwere   | External-Unauth | External-Auth | Internal-Network | Local | Supply-Chain |
|-----------|------------------|----------------|-------------------|-------|--------------|
| Critical  | **P0**           | **P0**         | P1                | P2    | P1           |
| High      | **P0**           | P1             | P1                | P2    | P2           |
| Medium    | P1               | P2             | P2                | P3    | P2           |
| Low       | P2               | P3             | P3                | P3    | P3           |
| Info      | P3               | P3             | P3                | P3    | P3           |

**P0** = sofort (Hotfix, idealerweise innerhalb von Tagen)
**P1** = Sprint-Priorität (innerhalb von ~2 Wochen)
**P2** = Backlog (innerhalb 1-3 Monate)
**P3** = Hardening / Optional

---

## Achse 3 — Konfidenz

Im Bericht wird auch die Konfidenz transparent gemacht:

| Konfidenz   | Bedeutung                                                                                   |
|-------------|---------------------------------------------------------------------------------------------|
| **Confirmed** | Exploit-Pfad nachvollzogen, Sink + Source + Kontrolle klar. Hohe Sicherheit.              |
| **Likely**    | Detection-Pattern eindeutig, Kontext spricht stark dafür. Wahrscheinlich verwundbar.       |
| **Possible**  | Pattern vorhanden, aber Kontext-Validierung unklar. Manuelle Prüfung empfohlen.            |

**Wichtig:** `Possible`-Befunde sind kein Freibrief für Spekulation. Wenn nach Kontext-Check der Verdacht NICHT belegbar ist, gehört der Punkt in den Abschnitt "Hinweise zur weiteren Untersuchung" — NICHT in die Befundliste.

## Auswirkung auf den Bericht

Im Bericht-Frontmatter immer:
```
**Schwere:** Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8)
**Ausnutzbarkeit:** External-Unauth
**Konfidenz:** Confirmed
**Priorität:** P0
```

So ist jede Bewertung herleitbar und reproduzierbar.
