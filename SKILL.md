---
name: security-review
description: Tiefgehende, strukturierte Schwachstellenanalyse von Quellcode nach OWASP Top 10 (2021/2025), OWASP API/LLM/Mobile Top 10, ASVS L1/L2/L3, CWE Top 25, OWASP CI/CD Top 10, MITRE ATT&CK und 25+ weiteren Tiefenmodulen (Krypto, OAuth/OIDC/SAML, Cloud, Container, Race-Conditions, DSGVO, Threat Modeling). Use this skill whenever the user asks for a security review, security audit, vulnerability scan, code security check, Schwachstellenanalyse, Sicherheitsprüfung, Sicherheitsaudit, Code-Audit, Pentest-Vorbereitung, threat model, ASVS-Verifikation, or asks "is this code secure". Also triggers on requests to find SQL injection, XSS, SSRF, IDOR, race conditions, auth/OAuth flaws, hardcoded secrets, prompt injection, insecure dependencies, container/K8s misconfigurations, or DSGVO/GDPR issues. Produces a deterministic, evidence-based report with severity, exploitability and a prioritized remediation TODO list — and refuses to invent findings not backed by concrete code evidence.
---

# Security Review — Strukturierte Schwachstellenanalyse

Dieser Skill führt eine systematische, evidenzbasierte Sicherheitsprüfung von Quellcode durch und liefert einen Befundbericht mit klassifizierter Schwere, externer Ausnutzbarkeit und konkreten Behebungsschritten.

Der Skill verfügt über **38 Tiefenmodule** unter `references/`, die je nach erkannter Technologie automatisch geladen werden — von OWASP Top 10 / ASVS über Cloud/Container/CI-CD/Crypto bis hin zu GraphQL, WebSockets, AI/ML-Pipelines, IoT-Firmware, Electron-Desktop, Webhooks, E-Mail/DNS, datenbankspezifischer Tiefenanalyse, Smart Contracts, Mobile, Threat Modeling, Authorization-Modellen und DSGVO-Mapping.

## Kernprinzipien (nicht verhandelbar)

1. **Evidenz vor Spekulation.** Jeder Befund MUSS auf einer konkreten Code-Stelle (Datei + Zeile + Snippet) basieren. Wenn keine Code-Evidenz vorliegt, wird kein Befund gemeldet — auch nicht "vorsichtshalber".
2. **Keine erfundenen Schwachstellen.** Hypothesen wie "könnte verwundbar sein, wenn X" gehören in einen separaten Abschnitt "Hinweise zur weiteren Untersuchung", NICHT in die Befundliste.
3. **Konfidenz transparent ausweisen.** Jeder Befund bekommt ein Konfidenz-Level: `Confirmed` (Exploit-Pfad nachvollzogen), `Likely` (Pattern eindeutig, Kontext spricht dafür), `Possible` (Pattern vorhanden, Kontext unklar).
4. **False Positives reduzieren.** Vor dem Melden prüfen, ob Frameworks, ORMs oder Bibliotheken die Schwachstelle bereits mitigieren (siehe `references/false-positive-rules.md`).
5. **Read-only.** Niemals den geprüften Code modifizieren. Nur Lesen, Analysieren, Berichten.

## Anti-Halluzinations-Checkliste (Pflicht vor jedem Befund)

Jeder einzelne Befund MUSS diese sieben Prüfungen bestehen, BEVOR er in den Bericht aufgenommen wird. Wenn auch nur eine Prüfung fehlschlägt → der Punkt geht nicht in die Befundliste, sondern in den Abschnitt "Hinweise zur weiteren Untersuchung" oder wird komplett verworfen.

| # | Prüfung | Pass-Kriterium | Fail-Konsequenz |
|---|---------|----------------|-----------------|
| 1 | **Datei existiert** | Pfad ist mit `view` lesbar und der genannte Code steht dort wirklich drin | Befund verwerfen — Datei wurde halluziniert |
| 2 | **Zeile existiert** | Zeilennummer im `view`-Output stimmt mit dem zitierten Snippet überein | Befund verwerfen — Zeilennummer halluziniert |
| 3 | **Snippet ist wörtlich** | Der zitierte Code ist Zeichen-für-Zeichen wie in der Datei (keine Paraphrase, keine "Verbesserung" durch Claude) | Befund verwerfen — Code halluziniert |
| 4 | **Source erreicht Sink** | Untrusted Source (HTTP-Input, externe API, User-Upload, etc.) erreicht nachweisbar einen gefährlichen Sink (`execute`, `eval`, `os.system`, Filesystem-Write, etc.) | In "Hinweise" verschieben — keine konkrete Schwachstelle |
| 5 | **Keine wirksame Mitigation auf dem Pfad** | Zwischen Source und Sink gibt es keine Sanitization / Parametrisierung / Validation / Framework-Schutz (Liste in `false-positive-rules.md` konsultieren) | Befund verwerfen — der Code ist sicher |
| 6 | **CWE/OWASP-ID belegbar** | Die zugewiesene CWE-Nummer und OWASP-Top-10-Kategorie passen zur Schwachstellenklasse — nicht erfunden, nicht ausgedacht | CWE/OWASP-ID weglassen oder Befund verwerfen |
| 7 | **Exploit-Skizze plausibel** | In einem Satz lässt sich beschreiben: "Ein <Profil> kann durch <Aktion> den Effekt <X> erreichen." Wenn das nicht ohne weitere Annahmen geht, ist es Spekulation | In "Hinweise" verschieben |

### Verbotene Halluzinations-Patterns

Diese Verhaltensweisen sind **strikt untersagt**:

- ❌ **CVE-Nummern erfinden.** Wenn keine CVE-Nummer mit Sicherheit zur konkreten Bibliotheksversion gehört: weglassen. Niemals raten (z. B. "wahrscheinlich CVE-2023-xxxxx").
- ❌ **CWE-IDs raten.** Wenn unsicher: CWE-Eintrag weglassen, nicht erfinden. Lieber nur OWASP-Kategorie nennen.
- ❌ **CVSS-Scores ohne Vektor.** Wenn CVSS-Score angegeben, MUSS der vollständige CVSS:3.1-Vektor mit angegeben sein (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). Sonst nur Severity-Stufe nennen.
- ❌ **Generische Behauptungen ohne Code-Stelle.** Sätze wie "Die Authentifizierung scheint schwach zu sein" ohne Datei+Zeile+Snippet → nicht in den Bericht.
- ❌ **Defensive "vorsichtshalber"-Befunde.** Wenn Mitigation-Check ergibt, dass der Code wahrscheinlich sicher ist: NICHT trotzdem melden, "nur damit es geprüft wurde". Stattdessen in "Hinweise" mit klarer Begründung.
- ❌ **Quervergleich mit Erinnerung.** Niemals behaupten "ich erinnere mich an eine ähnliche Schwachstelle in dieser Library" — nur belegbare, nachschlagbare Aussagen.
- ❌ **Mehr Befunde, um die Liste voller aussehen zu lassen.** Ein leerer/kurzer Befund-Report ist eine valide und ehrliche Antwort. Lieber 3 wasserdichte Befunde als 20 halbgare.
- ❌ **Behauptungen über Code, der NICHT im Scope ist.** Wenn eine Datei nicht gelesen wurde: keine Aussagen über deren Inhalt.

### Selbst-Kontrolle am Ende jedes Berichts

Bevor der Bericht final ausgegeben wird, MUSS folgender Block intern durchlaufen werden (kann als Kommentar im Bericht stehen):

```
[Self-Check vor Abgabe]
[ ] Jeder Befund hat einen via `view` verifizierbaren Datei-Pfad + Zeilennummer
[ ] Jedes Code-Snippet ist wörtlich aus der Datei kopiert (kein paraphrasierter Code)
[ ] Keine Befunde mit "könnte" / "möglicherweise" / "eventuell" in der Befundliste (nur in "Hinweise")
[ ] Alle CVE-Nummern, falls genannt, sind belegt (keine erfundenen IDs)
[ ] Konfidenz-Level ist transparent angegeben
[ ] Bei Konfidenz "Possible": "What I checked / What I couldn't check" ist dokumentiert
[ ] Keine Behauptung über ungeprüfte Dateien
```

Wenn auch nur ein Punkt nicht erfüllt ist: zurück zur Befundliste und korrigieren. **Lieber einen ehrlich kurzen Bericht als einen falsch aufgeblasenen.**

## Workflow — fünf Phasen

Folge diesen Phasen in Reihenfolge. Überspringe keine. Vor Beginn die Referenzdateien laden, die für das jeweilige Projekt relevant sind (siehe Phase 1).

### Phase 1 — Reconnaissance (Projekt verstehen)

Ziel: verstehen, was geprüft wird, bevor geprüft wird.

**Schritte:**
1. **Projekttyp identifizieren** durch Inspektion von Manifest-Dateien:
   - `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `pom.xml`, `build.gradle`, `Cargo.toml`, `composer.json`, `Gemfile`, `*.csproj`, `Package.swift`, `Podfile`, `pubspec.yaml`
   - `Dockerfile`, `docker-compose.yml`, `*.tf`, `*.yaml` (K8s), `.github/workflows/`, `.gitlab-ci.yml`
   - `*.sol`, `hardhat.config.*`, `foundry.toml` (Smart Contracts)
2. **Sprache(n) und Framework(s) erfassen.** Beispiel: "Python 3.11, FastAPI 0.110, SQLAlchemy 2.0, Pydantic 2.x, deployed via Terraform auf AWS"
3. **Anwendungsklasse(n) bestimmen** (eine Codebase kann mehrere haben):
   - `web-app`, `rest-api`, `graphql-api`, `llm-app`, `mobile-app`, `smart-contract`, `cli-tool`, `library`, `iac-only`
4. **Entry Points kartieren**: HTTP-Routen, GraphQL-Resolvers, Message-Consumer, CLI-Args, LLM-Tools, Smart-Contract-Functions, Deep-Links (Mobile).
5. **Vertrauensgrenzen identifizieren.** Auth-/AuthZ-Layer, Validation-Layer, externe API-Calls, DB-Sinks, Dateisystem-Sinks, Subprocess-Aufrufe, Cloud-API-Calls, IPC-Boundaries.

**Output:** Eine kurze Projekt-Zusammenfassung (5-10 Zeilen) für den Bericht + Liste der Entry Points + Liste der zu ladenden Tiefenmodule (siehe Phase 1.5).

### Phase 1.5 — Domain Detection & Module Loading

Anhand der Phase-1-Ergebnisse: bestimme, welche Tiefenmodule zu laden sind. Die Aktivierungs-Bedingungen sind unten in der **Modul-Übersicht** dokumentiert. Lade nur was relevant ist — Module nicht "vorsichtshalber" alle laden (Token-Effizienz).

**Immer geladen:**
- `references/owasp-top10.md` — Basis-Befundkatalog
- `references/cwe-top25.md` — Ergänzung
- `references/false-positive-rules.md` — Vor jedem Befund konsultieren
- `references/severity-scoring.md` — Klassifikation
- `references/secrets-and-deps.md` — Secret-Scan + Dependencies
- `references/language-patterns.md` — Sprachspezifische Patterns
- `references/report-template.md` — Bericht-Format

**Bedingt geladen** — siehe Modul-Übersicht unten.

### Phase 2 — Gezielte Analyse

Arbeite die geladenen Referenzdateien systematisch ab. Jede enthält Detection-Patterns (grep/rg), Unsafe-vs-Safe-Code-Beispiele und CWE-/OWASP-Mappings.

**Vorgehen pro Pattern:**
1. Mit `grep`/`rg`/`view` nach den Detection-Patterns suchen.
2. Bei Treffer: umliegenden Kontext (10-30 Zeilen) lesen.
3. Mitigation-Check gegen `false-positive-rules.md`.
4. Echte Schwachstelle → Befund anlegen. Unklar → "Hinweise zur weiteren Untersuchung".

**Mindest-Coverage** (jeder Entry Point aus Phase 1 muss mindestens dagegen geprüft sein):
- Injection (SQL, OS-Cmd, NoSQL, LDAP, etc.)
- Broken Access Control / BOLA
- Authentication & Session Management
- SSRF
- Hardcoded Secrets / Sensitive Data Exposure
- Bei APIs: BOPLA, Mass Assignment, Rate-Limit
- Bei LLM-Apps: Prompt Injection, Insecure Output Handling, Tool/Function-Abuse
- Bei Cloud/IaC: IAM-Overpermission, Public Storage, IMDS, Crypto-Defaults
- Bei Container: Root-User, privileged, unscoped Volume Mounts
- Bei CI/CD: pull_request_target, Action-Pinning, Secrets in Logs

### Phase 3 — Evidenz sammeln

Für jeden Verdachtsfall aus Phase 2:

1. **Code-Zitat extrahieren** (5-15 Zeilen mit Zeilennummer aus `view`). **Zeichen-für-Zeichen kopieren — nicht paraphrasieren.**
2. **Datenfluss skizzieren**: Source → Sink. Jeder Hop muss tatsächlich im Code stehen.
3. **Exploit-Skizze** (in einem Satz): "Ein <Profil> kann durch X den Effekt Y erreichen." Wenn der Satz Annahmen wie "vermutlich" oder "wenn der Server X tut" benötigt → in "Hinweise" verschieben.
4. **Mitigation-Check**: Framework-Defaults, ORM-Parametrisierung, WAF-Regel, Input-Validation, AuthZ-Layer? — gegen `references/false-positive-rules.md` prüfen.
5. **Anti-Halluzinations-Checkliste durchlaufen** (alle 7 Prüfungen oben). Auch nur EINE fehlgeschlagene Prüfung → Befund streichen.

Wenn nach diesem Check der Befund nicht mehr belegbar ist: streichen. Das ist nicht "Versagen", sondern Qualitätskontrolle.

### Phase 4 — Klassifikation

Jeder bestätigte Befund bekommt **zwei orthogonale Bewertungen**:

#### 4a. Schweregrad (CVSS-orientiert)

| Stufe        | CVSS-Score | Bedeutung                                                                |
|--------------|------------|--------------------------------------------------------------------------|
| **Critical** | 9.0 – 10.0 | Vollständige Kompromittierung möglich, sofort handeln                    |
| **High**     | 7.0 – 8.9  | Schwere Auswirkung auf Vertraulichkeit / Integrität / Verfügbarkeit      |
| **Medium**   | 4.0 – 6.9  | Begrenzte Auswirkung oder erschwerte Ausnutzung                          |
| **Low**      | 0.1 – 3.9  | Geringe Auswirkung, Defense-in-Depth                                     |
| **Info**     | 0.0        | Hinweis ohne unmittelbares Risiko (Hardening-Empfehlung)                 |

CVSS:3.1-Vektor wenn möglich angeben. Detail-Rubrik: `references/severity-scoring.md`.

#### 4b. Externe Ausnutzbarkeit

| Stufe                  | Voraussetzung des Angreifers                                              |
|------------------------|---------------------------------------------------------------------------|
| **External-Unauth**    | Erreichbar aus dem Internet, KEINE gültigen Credentials nötig             |
| **External-Auth**      | Erreichbar aus dem Internet, gültige Credentials einer Standardrolle nötig |
| **Internal-Network**   | Nur aus internem Netz / VPN / Service Mesh erreichbar                     |
| **Local**              | Lokale Code-Ausführung oder physischer Zugriff erforderlich               |
| **Supply-Chain**       | Ausnutzung erfordert Kompromittierung einer Build-/Dependency-Pipeline    |

#### 4c. Optional: ATT&CK-Mapping

Für sicherheitskritische Befunde zusätzlich die MITRE-ATT&CK-Technique-ID angeben (siehe `references/mitre-attack.md`) — hilft SOC-Teams bei der Detection-Integration.

#### 4d. Optional: Compliance-Mapping

Wenn relevant: Bezug zu DSGVO/PCI/HIPAA/NIS2/ISO27001 angeben (siehe `references/privacy-compliance.md`).

### Phase 5 — Bericht generieren

Bericht nach `references/report-template.md`. Pflichtstruktur:

1. **Executive Summary** (max. 10 Zeilen): Anzahl Findings pro Schwere, Top-3-Risiken, Gesamteinschätzung.
2. **Scope & Methodik**: Was geprüft, welche Frameworks, welche Limitierungen, welche Tiefenmodule geladen.
3. **Befundtabelle** — gruppiert nach Schwere (Critical zuerst):
   | # | Titel | OWASP | CWE | ATT&CK | Datei:Zeile | Schwere | Ausnutzbarkeit | Konfidenz |
4. **Befund-Details** pro Finding: Titel + IDs, Ort, Code-Evidenz, Beschreibung, Angriffsszenario, Auswirkung, Behebung (mit sicherem Code als Diff), Referenzen.
5. **TODO-Liste** priorisiert nach Schwere × Ausnutzbarkeit:
   ```
   - [ ] [P0] [CRITICAL/External-Unauth] Fix SQL Injection in src/api/users.py:42
   ```
   P0 = Critical+External | P1 = High+External oder Critical+Internal | P2 = Medium oder High-Internal | P3 = Low/Info
6. **Hinweise zur weiteren Untersuchung** (klar als unbestätigt markiert).
7. **Dependency- und Supply-Chain-Status**: Tabelle anfälliger Pakete.
8. **Compliance-Relevanz** (falls Phase 1 das ergab).
9. **Scan-Metadaten**: Datum, Anzahl geprüfter Dateien, nicht-geprüfte Bereiche, geladene Module.

## Was dieser Skill NICHT tut

- **Keine Penetration Tests.** Keine Exploits ausgeführt, keine Server angefragt.
- **Keine automatischen Code-Änderungen.** Behebungsvorschläge im Bericht, nicht committet.
- **Keine Behauptungen ohne Code-Beleg.** Vermutungen kommen in "Hinweise", nicht in die Befundliste.
- **Keine CVE-Lookups gegen Online-DBs**, wenn nicht explizit erlaubt.
- **Keine formale Compliance-Bewertung.** Compliance-Mapping ist Hilfe für Priorisierung, kein Audit-Ersatz.

## Aufruf-Varianten

- **Voll-Audit** (Standard): alle Phasen, ganzes Repo.
- **Diff-Modus**: nur geänderte Dateien (Phase 1 + 2 + 4 + 5).
- **Fokus-Modus**: "Prüfe nur Auth" / "Prüfe nur API" — Phase 2 auf relevante Referenzen reduziert.
- **Pre-Commit-Modus**: nur Critical/High, kompakter Output.
- **Threat-Model-Modus**: lädt `threat-modeling.md`, generiert DFD + STRIDE-Tabelle statt klassischem Audit.
- **Compliance-Modus**: lädt `privacy-compliance.md`, fokussiert auf DSGVO/NIS2/PCI-relevante Findings.

Bei unklarem Modus: einmal nachfragen, sonst Standard (Voll-Audit).

## Output-Konvention

- Bericht als Markdown: `SECURITY_REVIEW_<YYYY-MM-DD>.md` im Projekt-Root.
- Bei >500 Zeilen: Befund-Details in `security-review/findings/` auslagern, Haupt-Bericht enthält nur Tabelle + Links.
- Sprache: gleiche wie die Anfrage des Users. Technische Termini bleiben englisch.
- Anonymisiere Secrets, Keys, Passwörter, Tokens, etc. 

---

## Modul-Übersicht (38 Referenzen)

### Immer geladen (Phase 1.5)

| Modul | Inhalt |
|-------|--------|
| `owasp-top10.md` | OWASP Top 10 (2021 + 2025-Updates) — Basis-Befundkatalog |
| `cwe-top25.md` | CWE Top 25 Most Dangerous Software Weaknesses |
| `false-positive-rules.md` | Anti-Erfindungs-Regeln, Framework-Mitigations |
| `severity-scoring.md` | CVSS 3.1/4.0, EPSS, SBOM/VEX, Konfidenz-Rubrik |
| `secrets-and-deps.md` | Hardcoded Secrets, Dependency-Audit, Supply-Chain |
| `language-patterns.md` | Python/JS/Java/Go/C/Rust/PHP/C#/Ruby + IaC |
| `report-template.md` | Bericht-Format (Phase 5) |

### App-Typ-getriggert (Phase 1.5)

| Modul | Lade-Bedingung |
|-------|----------------|
| `owasp-api-top10.md` | REST/GraphQL-API erkannt |
| `owasp-llm-top10.md` | LLM-Komponente (Prompt, Embedding, Agent, RAG, Tool-Calling) |
| `owasp-mobile-top10.md` | iOS / Android / React Native / Flutter / Capacitor |
| `smart-contracts.md` | Solidity / Vyper / Move / Cairo / Solana-Rust |
| `ai-ml-security.md` | ML-Pipeline erkannt: torch / tensorflow / keras / sklearn / onnx / mlflow / transformers / joblib / pickle / HuggingFace |
| `electron-desktop.md` | Desktop-App-Framework: electron / tauri / nw.js / pywebview / cefpython |
| `iot-embedded-firmware.md` | Embedded/IoT: arduino / platformio / esp-idf / zephyr / freertos / yocto / buildroot / openwrt / embedded C/C++ |

### Tech-Stack-getriggert (Phase 1.5)

| Modul | Lade-Bedingung |
|-------|----------------|
| `cloud-security.md` | Cloud-SDKs (boto3/azure/google-cloud) oder IaC (Terraform/CFN/Bicep/Pulumi) |
| `container-k8s-security.md` | Dockerfile / docker-compose / K8s-Manifeste / Helm |
| `cicd-supply-chain.md` | `.github/workflows/`, GitLab-CI, Jenkinsfile, Build-Manifeste |
| `infrastructure-network.md` | NGINX/HAProxy/Traefik/Envoy/Istio-Configs, DNS, WAF |
| `graphql-deep.md` | GraphQL-Server erkannt: Apollo, GraphQL Yoga, Hot Chocolate, graphql-java, gqlgen, Strawberry, Mercurius, Hasura |
| `database-deep.md` | DB-Treiber erkannt: psycopg/pg/mysql2/pymongo/redis/elasticsearch/clickhouse/dynamodb/cassandra/neo4j/sqlite |
| `email-dns-security.md` | Mail-SDKs (nodemailer/smtplib/sendgrid/ses/mailgun/resend/postmark) oder DNS-IaC (Route53/Cloudflare/dnsimple) |

### Pattern-getriggert (Phase 2)

| Modul | Lade-Bedingung |
|-------|----------------|
| `crypto-deep-dive.md` | Crypto-Code: `hashlib`, `Cipher`, `JWT`, TLS-Config, `bcrypt`/`argon2` |
| `auth-oauth-saml.md` | OAuth/OIDC/SAML/Session/MFA/Password-Reset-Code |
| `authorization-models.md` | Mehr-Rollen-Modell, Multi-Tenancy, RBAC/ABAC/ReBAC, JWT-Scopes |
| `web-advanced.md` | Web-App + Reverse-Proxy / CDN (SSTI, Prototype-Pollution, Cache Poisoning, etc.) |
| `http-attacks-deep.md` | HTTP-Smuggling, Cache-Poisoning, Open-Redirect, CRLF |
| `client-side-deep.md` | Frontend-Code (JS/TS Frameworks, DOM, CSP, postMessage) |
| `xxe-and-xml.md` | XML-Parsing erkannt (Python/Java/.NET/PHP/Go) |
| `file-uploads-content.md` | File-Upload-Endpoints, Archive-Handling, Bildverarbeitung |
| `race-conditions.md` | Concurrency-Code, async/await, DB-Transactions, Locks |
| `business-logic.md` | Workflow-Logik, Geld-Flüsse, State-Machines, Quotas |
| `logging-monitoring.md` | Logger-Setup, Audit-Anforderungen, Crash-Reporting |
| `websocket-realtime.md` | Real-Time-Protokolle: WebSocket, `ws://`, `wss://`, socket.io, SignalR, EventSource/SSE, RTCPeerConnection, Phoenix.Channel, STOMP |
| `webhooks-callbacks.md` | Webhook-Endpoints (`/webhook`, `/callback`), Signature-Header (`Stripe-Signature`, `X-Hub-Signature`, `svix-*`), ausgehende Webhook-Aufrufe |

### Modus-getriggert (Phase 5)

| Modul | Lade-Bedingung |
|-------|----------------|
| `owasp-asvs.md` | Vollständiger Audit (nicht nur Top 10), oder L2/L3-Schutzbedarf |
| `mitre-attack.md` | SOC-Bericht angefragt oder sicherheitskritische Domain |
| `threat-modeling.md` | Threat-Model-Modus oder Architektur-Review |
| `privacy-compliance.md` | Compliance-Modus oder PII/PHI im Code erkannt |

---

**Beginne IMMER mit Phase 1.** Springe nie direkt zu Phase 2 ohne Reconnaissance, sonst entstehen False Positives durch fehlenden Kontext. Lade Module nicht "vorsichtshalber" alle — nur, wenn die Aktivierungs-Bedingung zutrifft.
