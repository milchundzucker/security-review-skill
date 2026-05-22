# security-review

Skill für Anthropic Claude — strukturierte, tiefgehende Sicherheitsprüfung von Quellcode.

## Was der Skill liefert

- **38 Tiefenmodule** mit Detection-Patterns (grep/rg), Unsafe-vs-Safe-Code-Beispielen, CWE-/OWASP-Mappings
- **5-Phasen-Workflow**: Reconnaissance → Domain-Detection → Analyse → Evidenz → Klassifikation → Bericht
- **Evidenzbasiert**: Jeder Befund mit konkreter Datei + Zeile + Code-Snippet. Keine erfundenen Findings.
- **Zwei-Achsen-Klassifikation**: Schwere (Critical/High/Medium/Low/Info) × Ausnutzbarkeit (External-Unauth/Auth, Internal, Local, Supply-Chain)
- **Konfidenz-Stufen**: Confirmed / Likely / Possible — transparent ausgewiesen
- **Modi**: Voll-Audit, Diff, Fokus, Pre-Commit, Threat-Model, Compliance

## Auslöser (Trigger)

Der Skill aktiviert sich u. a. bei:
- "Security Review / Audit / Code-Audit / Schwachstellenanalyse / Sicherheitsprüfung / Sicherheitsaudit"
- "Ist dieser Code sicher / is this code secure"
- Spezifische Vuln-Klassen: "SQL injection / XSS / SSRF / IDOR / OAuth / Prompt Injection / Race Condition / DSGVO / ..."
- "Threat Model / STRIDE"
- "Pentest-Vorbereitung"

Auch ohne explizite Framework-Nennung — der Skill erkennt den Bedarf am Kontext.

## Module (38)

### Immer geladen
- `owasp-top10.md` — OWASP Top 10 (2021/2025)
- `cwe-top25.md` — CWE Top 25
- `false-positive-rules.md` — Anti-Erfindungs-Regeln
- `severity-scoring.md` — CVSS 3.1/4.0, EPSS, Konfidenz
- `secrets-and-deps.md` — Secret-Scan, Dependencies, Supply-Chain
- `language-patterns.md` — Python, JS, Java, Go, Rust, C/C++, PHP, C#, Ruby + IaC
- `report-template.md` — Bericht-Format

### App-Typ-getriggert
- `owasp-api-top10.md` — REST/GraphQL
- `owasp-llm-top10.md` — LLM/RAG/Agent
- `owasp-mobile-top10.md` — iOS/Android/RN/Flutter
- `smart-contracts.md` — Solidity/Vyper/Move/Solana/Cairo
- `ai-ml-security.md` — Model Pickle/RCE, Prompt Injection in Pipelines, Vector-DB/RAG, MLflow/SageMaker, EU AI Act
- `electron-desktop.md` — Electron/Tauri/nw.js: nodeIntegration, contextIsolation, autoUpdater, Custom-Protocol-Hijack
- `iot-embedded-firmware.md` — ESP32/Arduino/Zephyr/Yocto/OpenWrt, Secure Boot, OTA, MQTT/CoAP/Modbus, BLE-Pairing, EU CRA

### Stack-getriggert
- `cloud-security.md` — AWS/Azure/GCP
- `container-k8s-security.md` — Docker/K8s/Helm
- `cicd-supply-chain.md` — GitHub Actions, GitLab CI, Jenkins
- `infrastructure-network.md` — NGINX, Service Mesh, DNS, WAF
- `graphql-deep.md` — Introspection, Query-Depth/Complexity, Alias-Overloading, BOLA in Resolvers, Federation
- `database-deep.md` — PostgreSQL RLS, MongoDB Operator-Injection, Redis Lua-Sandbox, Elasticsearch Script-Query, DynamoDB FilterExpression
- `email-dns-security.md` — SPF/DKIM/DMARC/MTA-STS/BIMI, Subdomain-Takeover, Email-Header-Injection, CAA

### Pattern-getriggert
- `crypto-deep-dive.md` — Hash, AES, RSA, JWT, TLS, Random
- `auth-oauth-saml.md` — OAuth 2.1, OIDC, SAML, MFA, Session
- `authorization-models.md` — RBAC/ABAC/ReBAC, Multi-Tenancy, JWT-Scopes
- `web-advanced.md` — SSTI, Prototype Pollution, Cache Poisoning
- `http-attacks-deep.md` — Smuggling, CRLF, Open Redirect
- `client-side-deep.md` — DOM, CSP, postMessage
- `xxe-and-xml.md` — XML/XXE/XSLT/SAML-Signaturen
- `file-uploads-content.md` — Zip Slip, SVG-XSS, Polyglots
- `race-conditions.md` — TOCTOU, Single-Packet, DB-Isolation
- `business-logic.md` — Workflow-Logik, Geld-Flüsse, Idempotency
- `logging-monitoring.md` — Log-Injection, PII-Leaks, Audit
- `websocket-realtime.md` — CSWSH, Per-Message-Authz, Compression-Bomb, SSE, WebRTC, SignalR/STOMP
- `webhooks-callbacks.md` — Signature-Verification, Replay, SSRF via Outgoing Webhook, Secret-Rotation, Standard Webhooks

### Modus-getriggert
- `owasp-asvs.md` — ASVS L1/L2/L3-Verifikationskatalog (280+ Controls)
- `mitre-attack.md` — ATT&CK-Mapping für SOC
- `threat-modeling.md` — STRIDE/DREAD/PASTA, DFD, Attack Trees
- `privacy-compliance.md` — DSGVO, NIS2, PCI, HIPAA, BSI, ISO 27001

## Installation

Der Skill kann in vier verschiedenen Umgebungen verwendet werden. Die zugrundeliegenden Markdown-Dateien (SKILL.md + 38 references/) sind dieselben — nur Speicherort und Aktivierungsmechanismus unterscheiden sich.

### 0. Komfortable Installation via npx skills

Wenn im System bereits NodeJS installiert ist, kann der Skill mit einem Skillmanager installiert werden:

```bash
npx skill i milchundzucker/security-review-skill
```

Danach den gewünschten Agent starten. Der Skill sollte verfügbar sein. Es kann mit dem Prompt: `Welche Skills kennst du?` eine Liste der registrierten Skills vom ausgewaehlten Modell abgerufen werden.

### 1. Claude Desktop App / claude.ai

Das Skill-Format ist nativ unterstützt seit der Skills-Einführung von Anthropic.

**Schritte:**
1. `security-review-claude-app.zip` herunterladen
2. In der App öffnen: `Settings → Capabilities → Skills` (oder `Customize → Skills`, je nach Build)
3. Auf **"+ Create skill"** (bzw. **"Upload skill"**) klicken
4. Die Zip-Datei auswählen
5. Im Skill-Detail den Toggle **aktivieren**
6. Skill ist sofort verwendbar — er triggert automatisch auf Anfragen wie "Mach ein Security-Review", "Audit diesen Code", "Schwachstellenanalyse"

> **Hinweis:** Die Zip muss zwingend `security-review/` als Top-Level-Ordner enthalten (NICHT die Files direkt im Wurzelverzeichnis). Diese Zip ist korrekt gepackt.

### 2. Claude Code (CLI)

Claude Code unterstützt Skills nativ ab Version 1.0+. Es gibt zwei Scopes:

**Repo-lokal** (nur für dieses Projekt, mit ins Git):
```bash
# Im Repo-Root
mkdir -p .claude/skills/
cp -r /pfad/zu/security-review/ .claude/skills/security-review/

# Optional: committen, damit das ganze Team den Skill hat
git add .claude/skills/security-review/
git commit -m "chore: add security-review skill"
```

**User-global** (für alle Projekte des aktuellen Users):
```bash
mkdir -p ~/.claude/skills/
cp -r /pfad/zu/security-review/ ~/.claude/skills/security-review/
```

**Verifikation:**
```bash
claude  # Claude Code starten
> /skills          # Listet alle geladenen Skills — "security-review" muss erscheinen
> Mach ein Security-Review von src/
```

> Falls der Skill nicht erscheint, prüfe mit `ls ~/.claude/skills/security-review/SKILL.md` und `ls ~/.claude/skills/security-review/references/` ob Struktur stimmt.

### 3. Cursor

Cursor verwendet kein Skill-Format, sondern **Rules** (`.cursor/rules/*.mdc`). Hierfür ist eine Adaptierung nötig: die SKILL.md wird in eine einzige `.mdc`-Datei mit YAML-Frontmatter konvertiert.

**Variante A: Repo-lokal über `.cursor/rules/`**

```bash
mkdir -p .cursor/rules/
```

Lege folgende Datei an: `.cursor/rules/security-review.mdc`

```markdown
---
description: Strukturierte, tiefgehende Schwachstellenanalyse nach OWASP Top 10, CWE Top 25, ASVS, MITRE ATT&CK. Aktiviere bei "Security Review", "Audit", "Schwachstellenanalyse", "Sicherheitsprüfung".
globs:
alwaysApply: false
---

# Security Review

[Vollständige SKILL.md hier einfügen — siehe security-review/SKILL.md]

Die Referenzmodule (`references/*.md`) liegen im selben Ordner unter `.cursor/rules/security-review-refs/`. Lade sie nach Bedarf entsprechend Phase 1.5.
```

Dann die Referenzen mitkopieren:
```bash
mkdir -p .cursor/rules/security-review-refs/
cp /pfad/zu/security-review/references/*.md .cursor/rules/security-review-refs/
```

**Aktivierungsmodus:** `alwaysApply: false` bedeutet "Agent Requested" — Cursor wählt den Skill nur, wenn die Beschreibung zur User-Anfrage passt. Das ist gewollt: der Skill soll nicht jede Konversation triggern, sondern nur Audit-Anfragen.

**Variante B: User-global über `~/.cursor/rules/`** — analog, aber im Home-Verzeichnis. Wirkt für alle Cursor-Projekte.

> Cursor liest `.cursor/rules/*.mdc` automatisch beim Start eines Workspaces. Reload via `Cmd+Shift+P → Reload Window` falls Änderung nicht sofort greift.

### 4. Visual Studio Code (mit GitHub Copilot Chat oder Continue/Cline)

In VS Code können Skills sowohl global (`~/.copilot/skills`) als auch projektbezogen (`.agents/skills`) installiert werden. In diesem Fall ergibt es Sinn, den Skill nur projektbezogen zu installieren um nicht versehentlich einen massiven Token-Verbrauch zu provozieren.

**a) GitHub Copilot Chat Extension:**

Die [GitHub Copilot Chat Extension](https://marketplace.visualstudio.com/items?itemName=GitHub.copilot-chat) wird mit VS Code ausgeliefert und muss nicht gesondert installiert werden.

```bash
mkdir -p .agents/skills
git clone git@github.com:milchundzucker/security-review-skill.git
```

Danach VS Code am Besten (neu-)starten. Der Skill kann implizit aufgerufen werden (siehe weiter unten "Aufruf-Beispiele") als auch explizit über `/security-review-skill`.

Referenz: [GitHub Docs: Adding agent skills for GitHub Copilot](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/customize-cloud-agent/add-skills)

**b) Continue (continue.dev) — Custom Slash-Command:**

In `~/.continue/config.json` (oder Workspace-`.continue/config.json`):
```json
{
  "customCommands": [
    {
      "name": "security-review",
      "prompt": "Du führst einen Security-Review durch. Lade als System-Kontext: [Inhalt von SKILL.md]. Beginne mit Phase 1.",
      "description": "Strukturierte Schwachstellenanalyse"
    }
  ]
}
```

Aufruf in Continue: `/security-review` im Chat.

**c) Cline / Roo Code — `.clinerules` bzw. `.roo/rules/`:**

```bash
# Cline
cp /pfad/zu/security-review/SKILL.md .clinerules

# Roo Code
mkdir -p .roo/rules/
cp /pfad/zu/security-review/SKILL.md .roo/rules/security-review.md
cp -r /pfad/zu/security-review/references/ .roo/rules/
```

### 5. OpenCode

[OpenCode](https://opencode.ai) ist ein Open-Source-Terminal-Agent (von SST), der mit jedem LLM-Provider arbeitet. Er unterstützt **AGENTS.md** sowie projekt-/user-globale Rules.

**Variante A: Über `.claude` (am einfachsten funktioniert dann auch für code claude)**

**User-global** (für alle Projekte des aktuellen Users):
```bash
mkdir -p ~/.claude/skills/
cp -r /pfad/zu/security-review/ ~/.claude/skills/security-review/
```
---

## Verifikation — funktioniert der Skill?

In allen IDEs gilt: nach Installation einen kurzen Test-Prompt absetzen:

```
Mach ein Security-Review von <eine bekannte Datei mit einer offensichtlichen Schwachstelle, z. B. ein f-string mit user-input in einer SQL-Query>
```

Erwartetes Verhalten:
1. Antwort beginnt mit einer Reconnaissance-Phase (Projekttyp, Frameworks, geladene Module)
2. Findet die offensichtliche Schwachstelle mit Datei + Zeile + Snippet
3. Klassifiziert mit Schwere + Ausnutzbarkeit + Konfidenz
4. Schreibt einen Bericht `SECURITY_REVIEW_YYYY-MM-DD.md`
5. Endet mit dem Self-Check-Block

Wenn der Skill nicht triggert: Skill in den Settings prüfen / Reload Window / SKILL.md-Pfad verifizieren.

## Aufruf-Beispiele

```
Mach ein Security-Review von src/auth.py
Audit das gesamte Repo auf Schwachstellen
Prüfe nur die geänderten Files im aktuellen Diff
Threat-Model für das Bestellsystem
Compliance-Check (DSGVO) für unsere User-Daten-Verarbeitung
Schwachstellenanalyse fokussiert auf Auth
Pentest-Vorbereitung — Pre-Commit-Modus
```

## Kernprinzipien — Anti-Halluzinations-Guardrails

Der Skill ist explizit gegen "erfundene Schwachstellen" gehärtet. Mehrstufige Schutzmechanismen:

1. **Evidenz vor Spekulation** — kein Befund ohne konkrete Datei + Zeile + Snippet
2. **Wörtliches Code-Zitat** — Snippets müssen Zeichen-für-Zeichen aus der Datei kommen, nicht paraphrasiert
3. **3-Fragen-Test** vor jedem Befund (Source erreicht Sink? Echter Sink? Keine wirksame Mitigation auf dem Pfad?) — siehe `references/false-positive-rules.md`
4. **7-Punkte-Anti-Halluzinations-Checkliste** in SKILL.md, die JEDEN Befund vor Aufnahme bestehen muss (Datei existiert, Zeile existiert, Snippet wörtlich, Source-Sink-Pfad, keine Mitigation, CWE belegbar, Exploit-Skizze plausibel)
5. **Konfidenz-Stufen transparent** — `Confirmed` / `Likely` / `Possible`. Bei "Possible" zwingend "What I checked / What I couldn't check"
6. **Verbotene Patterns explizit gelistet** — keine erfundenen CVE-Nummern, keine geratenen CWE-IDs, keine CVSS-Scores ohne Vektor, keine generischen "scheint schwach"-Behauptungen
7. **Vorsichtshalber-Befunde sind verboten** — wenn Mitigation greift, NICHT trotzdem melden
8. **Selbst-Kontrolle vor Abgabe** — 7-Punkte-Self-Check-Block am Ende jedes Berichts
9. **Hypothesen-Trennung** — alles Unklare geht in "Hinweise zur weiteren Untersuchung", nie in die Befundliste
10. **Read-only** — kein Code wird verändert
11. **Ehrlicher Kurzbericht statt aufgeblähter Falschbericht** — explizit als Tugend in SKILL.md verankert

Die zentralen Regeln stehen direkt in `SKILL.md` (Abschnitt "Anti-Halluzinations-Checkliste") und werden für jedes Tiefenmodul über `false-positive-rules.md` operationalisiert.

## Lizenz

MIT — kein Support-Anspruch, keine Garantie auf Vollständigkeit. Ersetzt keinen professionellen Penetration Test, keinen formalen Audit (ISO 27001-LA, PCI-QSA, CISA), keine rechtliche Beratung.
