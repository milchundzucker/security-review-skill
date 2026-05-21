# Secret Scanning & Dependency Vulnerability Check

Diese Referenz deckt zwei eng verwandte Bereiche ab: das Finden von hardcoded Secrets und das Identifizieren von anfälligen Dependencies.

## Teil 1 — Secret Scanning (CWE-798)

**Ziel:** Hardcoded Credentials und API-Keys finden, ohne in jedem `"test123"` einen False Positive zu produzieren.

### Hochrisiko-Patterns (Confidence: Confirmed/Likely)

Diese Patterns haben sehr niedrige False-Positive-Raten:

```
# AWS
rg "AKIA[0-9A-Z]{16}"                              # AWS Access Key ID
rg "aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]"

# Google Cloud
rg "AIza[0-9A-Za-z_-]{35}"                         # Google API Key
rg "ya29\.[0-9A-Za-z_-]+"                          # Google OAuth Access Token

# GitHub
rg "ghp_[A-Za-z0-9]{36}"                           # GitHub PAT (classic)
rg "github_pat_[A-Za-z0-9_]{82}"                   # GitHub PAT (fine-grained)
rg "ghs_[A-Za-z0-9]{36}"                           # GitHub App Token

# Stripe
rg "sk_(live|test)_[A-Za-z0-9]{24,}"               # Stripe Secret Key
rg "rk_(live|test)_[A-Za-z0-9]{24,}"               # Stripe Restricted Key

# Slack
rg "xox[abpr]-[A-Za-z0-9-]+"                       # Slack Token

# Generic high-confidence
rg "-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
rg "Bearer [A-Za-z0-9._-]{30,}"
rg "eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"  # JWT
```

### Mittel-Risiko-Patterns (Confidence: Possible — Kontext prüfen)

Diese brauchen Kontext-Validation:

```
rg -i "(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
rg -i "(jdbc:|mongodb:|mysql:|postgres:|redis:)//[^:]+:[^@]+@"  # Connection Strings
rg -i "(authorization|x-api-key)\s*:\s*['\"][^'\"]{10,}['\"]"
```

### Whitelist (NICHT als Befund melden)

- Werte in `/tests/`, `/test/`, `__tests__/`, `*.spec.*`, `*.test.*`
- Werte in Beispiel-Configs (`.env.example`, `.env.sample`, `config.example.*`)
- Offensichtliche Platzhalter: `your-key-here`, `changeme`, `REPLACE_ME`, `<.*>`, `xxx...`
- Public Keys (`-----BEGIN PUBLIC KEY-----`, `-----BEGIN CERTIFICATE-----`)
- Werte mit niedriger Entropie (z. B. `"password": "admin"` ist ein Default-Hinweis, kein konkretes Leak — eher A05 Misconfig)

### Pfade, die immer geprüft werden

```
.env, .env.local, .env.production
config/*.{yml,yaml,json,toml}
docker-compose.yml, kubernetes/*.yaml
src/**/*.{py,js,ts,java,go,rb,php,cs,rs}
*.tfvars
ansible/group_vars/*, ansible/host_vars/*
```

### Git-History-Hinweis

Im aktuellen Code keine Secrets ist NICHT genug — falls Tools wie `git log -p` verfügbar sind, prüfen, ob Secrets historisch im Repo waren. Wenn ja: als Befund mit Konfidenz "Confirmed" markieren, da das Secret rotiert werden muss (auch wenn jetzt nicht mehr im HEAD).

**Vorgehen:**
```bash
git log --all --full-history -p -- .env 2>/dev/null | rg "(AKIA|ghp_|sk_live)"
```

### Befund-Format für Secrets

```
[SEC-XX] Hardcoded AWS Access Key in src/config.py:42
Severity:    High (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5)
Exploitability: Supply-Chain (wenn Repo public) oder External-Unauth (wenn deployed)
Confidence:  Confirmed
CWE:         CWE-798
OWASP:       A02:2021 / A07:2021

Evidence:
src/config.py:42:    AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

Action:
1. Rotate the key immediately in AWS IAM (do NOT just remove from code).
2. Move to environment variable or secret manager.
3. Run `git filter-repo` / BFG to scrub from git history.
4. Audit CloudTrail for unauthorized use of this key.
```

---

## Teil 2 — Dependency Vulnerabilities (A06:2021, A03:2025)

**Ziel:** Bekannte CVEs in verwendeten Bibliotheken identifizieren — ohne externe Datenbank-Lookups (sofern nicht erlaubt).

### Vorgehen

1. **Manifest-Dateien identifizieren** (siehe Phase 1).
2. **Versionen extrahieren**.
3. **Gegen bekannte high-impact CVEs prüfen** (siehe Liste unten).
4. **Lock-File-Status prüfen**: Gibt es `package-lock.json`/`yarn.lock`/`poetry.lock`/`Gemfile.lock`? Pinning vorhanden?
5. **Wenn ein Tool wie `npm audit`, `pip-audit`, `safety`, `osv-scanner`, `govulncheck` verfügbar ist**, dessen Output einbeziehen. Aber: nicht erfinden, dass es einen CVE gibt, wenn das Tool nicht lief.

### Hoch-Impact-CVEs (Memorisierte Liste — Stand: bekannte historische Vorfälle)

Nur als Anker; bei modernem Code bitte trotzdem mit Tools verifizieren. Wenn diese Versionen im Manifest stehen, ist es ein **Confirmed**-Befund:

| Paket                 | Anfällige Version       | CVE / Hinweis                                 |
|-----------------------|--------------------------|------------------------------------------------|
| log4j-core (Java)     | 2.0 – 2.14.x             | CVE-2021-44228 (Log4Shell, Critical RCE)       |
| Spring Framework      | 5.3.0–5.3.17, 5.2.0–5.2.19 | CVE-2022-22965 (Spring4Shell, RCE)           |
| Apache Struts         | 2.0.0 – 2.3.34, 2.5–2.5.16 | CVE-2017-5638 (Equifax-Breach)                |
| jackson-databind      | < 2.10.x mit Default Typing | mehrere RCE-CVEs                             |
| Apache Commons Text   | 1.5 – 1.9                | CVE-2022-42889 (Text4Shell)                    |
| OpenSSL               | < 3.0.7 (3.0-Serie)      | CVE-2022-3602, CVE-2022-3786                   |
| Node.js               | < 18.x (alte LTS)        | mehrere CVEs, EoL-Status prüfen                |
| Django                | < 4.2.x (je nach Vuln)   | regelmäßig CVEs, immer LTS verwenden           |
| Flask < 2.3           | älter                    | mehrere CVEs in Dependencies (Werkzeug, Jinja) |
| lodash                | < 4.17.21                | Prototype Pollution (CVE-2020-8203)            |
| express               | < 4.17.x                 | DoS- und Header-Schwachstellen                 |
| Next.js               | < 13.4.20 / < 14.1.1     | mehrere SSRF / Cache-Poisoning                 |
| LangChain             | < 0.0.247                | Prompt-Injection-bezogene Issues               |
| transformers          | < 4.36                   | Unsafe pickle in einigen Models                |
| pyyaml                | < 5.1 mit `yaml.load`    | RCE                                            |
| Werkzeug              | < 3.0.1                  | RCE in dev-Server-Pfad                         |

### Indirekte Indikatoren

- **Lock-File fehlt** → Reproduzierbarkeit nicht gegeben, transient Dependencies können sich ändern. Befund "Software Integrity Failure" mit Severity Medium.
- **Lock-File alt** (z. B. >12 Monate) → wahrscheinlich enthält veraltete Versionen.
- **Manifest mit floating Versions**: `"package": "^1.0.0"`, `"package": "*"` → Risiko bei npm install.
- **Manifest mit EoL-Sprachen/-Runtimes**: Python 2.x, Node 14.x, Java 8 mit altem Update-Patch.

### Supply-Chain-Indikatoren (A03:2025)

- Dependencies aus inoffiziellen Registries (`npm install --registry=http://internal-mirror/`)
- Dependencies, die kürzlich Namens-Squatting-Reports hatten (`request` → `requests-py`, `pytorch` vs. `pytorh`, klassische Typosquats)
- Post-Install-Scripts (`postinstall` in `package.json`) — sollten geprüft werden
- Direct-from-GitHub Dependencies (`"package": "github:user/repo"`) — Hash-Pinning prüfen

**Patterns:**
```
rg "\"postinstall\":" package.json -A 2
rg "github:" package.json
rg "pip install -i\s+http://" --type sh
```

### CI/CD-Supply-Chain

- GitHub Actions ohne SHA-Pinning (siehe `language-patterns.md` → GitHub Actions)
- Fehlende SBOM-Generierung
- Fehlendes Image-Signing (Cosign, Sigstore)
- Builds, die `curl | sh` Installationen machen

---

## Befund-Format für Dependency-Vulnerabilities

```
[DEP-XX] Vulnerable Dependency: log4j-core 2.14.1
Severity:    Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0)
Exploitability: External-Unauth (sofern Anwendung Log-Daten von außen verarbeitet)
Confidence:  Confirmed
CVE:         CVE-2021-44228 (Log4Shell)
OWASP:       A06:2021 / A03:2025

Evidence:
pom.xml:34:    <version>2.14.1</version>

Action:
1. Upgrade to log4j-core 2.17.1+ (or 2.12.4 / 2.3.2 for older Java).
2. Set `log4j2.formatMsgNoLookups=true` as immediate stopgap if upgrade is blocked.
3. Audit logs for exploitation attempts (look for ${jndi:...} patterns in logs since deploy date).
```

## Hinweis

Wenn KEIN Tool-Run für Dependency-Check vorliegt (kein `npm audit`-Output etc.), dann im Bericht klarstellen:

> "Dependency-Check wurde gegen die bekannte Liste prominenter CVEs durchgeführt. Für eine vollständige Prüfung wird `osv-scanner`, `npm audit`, `pip-audit` oder `Trivy` empfohlen."

Niemals erfinden, dass ein Tool gelaufen ist, wenn es nicht gelaufen ist.
