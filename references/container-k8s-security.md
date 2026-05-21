# Container & Kubernetes Security

Wird geladen, wenn `Dockerfile`, `docker-compose.yml`, oder Kubernetes-Manifeste (`*.yaml` mit `kind:` Pod/Deployment/etc.) erkannt werden.

Basis: Microsoft "Threat Matrix for Kubernetes", CIS Docker/Kubernetes Benchmarks, NSA Kubernetes Hardening Guide.

## Dockerfile-Schwachstellen

### USER, Root-Vermeidung

```
# Findet Dockerfiles ohne explizites USER
for f in $(rg -l "^FROM" Dockerfile*); do
  if ! grep -q "^USER " "$f"; then echo "Kein USER in $f"; fi
done
```

**Anti-Patterns:**
- Kein `USER <nonroot>` → Container läuft als `root` (UID 0)
- `USER root` explizit gesetzt
- `chmod 777` in RUN
- Multi-Stage-Build ohne `USER` in finaler Stage

**Sicher:**
```dockerfile
FROM alpine:3.19
RUN adduser -D -u 10001 appuser
USER 10001:10001  # numerische UIDs für K8s runAsNonRoot Check
```

### Image-Hygiene

```
rg "^FROM\s+\S+:latest" Dockerfile*    # latest tag = nicht reproduzierbar
rg "^FROM\s+\S+@sha256:" Dockerfile*   # gut: SHA-Pinning
rg "^ADD\s+https?://" Dockerfile*      # ADD mit URL = Download zur Buildzeit
rg "^RUN\s+curl.*\|\s*(ba)?sh" Dockerfile*  # curl|bash → MITM-Risiko
rg "^RUN\s+wget.*\|\s*(ba)?sh" Dockerfile*
```

**Anti-Patterns:**
- `FROM image:latest` → unreproduzierbar, Supply-Chain-Risk
- `ADD <URL>` statt `COPY` → keine Integritätsprüfung
- `curl ... | sh` ohne Hash-Check
- Fehlende `--no-install-recommends` / `--no-cache-dir` → Bloat → mehr Angriffsfläche
- Keine `HEALTHCHECK`-Instruktion

### Secrets in Layers

```
rg "^ENV\s+(.*)(SECRET|PASSWORD|TOKEN|KEY)" Dockerfile*
rg "^ARG\s+(.*)(SECRET|PASSWORD|TOKEN|KEY)" Dockerfile*  # ARGs landen in History!
rg "^RUN\s+.*--build-arg" Dockerfile*
```

**Anti-Patterns:**
- `ENV API_KEY=xyz` → in finalem Image lesbar
- `ARG SECRET` → in `docker history` sichtbar, auch bei Multi-Stage
- `COPY .env /app/.env` → Secret im Image-Layer
- Secret in `RUN`-Befehl → in History, sogar wenn rm danach

**Sicher:** BuildKit `--secret` Mount oder Multi-Stage mit gezieltem COPY.

### docker-compose

```
rg "privileged:\s*true" docker-compose*.yml
rg "network_mode:\s*['\"]?host" docker-compose*.yml
rg "pid:\s*['\"]?host" docker-compose*.yml
rg "volumes:.*:/var/run/docker\.sock" docker-compose*.yml  # Docker-Socket-Mount!
rg "cap_add:" docker-compose*.yml -A 2
```

**Anti-Patterns:**
- `privileged: true` (entspricht `--privileged`)
- Mount von `/var/run/docker.sock` → Container Escape via Docker-API
- `cap_add: [SYS_ADMIN]`, `cap_add: [ALL]` → Capability-Eskalation
- `network_mode: host` oder `pid: host` → Container-Isolation aufgehoben

## Kubernetes — Pod Security

### Pod Security Standards (PSS)

```
rg "kind:\s*(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob)" -A 30 *.yaml
```

In jedem Pod/Workload prüfen:

**Sicherheitskontext (Pod-Level):**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  seccompProfile:
    type: RuntimeDefault
```

**Sicherheitskontext (Container-Level):**
```yaml
securityContext:
  allowPrivilegeEscalation: false
  privileged: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ "ALL" ]
    add: [ "NET_BIND_SERVICE" ]  # nur wenn nötig
```

**Detection (jede Verletzung = Befund):**
```
rg "privileged:\s*true" *.yaml --type yaml
rg "hostNetwork:\s*true" *.yaml
rg "hostPID:\s*true"
rg "hostIPC:\s*true"
rg "runAsUser:\s*0\b"
rg "allowPrivilegeEscalation:\s*true"
rg "readOnlyRootFilesystem:\s*false"
```

**Fehlende Felder sind auch Befunde:**
- Kein `runAsNonRoot: true` → Container kann als root laufen
- Kein `readOnlyRootFilesystem: true` → Tampering möglich
- Kein `seccompProfile` → keine Syscall-Filterung
- Kein `securityContext` insgesamt → alle Defaults aktiv

### Capabilities

Standard-Linux-Capabilities, die NIE in Containern gebraucht werden sollten:
- `SYS_ADMIN` — fast root-Äquivalent
- `NET_ADMIN` — Netz-Manipulation
- `SYS_PTRACE` — Process-Inspection
- `SYS_MODULE` — Kernel-Module
- `DAC_OVERRIDE` — File-Permission-Bypass
- `BPF` (auf neueren Systemen) — eBPF-Loader

Beste Praxis: `drop: [ "ALL" ]` + nur explizit notwendige hinzufügen.

### hostPath, sensitive Mounts

```
rg "hostPath:" *.yaml -A 3
```

**Kritische Mounts:**
- `/` (root filesystem)
- `/proc`, `/sys` → Kernel-Info-Disclosure
- `/var/run/docker.sock` → Docker-API → Container Escape
- `/etc/kubernetes`, `/var/lib/kubelet` → Cluster-Takeover
- `/dev` → Hardware-Access

## Kubernetes — Network

```
rg "kind:\s*NetworkPolicy" *.yaml  # vorhanden?
```

**Anti-Patterns:**
- Kein NetworkPolicy in einem Namespace → Default ist "alles erlaubt"
- Default-deny NetworkPolicy fehlt
- Egress-Policies fehlen (Pod kann ins Internet, exfilieren)

**Sicher:** Default-Deny + explizite Allow-Listen für Ingress und Egress.

### Service-Typen

```
rg "type:\s*LoadBalancer" *.yaml      # öffentlich exposed?
rg "type:\s*NodePort" *.yaml          # öffentlich exposed?
```

LoadBalancer und NodePort exponieren Services über die Cluster-Grenze. Prüfen, ob das beabsichtigt ist und Authentifizierung vorhanden ist.

## Kubernetes — Secrets

```
rg "kind:\s*Secret" *.yaml -A 10
rg "env:.*name:.*valueFrom:.*secretKeyRef" *.yaml -A 3  # OK
rg "value:\s*[\"']?[A-Za-z0-9+/=]{40,}[\"']?" *.yaml    # Inline-Secret?
```

**Anti-Patterns:**
- Secret als `value:` im Manifest statt `valueFrom.secretKeyRef`
- Secret-Manifest mit Plain-Base64-Wert in Git committet
- Secrets als Environment-Variable (statt Volume-Mount) → leakage via `/proc/<pid>/environ`
- Fehlende Verschlüsselung-at-rest in etcd (`--encryption-provider-config`)
- Service-Account-Token automatisch gemountet (`automountServiceAccountToken: true` Default)

**Sicher:** External Secrets Operator + KMS-backed Vault/SecretsManager/KeyVault.

## Kubernetes — RBAC

```
rg "kind:\s*(ClusterRoleBinding|RoleBinding)" *.yaml -A 10
rg "verbs:.*\*" *.yaml
rg "resources:.*\*" *.yaml
rg "name:\s*cluster-admin" *.yaml -A 5  # wer hat das?
```

**Anti-Patterns:**
- `verbs: ["*"]` oder `resources: ["*"]` in Role/ClusterRole
- ServiceAccount mit `cluster-admin`-Binding
- Default-ServiceAccount mit Permissions
- Anonymous user (`system:anonymous`) mit Permissions
- Bindings, die `system:authenticated` Gruppe Permissions geben (= alle authentifizierten Cluster-User)

### Service Account Token Mount

```
rg "automountServiceAccountToken:\s*false"  # gut wenn vorhanden
```

Per Default mountet K8s SA-Tokens in jeden Pod — auch wenn der Pod die K8s-API nicht braucht. Best Practice: `automountServiceAccountToken: false` als Default, nur opt-in.

## Admission Control / Policy Engines

Im Bericht als Empfehlung erwähnen, falls nicht vorhanden:
- **Kyverno** oder **OPA Gatekeeper** für policy-as-code
- **Pod Security Admission** (Built-in ab K8s 1.25, ersetzt PSP)
- **Falco** für Runtime-Detection

## Microsoft Threat Matrix for Kubernetes — Schlüssel-Techniken

Im Bericht bei K8s-Befunden auf diese Taktiken mappen:

- **Initial Access**: Compromised Image, Container Registry Compromise, kubeconfig File
- **Execution**: bash/cmd inside container, exec into container
- **Persistence**: Backdoor Container, Writable hostPath Mount
- **Privilege Escalation**: Privileged Container, Cluster-admin Binding, hostPath Mount, Access Cloud Resources
- **Defense Evasion**: Clear Container Logs, Delete K8s Events
- **Credential Access**: List K8s Secrets, Mount Service Principal, Access Container Service Account, Application credentials in configuration files
- **Discovery**: Access K8s API Server, Access Kubelet API, Network Mapping, Exposed Sensitive Interfaces, Instance Metadata API
- **Lateral Movement**: Access Cloud Resources, Container Service Account, Cluster Internal Networking, Application Credentials, Writable Volume Mounts on the Host, CoreDNS Poisoning, ARP Poisoning and IP Spoofing
- **Impact**: Data Destruction, Resource Hijacking (Crypto-Mining), Denial of Service

## Image-Scanning

Falls Build/CI sichtbar: prüfen ob Image-Scanning eingebaut ist.
```
rg "trivy|grype|snyk|anchore|clair|aquasec" .github/workflows/ .gitlab-ci.yml
```

Wenn nicht vorhanden: Befund "Fehlendes Container Image Scanning" (Medium).

## Befund-Format-Beispiele

```
[CONT-01] Privilegierter Container in deployment/api.yaml:23
Severity:    High (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H = 8.0)
Exploitability: External-Auth (Cluster-Zugriff erforderlich, dann Container-Escape möglich)
CWE:         CWE-269 Improper Privilege Management
ATT&CK:      T1611 Escape to Host

Evidence:
deployment/api.yaml:23:    privileged: true

Eine Privilege-Escalation in diesem Container ermöglicht Cluster-Node-Takeover
über Capabilities, /dev-Mounts und Kernel-Schnittstellen.

Action:
- privileged: false setzen
- securityContext mit drop ALL capabilities
- runAsNonRoot: true
- readOnlyRootFilesystem: true
```

## CWE-/OWASP-Mappings

- CWE-250 Execution with Unnecessary Privileges
- CWE-269 Improper Privilege Management
- CWE-732 Incorrect Permission Assignment
- A05 Security Misconfiguration
- A01 Broken Access Control (für RBAC-Misconfigs)
