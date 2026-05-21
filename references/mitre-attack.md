# MITRE ATT&CK — Mapping für Code-Befunde

MITRE ATT&CK ist kein Schwachstellenkatalog, sondern eine **Wissensbasis von Angreifer-Taktiken und -Techniken** über den gesamten Angriffslebenszyklus. Diese Referenz hilft, Code-Befunde auf den Angriff abzubilden, den sie ermöglichen — wertvoll für Threat-Modeling, SOC-Integration und Reporting an Security-Teams.

Diese Datei lädt man, wenn der User MITRE-Mapping explizit anfordert, ein SOC-relevanter Bericht erstellt wird, oder das Projekt sicherheitskritische Funktionen hat (Auth, Crypto, Network).

## Lifecycle-Phasen und relevante Befund-Kategorien

ATT&CK kennt 14 Taktiken (für Enterprise). Die folgende Tabelle zeigt typische Code-Befunde pro Taktik.

| Tactic | Typischer Befund-Pfad |
|--------|------------------------|
| **TA0042 Resource Development** | Domain-Squatting, gefälschte Pakete in der Supply-Chain |
| **TA0001 Initial Access** | RCE-Vektoren, schwache Auth, Public-facing-Misconfig |
| **TA0002 Execution** | Deserialization, SSTI, Command Injection |
| **TA0003 Persistence** | Webshells, Auto-Run-Mechanismen, Cron-Jobs, Cloud-IAM-Backdoors |
| **TA0004 Privilege Escalation** | sudo NOPASSWD, SUID-Binaries, K8s-Pods mit `privileged: true` |
| **TA0005 Defense Evasion** | Logging deaktiviert, Audit-Trail-Manipulation, Obfuscation |
| **TA0006 Credential Access** | Hardcoded Secrets, schwache Hashes, Memory-Dump |
| **TA0007 Discovery** | Verbose Error Messages, Stack-Traces, Debug-Endpoints |
| **TA0008 Lateral Movement** | SSRF, übermäßige Service-Account-Permissions, RPC ohne Auth |
| **TA0009 Collection** | DB-Volldump-Vektoren, BOLA, sensitive Logs |
| **TA0011 Command and Control** | Reverse-Shells, DNS-Tunneling-fähige Code-Paths |
| **TA0010 Exfiltration** | SSRF + Cloud-Storage, große Response-Limits, DB-Export-Endpoints |
| **TA0040 Impact** | Destruktive Aktionen ohne Bestätigung, Ransomware-Pfade |

## Häufig benötigte Technik-IDs

Mapping von typischen Findings auf ATT&CK-Technique-IDs:

### Initial Access (TA0001)

| Technique | Beschreibung | Typischer Befund |
|-----------|--------------|------------------|
| T1190 | Exploit Public-Facing Application | RCE durch Deserialization, SSTI, Log4Shell-artige |
| T1133 | External Remote Services | Public RDP/SSH, ungeschützte VPN-Gateways |
| T1078 | Valid Accounts | Stolen Credentials, default Credentials |
| T1195.002 | Compromise Software Supply Chain | Kompromittierte Dependency, Typosquatting |
| T1566 | Phishing | Nicht direkt im Code, aber Auth-Schwächen begünstigen |

### Execution (TA0002)

| Technique | Beschreibung | Typischer Befund |
|-----------|--------------|------------------|
| T1059 | Command and Scripting Interpreter | OS-Command-Injection |
| T1203 | Exploitation for Client Execution | XSS, Browser-RCE-Pfade |
| T1559 | Inter-Process Communication | Unsafe IPC, RPC ohne Auth |
| T1610 | Deploy Container | K8s-Pod-Creation durch Angreifer |

### Persistence (TA0003)

| Technique | Beschreibung | Typischer Befund |
|-----------|--------------|------------------|
| T1505.003 | Web Shell | File-Upload-Pfad zu Webshell |
| T1098 | Account Manipulation | IAM-Backdoor (eigene Permissions hinzufügen) |
| T1136 | Create Account | Selbst-Registrierung mit Admin-Rolle möglich |
| T1543 | Create or Modify System Process | systemd, cron, Windows-Services |
| T1547 | Boot or Logon Autostart Execution | Plist, Run-Keys |

### Privilege Escalation (TA0004)

| Technique | Beschreibung | Typischer Befund |
|-----------|--------------|------------------|
| T1068 | Exploitation for Privilege Escalation | Kernel/Container-Escape-Vuln |
| T1548 | Abuse Elevation Control Mechanism | sudoers misconfig, UAC-Bypass |
| T1611 | Escape to Host | Container-Escape via privileged-Container |
| T1078 | Valid Accounts | (Wiederverwendet aus Initial Access) |

### Defense Evasion (TA0005)

| Technique | Beschreibung | Typischer Befund |
|-----------|--------------|------------------|
| T1562.002 | Disable Windows Event Logging | Code, der Logging abschaltet |
| T1070 | Indicator Removal | `os.remove(log_file)`, Audit-Manipulation |
| T1027 | Obfuscated Files or Information | Base64-Loader, packed Binaries |
| T1140 | Deobfuscate/Decode Files | eval(base64.decode(...)) Patterns |

### Credential Access (TA0006)

| Technique | Beschreibung | Typischer Befund |
|-----------|--------------|------------------|
| T1552.001 | Credentials In Files | Hardcoded Secrets, `.env` im Repo |
| T1552.004 | Private Keys | Private Keys im Repo |
| T1555 | Credentials from Password Stores | Schwacher Keychain-Zugriff |
| T1110 | Brute Force | Auth-Endpoint ohne Rate-Limit |
| T1539 | Steal Web Session Cookie | XSS, schwache Cookies |
| T1606 | Forge Web Credentials | JWT alg=none, schwache HMAC-Secrets |

### Discovery (TA0007)

| Technique | Beschreibung | Typischer Befund |
|-----------|--------------|------------------|
| T1083 | File and Directory Discovery | Path-Traversal-Pfad zum Enumerieren |
| T1082 | System Information Discovery | Debug-Endpoints, `/health` mit zu viel Info |
| T1018 | Remote System Discovery | SSRF ermöglicht Netzwerk-Scan |
| T1087 | Account Discovery | User-Enumeration via Auth-Errors |

### Lateral Movement (TA0008)

| Technique | Beschreibung | Typischer Befund |
|-----------|--------------|------------------|
| T1210 | Exploitation of Remote Services | SSRF + interne Services |
| T1021 | Remote Services | Service-Account-Reuse über Services |
| T1078 | Valid Accounts | Stolen-Token-Wiederverwendung |
| T1550 | Use Alternate Authentication Material | Pass-the-Hash, Pass-the-Token |

### Collection (TA0009)

| Technique | Beschreibung | Typischer Befund |
|-----------|--------------|------------------|
| T1213 | Data from Information Repositories | BOLA, IDOR auf Datenbank-Inhalte |
| T1530 | Data from Cloud Storage | Public S3-Buckets |
| T1005 | Data from Local System | Path-Traversal auf Datenbank-Files |
| T1056 | Input Capture | Keylogger-Vektoren in Web-Apps |

### Command and Control (TA0011)

| Technique | Beschreibung | Typischer Befund |
|-----------|--------------|------------------|
| T1071 | Application Layer Protocol | RCE-Output bekommt C2-Channel |
| T1572 | Protocol Tunneling | DNS-Tunneling-fähige Komponenten |
| T1090 | Proxy | SSRF als initialer C2-Hop |

### Exfiltration (TA0010)

| Technique | Beschreibung | Typischer Befund |
|-----------|--------------|------------------|
| T1041 | Exfiltration Over C2 Channel | RCE + Pipe zu Daten |
| T1567 | Exfiltration Over Web Service | Webhook-Endpoints mit User-URL |
| T1048 | Exfiltration Over Alternative Protocol | DNS-Exfil, ICMP-Exfil |
| T1537 | Transfer Data to Cloud Account | Cloud-IAM-Misconfig + Cross-Account |

### Impact (TA0040)

| Technique | Beschreibung | Typischer Befund |
|-----------|--------------|------------------|
| T1486 | Data Encrypted for Impact | Ransomware-Pfad (Schreibzugriff auf alle Daten) |
| T1485 | Data Destruction | Destruktive Endpoints ohne Bestätigung |
| T1496 | Resource Hijacking | Crypto-Mining-Pfad in kompromittierter Lambda |
| T1499 | Endpoint Denial of Service | DoS-Schwachstellen |
| T1531 | Account Access Removal | Account-Lockout-Massenangriff |

## Cloud-spezifische Matrizen

ATT&CK hat dedizierte Matrizen für:

- **ATT&CK for Cloud**: AWS, Azure, GCP, Office 365, Azure AD, SaaS, IaaS
- **ATT&CK for Containers**: Docker, Kubernetes
- **ATT&CK for Mobile**: Android, iOS
- **ATT&CK for ICS**: Industrial Control Systems

Bei Cloud-Code-Audits zusätzlich relevante Techniken:

| ID | Beschreibung |
|----|--------------|
| T1078.004 | Valid Accounts: Cloud Accounts |
| T1098.001 | Account Manipulation: Additional Cloud Credentials |
| T1098.003 | Account Manipulation: Additional Cloud Roles |
| T1525 | Implant Internal Image (containerized) |
| T1538 | Cloud Service Dashboard |
| T1580 | Cloud Infrastructure Discovery |
| T1538 | Cloud Service Dashboard |
| T1611 | Escape to Host (Container Escape) |

## Wie das im Bericht angewendet wird

Für sicherheitsrelevante Befunde im Bericht zusätzlich zu OWASP/CWE die ATT&CK-Technique angeben:

```
[SEC-01] SQL Injection in /api/users/search
OWASP:     A03:2021 Injection
CWE:       CWE-89
ATT&CK:    T1190 (Exploit Public-Facing Application) → T1213 (Data from Information Repositories)
           Möglicher Lateral-Pfad: → T1213 (Data from DB) → T1041 (Exfiltration)
```

Bei Reporting an SOC-Teams hilft das ATT&CK-Mapping, weil sie damit ihre Detection-Logic verknüpfen können (welcher EDR-Alert würde diesen Angriff sehen?).

## Defense-Mapping (umgekehrt)

Für jeden Befund kann zusätzlich die "Mitigations"-Liste von ATT&CK referenziert werden (M-Codes), z. B.:

- M1041 Encrypt Sensitive Information
- M1027 Password Policies
- M1032 Multi-factor Authentication
- M1018 User Account Management
- M1026 Privileged Account Management
- M1037 Filter Network Traffic
- M1031 Network Intrusion Prevention
- M1042 Disable or Remove Feature or Program
- M1054 Software Configuration
- M1051 Update Software
- M1017 User Training

## Limitierungen / Ehrlichkeit

- ATT&CK-Mapping ist eine **Hilfe**, kein Selbstzweck. Befunde nicht künstlich auf Techniques mappen, wenn der Zusammenhang dünn ist.
- ATT&CK beschreibt Angreifer-Verhalten in echten Incidents — nicht jede Code-Schwachstelle hat einen ATT&CK-Code.
- Wenn unklar: weglassen statt erfinden. Ein falsches Mapping ist schlimmer als kein Mapping.

## Referenz

- Hauptseite: https://attack.mitre.org/
- ATT&CK Navigator: für visuelle Matrix-Darstellung
- D3FEND (komplementär): Defensive Techniques
- CAR (Cyber Analytics Repository): Detection Analytics
