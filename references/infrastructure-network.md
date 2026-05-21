# Infrastructure & Network Security

Geladen, wenn Infrastruktur-Komponenten erkannt werden: Reverse Proxies (NGINX, HAProxy, Traefik, Envoy), Service Meshes (Istio, Linkerd, Consul), Network-Policies, Load-Balancer-Configs, DNS-Configs, WAF-Rules.

Komplementiert `cloud-security.md` (Cloud-Provider-spezifisch) und `container-k8s-security.md` (Container/K8s).

## 1. Reverse-Proxy-Konfiguration

### NGINX

**Häufige Fehler:**
- `server_tokens on` → NGINX-Version in Headers
- Default-Server fehlt → falsche Host-Header treffen erste Server-Block
- `proxy_pass http://...` (HTTP) bei internem Routing — kein TLS in-cluster
- `add_header` ohne `always` → nicht bei Error-Responses gesetzt
- `client_max_body_size` zu groß (DoS) oder zu klein (Funktionsbruch)
- `underscores_in_headers off` (default) → Header mit Underscores ignoriert (HTTP-Smuggling-Vektor)

```
rg "server_tokens|server_name|proxy_pass" *.conf
rg "add_header.*X-(Frame|Content|Powered)" *.conf
rg "client_max_body_size" *.conf
```

### HAProxy

- `option httplog` mit User-Pfaden → PII in Logs
- `option forwardfor` ohne ACL — User kann `X-Forwarded-For` faken
- TLS: `ssl-default-bind-options` ohne `no-sslv3 no-tls10 no-tls11`
- ACLs mit String-Match auf Pfad — Bypass via URL-Encoding möglich

### Traefik

- `--api.insecure=true` exposed → Dashboard public
- IngressRoute ohne TLS-Middleware
- File-Provider mit world-readable Permissions

### Envoy / Service Mesh

- mTLS nicht enforced (`STRICT` vs `PERMISSIVE`)
- AuthorizationPolicy fehlt → alle Services dürfen alles
- External Auth Filter (ext_authz) ohne Fallback bei AuthZ-Server-Down

```
rg "PERMISSIVE|DISABLE" *.yaml | rg -i "mtls|peer"
rg "AuthorizationPolicy|VirtualService|DestinationRule" *.yaml
```

---

## 2. TLS-Termination

### Empfehlungen
- TLS 1.2 Minimum, 1.3 bevorzugt
- HSTS-Header (siehe `crypto-deep-dive.md`)
- OCSP-Stapling für Performance
- Certificate-Transparency-Monitoring
- ACME-Challenge-Endpoints nicht offen, sondern HTTP-01 oder DNS-01

### Anti-Patterns
- Self-signed Certs in Production
- Wildcard-Certs mit zu großem Scope (`*.example.com` für alle Subdomains, auch sensitive)
- Cert in Git committet (inkl. Private-Key!)
- Cert-Renewal-Job fehlt → Outage in 90 Tagen
- `ssl_verify_client off` für API-Endpoints, die mTLS brauchen

```
rg "ssl_protocols|TLSv1\.0|TLSv1\.1" *.conf
rg "BEGIN PRIVATE KEY|BEGIN RSA PRIVATE KEY" -r . | head -5
```

---

## 3. DNS-Konfiguration

### Sicherheitsrelevant

- **DNSSEC**: Schutz gegen DNS-Cache-Poisoning
- **CAA-Records**: nur erlaubte CAs dürfen Cert ausstellen
- **SPF/DKIM/DMARC**: Email-Spoofing-Schutz
- **DANE / TLSA**: TLS-Cert-Pinning via DNS (selten genutzt)
- **MTA-STS / TLS-RPT**: Email-TLS-Anforderungen

### Subdomain-Takeover
- DNS-Einträge zu nicht-mehr-existierenden Cloud-Resources (Heroku, S3, Azure, GitHub Pages) → Angreifer übernimmt
- Tools: `subjack`, `subzy`, `nuclei` Templates

### Detection (im Repo)
- Terraform mit Route53/Cloudflare/etc.-DNS-Records → manuell prüfen, ob Targets noch existieren

---

## 4. Network Policies (Kubernetes / Cloud)

### Default-Deny-Pattern

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

**Anti-Pattern:** Default-Allow (kein NetworkPolicy = alles erlaubt).

### Egress-Filter
- Lambda/Pod ohne Egress-Restriktion → Daten können beliebig exfiltriert werden
- Schutz: NAT-Gateway mit Allowlist, Egress-Proxy (Squid), Cloud-Native (AWS Network Firewall)

### Detection
```
rg "NetworkPolicy" *.yaml -A 10
rg "egress:" *.yaml -A 5
```

---

## 5. WAF (Web Application Firewall)

### Empfehlungen
- AWS WAF, Cloudflare, ModSecurity (OWASP CRS)
- Default-Mode: Block (nicht "Count")
- OWASP Core Rule Set (CRS) als Baseline
- Custom-Rules für App-spezifische Inputs
- Rate-Limiting pro IP / per ASN

### Pitfalls
- WAF im "Monitor"-Mode dauerhaft (false sense of security)
- WAF nur am Edge, nicht zwischen internen Services
- WAF-Bypass via:
  - Direct-IP-Access (CDN umgangen)
  - HTTP Smuggling (siehe `web-advanced.md` § 3)
  - Encoding-Variationen (Unicode, Double-URL-Encoding)
- WAF gibt False-Negative → primärer Schutz muss Application-Code sein

### Detection
```
rg "ModSecurity|SecRuleEngine|CRS|coraza" *.conf
rg "wafv2_web_acl|cloudflare_ruleset" --type tf
```

---

## 6. Load Balancer

### Health-Checks
- Health-Check-Endpoints mit zu viel Info (`/health` zeigt DB-Strings)
- Health-Check ohne Auth → öffentlich zugänglich
- Backend-Health-Probe als Detection-Vektor (Existenz internal services)

### Sticky Sessions
- Bei Auth-State im Cookie → OK
- Bei Auth-State im Server-Memory → Lock-in, schlecht skalierbar, Single-Point-of-Failure

### TLS-Offloading
- LB terminiert TLS → interne Calls HTTP → Internal-MITM möglich
- Solution: Re-Encrypt (LB → Backend wieder HTTPS)

---

## 7. Service Mesh

### Pro-Argumente (Security-Sicht)
- mTLS automatisch zwischen Services
- AuthZ via Policies (z. B. nur `frontend` darf `payment-api` aufrufen)
- Distributed Tracing
- Egress-Control

### Konfig-Checks
- Istio: `PeerAuthentication` mit `STRICT`-Mode
- Istio: `AuthorizationPolicy` mit Default-Deny pro Namespace
- Linkerd: `Server`-Resource mit `requireIdentityOnInbound`
- Envoy: SDS (Secret Discovery Service) für Cert-Rotation

### Pitfalls
- Sidecar-Bypass: Pod kommt direkt an Backend-IP ohne Sidecar
- Mesh nur intern → Edge bleibt schwach
- Performance-Overhead nicht kalkuliert
- Sidecar-Resource-Limits (kann selbst OOM crashen)

---

## 8. API Gateway

### Konfig-Checks
- Authentication am Gateway zentral (nicht bei jedem Backend)
- Rate Limiting zentral
- Request-Validation gegen OpenAPI-Schema
- Response-Validation (verhindert dass Backend mehr Daten leakt als Spec erlaubt)
- Logging am Gateway aktiv

### Anti-Patterns
- Gateway-Bypass: Backend-Services direkt im Public-Subnet
- Gateway als alleiniger Auth-Layer (Defense-in-Depth: Backend prüft auch)
- API-Keys als Query-Parameter

---

## 9. CDN-Konfiguration

### Cache-Control für sensitive Daten
- Auth-Endpoints: `Cache-Control: no-store`
- User-spezifische Pages: `Cache-Control: private, no-cache`
- Public-Assets: `public, max-age=31536000, immutable` mit Hash im Filename

### Anti-Patterns
- Auth-Token in URL → CDN cached die Response inkl. Token für andere User
- `Vary`-Header fehlt → Cross-User-Cache-Hits
- CDN-Bypass via `Host`-Header (siehe `web-advanced.md` § 4 Cache Poisoning)

### CDN-Specific Features
- AWS CloudFront: Origin-Access-Control (OAC) statt OAI
- Cloudflare: Workers für Request-Validation
- Fastly: VCL-Code-Review (selbst geschriebener Code = eigene Angriffsfläche)

---

## 10. Internal Network Segmentation

### Zero-Trust-Prinzipien
- Annahme: jedes Netzwerk-Segment ist kompromittiert
- Auth + Authz auf jedem Hop
- mTLS zwischen Services
- Identity-aware Proxy (BeyondCorp-Modell)

### Anti-Patterns
- "Flat Network" (alle Services in einem Subnet)
- DB-Server im selben Subnet wie Web-Server (kein DMZ-Pattern)
- Admin-Interfaces auf Internet (Kubernetes-Dashboard, Jenkins, Grafana, Kibana)
- Lateral-Movement-Pfade nicht segmentiert

---

## 11. VPN / Remote Access

### Code-relevant
- Hardcoded VPN-Credentials
- VPN-Configs im Repo (committet)
- Split-Tunneling-Konfigurationen mit Sicherheitslücken
- WireGuard-Keys committet

### Detection
```
rg "ovpn|wg-quick|tailscale|zerotier" -A 3
rg "BEGIN.*PRIVATE.*KEY" -- *.conf *.ovpn 2>/dev/null
```

---

## 12. Bastion / Jump Hosts

- SSH-Bastion mit Public-Key-Auth (kein Password)
- MFA für Bastion-Login
- Session-Recording (auditd / Teleport)
- Just-in-Time Access statt Standing-Permissions

---

## 13. IPv6-Spezifisch

- Firewall-Rules oft nur IPv4 → IPv6 vergessen → offene Ports
- Privacy-Extensions deaktiviert → Device-Tracking via IPv6-Adresse
- Link-Local-Adressen für interne Services?

---

## 14. Egress-Filter (für SSRF + Exfiltration-Schutz)

Pflicht für Apps, die HTTP-Requests basierend auf User-Input machen:

### Allowlist
- DNS-Resolver mit fixer Allowlist
- HTTP-Egress-Proxy mit URL-Whitelist
- Block: `169.254.*` (IMDS), `127.*`, `10.*`, `172.16-31.*`, `192.168.*`, IPv6-Privates

### Tooling
- AWS Network Firewall mit Domain-Allow
- Squid mit Allowlist
- OPA-basierter Egress-Gateway

---

## 15. Backup-Infrastructure

### Anforderungen
- 3-2-1-Regel: 3 Kopien, 2 Medien, 1 offsite
- Verschlüsselte Backups (Key NICHT auf demselben Backup-System)
- Immutable Backups (gegen Ransomware) — Object Lock, AWS Backup Vault Lock
- Regelmäßige Restore-Tests (Backup ohne Restore-Test ist kein Backup)

### Anti-Patterns
- Backup-Account mit gleichen Credentials wie Production → Ransomware compromittiert beides
- Backups im selben Region wie Primary → Region-Outage zerstört beides
- Keine MFA für Backup-Delete-Operations
- Backup-Restoration-Procedure undokumentiert

```
rg "backup|snapshot|s3 sync" --type yaml --type tf -A 5
```

---

## Mappings

- NIST SP 800-41 (Firewall Guidelines)
- NIST SP 800-46 (Telework)
- NIST SP 800-77 (IPsec VPN)
- BSI Grundschutz NET.*-Bausteine
- ISO 27001 A.8.20-A.8.23 (Network Security Management)
- CIS Benchmarks für jeweilige Komponenten (NGINX, Apache, etc.)
