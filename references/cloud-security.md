# Cloud Security — AWS, Azure, GCP

Wird geladen, wenn Cloud-Provider-SDKs, Cloud-Config-Dateien oder IaC erkannt werden:
- AWS: `boto3`, `aws-sdk`, `*.tf` mit `provider "aws"`, `cloudformation/*.{yml,yaml,json}`
- Azure: `azure-*`, `*.tf` mit `provider "azurerm"`, ARM-Templates
- GCP: `google-cloud-*`, `*.tf` mit `provider "google"`

## AWS

### IAM-Misconfigurations

**Hochrisiko-Patterns:**
```
rg "\"Action\":\s*\"\*\"" --type json --type tf
rg "\"Resource\":\s*\"\*\"" --type json --type tf
rg "Effect.*Allow.*Action.*\*"
rg "AssumeRolePolicyDocument" -A 10  # Trust Policy zu offen?
rg "iam:PassRole.*\"\*\""
rg "sts:AssumeRole" -A 5
```

**Anti-Patterns:**
- `"Action": "*"` + `"Resource": "*"` → Full Admin (Critical)
- `"Principal": "*"` ohne `Condition` → Public Access
- `iam:PassRole` mit `*` → Privilege Escalation via Service-Rollen
- Cross-Account `AssumeRole` ohne `ExternalId` und `MFA`
- Service-Rolle mit `iam:CreatePolicy`/`iam:AttachRolePolicy` → Self-Escalation

**Behebung:** Least-Privilege, IAM Access Analyzer, Service Control Policies, Resource-based statt Identity-based wo möglich.

### S3-Misconfigurations

```
rg "acl\s*=\s*[\"']public-(read|read-write)[\"']" --type tf
rg "PublicAccessBlockConfiguration" -A 5  # alle 4 Felder true?
rg "block_public_acls\s*=\s*false" --type tf
rg "server_side_encryption_configuration" --type tf  # fehlt = Befund
rg "versioning\s*\{[^}]*enabled\s*=\s*false" --type tf
```

**Anti-Patterns:**
- `acl = "public-read"` oder `"public-read-write"`
- Fehlendes `aws_s3_bucket_public_access_block` mit allen 4 Flags auf `true`
- Fehlende Server-Side-Encryption (SSE-S3 minimum, KMS bevorzugt)
- Fehlendes Versioning (für Ransomware-Schutz)
- Fehlendes Object Lock bei Compliance-Daten
- Pre-signed URLs mit zu langer Lifetime (>7 Tage = max, sollte ≤1h)
- Cross-Account-Access ohne Condition (`aws:SourceVpce`, `aws:PrincipalOrgID`)

### IMDS-Anfälligkeit (SSRF-Pfad)

**Kritisch:** Wenn die Anwendung SSRF erlaubt UND IMDSv1 erlaubt ist, kann ein Angreifer die EC2-Instance-Rolle abgreifen.

```
rg "metadata_options" --type tf -A 5
rg "http_tokens\s*=\s*[\"']optional[\"']" --type tf  # IMDSv1 erlaubt!
```

**Sicher:** `http_tokens = "required"` (erzwingt IMDSv2 mit Token-PUT).

### KMS / Secrets Manager

```
rg "kms_master_key_id" --type tf  # vorhanden? Customer-managed key?
rg "AWSEncryptionSDK|aws-encryption-sdk" -A 3
rg "secretsmanager" --type py --type js -A 3
rg "Decrypt\s*\(" --type py --type js  # Key-ID hardcoded?
```

**Anti-Patterns:**
- AWS-managed KMS Key (`alias/aws/...`) für sensible Daten → keine Key-Rotation-Kontrolle, kein Audit-Trail in eigenem Account
- Plaintext-Secrets in Lambda Environment-Variables → in CloudTrail sichtbar
- KMS Key Policies mit `"Principal": "*"`
- Secret-Versionen ohne Rotation (`rotation_lambda_arn` fehlt)

### Lambda / Serverless

```
rg "environment\s*\{" --type tf -A 10  # Env vars - secrets drin?
rg "role\s*=\s*aws_iam_role" --type tf -A 5
rg "timeout\s*=\s*\d{3,}"  # zu lange Timeouts → Cost-DoS
```

**Anti-Patterns:**
- Lambda-Rolle hat `lambda:InvokeFunction` auf `*` → Lateral Movement
- VPC-Lambda mit Internet-Egress über NAT, ohne Egress-Filter
- Fehlende Reserved Concurrency → Account-weite DoS möglich
- Plaintext-Secrets in `environment.variables`

### Andere AWS-Services

- **RDS**: `publicly_accessible = true`, fehlende `storage_encrypted`, fehlende Backup-Retention
- **ELB/ALB**: HTTP statt HTTPS Listener, fehlende WAF, schwache TLS-Policies
- **CloudFront**: `viewer_protocol_policy = "allow-all"`, fehlendes OAI/OAC für S3-Origin
- **API Gateway**: `authorization = "NONE"` auf sensitive Routen, fehlendes Rate-Limit
- **EKS**: `endpoint_public_access = true` + `endpoint_public_access_cidrs = ["0.0.0.0/0"]`
- **SNS/SQS**: Topic-/Queue-Policy mit `"Principal": "*"` ohne `aws:SourceAccount`-Condition

## Azure

```
rg "allow_blob_public_access\s*=\s*true" --type tf
rg "min_tls_version" --type tf  # < 1.2 = Befund
rg "public_network_access_enabled\s*=\s*true" --type tf
rg "AzureWebJobsStorage|ConnectionString" -A 2  # in Source-Code = Befund
rg "WEBSITE_AUTH_ENABLED" --type yaml  # App Service Auth?
```

**Anti-Patterns:**
- Storage Account: `allow_blob_public_access = true`, `min_tls_version < 1.2`
- Key Vault: `purge_protection_enabled = false`, fehlendes Soft Delete
- AKS: `enable_pod_security_policy = false`, fehlende Azure AD-Integration
- Function App: `public_network_access_enabled = true` ohne IP-Restrictions
- Service Principal mit `Contributor` oder höher auf Subscription-Ebene
- Managed Identity nicht verwendet → Credentials in Code

## GCP

```
rg "iam_binding|google_project_iam_member" --type tf -A 3
rg "roles/owner|roles/editor" --type tf  # zu breite Rollen
rg "allUsers|allAuthenticatedUsers" --type tf  # Public Access!
rg "private_ip_google_access\s*=\s*false" --type tf
```

**Anti-Patterns:**
- IAM-Binding mit `roles/owner`, `roles/editor` (zu breit) — fast immer ist eine spezifische Rolle besser
- `allUsers` oder `allAuthenticatedUsers` → öffentlicher Zugriff
- GCS-Bucket ohne `uniform_bucket_level_access = true` → ACL-Chaos möglich
- Cloud Function mit `ingress_settings = "ALLOW_ALL"`
- GKE ohne Workload Identity (Service-Account-Key-Files statt)

## Querschnitt: Cloud-Credentials

**Patterns für leakende Credentials:**
```
# AWS
rg "AKIA[0-9A-Z]{16}"                        # Access Key ID
rg "ASIA[0-9A-Z]{16}"                        # Temp Access Key
rg "aws_secret_access_key\s*=\s*[\"'][A-Za-z0-9/+=]{40}[\"']"

# Azure
rg "AccountKey=[A-Za-z0-9+/=]{88}"           # Storage Account Key
rg "DefaultEndpointsProtocol=https.*AccountKey="
rg "BEGIN PRIVATE KEY.*service_account" --multiline

# GCP
rg "\"type\":\s*\"service_account\"" --type json  # Service Account JSON in Repo?
rg "AIza[0-9A-Za-z\-_]{35}"                  # API Key
```

## Cloud-übergreifende Best Practices als Befund-Vorlage

- Fehlendes IAM Access Logging (CloudTrail / Azure Monitor / Cloud Audit Logs)
- Fehlende Multi-Region-Strategie für Backups
- Keine Tagging-Policy für Cost & Ownership
- Fehlende Service Quotas / Budget Alerts → Cost-DoS möglich
- Default-VPC verwendet (statt Custom-VPC mit Segmentation)
- Cross-Account-Trust ohne `ExternalId`/`MFA` Conditions

## CWE-/OWASP-Mappings

- CWE-732 Incorrect Permission Assignment
- CWE-200 Information Disclosure (Public Storage)
- CWE-798 Hard-coded Credentials
- A01 Broken Access Control
- A05 Security Misconfiguration
- A03:2025 Software Supply Chain (für IaC-Modules aus untrusted sources)

## Mitigation: cloud-native Tooling

Im Bericht als Empfehlung erwähnen, wenn nicht bereits eingesetzt:
- AWS: Security Hub, GuardDuty, Config, Access Analyzer, Inspector, Macie
- Azure: Defender for Cloud, Sentinel, Policy
- GCP: Security Command Center, Forseti
- Multi-Cloud: Prowler, ScoutSuite, CloudSploit, Trivy (für IaC)
