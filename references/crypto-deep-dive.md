# Cryptography Deep Dive

Wird geladen, wenn Krypto-Code erkannt wird: `hashlib`, `crypto`, `Cipher`, `JWT`, `bcrypt`, `argon2`, `OpenSSL`-Calls, oder TLS-Konfiguration.

## JWT — Die häufigsten Fehler

### alg=none Bypass

```
rg "algorithms\s*=\s*\[" --type py -A 2
rg "jwt.verify.*none" --type js
rg "alg.*none" --type js --type py -i
```

**Anti-Pattern:** Akzeptiert mehrere Algorithmen inklusive `none`:
```python
jwt.decode(token, key, algorithms=["HS256", "none"])  # KRITISCH
```

**Sicher:**
```python
jwt.decode(token, key, algorithms=["HS256"])  # nur eine konkrete Algo
```

### Algorithm Confusion (HS256 ↔ RS256)

**Pattern:** Server konfiguriert mit RSA Public Key + `algorithms=["HS256", "RS256"]`:
- Angreifer signiert sein Token mit HS256, wobei der Public Key als HMAC-Secret verwendet wird
- Server verifiziert mit Public Key als HMAC-Key → akzeptiert

**Sicher:** Genau einen Algorithmus erlauben; Algo strict an Key-Type binden.

### Schwacher HS256-Secret

```
rg "jwt.encode\(.*,\s*[\"'][^\"']{1,16}[\"']" --type py    # Secret < 16 Zeichen
rg "jwt.sign\(.*[\"'][^\"']{1,32}[\"']" --type js
rg "SECRET\s*=\s*[\"'][^\"']{1,32}[\"']"
```

**Faustregel:** HS256-Secret < 256 Bit (32 Bytes) = brute-forcable. Bevorzugt: RS256/ES256 mit asymmetrischen Keys.

### Fehlende Claim-Validation

```
rg "jwt.decode.*options.*verify_exp.*False"
rg "jwt.decode.*options.*verify_aud.*False"
rg "jwt.decode.*options.*verify_iss.*False"
rg "verify\s*:\s*false" --type js
```

**Pflicht-Claims zu validieren:**
- `exp` (Expiration) — Token muss expirieren
- `nbf` (Not Before) — falls gesetzt
- `iat` (Issued At) — gegen Replay über lange Zeiträume
- `aud` (Audience) — Token muss für diesen Service sein
- `iss` (Issuer) — Token muss vom richtigen IdP
- `sub` (Subject) — User-Identifier

### kid-Injection und JWK-Header-Injection

**Patterns:**
```
rg "jose|jwks|jose-pem" --type py --type js
rg "headers\[.kid.\]" --type py
```

**Anti-Patterns:**
- `kid` (Key ID) Header wird ohne Validation aus dem Token gelesen → SQL-Injection in DB-Lookup, Path Traversal beim Key-File-Lookup
- `jwk` (JSON Web Key im Header) wird zur Verifikation verwendet → Angreifer liefert eigenen Public Key mit
- `jku` (JWK Set URL im Header) wird ohne Allowlist gefolgt → SSRF + Trust-Bypass

### JWT Storage

**Patterns:**
```
rg "localStorage\.setItem.*token" --type js
rg "sessionStorage.*token" --type js
rg "document\.cookie.*token" --type js
```

**Anti-Patterns:**
- JWT in `localStorage` → XSS-anfällig (kein HttpOnly)
- JWT in Cookie ohne `HttpOnly`, `Secure`, `SameSite=Strict`/`Lax`
- JWT als URL-Parameter → in Logs, Referrer-Header

## TLS / SSL

### Validation deaktiviert

```
rg "verify\s*=\s*False" --type py                     # requests, httpx
rg "rejectUnauthorized\s*:\s*false" --type js          # node
rg "InsecureSkipVerify\s*:\s*true" --type go
rg "ServicePointManager.ServerCertificateValidationCallback" --type cs
rg "ALLOW_ALL_HOSTNAME_VERIFIER" --type java
rg "trustAllCerts|TrustAllX509" --type java
rg "NSAllowsArbitraryLoads.*true" --type xml          # iOS ATS aus
```

**Häufige falsche Begründungen:**
- "Self-signed Cert in Dev" → Dev-Code muss als solcher markiert sein (`if DEBUG:`), nicht generisch
- "Tests brauchen das" → Test-Code-Pfad isolieren

### Schwache TLS-Konfiguration

```
rg "ssl.*PROTOCOL_TLSv1\b|TLSv1\.0|TLSv1\.1"
rg "ciphers\s*=" --type py --type js
rg "SSLContext.*set_ciphers"
```

**Anti-Patterns:**
- TLS 1.0/1.1 erlaubt (Mindest: TLS 1.2; bevorzugt 1.3)
- Cipher-Suites mit `NULL`, `EXPORT`, `DES`, `RC4`, `MD5`
- Fehlende HSTS-Header
- Mixed-Content (HTTPS-Seite lädt HTTP-Ressourcen)

### Certificate Pinning

Für Mobile/Critical-Apps:
- Pinning komplett fehlt → MITM bei Provider-CA-Kompromittierung möglich
- Hardcoded Pin ohne Rotation-Strategie → App wird nach CA-Wechsel unbrauchbar

## Passwort-Hashing

```
rg "hashlib\.(md5|sha1|sha256|sha512)\(.*password" --type py
rg "MessageDigest\.getInstance\([\"'](MD5|SHA-?1|SHA-?256)" --type java
rg "createHash\([\"'](md5|sha1|sha256)" --type js
```

**Anti-Patterns:**
- MD5, SHA1, SHA256, SHA512 als Passwort-Hash → kein Stretching, GPU-trivial
- bcrypt-Cost < 10 (12+ empfohlen)
- scrypt mit niedrigen Parametern
- PBKDF2 mit < 100.000 Iterationen (NIST 2023: ≥ 600.000 für SHA256)

**Sicher (in Reihenfolge der Präferenz):**
1. **Argon2id** mit OWASP-Defaults (m=64MB, t=3, p=4)
2. **scrypt** (N=2^17, r=8, p=1)
3. **bcrypt** (Cost ≥ 12)
4. **PBKDF2-SHA256** (≥ 600.000 Iter., legacy fallback)

## Symmetric Encryption

### ECB-Mode

```
rg "AES.*ECB|MODE_ECB|Cipher\.getInstance\([\"']AES[\"']" --type py --type java --type js
```

ECB ist NIEMALS richtig (außer für 1 Block) — gleiche Plaintext-Blöcke = gleiche Ciphertext-Blöcke. Bilder mit ECB verschlüsselt zeigen ihre Struktur (siehe Tux-Bild).

### Fixed IV / Reused Nonce

**Patterns:**
```
rg "iv\s*=\s*[\"'][^\"']+[\"']"  # Hardcoded IV
rg "nonce\s*=\s*b?[\"'][^\"']+[\"']"
rg "IvParameterSpec\(" --type java -A 3
```

**Anti-Patterns:**
- IV hardcoded → semantic security verloren
- IV aus User-Input → Manipulation
- Counter-Wiederverwendung bei AES-GCM, ChaCha20-Poly1305 → fatal (Key-Recovery möglich!)
- IV nicht zufällig (z. B. aus `time.time()` oder `random.random()`)

### Unsichere Modes

- **ECB**: verboten (siehe oben)
- **CBC ohne Padding-MAC**: anfällig für Padding Oracle
- **CTR ohne MAC**: keine Authentizität → bitwise Manipulation möglich
- **OFB, CFB**: alt, selten gerechtfertigt
- **GCM, ChaCha20-Poly1305, AES-OCB**: AEAD, bevorzugt

**Sicher:**
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
nonce = os.urandom(12)  # 96-bit, niemals wiederverwenden!
ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
```

## Asymmetric Encryption

```
rg "RSA.*generate.*1024|RSA.*keysize.*1024" --type java --type py
rg "DSAGen" --type java
rg "secp192r1|secp224r1" --type py --type java   # zu kleine ECC
```

**Anti-Patterns:**
- RSA < 2048 Bit
- DSA (deprecated)
- ECC-Kurven < secp256r1 (P-256)
- RSA mit PKCS#1 v1.5 für Encryption (Bleichenbacher-Angriff) — OAEP verwenden
- Schlüssel-Generation mit `Math.random` / `random.random` (kein CSPRNG)

## Random Number Generation

```
rg "Math\.random\(\)" --type js
rg "random\.random\(\)|random\.randint" --type py
rg "new Random\(\)" --type java   # nicht SecureRandom
rg "rand\(\)" --type c --type cpp --type go
```

**Sicher:**
- **Python**: `secrets.token_bytes`, `secrets.token_urlsafe`, `os.urandom`
- **JavaScript (Node)**: `crypto.randomBytes`, `crypto.randomUUID`
- **JavaScript (Browser)**: `crypto.getRandomValues`
- **Java**: `SecureRandom`
- **Go**: `crypto/rand`
- **C++**: `std::random_device` für Seed, dann CSPRNG

## Constant-Time Comparisons

**Pattern:**
```
rg "(token|secret|hmac|signature)\s*==\s*" --type py --type js
rg "Arrays\.equals\(.*hmac" --type java
rg "memcmp\(" --type c
```

**Anti-Pattern:** String-Vergleich mit `==` für Secrets, Tokens, HMACs → Timing-Angriff.

**Sicher:**
- Python: `hmac.compare_digest(a, b)`, `secrets.compare_digest(a, b)`
- Node: `crypto.timingSafeEqual(a, b)`
- Java: `MessageDigest.isEqual(a, b)`
- Go: `subtle.ConstantTimeCompare(a, b) == 1`

## HMAC / Signature

```
rg "hmac\.new\(.*sha1|hmac\.new\(.*md5" --type py
rg "Hmac\.SHA1|HMACSHA1" --type java --type cs
```

- HMAC-MD5 / HMAC-SHA1 → nur für Legacy-Interop, sonst HMAC-SHA256+
- Signatur-Verifikation ohne Algorithm-Pin → siehe JWT alg=none

## Side-Channels & Klassische Krypto-Angriffe

### Padding Oracle

**Pattern:**
```
# CBC-Decrypt + spezifische Error-Messages für Padding
rg "BadPaddingException|Invalid padding|PaddingException" --type java --type py
```

Wenn der Server unterschiedliche Antworten gibt bei "Padding falsch" vs "Padding richtig, Inhalt ungültig" → klassisches Padding Oracle (POODLE, BEAST, Lucky 13, etc.). Sicher: AEAD-Cipher verwenden, oder Encrypt-then-MAC mit Constant-Time-MAC-Check.

### Length Extension

Betrifft SHA-1, SHA-256, SHA-512 (Merkle-Damgård). Wenn `H(secret || message)` als Signatur verwendet wird, kann ein Angreifer `H(secret || message || padding || extension)` berechnen — ohne `secret` zu kennen.

**Sicher:** HMAC verwenden (nicht naive Konkatenation), oder SHA-3.

### Bit-Flipping (CBC ohne MAC)

CBC ohne MAC erlaubt es, Bits im n-ten Plaintext-Block durch Bit-Flips im (n-1)-ten Ciphertext-Block zu kontrollieren. Sicher: AEAD (GCM, ChaCha20-Poly1305).

## Key Management

```
rg "PRIVATE KEY-----" --type py --type js --type java -l
rg "key_path\s*=|private_key_file\s*=" --type tf --type py
rg "kms_key_arn|kms_key_id" --type tf  # gut wenn vorhanden
```

**Anti-Patterns:**
- Private Keys im Repo (auch als "Test-Keys")
- Long-lived Keys ohne Rotation-Mechanism
- Selbst-gebackener Key-Wrapping-Mechanismus
- Keys in Application-DB statt KMS/HSM

**Sicher:** Cloud-native KMS (AWS KMS, Azure Key Vault, GCP KMS) oder HSM (PKCS#11) für sensible Keys. Envelope Encryption für Data-Keys.

## Cryptographic Agility

Code-Pattern für gut: Algorithm-Bezeichner ist in einer Konstante, die zentral änderbar ist.
Pattern für schlecht: Algo hardcoded an X verschiedenen Stellen → kann nicht migriert werden, wenn ein Algo brüchig wird.

## Post-Quantum Awareness

In Compliance-Bereichen (Government, Finance): erwähnen, dass NIST PQC-Migration (CRYSTALS-Kyber, CRYSTALS-Dilithium) ab 2030 erforderlich werden könnte. Code, der HARDCODED auf RSA/ECC setzt, ist langfristig migrationsbedürftig.

## Befund-Beispiel

```
[CRYPTO-01] JWT akzeptiert Algorithm 'none'
Severity:    Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8)
Exploitability: External-Unauth
CWE:         CWE-347 Improper Verification of Cryptographic Signature
OWASP:       A02:2021, A07:2021

Evidence:
src/auth/jwt.py:34:    decoded = jwt.decode(token, KEY, algorithms=["HS256", "none"])

Ein Angreifer kann ein Token mit Header {"alg": "none"} und beliebigen Claims
erzeugen — keine Signatur, aber wird akzeptiert.

Action:
1. algorithms=["HS256"] (nur ein Algo)
2. Audit aller Token-Verarbeitung
3. Bei Schweregrad: alle aktiven Sessions invalidieren (Schlüssel-Rotation)
```

## Mappings

- CWE-326 Inadequate Encryption Strength
- CWE-327 Use of a Broken or Risky Cryptographic Algorithm
- CWE-328 Reversible One-Way Hash
- CWE-329 Generation of Predictable IV
- CWE-330 Use of Insufficiently Random Values
- CWE-347 Improper Verification of Cryptographic Signature
- CWE-916 Use of Password Hash With Insufficient Computational Effort
- A02:2021 Cryptographic Failures
