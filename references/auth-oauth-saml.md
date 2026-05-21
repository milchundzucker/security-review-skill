# Authentication, OAuth, OIDC, SAML — Deep Dive

Wird geladen, wenn Auth-Code erkannt wird: OAuth-Libraries, OIDC-Clients, SAML-Libraries, Session-Handling, MFA-Code.

## OAuth 2.0 / 2.1 — Klassische Schwachstellen

### redirect_uri-Validation

```
rg "redirect_uri" --type py --type js -A 3
rg "ALLOWED_REDIRECT|redirect_uris\s*=" --type py
```

**Anti-Patterns:**
- Wildcard-Matching: `redirect_uri=https://app.example.com/*` → Angreifer nutzt `/cb?xss=...`
- Prefix-Matching: `startsWith("https://app.example.com")` → `https://app.example.com.attacker.com` passt!
- Open Redirect auf erlaubter Domain → Token-Leak via Redirect-Chain
- Path-Traversal in Pfad: `https://app.example.com/oauth/callback/../../evil`
- Sub-Domain wildcards in Trust → eine kompromittierte Subdomain reicht

**Sicher:** **Exakter String-Match** mit registriertem `redirect_uri`.

### State-Parameter (CSRF auf OAuth-Flow)

```
rg "state\s*=" --type py --type js -A 3
rg "oauth.*authorize" --type py --type js
```

**Anti-Patterns:**
- `state` wird nicht gesetzt im Authorization Request
- `state` wird nicht im Callback validiert (server vergleicht nicht mit Session)
- `state` ist nicht zufällig (z. B. Username-Hash)
- `state` wird nur einmal generiert und wiederverwendet

**Sicher:** Pro Authorization Request ein neuer zufälliger `state` (128-bit), in Session-Storage gespeichert, beim Callback verglichen, dann gelöscht.

### PKCE (Proof Key for Code Exchange)

```
rg "code_verifier|code_challenge|PKCE|pkce" --type py --type js
```

**Pflicht** in OAuth 2.1 für alle Public Clients (SPAs, Mobile Apps) — und auch für Confidential Clients empfohlen.

**Anti-Patterns:**
- Public Client (SPA, Mobile) ohne PKCE
- `code_challenge_method=plain` statt `S256`
- `code_verifier` zu kurz (< 43 Zeichen) oder vorhersagbar
- Server verifiziert PKCE nicht (akzeptiert Token-Exchange ohne `code_verifier`)

### Authorization Code Injection

**Angriff:** Angreifer fängt einen gültigen `code` ab (z. B. via Open Redirect, Referrer-Leak) und tauscht ihn in seinem eigenen Browser ein.

**Mitigation:** PKCE (binding code an `code_verifier`, das nur der echte Client kennt).

### Refresh Token Rotation

```
rg "refresh_token" --type py --type js -A 5
```

**Anti-Patterns:**
- Refresh Tokens sind lang-lebig, ohne Rotation
- Bei Refresh wird nicht ein neuer Refresh Token ausgegeben (Token Family)
- Keine Detection für Token-Reuse (alter RT wird verwendet, nachdem neuer RT ausgegeben wurde → Diebstahl-Indikator)

**Sicher:** Refresh Token Rotation mit Replay-Detection (gestohlene Token werden bei Wiederverwendung als gestohlen erkannt, alle Tokens der Familie revoked).

### Implicit Flow (deprecated)

```
rg "response_type=token|response_type=id_token\s+token" --type py --type js
```

**Anti-Pattern:** Implicit Flow (`response_type=token`) ist in OAuth 2.1 verboten. Tokens landen im URL-Fragment → in Browser-History, Referrer, JS-Zugriff.

**Sicher:** Authorization Code Flow + PKCE für alle Client-Typen.

### Resource Owner Password Credentials (ROPC)

```
rg "grant_type=password" --type py --type js
```

**Anti-Pattern:** ROPC ist in OAuth 2.1 verboten. Der Client sieht das Passwort des Users.

**Sicher:** Authorization Code Flow mit Browser-Login.

### Token Audience Confusion

```
rg "validate.*audience|aud.*claim" --type py --type js
```

**Anti-Pattern:** Token, ausgestellt für Service A, wird bei Service B akzeptiert, weil dieser den `aud`-Claim nicht prüft.

**Sicher:** Jeder Service prüft strikt seinen eigenen `aud`-Claim.

### Mix-Up Attack

Bei Multi-IdP-Support: Angreifer leitet Auth-Flow zu seinem eigenen IdP, gibt aber Issuer-URL eines vertrauten IdPs an → Client wechselt mid-flow zwischen IdPs.

**Mitigation:** `iss`-Parameter im Authorization Response prüfen (OAuth 2.1 Best Practice).

## OIDC (OpenID Connect)

### nonce-Parameter

```
rg "nonce" --type py --type js -A 3
```

**Anti-Pattern:** OIDC ohne `nonce` → ID Token Replay möglich.

**Sicher:** Pro Authentication Request ein neuer zufälliger `nonce` in der Session gespeichert. Im ID Token muss derselbe `nonce` zurückkommen.

### ID Token Validation

Pflicht-Validierungen für ein ID Token:
1. Signatur gegen JWKS-Endpoint des IdP (JWKS auch caching mit TTL)
2. `iss` matched konfigurierten IdP
3. `aud` enthält Client-ID
4. `exp` in der Zukunft
5. `iat` nicht zu alt
6. `nonce` matched gespeicherter Nonce
7. `at_hash` (wenn Access Token präsent) matched

### Userinfo-Endpoint Vertrauen

Wenn der Userinfo-Endpoint nur das `sub`-Claim zurückgibt, aber andere Claims fehlen — und der Client diesen Claims trotzdem vertraut — Privilege Confusion möglich. Sicher: Userinfo gegen ID-Token-Claims abgleichen.

## SAML

### Signature Wrapping (XSW)

SAML-Assertions können in XML-Comments, in zusätzlichen Elementen, oder durch Element-Verschiebung "wrapped" werden. Der Signatur-Check passt, aber der Parser liest andere Daten.

**Mitigation:** Schema-Validation, XPath-basiertes Lesen NUR aus dem signierten Element.

### XXE in SAML

SAML-Parser sind oft XML-Parser → klassisches XXE-Risiko.
```
rg "lxml|xml.etree" --type py | rg -v "defusedxml"
rg "DocumentBuilderFactory" --type java -A 5  # setFeature für XXE-Schutz?
```

**Sicher:** `defusedxml` (Python), `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` (Java).

### Replay-Attacks

SAML-Assertion ohne `NotBefore`/`NotOnOrAfter` Constraints → wiederverwendbar.
- ID des Assertions sollte gegen Replay-Cache geprüft werden
- AudienceRestriction muss passen

### Signature Bypass via Algorithm

SAML akzeptiert auch unsignierte Assertions, wenn der Code es nicht erzwingt.

**Pattern:**
```
rg "DigestMethod|SignatureMethod" --type xml
rg "sha1" --type xml  # SHA1 in SAML → schwach
```

## Session Management

### Session Fixation

```
rg "regenerate.*session|session\.regenerate" --type py --type js
```

**Anti-Pattern:** Session-ID wird nach Login NICHT regeneriert → Angreifer-vorgesetzte Session-ID bleibt gültig.

**Sicher:** Bei Login (und MFA-Step) Session-ID rotieren.

### Session-Lifetime

- Idle-Timeout: 15-30min für sensitive Apps, 1-8h für reguläre
- Absolute-Timeout: 8-24h
- "Remember me": getrenntes Long-Lived-Token mit Rotation, nicht "Session unendlich"

### Cookie-Flags

```
rg "set_cookie|set-cookie" -i --type py --type js
```

Pflicht für Session-Cookies:
- `HttpOnly` (kein JS-Zugriff → XSS-Mitigation)
- `Secure` (nur HTTPS)
- `SameSite=Lax` (Default) oder `Strict` (für High-Security)
- `__Host-` Prefix für Cookies, die nicht Subdomain-shared sein sollen
- Path möglichst restriktiv

**Anti-Pattern:** `SameSite=None` ohne `Secure` (Browser blocken das mittlerweile, aber alte Code-Pfade).

### Logout

```
rg "logout|sign_out" --type py --type js -A 5
```

**Anti-Patterns:**
- Logout invalidiert nur die Cookie clientseitig, nicht serverseitig
- Refresh-Tokens überleben Logout
- "Single Logout" (SLO) bei SAML/OIDC fehlt → User bleibt in anderen Apps eingeloggt
- Logout-Endpoint per GET (CSRF-anfällig: `<img src="/logout">`)

## MFA / 2FA

### TOTP-Schwachstellen

```
rg "totp|TOTP|pyotp|otplib" --type py --type js
```

**Anti-Patterns:**
- `secret_length < 16` Bytes
- Window > 1 Step (mehr Toleranz = mehr Brute-Force-Raum)
- Kein Rate-Limit auf TOTP-Endpoint (Brute-Force 6-Stellen = 1M Tries)
- Reused-Code-Detection fehlt (jeder TOTP-Code sollte nur einmal akzeptiert werden)
- Secret in QR-Code in URL-Querystring → in History/Logs

### SMS-2FA

- SMS-OTP für High-Value-Konten → SIM-Swap-anfällig (NIST hat SMS-OTP deprecated)
- OTP in SMS-Body in Server-Logs

### Recovery Codes

- Recovery Codes als Plaintext gespeichert (sollten gehashed sein)
- Recovery Codes mit zu wenig Entropie (< 80 Bit)
- Recovery Codes ohne One-Time-Use (kann mehrfach genutzt werden)

### MFA-Bypass-Patterns

- MFA-Step kann übersprungen werden, wenn ein Pre-MFA-Token aus dem Browser direkt zum Logged-in-State gepostet wird (klassischer "Forced Browsing")
- MFA-Bypass über Password-Reset-Flow (Reset-Link loggt direkt ein, ohne MFA zu fordern)
- "Trust this device" mit ewig gültigem Token

## Passwort-Reset

```
rg "reset.*token|password.*reset" --type py --type js -A 5
```

**Anti-Patterns:**
- Reset-Token mit niedriger Entropie (< 128 Bit)
- Reset-Token in URL-Querystring → in Logs/Referrer
- Reset-Token expiriert nicht (oder zu lange Lifetime: > 1h)
- Reset-Token wird nach Verwendung nicht invalidiert
- Reset-Email an E-Mail-Adresse aus User-Input gesendet (Host-Header-Injection)
- Reset-Flow enumeriert Existenz von Accounts ("Diese Email existiert nicht" vs "Reset-Link gesendet")

**Sicher:**
- Token: ≥ 128 Bit Entropie, gehashed in DB (so wie Passwörter)
- Lifetime: 30-60 Minuten
- Einmalig verwendbar
- Bei Verwendung: Session-Rotation + Notification-Email
- Einheitliche Response, unabhängig davon, ob die E-Mail existiert

## Account Enumeration

Endpoints, die ungewollt verraten, ob ein Account existiert:
- Login: "Falsches Passwort" vs "User nicht gefunden"
- Registrierung: "Email schon registriert" — fast immer ein Befund
- Passwort-Reset: siehe oben
- Forgot-Username: bietet sich an für Enumeration

**Sicher:** Einheitliche Responses + Timing-Constant + Rate-Limits.

## Brute-Force-Schutz

```
rg "rate_limit|RateLimit|throttle|slowapi" --type py --type js
rg "max_attempts|lockout" --type py --type js
```

**Pflichten:**
- Rate-Limit auf Login, Reset, OTP, Registrierung
- Account-Lockout nach N Fehlversuchen (mit Unlock-Mechanismus)
- IP-basiertes Rate-Limit (im Backend, nicht nur clientseitig)
- CAPTCHA bei verdächtigem Traffic
- Detection für credential-stuffing-Pattern (viele Login-Versuche, jeweils anderer User)

## WebAuthn / FIDO2

Wenn vorhanden, prüfen:
- `userVerification: "required"` (nicht `"preferred"`)
- Attestation-Validation (für High-Security)
- Origin-Validation strict
- challenge ist nonce-frisch und gespeichert

## Befund-Beispiel

```
[AUTH-01] OAuth-State-Parameter wird nicht validiert
Severity:    High (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N = 8.1)
Exploitability: External-Unauth
CWE:         CWE-352 CSRF, CWE-287 Improper Authentication

Evidence:
src/auth/oauth.py:78: code = request.args.get("code")
                  79: # state wird nicht geprüft!
                  80: token = exchange_code(code)
                  81: login_user(token.user_id)

Klassischer "Stolen Session"-Angriff: Angreifer initiiert OAuth-Flow, lockt
Opfer auf eine Seite mit Callback-Link → Opfer wird mit Angreifer-Account eingeloggt.

Action:
1. State-Parameter beim Authorization Request generieren und in Session speichern.
2. Im Callback: state matcht Session-Wert → sonst 400.
3. State nach Verwendung aus Session entfernen.
```

## Mappings

- CWE-287 Improper Authentication
- CWE-294 Authentication Bypass by Capture-Replay
- CWE-304 Missing Critical Step in Authentication
- CWE-352 CSRF
- CWE-384 Session Fixation
- CWE-521 Weak Password Requirements
- CWE-522 Insufficiently Protected Credentials
- CWE-613 Insufficient Session Expiration
- A07:2021 Identification and Authentication Failures
- API2:2023 Broken Authentication
