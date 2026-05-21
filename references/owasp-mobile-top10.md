# OWASP Mobile Top 10 (2024)

Geladen, wenn das Projekt Mobile-Komponenten enthält:
- iOS: `*.swift`, `*.m`, `Info.plist`, `*.xcodeproj`, `Package.swift`, `Podfile`
- Android: `*.java`, `*.kt`, `AndroidManifest.xml`, `build.gradle`, `proguard-rules.pro`
- Cross-Platform: `pubspec.yaml` (Flutter), `package.json` + `react-native` (RN), `Capacitor.config.ts`, Xamarin

Mobile-Apps haben ein anderes Threat-Model als Web-Apps: das Device ist nicht vertrauenswürdig, App-Reverse-Engineering ist trivial, alle Client-seitigen Checks sind umgehbar.

## M1: Improper Credential Usage

**Was:** Hardcoded Credentials, Default-Passwörter, ungeschützte Token-Speicherung.

### Detection
```
rg "(password|secret|api_?key|token)\s*=\s*['\"][A-Za-z0-9+/=_-]{8,}['\"]" --type swift --type java --type kotlin
rg "SharedPreferences.*putString" --type java -A 3  # ohne EncryptedSharedPreferences
rg "UserDefaults\.standard\.set" --type swift  # für Credentials = Befund
rg "Keychain|KeyStore" --type swift --type java -A 3
```

### Mitigation
- iOS: Keychain Services mit `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- Android: AndroidKeyStore + EncryptedSharedPreferences (Jetpack Security)
- Cross-Platform: `react-native-keychain`, `flutter_secure_storage`

### Pitfalls
- Keychain mit `kSecAttrAccessibleAlways` → auch ohne PIN lesbar
- iCloud-Backup enthält Keychain (außer `ThisDeviceOnly`)
- API-Keys im Code: per `strings binary | grep ...` extrahierbar (auch nach ProGuard)
- Hardcoded Keys, die "nur die App kennt" — Reverse-Engineering ist trivial mit Jadx/Hopper/Ghidra

---

## M2: Inadequate Supply Chain Security

→ Siehe `cicd-supply-chain.md` und `secrets-and-deps.md`. Mobile-spezifisch:

- Pods/SPM/Carthage-Dependencies ohne Versions-Pinning
- Gradle-Dependencies mit `+` Wildcards
- Native Libraries (.so, .dylib) aus untrusted Sources
- JCenter (deprecated) als Repository

```
rg "implementation\s+'.*:\+'" build.gradle
rg "jcenter\(\)" build.gradle
rg ":git\s*=>" Podfile  # git-based pods (kein Hash-Lock)
```

---

## M3: Insecure Authentication / Authorization

→ Siehe `auth-oauth-saml.md`. Mobile-spezifisch:

### Biometric Auth Pitfalls
- iOS: `LAContext.evaluatePolicy` ist oft NUR UI-Gate — die Auth-Logik muss serverseitig anhängen. Biometric MUSS einen Token freischalten, der im Keychain liegt.
- Android: `BiometricPrompt` mit `BIOMETRIC_STRONG` (nicht `BIOMETRIC_WEAK`)
- **Anti-Pattern:** `if (biometric.success) { isLoggedIn = true }` — clientseitig manipulierbar

```
rg "evaluatePolicy" --type swift -A 5
rg "BiometricPrompt|setAllowedAuthenticators" --type java --type kotlin -A 5
```

### Token-Storage
- Tokens in UserDefaults/SharedPreferences statt Keychain/KeyStore → trivial extrahierbar
- Refresh-Token mit zu langer Lifetime + ohne Rotation

---

## M4: Insufficient Input/Output Validation

→ Web-Top-10 + Mobile-Spezifika:
- Deep-Link-Parameter ungeprüft (custom URL schemes)
- WebView-Bridges (`@JavascriptInterface` ohne Validation)
- IPC-Parameter (Intents, NSExtensionContext) ungeprüft

```
rg "@JavascriptInterface" --type java --type kotlin -B 2 -A 5
rg "openURL\(|application\(.*open url" --type swift -A 5
rg "getIntent\(\)\.getStringExtra" --type java -A 3
```

---

## M5: Insecure Communication

### TLS-Fehlkonfiguration
- `NSAllowsArbitraryLoads = true` in `Info.plist`
- `cleartextTrafficPermitted="true"` in Android Manifest
- Self-signed Certs ohne Pinning akzeptiert
- TLS-Hostname-Verifier umgangen

```
rg "NSAllowsArbitraryLoads" --type plist --type xml
rg "cleartextTrafficPermitted=\"true\"" --type xml
rg "checkServerTrusted.*\{\s*\}" --type java  # leere Implementation = Befund
rg "ServerTrustManager|TrustKit|OkHttpClient.*hostnameVerifier" --type java --type swift
```

### Certificate Pinning
- Mobile-Apps OHNE Pinning sind MITM-anfällig bei kompromittierter CA
- Empfehlung: TrustKit (iOS), OkHttp CertificatePinner (Android)
- Pinning auf SubjectPublicKeyInfo-Hash, nicht Cert-Hash (Cert-Rotation)
- Backup-Pins für Notfall (sonst App-Block bei Cert-Wechsel)

---

## M6: Inadequate Privacy Controls

### Sensible Daten
- Health, Location, Camera, Mikrofon, Contacts, Calendar → spezielle Permissions
- iOS: Purpose-Strings in `Info.plist` (`NSCameraUsageDescription`, etc.)
- Android: Runtime-Permissions ab API 23, mit Begründung

### Tracking
- IDFA / Advertising-ID nutzen → AppTrackingTransparency-Framework (iOS 14.5+)
- Google Play Privacy: Data-Safety-Section Pflicht

### Logging von PII
- `NSLog`/`Log.d` mit User-Daten → in Crash-Reports landet PII
- App-Switch-Snapshot: sensitive UI sichtbar, wenn App in Background geht (Lösung: Blur-View oder leeres View beim `applicationWillResignActive`)

```
rg "NSLog\(|os_log\(" --type swift -A 1 | rg -i "user|email|password|token"
rg "Log\.(d|i|v|w|e)\(.*user|Log\..*email" --type java --type kotlin
```

---

## M7: Insufficient Binary Protections

### Reverse-Engineering-Schutz
- ProGuard/R8 (Android): Code-Obfuscation aktiv?
- iOS: Symbols stripped (Build-Settings)
- Root/Jailbreak-Detection: nicht trivial, aber Defense-in-Depth
- Anti-Debugging: `ptrace`/`sysctl` (iOS), Frida-Detection

### Detection
```
rg "minifyEnabled\s+true" build.gradle  # ProGuard aktiv?
rg "isRooted|isJailbroken|RootBeer" --type java --type swift
rg "FRIDA|substrate|cydia" --type swift --type java -i
```

**Wichtig:** Binary-Protection ist NICHT alleinige Security-Maßnahme — Server-Side-Auth ist Pflicht. Aber Defense-in-Depth gegen casual Reverse-Engineering.

---

## M8: Security Misconfiguration

### Android
- `debuggable="true"` in Production
- `allowBackup="true"` (App-Daten via `adb backup` extrahierbar)
- `exported="true"` ohne `permission`-Attribut auf Activities/Services/Receivers
- `usesCleartextTraffic="true"`
- Custom URL Schemes ohne Verification (App-Links statt Deep-Links)

```
rg "debuggable=\"true\"" AndroidManifest.xml
rg "allowBackup=\"true\"" AndroidManifest.xml
rg "exported=\"true\"" AndroidManifest.xml -B 2
```

### iOS
- `UIFileSharingEnabled` für non-document Apps
- `UISupportsDocumentBrowser` ungeprüft
- ATS (App Transport Security) deaktiviert

---

## M9: Insecure Data Storage

→ Mit M1 verwoben. Speicherorte:

### iOS
- Keychain → für Credentials, Tokens
- Core Data / Realm → für strukturierte Daten (verschlüsselt!)
- UserDefaults → NUR für Settings, KEINE PII
- Documents/Library → Backup-relevant, sensible Daten verschlüsseln

### Android
- AndroidKeyStore → für Credentials
- EncryptedSharedPreferences / EncryptedFile (Jetpack Security)
- Room mit SQLCipher
- Internal Storage (NICHT External wegen Lesbarkeit anderer Apps)

### Pitfalls
- WebView-Cache (kann sensitive Daten enthalten)
- SQLite ohne Verschlüsselung
- File-Provider mit zu offenen Permissions
- Logs in `/sdcard/`

```
rg "openOrCreateDatabase|SQLiteOpenHelper" --type java --type kotlin -A 5
rg "openFileOutput.*MODE_WORLD" --type java  # deprecated, aber existiert
```

---

## M10: Insufficient Cryptography

→ Siehe `crypto-deep-dive.md`. Mobile-spezifisch:

- iOS: `CommonCrypto` mit ECB-Modus = Standard-Bug
- Android: `Cipher.getInstance("AES")` → ECB Default!
- Hardcoded IVs / Keys
- Schwache Random-Quelle: `java.util.Random` statt `SecureRandom`
- `Math.random()` in React Native / Cordova

```
rg "Cipher\.getInstance\(\"AES\"\)" --type java  # Modus fehlt → ECB
rg "CCCrypt\(.*kCCOptionECBMode" --type swift --type c
rg "new Random\(\)" --type java
rg "Math\.random\(\)" --type ts --type js  # in RN/Cordova
```

---

## Hybrid / Cross-Platform-spezifisch

### React Native
- JS-Bundle ist im App-Bundle entpackbar
- `__DEV__` Checks → in Production-Build entfernen
- `react-native-config` mit Secrets im `.env` → landet im Bundle (öffentlich!)
- Native Modules mit unsicheren Bridges

### Flutter
- Dart-Code ist nach Kompilierung schwerer zu analysieren, aber nicht unmöglich
- `flutter_secure_storage` für Secrets verwenden
- Platform-Channels: Validation auf Native-Seite

### Capacitor / Cordova
- Plugins mit Vollzugriff auf Native-APIs
- WebView mit `allowFileAccess` etc. — siehe `web-advanced.md` § 16

### Xamarin / MAUI
- C#-Bundle reverse-engineerbar mit dnSpy/ILSpy
- Linker-Settings für Production: "SDK Assemblies Only" minimum

---

## Mobile-spezifische Test-Tools (im Bericht erwähnen)

- MobSF (Mobile Security Framework) — statische + dynamische Analyse
- Frida — dynamische Instrumentation
- Objection — Runtime-Hooking
- Hopper / Ghidra / IDA — Reverse Engineering
- jadx — Java-Decompiler
- Hopper / class-dump — iOS Reverse
- iMAS / OWASP MASVS — Standardbasiertes Audit

---

## Mappings

- OWASP MASTG (Mobile Application Security Testing Guide) als Referenz
- OWASP MASVS (Mobile Application Security Verification Standard) Levels:
  - L1 — Standard Security (generelle App)
  - L2 — Defense-in-Depth (Banking, Health)
  - R — Resilience (gegen Reverse-Engineering)
- CWE-200, CWE-311, CWE-312, CWE-319, CWE-326, CWE-548, CWE-919, CWE-921, CWE-927
