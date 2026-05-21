# IoT / Embedded / Firmware-Sicherheit

**Wird geladen, wenn** Embedded/IoT-Code erkannt wird: `arduino`, `platformio`, `esp-idf`, `zephyr`, `freertos`, `nuttx`, `yocto`, `buildroot`, `openwrt`, `mqtt`, `coap`, `lwm2m`, `modbus`, `*.dts`, `*.dtsi`, `Cargo.toml mit embedded-hal`, C/C++-Code für ARM Cortex/AVR/RISC-V.

IoT-Geräte sind oft jahrelang im Einsatz, ohne Updates, mit eingebauten Schwächen. Dieses Modul behandelt Firmware-, Hardware- und Protokoll-spezifische Issues. Ergänzt `owasp-top10.md` und `crypto-deep-dive.md` um Embedded-Spezifika.

## 1. Hard-coded Credentials / Default Passwords

**CWE-798 / CWE-1392** — OWASP-IoT-Top-10 #1 (Weak/Guessable/Hardcoded Passwords).

**Detection:**
```bash
rg -n "admin.*admin|root.*root|user.*password|default_password" --type=c --type=cpp --type=h
rg -n "PASSWD|PASSWORD\\s*=" -g "*.c" -g "*.cpp" -g "*.h" -g "*.ino"
# Auch in compilierten Binaries:
strings firmware.bin | grep -iE 'password|passwd|secret|admin'
```

**Mitigation:**
- **Unique-Per-Device Credentials** (z.B. von Production Test Programm auf eFuse / OTP)
- Forced-Change on First Boot
- Credentials nicht in Firmware-Image

## 2. Insecure Boot / Verified Boot Missing

**CWE-693** — Bootloader führt jede Firmware aus → physisch oder via OTA-Hijack injizierbare Backdoor.

**Detection:** Build-Config:
```bash
rg -n "CONFIG_SECURE_BOOT|CONFIG_FLASH_ENC|ESP_SECURE_BOOT" sdkconfig
rg -n "fuse_efuse|efuse_burn" --type=c --type=cpp
```

**Anforderungen:**
- Cryptographic Verified Boot (Chain of Trust)
- ROM-stored Root-of-Trust
- Anti-Rollback Counter (gegen Downgrade auf vulnerable Firmware)
- Encrypted Flash (mindestens für Secrets-Region)

**ESP32 z.B.:** `Secure Boot V2` (RSA-PSS-3072) + `Flash Encryption` mit Key in eFuse.

## 3. Insecure Firmware Update (OTA)

**CWE-494 / CWE-345** — OWASP IoT-Top-10 #5.

**Pflicht-Kette:**
1. HTTPS mit Cert-Pinning für Manifest + Image
2. Image signiert (RSA-PSS-2048+ oder Ed25519)
3. Signature in ROM-bestimmtem Root verified
4. Anti-Rollback Counter
5. A/B-Partition für Rollback bei Fehler
6. Manifest enthält Image-Hash, Version, Hardware-ID

**Detection:**
```bash
rg -n "esp_https_ota|esp_http_ota|update\\.h|FOTA|OTA_BEGIN" --type=c --type=cpp
rg -n "verify_signature|mbedtls_pk_verify|ECDSA_verify" --type=c --type=cpp
```

**Anti-Pattern:** OTA über HTTP, ohne Signature-Check, mit Version aus Manifest ungeprüft → siehe Mirai-artige Botnets.

## 4. Open Debug Interfaces (UART, JTAG, SWD)

**CWE-1244** — UART-Console mit Root, JTAG ungesperrt → physisch RCE.

**Detection:**
- Devicetree, Pin-Config: aktivierte UART, JTAG-Pins
- `CONFIG_ESP_CONSOLE_UART_DEFAULT` für Prod-Builds AUS
- eFuse-Konfig: JTAG-Disable Bit gesetzt?

**Mitigation:**
- Console-Disable in Prod-Builds
- JTAG-Lock (eFuse), Password-Protected JTAG (ARMv8-M Secure Debug)
- Glitching-Resistenz: dual-redundante Checks

## 5. Memory-Safety in C/C++ Embedded-Code

**CWE-119 / CWE-787 / CWE-125 / CWE-416** — Buffer-Overflow, OOB-Write/Read, UAF.

→ siehe `language-patterns.md` für C/C++-Patterns. Embedded-spezifisch:

- **Stack-Canaries** aktiviert? (`-fstack-protector-strong`)
- **MPU/MMU** für Privilege-Separation genutzt?
- **NX/W^X** auf Flash und RAM-Regionen?
- **ASLR** auf Bare-Metal nicht möglich → Verteidigung über CFI (Control-Flow Integrity, ARM Cortex-M v8.1+)
- **Heap-Hardening:** Guard-Zones, Double-Free-Detection (Newlib-Nano lacks these)

**Detection:**
```bash
rg -n "strcpy|strcat|sprintf|gets" --type=c --type=cpp
rg -n "memcpy.*sizeof|memmove" --type=c --type=cpp  # Manuelle Prüfung nötig
rg -n "-fno-stack-protector|-fno-pic" Makefile platformio.ini
```

## 6. Cryptographic Weakness in Embedded

**CWE-327 / CWE-338** — Beliebte Fehler:
- TRNG nicht initialisiert → vorhersagbare "Random"-Werte
- Symmetric Keys gemeinsam für alle Devices (Klasse-1-Key)
- Asymmetric Keys mit kleinem Bit-Count
- AES-CBC ohne MAC (Padding-Oracle)
- Custom-Crypto

**Detection:**
```bash
rg -n "rand\\(\\)|srand" --type=c --type=cpp  # NIE in Crypto!
rg -n "AES_set_encrypt_key.*128|RSA.*1024" --type=c --type=cpp
rg -n "mbedtls_ctr_drbg|esp_fill_random|trng_read|getrandom" --type=c --type=cpp  # gut
```

**Best Practice:**
- Hardware-RNG nutzen (`esp_fill_random`, STM32 RNG)
- Pro-Device-Keys aus Hardware-Entropy
- Bewährte Bibliotheken (mbedTLS, wolfSSL, BoringSSL)
- ECC P-256/Ed25519 statt RSA-2048 (kleinere Speicher-Footprint)

## 7. Telnet / FTP / HTTP Ports Offen

**CWE-319** — Legacy-Klartext-Protokolle bleiben offen.

**Detection:**
```bash
# Netstat/etc nicht verfügbar im statischen Audit, aber:
rg -n "listen.*23|telnetd|ftp_server|http_server" --type=c --type=cpp
rg -n "PORT_TELNET|TELNET_DEFAULT_PORT" --type=c --type=cpp
```

**Mitigation:** SSH statt Telnet, SFTP statt FTP, HTTPS statt HTTP, mTLS bei M2M.

## 8. MQTT-Sicherheit

**CWE-319 / CWE-285** — MQTT-Default ist TCP-1883 ohne Auth, ohne TLS.

**Detection:**
```bash
rg -n "mqtt.*1883|MQTT_DEFAULT_PORT|mqtts://|mqtt://" --type=c --type=cpp --type=py --type=ts
rg -n "MQTTClient_connectOptions|esp_mqtt_client_init" -A 10
```

**Pflichtkonfig:**
- MQTT over TLS (Port 8883)
- Username/Password ODER mTLS
- Topic-ACL (z.B. `client_id` darf nur `device/${client_id}/#` publishen)
- Retain-Flag-Audit (sensible Daten nicht retain)
- Will-Message-Privacy

**Häufige Bugs:**
- `mqtt.publish('device/xxx/secrets', token, retain=True)` → Broker speichert dauerhaft
- Wildcard-Subscriptions ohne ACL → andere Devices snooping
- Shared Credentials für ganze Device-Class

## 9. CoAP-Sicherheit

**CWE-319** — CoAP-Default ist UDP-5683 ohne DTLS.

**Mitigation:** CoAP über DTLS (Port 5684), PSK oder RPK.

```bash
rg -n "coap://|CoAP.*5683" --type=c --type=cpp --type=py
```

## 10. Modbus / SCADA / OT-Protokolle

**CWE-285** — Modbus, DNP3, IEC 60870-5 haben **keine eingebaute Auth/Verschlüsselung**. → Netzwerk-Layer-Schutz (VLAN, Firewall, VPN) ist Pflicht.

**Im Code-Review:**
- Wird Modbus über öffentliche Netze tunneled? (TCP-Modbus auf öffentlicher IP = Critical)
- Ist Mod-Bus-Function-Code-Validation implementiert? (`Function 8 — Diagnostics` → DoS-Vektor)
- DNP3 Secure Authentication aktiviert?

## 11. LwM2M-Sicherheit

**CWE-285** — LwM2M nutzt DTLS oder OSCORE. Konfiguration prüfen.

```bash
rg -n "LWM2M_SECURITY_MODE|LWM2M_BS_SERVER|wakaama" --type=c --type=cpp
```

**Modi:**
- PSK (Pre-Shared Key) — Default; Key-Distribution-Problem
- RPK (Raw Public Key)
- X.509 — bevorzugt für skalierbare Deployments
- NoSec — nur Test

## 12. Bluetooth / BLE Pairing-Modes

**CWE-1240** — Just-Works-Pairing erlaubt MITM.

**Detection:**
```bash
rg -n "SMP_IO_CAP|BLE_GAP_IO_CAPS|BT_IO_CAP_NO" --type=c --type=cpp
```

**Pairing-Modes (Sicherheit aufsteigend):**
1. Just Works — kein MITM-Schutz, FIDO würde es nicht erlauben
2. Passkey Entry — Six-digit-Code, MITM-resistent
3. Numeric Comparison (LE Secure Connections) — sicher
4. Out-of-Band — sehr sicher (NFC, QR)

**Mitigation:** LE Secure Connections + Mindest-Key-Length erzwingen.

## 13. WiFi-Provisioning-Schwächen

**CWE-200 / CWE-319** — Provisioning-Mode öffnet Open-AP mit Default-SSID → Credentials werden im Klartext gesendet.

**Mitigationen:**
- ESP-IDF WPA2-Personal Provisioning, BLE-Provisioning mit Verschlüsselung
- Soft-AP nur kurzlebig
- Provisioning-Token QR-basiert (out-of-band)

## 14. Watchdog & Brick-Protection

**CWE-754** — Geräte ohne Watchdog hängen sich nach Fehlern auf. Verteidigung:
- Hardware-Watchdog aktiv
- Anti-Brick: Goldenes Firmware-Image im Recovery-Partition
- A/B Rollback bei Boot-Loops (z.B. Mender)

## 15. Power-Analysis & Glitching

**CWE-1300** — Side-Channel-Attacken auf Crypto-Operations und Secure Boot.

**Mitigation:**
- Constant-time Crypto (mbedTLS hat das, OpenSSL teilweise)
- Random-Delay in Boot-Routine
- Glitch-Detection (Voltage/Frequency-Monitor)
- Tamper-Detection (Mesh, Light-Sensor)

## 16. Side-Channel via Cache (Embedded Linux)

CPUs in Embedded-Linux (z.B. ARM Cortex-A) sind Spectre/Meltdown-anfällig. Wichtig bei Multi-Tenant-Geräten (z.B. Gateway mit Container).

→ Kernel-Updates + Microcode + Mitigations-Flags.

## 17. Bootloader-Bugs (Bootkits)

**CWE-285** — U-Boot hat history of vulnerabilities. Verified Boot fängt manche, nicht alle.

**Hardening:**
- U-Boot Environment-Variablen nicht änderbar (NOR-Flash read-only)
- Boot-Commands gehärtet
- Recovery-Mode mit Auth

## 18. Hardware-Backdoors / Hidden UART

**CWE-1294** — Vendor lässt Debug-UART/JTAG auf PCB. Visual Inspection im physischen Audit, im Code: `cat /sys/firmware/devicetree/base/...` für Hinweise.

## 19. RPMB / Secure Element / TrustZone

**Sichere Speicherung:**
- ATECC608, NXP A71CH (External Secure Element)
- ARM TrustZone (Cortex-M33+, Cortex-A)
- Replay Protected Memory Block (RPMB) für Anti-Replay-Storage

→ Sensible Keys + Anti-Rollback-Counter dort, nicht in normaler Flash.

## 20. SBOM & Vulnerability Tracking für Firmware

**Compliance** — Cyber Resilience Act (EU, in Kraft ab 2027) und FDA Pre-Market für Medical: SBOM Pflicht.

**Tools:**
- `cve-bin-tool` — binary CVE scan
- `binwalk` — extract & analyze
- `EMBA` — automated firmware analysis
- `Yocto/Buildroot` — SBOM-Output (CycloneDX/SPDX)

## 21. License-Compliance & Re-Distribution

GPL-2/3 Komponenten in Firmware → Source-Disclosure-Pflicht. Auch sicherheitsrelevant: Updates müssen verfügbar bleiben.

## 22. OpenWrt / Embedded Linux Hardening

**CWE-1188**:
- Default-Password (admin/admin)
- Unnötige Services (Telnet, SNMPv2 ohne Community-Auth)
- UCI-Config writable für unprivileged User
- LuCI mit weak HTTP-Auth

→ Hardening-Profile (CIS, AppArmor, SELinux), Audit-Logging, dropbear-Auth-Mode.

## 23. CRA Compliance (EU Cyber Resilience Act)

Für Produkte ab 2027 (Volle Anwendung):
- Vulnerability-Reporting innerhalb 24h an ENISA
- Security-Update-Lifetime mind. 5 Jahre (länger empfohlen)
- CE-Konformitätserklärung mit Cybersecurity-Aspekt
- Strict Liability für Sicherheits-Defekte

→ siehe `privacy-compliance.md` für Compliance-Mapping.

## Severity-Heuristik

| Befund | Default-Severity | Eskalation |
|--------|------------------|------------|
| Hardcoded Default-Password | Critical | identisch auf allen Devices → Critical |
| OTA ohne Signature | Critical |  |
| OTA über HTTP | Critical |  |
| Open Telnet in Prod | High | + öffentliches Netz → Critical |
| MQTT ohne TLS | High | + Auth-Tokens → Critical |
| Verified Boot fehlt | High | + Internet-facing → Critical |
| JTAG/SWD nicht gelockt | High | physisch zugänglich → Critical |
| `rand()` für Crypto | Critical |  |
| AES-CBC ohne MAC | High | confirmed Padding-Oracle → Critical |
| Just-Works BLE-Pairing | Medium | + sensitive Data → High |
| Modbus auf öffentlicher IP | Critical |  |
| Watchdog fehlt | Medium |  |
| Keine Anti-Rollback | High |  |
| Cleartext Provisioning | High |  |
| Keine SBOM (CRA-Scope) | Medium | + Marktstart 2027 → High |

## Referenzen

- OWASP IoT Top 10 (2018) — bleibt aktuell
- OWASP ISVS (IoT Security Verification Standard)
- NIST IR 8259 (IoT Cybersecurity Capabilities)
- EU Cyber Resilience Act (2024/2847)
- ETSI EN 303 645 (Consumer IoT Baseline)
- IEC 62443 (Industrial IoT / OT)
- CWE-798, CWE-494, CWE-693, CWE-1244, CWE-1300, CWE-1392
