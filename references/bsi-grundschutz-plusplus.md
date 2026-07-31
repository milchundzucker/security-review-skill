# BSI IT-Grundschutz++ — Mapping-Modul

Dieses Modul mappt bestätigte Findings zusätzlich gegen den **BSI Grundschutz++**
(Weiterentwicklung des IT-Grundschutzes, „Stand der Technik" i. S. d. NIS-2-Umsetzung).
Es dient — analog zu `privacy-compliance.md` und `mitre-attack.md` — der Priorisierung
und der Nachweisführung, **nicht** als formales Audit.

## Was ist Grundschutz++?

- Modernisierte, prozessorientierte (PDCA) Neufassung des BSI IT-Grundschutzes.
- Wird vom BSI **maschinenlesbar im OSCAL-Format (JSON)** bereitgestellt — nicht mehr als PDF-Bausteine.
- Befindet sich seit 2025/2026 in einer Pilotierungs-/Erprobungsphase; die Edition 2023
  bleibt parallel gültig (bis ca. Ende 2028). Grundschutz++ ist **kein** sofortiger Ersatz.

## Quelle (autoritativ)

- Repository: `BSI-Bund/Stand-der-Technik-Bibliothek` (GitHub, öffentlich)
- Katalog: `control_layer/Grundschutz++/Grundschutz++-resolved_catalog.json`
  (aufgelöster OSCAL-Catalog, `oscal-version` 1.1.3)
- Titel: **„Anwenderkatalog Grundschutz++"**
- Lizenz: **CC-BY-SA-4.0** (Namensnennung + Weitergabe unter gleichen Bedingungen — bei
  Zitat/Weiterverwendung im Bericht Quelle nennen)
- Raw-URL des Katalogs:
  `https://raw.githubusercontent.com/BSI-Bund/Stand-der-Technik-Bibliothek/main/control_layer/Grundschutz++/Grundschutz++-resolved_catalog.json`

> **Aktualität:** Das BSI ergänzt den Katalog laufend. Im Bericht die im Katalog
> hinterlegte `metadata.version` (ein ISO-Zeitstempel) als Stand vermerken. Wenn Netz-
> zugriff erlaubt ist, kann der Katalog live geladen und die Control-Titel gegengeprüft
> werden; sonst gilt die unten hinterlegte, verifizierte Auswahl.

## Aktivierungs-Bedingung (Phase 1.5)

Dieses Modul laden, wenn eine der folgenden Bedingungen zutrifft:

- Nutzer nennt explizit **BSI IT-Grundschutz / Grundschutz++ / SdT-Bibliothek**.
- **NIS-2**-Kontext, deutsche Behörde/KRITIS oder „Stand der Technik"-Nachweis gefragt.
- Compliance-Modus mit Fokus DE-Regulatorik.

## Katalog-Struktur (20 Top-Gruppen)

Jede Gruppe hat eine kurze ID; Controls sind hierarchisch nummeriert (`GRUPPE.n.m`).
Prozess-/Governance-Gruppen sind für einen **Code**-Review meist nur indirekt relevant;
die für Quellcode-/Konfigurations-Findings **primär relevanten** Gruppen sind **fett**.

| ID | Gruppe | Für Code-Review |
|----|--------|-----------------|
| GC | Governance und Compliance | indirekt (ISMS) |
| STM | Strukturmodellierung | indirekt |
| UMS | Umsetzung | indirekt |
| VRB | Verbesserung | indirekt |
| PERF | Monitoring-Evaluation | indirekt |
| RISK | Risikomanagement | indirekt |
| **ASST** | **Informationen und Assets** | **Datenklassifizierung, Transport, Löschung** |
| PERS | Personal | indirekt |
| BES | Beschaffungsmanagement | Supply-Chain (Lieferanten) |
| **DLS** | **Dienstleistersteuerung** | **MFA/Transport-/Vollverschlüsselung ggü. Dienstleistern** |
| **TEST** | **Änderungen und Tests** | **Sicherheitstests, Change-Freigabe, Signatur** |
| GEB | Gebäudemanagement | nein (physisch) |
| SENS | Sensibilisierung | indirekt |
| **ARCH** | **Architektur** | **Netzsegmentierung, Perimeter, DoS-Schutz, WAN-Krypto** |
| **BER** | **Berechtigung** | **AuthN/AuthZ, Zugangskonten, Passwörter, Schlüsselmanagement** |
| NOT | Notfallplanung | Backup/Recovery |
| **DET** | **Detektion** | **Protokollierung, Monitoring, Schwachstellenmanagement** |
| **REA** | **Sicherheitsvorfallsbehandlung** | Incident-Response |
| **KONF** | **Konfiguration** | **Eingabevalidierung, Default-Creds, Krypto, Hardening, Upload, DoS** |
| **DEV** | **Entwicklung** | **Security by Design, Härtung, Fehlerbehandlung, SBOM, Passwort-Hashing** |

## Finding → Grundschutz++ Mapping (verifizierte Control-IDs)

Alle folgenden IDs + Titel stammen wörtlich aus dem Anwenderkatalog. Für ein Finding die
**treffendsten** Controls auswählen (nicht die ganze Zeile pauschal übernehmen).

| Finding-Klasse (CWE / OWASP) | Grundschutz++ Controls (ID :: Titel) |
|------------------------------|--------------------------------------|
| **Injection** — SQLi/XSS/Cmd/LDAP (CWE-89/79/78/90; A03) | `KONF.12.1` :: Eingabevalidierung · `DEV.2.6` :: Widerstandsfähigkeit gegen gängige Angriffsmuster · `DEV.3.2` :: Routinen zur Fehlerbehandlung |
| **Broken Access Control / IDOR / BOLA** (CWE-284/639/862; A01) | `BER.4.1` :: Prinzip der geringsten Berechtigungen · `BER.4.6` :: Anwendungsfunktionen ohne Authentifizierung · `KONF.6.13` :: Dynamische Zugriffskontrolle in der Anwendung · `KONF.11.1` :: Authentifizierung vor dem Zugriff |
| **Broken Authentication / Session** (CWE-287/384/613; A07) | `BER.3.10` :: Anmeldeversuchsgrenze am System · `BER.3.11` :: Anmeldeversuchsgrenze an der Anwendung · `BER.5.8` :: Mehr-Faktor-Authentisierung am Perimeter · `BER.5.9` :: MFA für weitreichende Berechtigungen · `KONF.5.1` :: Authentifizierung am System |
| **Hardcoded / Default Credentials** (CWE-798/1188/259) | `KONF.2.3` :: Änderung von Default-Zugangsdaten (Systeme) · `KONF.10.3` :: Änderung von Default-Zugangsdaten (Anwendungen) · `DEV.4.8` :: Default-Zugangsdaten · `DEV.2.5` :: Einschränkung des Zugriffs auf Zugangsdaten · `KONF.1.5` :: Verschlüsselung von Konfigurationsgeheimnissen |
| **Sensitive Data Exposure / Info-Disclosure** (CWE-200; A01/A02) | `DEV.3.3` :: Deaktivierung der Ausgabe schützenswerter Daten durch Fehlermeldungen · `KONF.11.8` :: Verschlüsselung schützenswerter Daten (at-rest) · `ASST.4.2` :: Vertraulichkeit und Integrität beim Transport |
| **Verbose Error Messages** (CWE-209/210/497) | `DEV.3.2` :: Routinen zur Fehlerbehandlung · `DEV.3.3` :: Deaktivierung der Ausgabe schützenswerter Daten durch Fehlermeldungen |
| **Cryptographic Failures / Transport** (CWE-327/326/319; A02) | `KONF.2.2` :: Kryptographische Verfahren in IT-Systemen · `KONF.10.2` :: Kryptographische Verfahren in Anwendungen · `KONF.14.1` :: Verschlüsselung beim Transport · `DLS.2.2` :: Transportverschlüsselung · `BER.7.1` :: Etablierte Algorithmen bei der Schlüsselerzeugung · `BER.7.2` :: Schlüssellänge |
| **Weak Randomness** (CWE-330/338) | `BER.7.5` :: Kriterien für die Qualität von Zufallszahlen |
| **Insecure Password Storage** (CWE-256/916) | `DEV.3.4` :: Passwort-Hashing · `BER.6.4` :: Kriterien für die Qualität von Passwörtern |
| **Key Management** (CWE-320/321) | `BER.7.7` :: Kein Transport privater Schlüssel · `BER.7.8` :: Etablierte Algorithmen bei der Schlüsselnutzung · `BER.7.10` :: Abgelaufene Schlüssel |
| **SSRF** (CWE-918; A10) | `ARCH.5.1` :: Einschränkung und Inspektion von Verbindungen · `ARCH.5.2` :: Blockieren direkter öffentlicher Verbindungen · `KONF.12.1` :: Eingabevalidierung |
| **Vulnerable / Outdated Components / Supply-Chain** (CWE-1104/1035; A06/A08) | `DEV.4.2` :: Einbindung externer Software · `DEV.4.3` :: Softwarebestandteile (SBOM) · `DEV.4.4` :: Integrität externer Software · `DEV.4.5` :: Updates externer Software · `DET.5.1` :: Zeitnahes Schwachstellenmanagement · `DET.5.10` :: Zeitnahes Patchmanagement |
| **Integrity / Insecure Deserialization** (CWE-502/345; A08) | `DEV.5.3` :: Integritätsprüfung · `TEST.4.2` :: Signatur |
| **Security Logging & Monitoring Failures** (CWE-778/223; A09) | `DET.3.1` :: Protokollierung sicherheitsrelevanter Ereignisse · `DET.3.5` :: Revisionssicherheit · `DET.3.6` :: Unbestreitbarkeit · `DET.4.1` :: Überwachung der Protokollierung |
| **Security Misconfiguration** (CWE-16/732; A05) | `KONF.2.1` :: Grundkonfiguration für Systeme · `KONF.10.1` :: Grundkonfiguration für Anwendungen · `KONF.2.4` :: Deaktivierung nicht benötigter Systemfunktionen · `KONF.2.5` :: Überprüfung der Konfiguration |
| **Unrestricted File Upload** (CWE-434) | `KONF.6.11` :: Einschränkung von Uploads · `KONF.7.1` :: Echtzeitscanner |
| **Source-/Directory-Exposure** (CWE-527/548) | `KONF.6.9` :: Zugriff auf Code · `KONF.6.10` :: Auflistung von Verzeichnisinhalten |
| **DoS / Missing Rate-Limit** (CWE-770/400; A04) | `KONF.15.3` :: Denial of Service · `ARCH.9.5` :: Schutz gegen volumetrische DoS-Angriffe · `KONF.15.1` :: Begrenzung des Speicherplatzes · `KONF.15.2` :: Begrenzung der Rechenleistung |
| **CSRF / Cookie-Flags** (CWE-352/1004/614) | `KONF.12.10` :: Cookie-Attribute · `KONF.12.3` :: Cookies |
| **Fehlende Sicherheitstests** (Prozess) | `TEST.3.1` :: Sicherheitstest · `TEST.3.2` :: Testabdeckung · `DEV.4.11` :: Test bei Änderungen am Quellcode |
| **Secrets in Config / Repo** (CWE-538/540) | `KONF.1.5` :: Verschlüsselung von Konfigurationsgeheimnissen · `DEV.2.4` :: Einschränkung Zugriffs auf Quellcode · `DEV.2.5` :: Einschränkung des Zugriffs auf Zugangsdaten |
| **Network Segmentation / Perimeter** (A05/Arch) | `ARCH.2.1` :: Netzsegmente · `ARCH.2.2` :: Einschränkung von Verbindungen zwischen Segmenten · `ARCH.5.2` :: Blockieren direkter öffentlicher Verbindungen |

## Bericht-Integration (Phase 5)

Ergebnis dieses Moduls fließt in **Bericht-Sektion 8 (Compliance-Relevanz)** ein — als
eigene Untertabelle „BSI Grundschutz++":

| Finding | CWE | Grundschutz++ Control(s) | Gruppe | Bemerkung |
|---------|-----|--------------------------|--------|-----------|

Am Tabellenkopf den Katalog-Stand vermerken, z. B.:
*„Mapping gegen Anwenderkatalog Grundschutz++ (BSI-Bund/Stand-der-Technik-Bibliothek, OSCAL, CC-BY-SA-4.0), Katalog-Version <metadata.version>."*

## Anti-Halluzinations-Regeln (verbindlich)

- Es werden **nur** Control-IDs in den Bericht übernommen, die im Anwenderkatalog
  **tatsächlich existieren** — entweder aus der verifizierten Tabelle oben oder durch
  Live-Abgleich mit dem OSCAL-Katalog. **Keine** Control-IDs raten oder erfinden.
- Control-**Titel** immer wörtlich aus dem Katalog übernehmen (nicht paraphrasieren).
- Gibt es für ein Finding keine sinnvoll passende Control, wird das so vermerkt
  („kein direkter Grundschutz++-Bezug") — es wird **keine** unpassende Control zugeordnet.
- Grundschutz++ ist in Erprobung: Im Bericht darauf hinweisen, dass das Mapping der
  Orientierung dient und die Edition 2023 weiterhin zertifizierungsrelevant ist.
- Kein Anspruch auf Vollständigkeit der Control-Zuordnung — Schwerpunkt sind die
  code-/konfigurationsnahen Gruppen (DEV, KONF, BER, ARCH, DET, ASST, TEST, DLS).
