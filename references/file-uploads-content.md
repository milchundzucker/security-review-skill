# File Uploads & Content Handling

Wird geladen, wenn File-Upload-Code, Archiv-Verarbeitung oder Bild-/Dokument-Konvertierung erkannt wird.

## Klassische Upload-Schwachstellen

### MIME-Type-Validation per Magic Bytes

```
rg "content_type|mimetype|filename" --type py --type js -A 3
rg "endswith\(['\"]\.(jpg|png|pdf|doc)" --type py    # nur Endung geprüft!
```

**Anti-Patterns:**
- Nur Dateiendung geprüft (Datei `shell.php.jpg` umgeht)
- Nur Content-Type-Header geprüft (User-kontrolliert)
- Server-seitige Validation deckungsgleich mit Client-Validation

**Sicher:** Magic Bytes / File Signature prüfen:
```python
import magic
mime = magic.from_buffer(file.read(2048), mime=True)
if mime not in ALLOWED_MIMES:
    abort(400)
```

### Filename-Sanitization

```
rg "request\.files\[.*\]\.save|save_as.*request" --type py --type js
rg "secure_filename" --type py    # gut wenn vorhanden
```

**Anti-Patterns:**
- `file.save(file.filename)` direkt → `../../etc/passwd`
- Path-Concat: `os.path.join(UPLOAD_DIR, file.filename)` → Path Traversal
- Filename mit Sonderzeichen (`\x00`, `\r\n`, control chars) → Truncation, Log Injection

**Sicher:**
- `werkzeug.utils.secure_filename()` (Python)
- `path.basename()` + Allowlist-Regex `[A-Za-z0-9_.-]{1,128}`
- UUID-basierte interne Filenames, original Filename nur in DB

### Storage Location

**Anti-Patterns:**
- Upload-Verzeichnis ist webserver-reachable + Server interpretiert PHP/JSP/ASP
  → klassischer Webshell-Pfad
- Upload-Verzeichnis ist nicht außerhalb des document_root
- Files werden in Repository-Verzeichnis geschrieben → Persistence über Deploys

**Sicher:**
- Upload-Verzeichnis: separates Volume, kein execute-Bit, nicht über Webserver erreichbar
- Serve über separaten Endpoint mit `Content-Disposition: attachment` und festem Content-Type
- S3/Blob-Storage mit pre-signed URLs

### Size Limits

```
rg "MAX_CONTENT_LENGTH|client_max_body_size|maxFileSize" --type py --type js --type conf
```

**Pflicht:**
- Frontend: zur UX
- Webserver (NGINX `client_max_body_size`, Apache `LimitRequestBody`)
- Application (`MAX_CONTENT_LENGTH` in Flask)
- Pro-User-Quota (Gesamtspeicher-Limit pro Account)

## Zip Slip / Tar Slip

```
rg "extractall\(|ZipFile.*extract|tarfile.*extract" --type py
rg "zip\.entries\(\)" --type java
rg "unzipper|adm-zip|node-stream-zip" --type js -A 5
```

**Anti-Pattern:**
```python
with zipfile.ZipFile(uploaded) as z:
    z.extractall(DEST)  # Anfällig für Pfade wie ../../etc/passwd
```

Auch in Tar-Archiven, 7z, RAR ist das Problem identisch.

**Sicher:**
```python
import os
for member in z.namelist():
    target = os.path.realpath(os.path.join(DEST, member))
    if not target.startswith(os.path.realpath(DEST) + os.sep):
        raise SecurityError("Path traversal in archive")
    z.extract(member, DEST)
```

Bei Python 3.12+: `extractall(filter='data')` (Tarfile).

## Archive Bombs

### Zip Bomb

Datei wie `42.zip` (komprimiert 42KB, dekomprimiert 4.5PB) durch verschachtelte Recursion oder massive Wiederholung in einem einzigen Archiv.

**Sicher:**
- Größenlimits pro entpackter Datei
- Gesamtgröße aller entpackten Dateien limitieren
- Anzahl Dateien limitieren
- Bei `zipfile`: `getinfo().file_size` vor Entpacken prüfen

```python
MAX_SIZE = 100 * 1024 * 1024  # 100MB
total = 0
for info in z.infolist():
    total += info.file_size
    if total > MAX_SIZE:
        raise SecurityError("Zip bomb suspected")
```

### Gzip Bomb / "Decompression Bomb"

Ähnliches Problem bei einzelnen gzip/bz2/xz-Files. HTTP-Frameworks akzeptieren `Content-Encoding: gzip` und decompressen vor Handler.

```
rg "gzip\.decompress|gunzip|zlib\.decompress" --type py --type js
```

## SVG XSS

SVG-Dateien können `<script>`-Tags enthalten und werden vom Browser als XML interpretiert.

**Patterns:**
```
rg "image/svg\+xml|\.svg" --type py --type js
rg "svg.*innerHTML|set.*svg.*content"
```

**Anti-Patterns:**
- SVG als Avatar akzeptiert, dann via `<img src="user.svg">` eingebunden → kein JS-Trigger
- ABER: SVG als `<object>` oder direkt im DOM → JS läuft
- SVG mit `onload`/`onerror`-Attributen
- SVG-Foreign-Object kann beliebiges HTML einbetten

**Sicher:**
- SVG-Uploads sanitisieren (DOMPurify mit SVG-Support, svg-sanitizer in PHP)
- Oder SVG zu PNG/WebP konvertieren beim Upload
- `Content-Disposition: attachment` statt inline
- Strikte CSP

## PDF-Risiken

PDFs können:
- JavaScript enthalten (Acrobat-Reader-spezifisch, in Browsern oft deaktiviert)
- Externe Ressourcen laden
- Formulare mit Auto-Submit
- XFA-Forms mit eigener Script-Engine

**Sicher:** Server-seitige Sanitization (Ghostscript-Konvertierung als Defense), Content-Disposition: attachment.

## ImageMagick / ImageTragick (CVE-2016-3714 und Folgen)

ImageMagick + Ghostscript hat Historie von RCE-CVEs.

```
rg "MagickWand|Image\.open\(.*request|sharp\(|Jimp" --type py --type js
rg "convert\s+|magick\s+" --type py --type sh   # command-line magick
```

**Sicher:**
- Aktualisierte ImageMagick-Version mit `policy.xml`, das `MVG`, `MSL`, `PDF`, `HTTP`, `HTTPS`, `URL` Coder DISABLES
- Pillow / sharp / Jimp als Alternative (kleinere Attack Surface)
- Niemals raw user-Images direkt an ImageMagick-Kommandozeile (Format-String und Argument-Injection)

## Polyglot Files

Eine Datei ist gleichzeitig gültiges:
- JPG + JavaScript (`GIFAR`)
- PDF + ZIP (`PDF/ZIP polyglot`)
- HTML + Image
- Image + PE-Executable

**Risiko:** File-Type-Detection passt, aber das polyglotte File führt im falschen Kontext aus (z. B. Browser interpretiert als HTML statt Image).

**Mitigation:** Re-Encoding nach Validierung (z. B. JPG-Upload → server konvertiert zu neuem JPG, was Polyglot-Strukturen zerstört).

## EXIF / Metadata Leakage

```
rg "exif|metadata|piexif|ExifReader" --type py --type js
```

**Anti-Patterns:**
- User-Uploads (Profilbilder) werden mit EXIF-Daten (GPS, Camera-Serial, Username) serviert
- Office-Dokumente mit "Author"-Feld, Track-Changes-History

**Sicher:** EXIF-Strip beim Upload (Pillow: `Image.save()` ohne `exif=...`-Argument oder explizit leeren).

## Server-Side Request via File Format

Manche Image-Loader fetchen externe URLs (SVG referenced raster, PDF embedded URLs). Polyglot-Attack-Pfad zu SSRF.

## Content-Disposition / MIME-Sniffing

```
rg "Content-Disposition" --type py --type js
rg "X-Content-Type-Options.*nosniff" --type py --type js
```

**Anti-Patterns:**
- User-Upload wird mit `Content-Type: text/html` ausgeliefert
- Browser MIME-sniffing aktiv (kein `X-Content-Type-Options: nosniff`)
- Direkt aus User-Domain bedient → XSS via Upload (Auch `text/plain` mit HTML kann gesnifft werden)

**Sicher:**
- User-Uploads über separate Domain bedienen (z. B. `usercontent.example.com`)
- `Content-Type` strict, basierend auf Magic Bytes
- `Content-Disposition: attachment; filename="..."`
- `X-Content-Type-Options: nosniff`

## CSV Injection (Formula Injection)

```
rg "csv\.writer|write_csv|to_csv|outputCSV" --type py --type js
```

CSV-Dateien, die in Excel/LibreOffice geöffnet werden, interpretieren Felder beginnend mit `=`, `+`, `-`, `@`, Tab, CR als Formel — RCE möglich.

**Beispiel:** Field-Wert `=cmd|'/C calc'!A1` öffnet calc in Windows.

**Sicher:**
- Werte, die mit `= + - @ \t \r` beginnen, mit `'` (Apostroph) prefixen
- Oder Field in Quotes packen
- Oder explizit als `.txt` ausliefern

## Office-Macro-Files

Beim Akzeptieren von DOCX/XLSX:
- DOCM/XLSM/PPTM (Macro-enabled) ablehnen
- Office-Dokumente automatisch über LibreOffice-Headless in PDF konvertieren (Sandboxed)

## Befund-Beispiel

```
[FILE-01] Zip Slip in Backup-Restore-Endpoint
Severity:    Critical (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8)
Exploitability: External-Auth (Standard-User mit Backup-Privileg)
CWE:         CWE-22 Path Traversal in Archive Extraction

Evidence:
src/api/restore.py:42:
  with zipfile.ZipFile(uploaded_backup) as z:
      z.extractall("/var/app/data/")

Backup mit Members wie "../../etc/cron.d/evil" wird in beliebige
Server-Pfade entpackt → Persistenz über Cron, RCE als root möglich.

Action:
1. Vor extract jeden Member-Pfad gegen DEST normalisieren und prüfen.
2. zipfile.Path API (Python 3.8+) für Path-Confinement nutzen.
3. Backup-Files signieren (HMAC) und Signatur prüfen vor Entpacken.
```

## Mappings

- CWE-22 Path Traversal
- CWE-434 Unrestricted Upload of File with Dangerous Type
- CWE-409 Improper Handling of Highly Compressed Data (Zip Bomb)
- CWE-1336 Improper Neutralization of Special Elements in Spreadsheet (CSV Injection)
- CWE-79 XSS (für SVG XSS)
- A03 Injection, A05 Misconfig, A08 Integrity
