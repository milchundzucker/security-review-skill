# Desktop App Security — Electron, Tauri, NW.js, Native

**Wird geladen, wenn** Desktop-App-Frameworks erkannt werden: `electron`, `tauri`, `nw.js`, `pywebview`, `cefpython`, `flutter_desktop`, `*.entitlements`, `electron-builder`, `@tauri-apps/api`.

Desktop-Apps mit Web-Tech laufen mit nativen System-Rechten. Eine XSS, die im Browser harmlos wäre, wird hier zu RCE auf dem Host.

## 1. Electron — `nodeIntegration: true` im Renderer

**CWE-94** — Critical. Renderer hat Zugang zu `require('child_process').exec(...)`.

**Detection:**
```bash
rg -n "nodeIntegration:\\s*true|nodeIntegration\\s*=\\s*true" --type=ts --type=js
rg -n "new BrowserWindow" -A 15 --type=ts --type=js
```

**Unsafe:**
```typescript
const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: true,           // ⚠️ XSS = RCE
    contextIsolation: false,         // ⚠️ Renderer hat Hauptthread-Zugriff
  },
});
```

**Safe (Modern Electron):**
```typescript
const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,
    contextIsolation: true,
    sandbox: true,                   // OS-Level-Sandbox
    webSecurity: true,
    allowRunningInsecureContent: false,
    experimentalFeatures: false,
    preload: path.join(__dirname, 'preload.js'),
  },
});
```

## 2. Electron — `contextIsolation: false`

**CWE-1188** — Renderer und Preload teilen `window` → Renderer kann Preload-Code überschreiben.

**Safe Preload-Pattern mit `contextBridge`:**
```typescript
// preload.ts
import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('api', {
  saveFile: (content: string) => ipcRenderer.invoke('save-file', content),
  // KEINE generischen Bridges wie `invoke: (...args) => ipcRenderer.invoke(...args)`
});

// main.ts — Whitelist und Validation
ipcMain.handle('save-file', async (event, content) => {
  if (typeof content !== 'string' || content.length > 10_000_000) throw new Error('bad input');
  // Pfad serverseitig festlegen, nicht aus Renderer:
  const filePath = await dialog.showSaveDialog({...});
  if (!filePath.canceled) await fs.writeFile(filePath.filePath!, content);
});
```

## 3. Electron — `webview` / `nativeWindowOpen` / Embedded Content

**CWE-829** — `<webview>` ist ein Sub-Renderer, kann eigene Rechte haben. `nativeWindowOpen` kann Remote-Content laden.

**Safe:**
- `nativeWindowOpen: false` (oder Filter in `setWindowOpenHandler`)
- `<webview>` nur mit `nodeIntegration=off`, `disablewebsecurity=off`
- `setWindowOpenHandler` filtert URLs:

```typescript
win.webContents.setWindowOpenHandler(({ url }) => {
  if (url.startsWith('https://')) shell.openExternal(url);  // im Default-Browser
  return { action: 'deny' };
});
```

## 4. Electron — `shell.openExternal` mit User-Input

**CWE-94** — `shell.openExternal('file:///path/to/.bat')` führt unter Windows die Batch-Datei aus.

**Detection:**
```bash
rg -n "shell\\.openExternal\\(.*req|shell\\.openExternal\\(.*userInput|shell\\.openExternal\\(.*url" --type=ts --type=js
```

**Safe:**
```typescript
import { shell } from 'electron';

function safeOpenExternal(url: string) {
  let u: URL;
  try { u = new URL(url); } catch { return; }
  if (!['https:', 'http:', 'mailto:'].includes(u.protocol)) return;
  shell.openExternal(u.toString());
}
```

## 5. Electron — Custom Protocol Handler Hijack

**CWE-94** — `app.setAsDefaultProtocolClient('myapp')` → externe Site sendet `myapp://...` → App parsed das.

**Risiken:**
- URL-Parameter werden in CLI eingebaut
- `--gpu-launcher`, `--no-sandbox` als Argument
- Code-Execution via crafted protocol-URL

**Mitigation:**
- Strict Parsing
- Argumente nicht zur Process-Spawn weitergeben
- ASAR + Code-Signing
- Bei `single-instance-lock`: zweite Instanz validiert Args, bevor weitergeleitet

## 6. Electron — Update-Channel (Autoupdater) Hijacking

**CWE-494** — `electron-updater` muss signierte Manifests verifizieren.

**Detection:**
```bash
rg -n "autoUpdater|electron-updater" -A 10 --type=ts --type=js
```

**Pflicht:**
- HTTPS-Endpoint (kein HTTP)
- Code-Signed Releases (Apple Developer / Windows EV Cert)
- Public Key Pinning oder TUF (The Update Framework)
- Squirrel.Windows hat eigene Update-Pfade — validieren

## 7. Electron — ASAR ist KEINE Verschlüsselung

**CWE-200** — `.asar` ist nur ein TAR-ähnliches Format, jeder kann es entpacken.

→ Keine Secrets in der App. Wenn nötig: OS-Secret-Store (Keychain, Credential Manager, libsecret), nicht im App-Bundle.

## 8. Electron — Local File:// Access

**CWE-22** — Renderer hat `file://`-Zugriff → liest beliebige Dateien.

**Detection:**
```bash
rg -n "webSecurity:\\s*false|allowFileAccessFromFiles" --type=ts --type=js
```

**Safe:**
- `webSecurity: true` (default)
- Wenn lokale Files nötig: über Custom Protocol mit Path-Validation:

```typescript
protocol.registerFileProtocol('app', (request, callback) => {
  const url = request.url.substring(6);  // 'app://'
  const resolved = path.normalize(path.join(__dirname, 'public', url));
  if (!resolved.startsWith(path.join(__dirname, 'public'))) {
    return callback({error: -10});  // ACCESS_DENIED
  }
  callback({path: resolved});
});
```

## 9. Electron — Insecure Content Security Policy (CSP)

CSP wird oft via `<meta>` gesetzt, das ist aber für `file://` und manche Pre-Loads zu spät.

**Safe:**
```typescript
session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({
    responseHeaders: {
      ...details.responseHeaders,
      'Content-Security-Policy': ["default-src 'self'; script-src 'self'"],
    },
  });
});
```

## 10. Tauri — `tauri.conf.json` Capability-Misconfig

**CWE-732** — Tauri nutzt Capability-Modell. Default ist sehr restriktiv, aber Apps lockern oft.

**Detection:**
```bash
rg -n "\"all\":\\s*true|\"dangerous\"" tauri.conf.json src-tauri/
rg -n "\"shell\":" -A 5 src-tauri/tauri.conf.json
rg -n "tauri.*invoke\\(" --type=ts --type=js
```

**Unsafe Tauri-Config:**
```json
{
  "allowlist": {
    "shell": {"all": true, "open": true, "execute": true},
    "fs": {"all": true, "scope": ["**"]},
    "http": {"all": true, "request": true, "scope": ["**"]}
  }
}
```

**Safe (Tauri 2.x Capabilities):**
```json
{
  "identifier": "main-capability",
  "windows": ["main"],
  "permissions": [
    "core:default",
    {
      "identifier": "fs:read-text-file",
      "allow": [{"path": "$APPDATA/*.json"}]
    },
    "shell:allow-open"
  ]
}
```

## 11. Tauri — Custom Commands ohne Input-Validation

**CWE-78** — Rust-Backend nimmt User-Input von Frontend:

```rust
// Unsafe
#[tauri::command]
fn run_cmd(cmd: String) -> String {
    std::process::Command::new("sh").arg("-c").arg(cmd).output()  // ⚠️ RCE
}

// Safe — enum mit fixen Optionen
#[tauri::command]
fn run_action(action: AllowedAction) -> Result<String, String> {
    match action {
        AllowedAction::ListFiles => list_files(),
        AllowedAction::GetVersion => Ok(env!("CARGO_PKG_VERSION").into()),
    }
}
```

## 12. Native Binaries / DLL-Hijacking

**CWE-427** — Search-Path-Hijack: App lädt `comctl32.dll` aus Working-Directory → Angreifer pflanzt eigene DLL.

**Mitigation:**
- App-Pfad absolut bestimmen
- `SetDllDirectory` / Safe-Search-Mode setzen (Windows)
- Notarisierung & Signing
- Hardened Runtime auf macOS

## 13. macOS — Entitlements & Hardened Runtime

**CWE-732** — `*.entitlements` mit überzogenen Privilegien:
- `com.apple.security.cs.allow-unsigned-executable-memory` — kompromittiert Hardened-Runtime-Wert
- `com.apple.security.cs.disable-library-validation` — ermöglicht DLL-Hijack-Pendant
- `com.apple.security.get-task-allow` — Debugger-Attach, Production = nein

**Detection:**
```bash
rg -n "com\\.apple\\.security" -A 1 -B 1 -g "*.entitlements"
```

## 14. Code-Signing & Notarization

**CWE-345** — App ohne Signatur oder mit Self-Signed-Cert → User bekommt SmartScreen-Warnung → klickt blind weg → Update-Vektor offen.

**Pflicht (Prod-Builds):**
- Windows: EV Code Signing Certificate
- macOS: Apple Developer ID + Notarization (ab macOS 10.15)
- Linux: AppImage mit GPG Signature, oder Distro-Repository

## 15. Inter-Process Communication Hijacking

**CWE-285** — Wenn IPC über Named Pipes / Unix Sockets ohne Auth → andere User auf Host können IPC abhören.

**Mitigation:**
- Unix-Socket im User-private-Dir (`~/.config/myapp/socket`)
- Windows: ACLs auf Named Pipe
- Token-basierte Auth auch lokal

## 16. Telemetrie & Crash-Reporting Privacy

**Compliance** — Sentry / Bugsnag / Custom Crash-Reporter sammelt Stacktraces inkl. lokaler Pfade, ggf. User-Input.

→ Redaction-Layer + Opt-In für PII. Siehe `logging-monitoring.md`.

## 17. Tauri vs Electron — Architektur-Wahl

Tauri ist (aus Sicherheitsperspektive) bevorzugt:
- Rust-Backend = Memory-Safety
- System-WebView (kein gebundeltes Chromium → kleinere Angriffsfläche, Sicherheits-Patches vom OS)
- Capability-System restriktiver

Nachteil: Plattform-Webview-Inkonsistenz (WebKit/Edge/WebKit2GTK).

## 18. Squirrel.Mac / Squirrel.Windows Specifics

**CWE-494** — Squirrel-Update-Flow:
- macOS: Update-ZIP wird in `~/Library/Caches/...` extrahiert und beim Restart geswappt
- Risiken: TOCTOU zwischen Download und Verify

→ Code-Signature wird vom OS beim Launch geprüft, aber Mid-Air-Tampering möglich, wenn Cert-Pin fehlt.

## 19. Auto-Update SSRF / DNS-Rebinding

Update-Server-DNS muss strict aufgelöst werden:
- Pin Server-Cert
- Falls cross-platform Update-Service: HSTS-Preload

## 20. Renderer-Sandbox & Site-Isolation

Electron ab v20: Site-Isolation kann aktiviert werden. Tauri: System-Webview hat eigene Sandbox.

**Empfehlung:**
- Electron: `sandbox: true` als Default
- Renderer mit User-Content im strikten Sandbox-Modus

## 21. Drag&Drop / Datei-Handler

User dropped Datei → App liest sie. Wenn Pfad-Validation fehlt: PoC-Datei aus untrusted Quellen wird gelesen + verarbeitet (Pickle, Excel-Macro, XML-XXE etc.) → siehe `file-uploads-content.md`.

## 22. Browser-Extension-Edge — `web_accessible_resources`

Wenn die Desktop-App auch eine Browser-Extension hat:
- `web_accessible_resources` minimal halten
- `externally_connectable` nur known Origins
- Content-Scripts isoliert vom Page-Context

## Severity-Heuristik

| Befund | Default-Severity | Eskalation |
|--------|------------------|------------|
| `nodeIntegration: true` | Critical | wenn Remote-Content geladen → Critical |
| `contextIsolation: false` | Critical |  |
| `webSecurity: false` | High |  |
| `shell.openExternal` mit User-Input | High | + `file://`-Schema möglich → Critical |
| Tauri `"all": true` für shell | Critical |  |
| Tauri Custom Command mit Shell | Critical |  |
| Update ohne Signatur | Critical |  |
| Secrets im ASAR-Bundle | High | + Auth-Tokens → Critical |
| Custom Protocol mit User-Args zum Spawn | Critical |  |
| macOS `get-task-allow` in Prod | High |  |
| CSP fehlt | Medium | + Remote-Content → High |
| Code-Signing fehlt | High | + öffentlich verteilt → Critical |
| Telemetrie ohne Redaction | Medium | + PII → High |
| WebSec für file:// AUS | High |  |
| `<webview>` mit `nodeIntegration` | Critical |  |

## Referenzen

- Electron Security Guidelines (offiziell)
- Tauri Security Documentation
- "Doyensec Electron Security Checklist"
- Trail of Bits Electron Audits
- CWE-94, CWE-829, CWE-732, CWE-494, CWE-427
- macOS Hardened Runtime Documentation
- Microsoft AppContainer / WinSandbox
