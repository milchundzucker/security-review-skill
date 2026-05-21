# WebSocket / SSE / WebRTC — Real-Time-Sicherheit

**Wird geladen, wenn** Real-Time-Protokolle erkannt werden: `WebSocket`, `ws://`, `wss://`, `socket.io`, `SignalR`, `EventSource`, `text/event-stream`, `RTCPeerConnection`, `Phoenix.Channel`, `ActionCable`, `centrifuge`, `mercure`.

Real-Time-Protokolle umgehen viele Defaults (CORS, CSRF-Tokens, Standard-Auth-Middleware) und haben eigene Angriffsklassen.

## 1. Cross-Site WebSocket Hijacking (CSWSH)

**CWE-352 / CWE-1385** — WebSocket-Handshake folgt nicht der Same-Origin-Policy. Wenn nur Cookie-Auth verwendet wird, kann eine fremde Origin den Socket öffnen.

**Detection:**
```bash
rg -n "WebSocketServer|new WebSocket\\.Server|io\\(.*\\)|verifyClient" --type=ts --type=js --type=py
rg -n "origin.*\\*|cors:.*true.*ws|cors:.*origin.*\\*" --type=ts --type=js
# Negative match — Origin-Check fehlt
rg -n "WebSocketServer|ws\\.Server" -A 20 | rg -v "origin|Origin"
```

**Unsafe (ws/Node):**
```typescript
const wss = new WebSocketServer({ port: 8080 });
wss.on('connection', (ws, req) => {
  // ⚠️ Kein Origin-Check, Cookie wird automatisch gesendet
  const user = parseCookie(req.headers.cookie).userId;
  ws.on('message', (msg) => handleMessage(user, msg));
});
```

**Safe — Origin Allowlist + Token statt Cookie:**
```typescript
const ALLOWED_ORIGINS = new Set(['https://app.example.com', 'https://admin.example.com']);

const wss = new WebSocketServer({
  port: 8080,
  verifyClient: ({ origin, req }, callback) => {
    if (!ALLOWED_ORIGINS.has(origin)) return callback(false, 403, 'Forbidden origin');
    const token = new URL(req.url, 'http://x').searchParams.get('token');
    verifyToken(token).then(
      (user) => { (req as any).user = user; callback(true); },
      () => callback(false, 401, 'Unauthorized')
    );
  },
});
```

**Socket.IO:**
```typescript
const io = new Server(server, {
  cors: { origin: ALLOWED_ORIGINS, credentials: true },
});
io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  const user = await verifyToken(token);
  if (!user) return next(new Error('unauthorized'));
  socket.data.user = user;
  next();
});
```

## 2. Auth-Token im URL-Query → Log-Leak

**CWE-598** — `wss://server/?token=eyJhbGc...` landet in Server-Access-Logs, Proxy-Logs, Browser-History.

**Detection:**
```bash
rg -n "new WebSocket\\(.*token=|new WebSocket\\(.*jwt=" --type=ts --type=js
rg -n "EventSource\\(.*token=" --type=ts --type=js
```

**Safe — Token via `Sec-WebSocket-Protocol`-Header (Browser) oder Subprotocol:**
```typescript
// Client
const ws = new WebSocket('wss://server', ['v1.auth.bearer', token]);

// Server
const wss = new WebSocketServer({
  handleProtocols: (protocols, req) => {
    const proto = [...protocols].find(p => p.startsWith('v1.auth.bearer'));
    if (!proto) return false;
    const token = [...protocols].find(p => p !== proto);
    // Token validieren, an req attachen
    return proto;
  },
});
```

**Server-Sent Events:** SSE läuft nur über GET → Token muss aus Cookie (Same-Site=Strict) oder via initialem POST gesetztem Session-Token kommen. KEIN Token in URL.

## 3. Fehlende Per-Message Authorization

**CWE-862** — Nach Verbindungsaufbau bekommt die Session "alles". Auch wenn die Connection authentifiziert ist, muss jede Nachricht/Subscription pro Ressource autorisiert werden.

**Unsafe:**
```typescript
ws.on('message', async (raw) => {
  const msg = JSON.parse(raw.toString());
  if (msg.type === 'subscribe') {
    subscribeTo(msg.channel, ws);  // ⚠️ Jeder darf jeden Channel
  }
});
```

**Safe:**
```typescript
ws.on('message', async (raw) => {
  const msg = JSON.parse(raw.toString());
  if (msg.type === 'subscribe') {
    if (!await canAccessChannel(ws.user, msg.channel)) {
      return ws.send(JSON.stringify({error: 'forbidden'}));
    }
    subscribeTo(msg.channel, ws);
  }
});
```

## 4. Tenant-Crossover via Channel-Naming

**CWE-639 / IDOR** — Channel-Namen enthalten User-IDs ohne Tenant-Validation.

**Unsafe:**
```typescript
// Frontend: socket.emit('join', `user:${prompt('User ID?')}`)
io.on('connection', (socket) => {
  socket.on('join', (room) => socket.join(room));  // ⚠️ Cross-Tenant-Leak
});
```

**Safe:**
```typescript
socket.on('join', (room) => {
  const ALLOWED = [
    `user:${socket.data.user.id}`,
    `tenant:${socket.data.user.tenantId}`,
  ];
  if (!ALLOWED.includes(room)) {
    return socket.emit('error', 'forbidden');
  }
  socket.join(room);
});
```

## 5. Message-Size & Rate-Flooding

**CWE-770 / CWE-400** — Ein offener Socket kann 1 GB Junk senden oder 100k msgs/s.

**Detection:**
```bash
rg -n "maxPayload|maxBackpressure|maxMessageSize|messageDeflate" --type=ts --type=js
# Defaults sind oft generös
```

**Safe (ws):**
```typescript
const wss = new WebSocketServer({
  maxPayload: 64 * 1024,         // 64 KiB pro Frame
  perMessageDeflate: false,      // gegen Compression-Bombs
});

// Rate-Limit pro Connection:
import { RateLimiterMemory } from 'rate-limiter-flexible';
const limiter = new RateLimiterMemory({ points: 100, duration: 10 });

ws.on('message', async (raw) => {
  try {
    await limiter.consume(ws.user.id);
  } catch {
    return ws.close(1008, 'rate limit');
  }
  // ...
});
```

**uWebSockets.js:** maxBackpressure setzen, sonst frisst die Connection Heap.

## 6. Permessage-Deflate Compression Bomb

**CWE-409** — `perMessageDeflate` mit unbegrenzter Dekompression → 1 KiB komprimiert → 100 MiB im Speicher.

**Safe:**
```typescript
const wss = new WebSocketServer({
  perMessageDeflate: {
    serverMaxWindowBits: 10,
    threshold: 1024,
    zlibInflateOptions: { chunkSize: 10 * 1024 },
  },
});
```

Wenn nicht zwingend nötig: ausschalten.

## 7. Mixed-Origin DNS Rebinding gegen lokale WebSockets

**CWE-350** — Dev-Tools oder Desktop-Apps hören auf `ws://localhost:PORT`. DNS-Rebinding ermöglicht externen Sites Zugriff.

**Safe:**
- Origin-Header strict prüfen
- `Host`-Header gegen Allowlist (`localhost`, `127.0.0.1`)
- Token-Auth auch lokal

## 8. Server-Sent Events spezifische Risiken

**CWE-352** — `EventSource` ist immer ein GET, nimmt Cookies mit → CSRF-Surface.

**Safe:**
- SameSite=Strict für Auth-Cookie
- Origin-Check serverseitig
- Optional Custom Header — aber `EventSource` unterstützt keine Custom Headers ohne Polyfill (also Cookie + Origin oder Token im Query mit kurzem TTL)

```typescript
// Express SSE
app.get('/events', (req, res) => {
  if (!ALLOWED_ORIGINS.has(req.get('origin') || req.get('referer')?.split('/').slice(0,3).join('/'))) {
    return res.status(403).end();
  }
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  // ...
});
```

## 9. SSE Connection Limit Browser-Sided

Browser erlauben nur 6 SSE-Connections pro Origin (HTTP/1.1). HTTP/2 hebt das auf, aber andere Apps können den Server lahmlegen. → Connection-Pool serverseitig limitieren pro User.

## 10. WebRTC Signaling-Server Injection

**CWE-94** — Signaling-Nachrichten (SDP/ICE) werden weitergeleitet, ohne validiert zu werden.

**Risiken:**
- SDP-Injection → Peers tauschen Daten über Angreifer-Server (TURN/STUN-Hijack)
- ICE-Candidate enthält interne IPs → Network-Topology-Leak (siehe `infrastructure-network.md`)

**Safe:**
- Signaling-Server prüft Sender/Empfänger
- SDP wird normalisiert (keine arbiträren Attribute durchreichen)
- TURN-Credentials kurzlebig (siehe `secrets-management-deep.md`)

## 11. WebRTC IP-Leak via STUN/ICE

**CWE-200** — `RTCPeerConnection` mit `iceServers` und ohne `iceTransportPolicy: 'relay'` leakt lokale IPs an Peer.

**Detection:**
```bash
rg -n "RTCPeerConnection|iceTransportPolicy|iceServers" --type=ts --type=js
```

**Mitigation:**
- `iceTransportPolicy: 'relay'` erzwingt TURN → keine direkten IPs
- TURN-Credentials per HMAC, kurzlebig

```typescript
const pc = new RTCPeerConnection({
  iceServers: [{ urls: 'turn:turn.example.com:3478', username, credential }],
  iceTransportPolicy: 'relay',  // für sensible Anwendungen
});
```

## 12. STOMP / SockJS / Phoenix-Kanäle

**CWE-862** — Phoenix Channels haben `join/3`-Callback, oft mit `{:ok, socket}` ohne Auth-Check.

**Phoenix-Pattern:**
```elixir
def join("room:" <> room_id, _payload, socket) do
  user = socket.assigns.user
  case Repo.get(Room, room_id) do
    %Room{tenant_id: t} when t == user.tenant_id -> {:ok, socket}
    _ -> {:error, %{reason: "unauthorized"}}
  end
end
```

**Spring STOMP:**
```java
@MessageMapping("/topic/{id}")
@PreAuthorize("@authz.canReadRoom(authentication, #id)")
public void send(@DestinationVariable String id, Message msg) { ... }
```

## 13. SignalR Hub-Method-Authorization

**CWE-862** — SignalR `Hub`-Methoden ohne `[Authorize]` sind public.

**Safe (.NET):**
```csharp
[Authorize]
public class ChatHub : Hub
{
    [Authorize(Roles = "Admin")]
    public async Task BroadcastAdmin(string msg) { ... }

    public async Task JoinRoom(string room)
    {
        var user = Context.User;
        if (!await _authz.CanJoin(user, room)) {
            throw new HubException("forbidden");
        }
        await Groups.AddToGroupAsync(Context.ConnectionId, room);
    }
}
```

## 14. Reverse Proxy / Load Balancer Stickiness

**CWE-444** — WebSocket-Upgrade muss durch Proxy korrekt durchgereicht werden. NGINX-Defaults verlieren oft Sticky-Session → User landet auf Server ohne Session-State → Auth-Bypass möglich.

```nginx
location /ws {
    proxy_pass http://backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 3600s;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## 15. Connection-Lifecycle Memory-Leaks → DoS

**CWE-401** — Listener nicht entfernt → bei Reconnect-Storm OOM.

**Pattern:**
```typescript
wss.on('connection', (ws) => {
  const interval = setInterval(() => ws.ping(), 30000);
  ws.on('close', () => clearInterval(interval));  // muss aufgeräumt werden
  ws.on('error', () => clearInterval(interval));
});
```

## 16. Token-Refresh über WebSocket

Long-lived Connections + kurzlebige JWTs: nach Token-Ablauf ist die Connection "stale-auth". Zwei Optionen:
- **Force-Reconnect**: Server schließt Connection bei Token-Ablauf, Client reconnected mit neuem Token.
- **Re-Auth-Frame**: Client schickt periodisch neues Token, Server verifiziert und ersetzt `socket.user`.

```typescript
ws.on('message', async (raw) => {
  const msg = JSON.parse(raw.toString());
  if (msg.type === 'reauth') {
    const user = await verifyToken(msg.token);
    if (!user || user.id !== ws.user.id) return ws.close(4401, 'reauth-failed');
    ws.user = user;
    ws.exp = user.exp;
  }
});

// Watchdog
setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.exp && ws.exp * 1000 < Date.now()) ws.close(4401, 'token expired');
  }
}, 30000);
```

## 17. WebSocket Smuggling über HTTP/1.1 Upgrade

**CWE-444** — Wenn Reverse-Proxy `Connection`-Header nicht hop-by-hop entfernt, kann Smuggling-Variante entstehen. → siehe `web-advanced.md` und `http-attacks-deep.md`.

## 18. Origin Spoofing in Non-Browser-Clients

**Kritisch:** Origin-Header wird nur von Browsern erzwungen. Native Clients können beliebige Origin senden. → Auth via Token ist Pflicht, Origin-Check nur Defense-in-Depth gegen Browser-CSWSH.

## Severity-Heuristik

| Befund | Default-Severity | Eskalation |
|--------|------------------|------------|
| CSWSH möglich (kein Origin + Cookie-Auth) | High | Admin-Operationen → Critical |
| Token im Query/URL | Medium | langlebige JWT → High |
| Fehlende Per-Message-AuthZ | High | Multi-Tenant → Critical |
| Channel-Tenant-Crossover | High | PII/Payment → Critical |
| MaxPayload/Rate-Limit fehlt | Medium | öffentlich → High |
| Compression-Bomb möglich | Medium | öffentlich → High |
| SSE ohne Origin-Check | Medium | Cookie-Auth → High |
| WebRTC IP-Leak | Low | sensible Identitäten → Medium |
| SignalR Hub ohne `[Authorize]` | High | Admin-Methoden → Critical |
| Memory-Leak im Lifecycle | Low | öffentlich + Reconnect-Storm → Medium |
| Token-Refresh fehlt | Medium |

## Referenzen

- CWE-352, CWE-639, CWE-770, CWE-862, CWE-1385
- "Hacking the Cable Modem" / "Real-time Web Vulnerabilities" — PortSwigger Research
- IETF RFC 6455 (WebSocket)
- IETF RFC 8030 (Web Push) — Push-spezifische Risiken
- OWASP WebSocket Cheat Sheet
