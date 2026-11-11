#!/usr/bin/env python3
"""
Akatsuki -- PS4 14.00/14.02 exploit host
  Exploit files : http://<ip>:<port>/?key=<access_key>
  Admin panel   : http://<ip>:<port>/admin?ak=<admin_key>
"""

import sys, os, json, secrets, socket, threading
from datetime import datetime, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
try:
    from urllib.request import urlopen
except ImportError:
    urlopen = None

# ── ngrok tunnel detection ─────────────────────────────────────────────────────
def _ngrok_url() -> str:
    """Query ngrok's local API for the active public HTTPS tunnel URL."""
    try:
        with urlopen("http://127.0.0.1:4040/api/tunnels", timeout=2) as r:
            data = json.loads(r.read())
        for t in data.get("tunnels", []):
            if t.get("proto") == "https":
                return t["public_url"].rstrip("/")
        # fallback: first tunnel of any proto
        tunnels = data.get("tunnels", [])
        if tunnels:
            return tunnels[0]["public_url"].rstrip("/")
    except Exception:
        pass
    return ""

NGROK_URL = _ngrok_url()   # empty string if ngrok not running

# ── Key store ─────────────────────────────────────────────────────────────────
ADMIN_KEY  = secrets.token_hex(8)          # 16-char; new every restart
_keys: dict[str, dict] = {}               # key -> {created, hits, note, expires}
_keys_lock = threading.Lock()

_KEYS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys.json")

def _save_keys():
    try:
        with open(_KEYS_FILE, "w") as f:
            json.dump(_keys, f, indent=2, default=str)
    except Exception as e:
        sys.stderr.write("keys save error: %s\n" % e)

def _load_keys():
    global _keys
    if not os.path.exists(_KEYS_FILE):
        return
    try:
        with open(_KEYS_FILE) as f:
            _keys = json.load(f)
        sys.stderr.write("loaded %d key(s) from keys.json\n" % len(_keys))
    except Exception as e:
        sys.stderr.write("keys load error: %s\n" % e)

def _new_key(note: str = "", expires_hours: int = 0) -> str:
    k = secrets.token_hex(5)
    expires = ""
    if expires_hours > 0:
        from datetime import timedelta
        expires = (datetime.now(timezone.utc) + timedelta(hours=expires_hours)).isoformat()
    with _keys_lock:
        _keys[k] = {
            "created": datetime.now(timezone.utc).isoformat(),
            "hits": 0,
            "note": note,
            "expires": expires,
            "ip": "auto",
        }
        _save_keys()
    return k

def _key_expired(entry: dict) -> bool:
    exp = entry.get("expires", "")
    if not exp:
        return False
    try:
        return datetime.now(timezone.utc) > datetime.fromisoformat(exp)
    except Exception:
        return False

_load_keys()
if not _keys:
    initial_key = _new_key("initial")
else:
    initial_key = next(iter(_keys))

# ── Admin panel HTML ───────────────────────────────────────────────────────────
_ADMIN_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Akatsuki :: Admin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--red:#cc0000;--red-bright:#ff0000;--green:#00ff41;--cyan:#0ff;--bg:#000;--card-bg:rgba(204,0,0,.04)}
body{background:var(--bg);color:var(--green);font-family:'Courier New',Courier,monospace;min-height:100vh;padding:24px 20px}

.hdr{border-bottom:1px solid #1a0000;padding-bottom:16px;margin-bottom:22px}
.hdr h1{color:var(--red-bright);font-size:1.3rem;letter-spacing:.18em;text-shadow:0 0 10px var(--red);margin-bottom:3px}
.hdr .sub{color:#444;font-size:.72rem;letter-spacing:.1em}

.card{border:1px solid var(--red);background:var(--card-bg);padding:16px 20px;margin-bottom:18px}
.card-title{color:#ff4040;font-size:.82rem;letter-spacing:.14em;margin-bottom:12px;text-transform:uppercase}

.ak-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.ak-val{font-family:monospace;color:#ff0;background:#0d0d00;border:1px solid #332200;padding:5px 12px;font-size:.88rem;letter-spacing:.12em;flex:1;min-width:0;word-break:break-all}
.ak-hint{color:#333;font-size:.7rem;margin-top:6px}

.btn{background:transparent;border:1px solid currentColor;color:inherit;padding:4px 12px;
     font-family:'Courier New',monospace;font-size:.75rem;letter-spacing:.07em;
     cursor:pointer;transition:background .12s,color .12s;white-space:nowrap}
.btn:hover{background:currentColor;color:#000}
.btn-green{color:var(--green);border-color:var(--green)}
.btn-cyan {color:var(--cyan);border-color:var(--cyan)}
.btn-red  {color:#ff4040;border-color:#ff4040}
.btn-gen{padding:8px 20px;font-size:.85rem;margin-bottom:14px}

.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.8rem;min-width:620px}
th{color:#333;text-align:left;padding:4px 8px;border-bottom:1px solid #1a0000;font-weight:normal;letter-spacing:.07em;white-space:nowrap}
td{padding:5px 8px;border-bottom:1px solid #0d0000;vertical-align:middle}
.td-key{color:var(--cyan);font-family:monospace;letter-spacing:.06em}
.td-url{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#2a6a2a;font-size:.7rem}
.td-ts {color:#333;font-size:.72rem;white-space:nowrap}
.td-hits{color:#555;text-align:right;white-space:nowrap}
.td-note{color:#444;font-size:.72rem;max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.td-exp{color:#663300;font-size:.7rem;white-space:nowrap}
.td-ip{font-size:.72rem;white-space:nowrap}
.ip-open{color:#333}.ip-auto{color:#aaaa00}.ip-locked{color:var(--cyan);font-family:monospace;font-size:.7rem}
.td-actions{white-space:nowrap;text-align:right}
.td-actions .btn{margin-left:4px}
.empty{color:#222;padding:12px 8px}
.expired-row td{opacity:.45}

.note-input,.exp-input{background:#0a0a0a;border:1px solid #1a1a1a;color:var(--green);padding:4px 8px;
            font-family:'Courier New',monospace;font-size:.8rem}
.note-input{width:180px}
.exp-input{width:60px}
.note-input:focus,.exp-input:focus{outline:1px solid #333}
.exp-label{color:#333;font-size:.75rem;margin-left:6px;margin-right:2px}

.stats{color:#222;font-size:.72rem;margin-bottom:10px;letter-spacing:.06em}
.stats span{color:#333;margin-right:16px}

#toast{position:fixed;bottom:20px;right:20px;padding:7px 14px;font-size:.78rem;
       border:1px solid;opacity:0;transition:opacity .2s;pointer-events:none;z-index:999}
#toast.show{opacity:1}

.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);
     margin-right:6px;box-shadow:0 0 5px var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
</style>
</head>
<body>
<div class="hdr">
  <h1><span class="dot"></span>Akatsuki :: Key Admin</h1>
  <div class="sub">&gt;&gt; PS4 14.00 / 14.02 &nbsp;|&nbsp; Key Management Console</div>
</div>

<div class="card">
  <div class="card-title">Admin Key &mdash; this session only</div>
  <div class="ak-row">
    <div class="ak-val" id="akVal">...</div>
    <button class="btn btn-cyan" onclick="copyText(document.getElementById('akVal').textContent)">COPY</button>
  </div>
  <div class="ak-hint">Changes every server restart. Keep it private &mdash; anyone with this key can manage all access keys.</div>
  <div style="margin-top:14px;border-top:1px solid #1a0000;padding-top:14px">
    <div class="card-title" style="margin-bottom:8px">Daily Access Code</div>
    <div class="ak-row">
      <div class="ak-val" id="dailyCode" style="max-width:160px;letter-spacing:.25em;font-size:1.1rem">...</div>
      <button class="btn btn-green" onclick="copyText(document.getElementById('dailyCode').textContent)">COPY</button>
    </div>
    <div class="ak-hint">Type this into the PS4 browser gate. Rotates at midnight.</div>
  </div>
</div>

<div class="card">
  <div class="card-title">Access Keys</div>
  <div class="stats" id="stats">&nbsp;</div>

  <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px">
    <input class="note-input" id="noteIn" placeholder="Label (optional)" maxlength="40">
    <span class="exp-label">Expires (hrs)</span>
    <input class="exp-input" id="expIn" placeholder="0 = never" type="number" min="0" value="0">
    <button class="btn btn-green btn-gen" onclick="generateKey()">[ + GENERATE KEY ]</button>
    <button class="btn btn-red" onclick="revokeExpired()" style="margin-left:auto">[ PURGE EXPIRED ]</button>
  </div>

  <div class="tbl-wrap" id="tbl"></div>
</div>

<div id="toast"></div>

<script>
(async function(){
  var SALT='ak4ts0k1';
  var d=new Date();
  var today=d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');
  var data=new TextEncoder().encode(SALT+today);
  var hash=await crypto.subtle.digest('SHA-256',data);
  var hex=Array.from(new Uint8Array(hash)).map(function(b){return b.toString(16).padStart(2,'0')}).join('');
  document.getElementById('dailyCode').textContent=hex.slice(0,6);
})();

const AK = new URLSearchParams(location.search).get('ak') || '';
let _ip = '', _port = location.port, _ngrok = '';

function toast(msg, ok=true){
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.style.borderColor = el.style.color = ok ? '#00ff41' : '#ff4040';
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2200);
}

function fallbackCopy(s){
  const ta=document.createElement('textarea');
  ta.style.cssText='position:fixed;top:0;left:0;width:1px;height:1px;opacity:0';
  document.body.appendChild(ta);ta.value=s;ta.focus();ta.select();
  try{document.execCommand('copy');toast('Copied!');}
  catch(e){toast('Copy failed',false);}
  document.body.removeChild(ta);
}
function copyText(t){
  const s=t.trim();
  if(navigator.clipboard&&window.isSecureContext)
    navigator.clipboard.writeText(s).then(()=>toast('Copied!')).catch(()=>fallbackCopy(s));
  else fallbackCopy(s);
}

function fullUrl(k){
  if (_ngrok) return _ngrok + '/?key=' + k;
  return 'http://' + _ip + ':' + _port + '/?key=' + k;
}

function localUrl(k){
  return 'http://' + _ip + ':' + _port + '/?key=' + k;
}

async function api(method, path, body){
  const r = await fetch('/admin/api' + path + '?ak=' + AK, {
    method,
    headers: {'Content-Type':'application/json'},
    body: body != null ? JSON.stringify(body) : undefined
  });
  if (!r.ok) throw new Error((await r.json().catch(()=>({error:r.status}))).error || r.status);
  return r.json();
}

async function load(){
  try {
    const d = await api('GET', '/status');
    document.getElementById('akVal').textContent = d.admin_key;
    _ip = d.ip;
    _ngrok = d.ngrok || '';
    renderKeys(d.keys);
  } catch(e) {
    toast('Load error: ' + e.message, false);
  }
}

function isExpired(exp){
  if (!exp) return false;
  return new Date() > new Date(exp);
}

function fmtExp(exp){
  if (!exp) return 'never';
  const d = new Date(exp);
  if (isExpired(exp)) return '<span style="color:#ff4040">EXPIRED</span>';
  return d.toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
}

function renderKeys(keys){
  const entries = Object.entries(keys);
  const active  = entries.filter(([,v]) => !isExpired(v.expires)).length;
  const expired = entries.length - active;
  const totalHits = entries.reduce((s,[,v]) => s + v.hits, 0);
  const locked = entries.filter(([,v]) => v.ip && v.ip !== 'auto').length;
  document.getElementById('stats').innerHTML =
    '<span>ACTIVE: ' + active + '</span>' +
    (expired ? '<span style="color:#663300">EXPIRED: ' + expired + '</span>' : '') +
    (locked ? '<span style="color:var(--cyan)">LOCKED: ' + locked + '</span>' : '') +
    '<span>TOTAL HITS: ' + totalHits + '</span>';

  if (!entries.length) {
    document.getElementById('tbl').innerHTML = '<div class="empty">No keys. Generate one above.</div>';
    return;
  }

  const rows = entries.map(([k, v]) => {
    const url   = fullUrl(k);
    const local = localUrl(k);
    const ts    = new Date(v.created).toLocaleString(undefined, {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
    const exp   = isExpired(v.expires);
    const urlCell = _ngrok
      ? `<div style="color:#2a6a2a;font-size:.7rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:240px" title="${url}">${url}</div>
         <div style="color:#1a3a1a;font-size:.62rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:240px" title="${local}">${local}</div>`
      : `<span class="td-url" title="${url}">${url}</span>`;
    return `<tr class="${exp ? 'expired-row' : ''}">
      <td class="td-key">${k}</td>
      <td>${urlCell}</td>
      <td class="td-ts">${ts}</td>
      <td class="td-hits">${v.hits}</td>
      <td class="td-note" title="${v.note||''}">${v.note||'—'}</td>
      <td class="td-exp">${fmtExp(v.expires)}</td>
      ${ipCell(k,v)}
      <td class="td-actions">
        <button class="btn btn-cyan" onclick="copyText('${url}')">${_ngrok ? 'COPY NGROK' : 'COPY URL'}</button>
        ${_ngrok ? `<button class="btn btn-green" onclick="copyText('${local}')">LAN</button>` : ''}
        <button class="btn btn-red"  onclick="revokeKey('${k}')">REVOKE</button>
      </td>
    </tr>`;
  }).join('');

  document.getElementById('tbl').innerHTML = `
    <table>
      <tr><th>KEY</th><th>PS4 URL</th><th>CREATED</th><th style="text-align:right">HITS</th><th>LABEL</th><th>EXPIRES</th><th>IP LOCK</th><th></th></tr>
      ${rows}
    </table>`;
}

async function generateKey(){
  const note  = document.getElementById('noteIn').value.trim();
  const hours = parseInt(document.getElementById('expIn').value) || 0;
  try {
    await api('POST', '/keys', {note, expires_hours: hours});
    document.getElementById('noteIn').value = '';
    document.getElementById('expIn').value  = '0';
    toast('Key generated!');
    load();
  } catch(e) { toast('Error: ' + e.message, false); }
}

async function revokeKey(k){
  if (!confirm('Revoke key  ' + k + '?')) return;
  try {
    await api('DELETE', '/keys/' + k);
    toast('Key revoked.');
    load();
  } catch(e) { toast('Error: ' + e.message, false); }
}

async function revokeExpired(){
  if (!confirm('Purge all expired keys?')) return;
  try {
    await api('DELETE', '/keys/expired');
    toast('Expired keys purged.');
    load();
  } catch(e) { toast('Error: ' + e.message, false); }
}

function ipCell(k, v){
  const ip = v.ip || '';
  if (!ip || ip === '') {
    return `<td class="td-ip"><span class="ip-open">open</span></td>`;
  }
  if (ip === 'auto') {
    return `<td class="td-ip"><span class="ip-auto">auto</span> <button class="btn" style="font-size:.65rem;padding:2px 6px" onclick="setIpAuto('${k}',false)">CLR</button></td>`;
  }
  return `<td class="td-ip"><span class="ip-locked" title="${ip}">${ip}</span> <button class="btn btn-cyan" style="font-size:.65rem;padding:2px 6px" onclick="clearIp('${k}')">CLR</button></td>`;
}

async function setIpAuto(k, val){
  try {
    await api('PATCH', '/keys/' + k, {ip: val ? 'auto' : ''});
    toast(val ? 'Set to auto-lock' : 'IP lock cleared');
    load();
  } catch(e) { toast('Error: ' + e.message, false); }
}

async function clearIp(k){
  await setIpAuto(k, false);
}

load();
setInterval(load, 8000);
</script>
</body>
</html>
"""

# ── Helpers ────────────────────────────────────────────────────────────────────
def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

_DENY_KEY_PAGE = b"""<!doctype html><html><head><title>403</title></head>
<body style="background:#000;color:#f00;font-family:monospace;text-align:center;padding-top:20vh">
<h1>[ ACCESS DENIED ]</h1><p>Wrong or missing key. Use the full URL shown in the server window.</p>
</body></html>"""

_DENY_PAGE = b"""<!doctype html><html><head><title>403</title></head>
<body style="background:#000;color:#f00;font-family:monospace;text-align:center;padding-top:20vh">
<h1>[ ACCESS DENIED ]</h1><p>Admin key required.</p>
</body></html>"""

# ── Request handler ────────────────────────────────────────────────────────────
class Handler(SimpleHTTPRequestHandler):
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".js":  "text/javascript",
        ".css": "text/css",
        ".bin": "application/octet-stream",
        ".mp3": "audio/mpeg",
        ".ogg": "audio/ogg",
        ".wav": "audio/wav",
    }
    CACHEABLE = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".mp3", ".ogg", ".wav")

    def _qs(self):
        return parse_qs(urlparse(self.path).query)

    def _admin_ok(self):
        return self._qs().get("ak", [""])[0] == ADMIN_KEY

    def _client_ip(self):
        fwd = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        return fwd if fwd else self.client_address[0]

    def _key_ok(self):
        vals = self._qs().get("key", [])
        if not vals:
            return False
        k = vals[0]
        client_ip = self._client_ip()
        with _keys_lock:
            if k not in _keys:
                return False
            entry = _keys[k]
            if _key_expired(entry):
                return False
            locked_ip = entry.get("ip", "")
            if locked_ip == "auto":
                entry["ip"] = client_ip   # lock on first use
            elif locked_ip and locked_ip != client_ip:
                return False              # IP mismatch
            entry["hits"] += 1
            _save_keys()
        return True

    def do_GET(self):
        route = urlparse(self.path).path.rstrip("/")

        if route == "/admin":
            if not self._admin_ok():
                self._send_bytes(403, "text/html", _DENY_PAGE)
                return
            self._send_bytes(200, "text/html; charset=utf-8", _ADMIN_HTML.encode())
            return

        if route == "/admin/api/status":
            if not self._admin_ok():
                self._json({"error": "Unauthorized"}, 403); return
            self._json({"admin_key": ADMIN_KEY, "ip": _local_ip(), "ngrok": _ngrok_url() or NGROK_URL, "keys": _keys})
            return

        if route == "/admin/api/keys":
            if not self._admin_ok():
                self._json({"error": "Unauthorized"}, 403); return
            self._json({"keys": _keys})
            return

        if not self._key_ok():
            self._send_bytes(403, "text/html", _DENY_KEY_PAGE)
            return

        self.path = urlparse(self.path).path
        super().do_GET()

    def do_HEAD(self):
        if not self._key_ok():
            self.send_response(403); self.end_headers(); return
        self.path = urlparse(self.path).path
        super().do_HEAD()

    def do_POST(self):
        if urlparse(self.path).path == "/admin/api/keys":
            if not self._admin_ok():
                self._json({"error": "Unauthorized"}, 403); return
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            k = _new_key(str(body.get("note", ""))[:40], int(body.get("expires_hours", 0)))
            self._json({"key": k, "data": _keys[k]})
        else:
            self.send_response(404); self.end_headers()

    def do_DELETE(self):
        parts = urlparse(self.path).path.split("/")
        if len(parts) == 5 and parts[1:4] == ["admin", "api", "keys"]:
            if not self._admin_ok():
                self._json({"error": "Unauthorized"}, 403); return
            target = parts[4]
            if target == "expired":
                with _keys_lock:
                    before = len(_keys)
                    expired_list = [k for k, v in list(_keys.items()) if _key_expired(v)]
                    for k in expired_list:
                        del _keys[k]
                    _save_keys()
                self._json({"ok": True, "purged": before - len(_keys)})
            elif target in _keys:
                with _keys_lock:
                    del _keys[target]
                    _save_keys()
                self._json({"ok": True})
            else:
                self._json({"error": "Key not found"}, 404)
        else:
            self.send_response(404); self.end_headers()

    def do_PATCH(self):
        parts = urlparse(self.path).path.split("/")
        if len(parts) == 5 and parts[1:4] == ["admin", "api", "keys"]:
            if not self._admin_ok():
                self._json({"error": "Unauthorized"}, 403); return
            target = parts[4]
            with _keys_lock:
                if target not in _keys:
                    self._json({"error": "Key not found"}, 404); return
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                if "ip" in body:
                    _keys[target]["ip"] = str(body["ip"])[:64]
                if "note" in body:
                    _keys[target]["note"] = str(body["note"])[:40]
                _save_keys()
            self._json({"ok": True, "data": _keys[target]})
        else:
            self.send_response(404); self.end_headers()

    def _send_bytes(self, code, ctype, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, code=200):
        body = json.dumps(data, default=str).encode()
        self._send_bytes(code, "application/json", body)

    def end_headers(self):
        p = urlparse(self.path).path.lower()
        if p.startswith("/admin"):
            pass
        elif p.endswith(self.CACHEABLE):
            self.send_header("Cache-Control", "public, max-age=604800")
        else:
            self.send_header("Cache-Control", "no-store, must-revalidate")
            self.send_header("Pragma",        "no-cache")
            self.send_header("Expires",       "0")
        super().end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    serve_dir = os.path.dirname(os.path.abspath(__file__))
    server = ThreadingHTTPServer(
        ("0.0.0.0", port),
        partial(Handler, directory=serve_dir)
    )

    ip = _local_ip()
    print()
    print("  +-------------------------------------------------+")
    print("  |   Akatsuki :: Exploit Host                      |")
    print("  +-------------------------------------------------+")
    print()
    print("  Admin panel  ->  http://%s:%d/admin?ak=%s" % (ip, port, ADMIN_KEY))
    print()
    if NGROK_URL:
        print("  PS4 (ngrok)  ->  %s/?key=%s" % (NGROK_URL, initial_key))
        print("  PS4 (LAN)    ->  http://%s:%d/?key=%s" % (ip, port, initial_key))
    else:
        print("  PS4 browser  ->  http://%s:%d/?key=%s" % (ip, port, initial_key))
        print("  (start ngrok to expose externally)")
    print()
    print("  Ctrl-C to stop.")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
