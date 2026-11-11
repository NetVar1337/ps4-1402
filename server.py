#!/usr/bin/env python3
"""
NanospeedGamer -- PS4 14.00/14.02 exploit host
  Exploit files : http://<ip>:<port>/?key=<access_key>
  Admin panel   : http://<ip>:<port>/admin?ak=<admin_key>
"""

import sys, os, json, secrets, socket
from datetime import datetime, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ── Key store ─────────────────────────────────────────────────────────────────
ADMIN_KEY = secrets.token_hex(8)          # 16-char; new every restart
_keys: dict[str, dict] = {}               # key -> {created, hits, note}

def _new_key(note: str = "") -> str:
    k = secrets.token_hex(5)              # 10 hex chars
    _keys[k] = {
        "created": datetime.now(timezone.utc).isoformat(),
        "hits": 0,
        "note": note,
    }
    return k

initial_key = _new_key("initial")

# ── Admin panel HTML ───────────────────────────────────────────────────────────
_ADMIN_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NanospeedGamer :: Admin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--red:#cc0000;--red-bright:#ff0000;--green:#00ff41;--cyan:#0ff;--bg:#000;--card-bg:rgba(204,0,0,.04)}
body{background:var(--bg);color:var(--green);font-family:'Courier New',Courier,monospace;min-height:100vh;padding:24px 20px}

/* header */
.hdr{border-bottom:1px solid #1a0000;padding-bottom:16px;margin-bottom:22px}
.hdr h1{color:var(--red-bright);font-size:1.3rem;letter-spacing:.18em;text-shadow:0 0 10px var(--red);margin-bottom:3px}
.hdr .sub{color:#444;font-size:.72rem;letter-spacing:.1em}

/* cards */
.card{border:1px solid var(--red);background:var(--card-bg);padding:16px 20px;margin-bottom:18px}
.card-title{color:#ff4040;font-size:.82rem;letter-spacing:.14em;margin-bottom:12px;text-transform:uppercase}

/* admin-key pill */
.ak-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.ak-val{font-family:monospace;color:#ff0;background:#0d0d00;border:1px solid #332200;padding:5px 12px;font-size:.88rem;letter-spacing:.12em;flex:1;min-width:0;word-break:break-all}
.ak-hint{color:#333;font-size:.7rem;margin-top:6px}

/* buttons */
.btn{background:transparent;border:1px solid currentColor;color:inherit;padding:4px 12px;
     font-family:'Courier New',monospace;font-size:.75rem;letter-spacing:.07em;
     cursor:pointer;transition:background .12s,color .12s;white-space:nowrap}
.btn:hover{background:currentColor;color:#000}
.btn-green{color:var(--green);border-color:var(--green)}
.btn-cyan {color:var(--cyan);border-color:var(--cyan)}
.btn-red  {color:#ff4040;border-color:#ff4040}
.btn-gen{padding:8px 20px;font-size:.85rem;margin-bottom:14px}

/* table */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.8rem;min-width:580px}
th{color:#333;text-align:left;padding:4px 8px;border-bottom:1px solid #1a0000;font-weight:normal;letter-spacing:.07em;white-space:nowrap}
td{padding:5px 8px;border-bottom:1px solid #0d0000;vertical-align:middle}
.td-key{color:var(--cyan);font-family:monospace;letter-spacing:.06em}
.td-url{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#2a6a2a;font-size:.7rem}
.td-ts {color:#333;font-size:.72rem;white-space:nowrap}
.td-hits{color:#555;text-align:right;white-space:nowrap}
.td-note{color:#444;font-size:.72rem;max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.td-actions{white-space:nowrap;text-align:right}
.td-actions .btn{margin-left:4px}
.empty{color:#222;padding:12px 8px}

/* note input */
.note-input{background:#0a0a0a;border:1px solid #1a1a1a;color:var(--green);padding:4px 8px;
            font-family:'Courier New',monospace;font-size:.8rem;width:200px}
.note-input:focus{outline:1px solid #333}

/* stats bar */
.stats{color:#222;font-size:.72rem;margin-bottom:10px;letter-spacing:.06em}
.stats span{color:#333;margin-right:16px}

/* toast */
#toast{position:fixed;bottom:20px;right:20px;padding:7px 14px;font-size:.78rem;
       border:1px solid;opacity:0;transition:opacity .2s;pointer-events:none;z-index:999}
#toast.show{opacity:1}

/* ping dot */
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);
     margin-right:6px;box-shadow:0 0 5px var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
</style>
</head>
<body>
<div class="hdr">
  <h1><span class="dot"></span>NanospeedGamer :: Key Admin</h1>
  <div class="sub">&gt;&gt; PS4 14.00 / 14.02 &nbsp;|&nbsp; Key Management Console</div>
</div>

<div class="card">
  <div class="card-title">Admin Key &mdash; this session only</div>
  <div class="ak-row">
    <div class="ak-val" id="akVal">...</div>
    <button class="btn btn-cyan" onclick="copyText(document.getElementById('akVal').textContent)">COPY</button>
  </div>
  <div class="ak-hint">Changes every server restart. Keep it private &mdash; anyone with this key can manage all access keys.</div>
</div>

<div class="card">
  <div class="card-title">Access Keys</div>
  <div class="stats" id="stats">&nbsp;</div>

  <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px">
    <input class="note-input" id="noteIn" placeholder="Label (optional)" maxlength="40">
    <button class="btn btn-green btn-gen" onclick="generateKey()">[ + GENERATE KEY ]</button>
  </div>

  <div class="tbl-wrap" id="tbl"></div>
</div>

<div id="toast"></div>

<script>
const AK = new URLSearchParams(location.search).get('ak') || '';
let _ip = '', _port = location.port;

function toast(msg, ok=true){
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.style.borderColor = el.style.color = ok ? '#00ff41' : '#ff4040';
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2200);
}

function copyText(t){
  navigator.clipboard.writeText(t.trim()).then(() => toast('Copied!'));
}

function fullUrl(k){
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
    renderKeys(d.keys);
  } catch(e) {
    toast('Load error: ' + e.message, false);
  }
}

function renderKeys(keys){
  const entries = Object.entries(keys);
  const total = entries.length;
  const totalHits = entries.reduce((s,[,v]) => s + v.hits, 0);
  document.getElementById('stats').innerHTML =
    '<span>ACTIVE KEYS: ' + total + '</span><span>TOTAL HITS: ' + totalHits + '</span>';

  if (!total) {
    document.getElementById('tbl').innerHTML = '<div class="empty">No active keys. Generate one above.</div>';
    return;
  }

  const rows = entries.map(([k, v]) => {
    const url = fullUrl(k);
    const ts  = new Date(v.created).toLocaleString(undefined, {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
    return `<tr>
      <td class="td-key">${k}</td>
      <td class="td-url" title="${url}">${url}</td>
      <td class="td-ts">${ts}</td>
      <td class="td-hits">${v.hits}</td>
      <td class="td-note" title="${v.note||''}">${v.note||'—'}</td>
      <td class="td-actions">
        <button class="btn btn-cyan" onclick="copyText('${url}')">COPY URL</button>
        <button class="btn btn-red"  onclick="revokeKey('${k}')">REVOKE</button>
      </td>
    </tr>`;
  }).join('');

  document.getElementById('tbl').innerHTML = `
    <table>
      <tr><th>KEY</th><th>PS4 URL</th><th>CREATED</th><th style="text-align:right">HITS</th><th>LABEL</th><th></th></tr>
      ${rows}
    </table>`;
}

async function generateKey(){
  const note = document.getElementById('noteIn').value.trim();
  try {
    await api('POST', '/keys', {note});
    document.getElementById('noteIn').value = '';
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
    }
    CACHEABLE = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico")

    # ── query helpers ──────────────────────────────────────────────────────────
    def _qs(self):
        return parse_qs(urlparse(self.path).query)

    def _admin_ok(self):
        return self._qs().get("ak", [""])[0] == ADMIN_KEY

    def _key_ok(self):
        vals = self._qs().get("key", [])
        if not vals:
            return False
        k = vals[0]
        if k not in _keys:
            return False
        _keys[k]["hits"] += 1
        return True

    # ── routing ────────────────────────────────────────────────────────────────
    def do_GET(self):
        route = urlparse(self.path).path.rstrip("/")

        # ── Admin panel UI ────────────────────────────────────────────────────
        if route == "/admin":
            if not self._admin_ok():
                self._send_bytes(403, "text/html", _DENY_PAGE)
                return
            self._send_bytes(200, "text/html; charset=utf-8", _ADMIN_HTML.encode())
            return

        # ── Admin API: status + keys list ────────────────────────────────────
        if route == "/admin/api/status":
            if not self._admin_ok():
                self._json({"error": "Unauthorized"}, 403); return
            self._json({"admin_key": ADMIN_KEY, "ip": _local_ip(), "keys": _keys})
            return

        if route == "/admin/api/keys":
            if not self._admin_ok():
                self._json({"error": "Unauthorized"}, 403); return
            self._json({"keys": _keys})
            return

        # ── Exploit files — access key required ──────────────────────────────
        if not self._key_ok():
            self._send_bytes(403, "text/html", _DENY_KEY_PAGE)
            return

        self.path = urlparse(self.path).path   # strip ?key=... before serving
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
            k = _new_key(str(body.get("note", ""))[:40])
            self._json({"key": k, "data": _keys[k]})
        else:
            self.send_response(404); self.end_headers()

    def do_DELETE(self):
        parts = urlparse(self.path).path.split("/")
        # /admin/api/keys/<key>
        if len(parts) == 5 and parts[1:4] == ["admin", "api", "keys"]:
            if not self._admin_ok():
                self._json({"error": "Unauthorized"}, 403); return
            k = parts[4]
            if k in _keys:
                del _keys[k]
                self._json({"ok": True})
            else:
                self._json({"error": "Key not found"}, 404)
        else:
            self.send_response(404); self.end_headers()

    # ── response helpers ───────────────────────────────────────────────────────
    def _send_bytes(self, code, ctype, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, code=200):
        body = json.dumps(data, default=str).encode()
        self._send_bytes(code, "application/json", body)

    # ── cache headers ──────────────────────────────────────────────────────────
    def end_headers(self):
        p = urlparse(self.path).path.lower()
        if p.startswith("/admin"):
            pass   # no cache headers on admin routes
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
    print("  |   NanospeedGamer :: Exploit Host                |")
    print("  +-------------------------------------------------+")
    print()
    print("  Admin panel  ->  http://%s:%d/admin?ak=%s" % (ip, port, ADMIN_KEY))
    print()
    print("  PS4 browser  ->  http://%s:%d/?key=%s" % (ip, port, initial_key))
    print()
    print("  Ctrl-C to stop.")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
