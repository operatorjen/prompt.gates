# -*- coding: utf-8 -*-

import base64, hashlib, hmac, json, logging, mimetypes, os, redis, time
import gates
from functools import lru_cache
from urllib.parse import urlparse, parse_qs
from socketserver import ThreadingMixIn
from http.server import HTTPServer, BaseHTTPRequestHandler
from themes import resolve as resolve_theme, THEMES
from dotenv import load_dotenv

load_dotenv(os.getenv("ENV_FILE", ".env"))
logging.basicConfig(level=os.environ.get("LOG_LEVEL","INFO"), format="%(asctime)s %(levelname)s %(message)s")

LABEL = os.environ.get("LABEL", "prompt_gates")
SECRET = os.environ["SECRET"]
INDEX_PATH = os.environ.get("INDEX_HTML", "index.html")
CSRF_TTL = int(os.environ.get("CSRF_TTL", "300"))
TOKEN_TTL = int(os.environ.get("TOKEN_TTL", "3600"))
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(64 * 1024)))
BIND_URL = os.environ.get("BIND_URL", "http://127.0.0.1:8080")
STATIC_DIR = os.environ.get("STATIC_DIR", "static")
STATIC_ROOT = os.path.realpath(STATIC_DIR)

REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def b64u(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")
def b64u_json(obj) -> str: return b64u(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
def from_b64u(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

def sign(payload: dict) -> str:
    body = b64u_json(payload)
    mac  = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{b64u(mac)}"

def verify(tok: str) -> dict | None:
    try:
        body_b64, mac_b64 = tok.split(".", 1)
        mac = from_b64u(mac_b64)
        exp = hmac.new(SECRET.encode(), body_b64.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(mac, exp): return None
        payload = json.loads(from_b64u(body_b64).decode("utf-8"))
        return payload
    except Exception:
        return None

def ip_of(h): return h.client_address[0] if h.client_address else "0.0.0.0"
def ua_of(h): return h.headers.get("User-Agent", "")
def ua_fp(ua: str) -> str: return hashlib.sha256(ua.encode("utf-8")).hexdigest()[:16]
def make_sub(h): return f"{ua_fp(ua_of(h))}:{ip_of(h)}"
def token_key(sub: str) -> str: return f"{LABEL}:tokens:{sub}"

def set_csrf(handler: BaseHTTPRequestHandler) -> str:
    now = int(time.time())
    payload = {"iss": LABEL, "exp": now + CSRF_TTL, "ip": ip_of(handler), "uaf": ua_fp(ua_of(handler)), "n": b64u(os.urandom(8))}
    return sign(payload)

def csrf_ok(handler, form):
    tok = (form.get("csrf", [""])[0] or "").strip()
    p = verify(tok)
    if not p: return _deny(handler, 403, "bad_csrf")
    if int(time.time()) > int(p.get("exp", 0)): return _deny(handler, 403, "expired")
    if p.get("ip") != ip_of(handler) or p.get("uaf") != ua_fp(ua_of(handler)): return _deny(handler, 403, "mismatch")
    if not r.setnx(f"{LABEL}:csrf:{tok}", "1"): return _deny(handler, 403, "replay")
    r.expire(f"{LABEL}:csrf:{tok}", CSRF_TTL)
    return True

def set_user_token(sub: str) -> str:
    now = int(time.time())
    payload = {"iss": LABEL, "sub": sub, "exp": now + TOKEN_TTL, "n": b64u(os.urandom(8))}
    tok = sign(payload)
    r.setex(token_key(sub), TOKEN_TTL, tok)
    return tok

def require_user_token(handler: BaseHTTPRequestHandler, form: dict, sub: str) -> bool:
    tok = (form.get("user_token", [""])[0] or "").strip()
    if not tok: return _deny(handler, 403, "no_token")
    p = verify(tok)
    if not p: return _deny(handler, 403, "bad_token")
    if p.get("sub") != sub: return _deny(handler, 403, "token_mismatch")
    if int(time.time()) > int(p.get("exp", 0)): return _deny(handler, 403, "token_expired")
    stored = r.get(token_key(sub))
    if stored != tok: return _deny(handler, 403, "token_revoked")
    return True

def _deny(handler: BaseHTTPRequestHandler, code: int, err: str) -> bool:
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.end_headers()
    handler.wfile.write(json.dumps({"ok": False, "err": err}, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    return False

def send_json(handler, code, obj):
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.end_headers()
    handler.wfile.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

def jerr(handler, code, err):
    send_json(handler, code, {"ok": False, "err": err})

def paid_key(sub: str) -> str:
    return f"{LABEL}:paid:{sub}"

def is_paid(sub: str) -> bool:
    return r.get(paid_key(sub)) == "1"

def set_paid(sub: str, val: bool, ttl: int | None = None):
    k = paid_key(sub)
    if val:
        r.set(k, "1", ex=ttl or TOKEN_TTL)
    else:
        r.delete(k)

@lru_cache(maxsize=1)
def _index_bytes():
    with open(INDEX_PATH, "rb") as f:
        return f.read()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logging.info("%s - %s", self.address_string(), fmt % args)

    def _set_headers(self, code=200, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()

    def _serve_static(self, relpath: str, ctype: str):
        fullpath = os.path.realpath(os.path.join(STATIC_ROOT, relpath))

        if not (fullpath == STATIC_ROOT or fullpath.startswith(STATIC_ROOT + os.sep)):
            jerr(self, 404, "not_found"); return

        if os.path.isdir(fullpath):
            jerr(self, 404, "not_found"); return

        try:
            with open(fullpath, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            jerr(self, 404, "not_found"); return
        except PermissionError:
            jerr(self, 403, "forbidden"); return

        etag = hashlib.sha256(data).hexdigest()[:16]
        inm = self.headers.get("If-None-Match")
        if inm and inm == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=300")
        self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(data)
    
    def _guess_type(self, path: str) -> str:
        return (mimetypes.guess_type(path)[0] or "application/octet-stream") + "; charset=utf-8" \
            if (path.endswith(".html") or path.endswith(".css") or path.endswith(".js")) \
            else (mimetypes.guess_type(path)[0] or "application/octet-stream")

    def _render_gate(self, gate_name: str | None, reason: str | None, status: int, user_token: str | None):
        cls, title, line = resolve_theme(gate_name, reason)
        csrf = set_csrf(self)
        html = _index_bytes().decode("utf-8")      
        paid_class = "subscription" if (user_token and is_paid(make_sub(self))) else "free"
        html = (html
            .replace("__CSRF_TOKEN__", csrf)
            .replace("__USER_TOKEN__", user_token or "")
            .replace("__GATE_CLASS__", cls)
            .replace("__AUTH_CLASS__", "has-token" if user_token else "no-token")
            .replace("__GATE_TITLE__", title)
            .replace("__PAY_CLASS__", paid_class)
            .replace("__GATE_LINE__", line)
            .replace("__GATE_VISIBLE__", "show" if gate_name else "hide")
        )
        self._set_headers(200, "text/html; charset=utf-8")
        self.wfile.write(html.encode("utf-8"))

    def do_GET(self):
        path = (self.path or "/").split("?", 1)[0].rstrip("/") or "/"
        if path.startswith("/static/"):
          rel = os.path.normpath(path[len("/static/"):]).lstrip(os.sep)
          return self._serve_static(rel, self._guess_type(rel))
        if path == "/" or path.startswith("/gate/"):
            gate_name = path.split("/", 2)[2] if path.startswith("/gate/") else None
            return self._render_gate(gate_name, None,  status=200, user_token=None)
        jerr(self, 404, "not_found")

    def do_POST(self):
        path = (self.path or "/").split("?", 1)[0].rstrip("/") or "/"
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/x-www-form-urlencoded":
            jerr(self, 415, "unsupported_media_type"); return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length > MAX_CONTENT_LENGTH:
            jerr(self, 413, "too_large"); return

        body = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_qs(body, keep_blank_values=True)
        sub = make_sub(self)

        if not csrf_ok(self, form):
            return

        def _resolve_gate(name: str) -> str:
            if not name:
                return "Labyrinth"
            if name in THEMES:
                return name
            norm = name.replace("_", "-").strip().lower()
            for k in THEMES.keys():
                if k.lower() == norm:
                    return k
            return "Labyrinth"

        if path == "/register":
            tok = set_user_token(sub)
            gates.route_and_record("register", "", sub)
            return self._render_gate("Antechamber", "token issued", status=200, user_token=tok)

        if not require_user_token(self, form, sub):
            return
        tok = (form.get("user_token", [""])[0] or "")

        if path == "/payment":
            try:
                set_paid(sub, True)
                res = gates.route_and_record("payment", "", sub)
                gate_name = _resolve_gate(res.get("gate", "OK"))
                reason = res.get("reason", "payment recorded")
                status = int(res.get("status") or 200)
            except Exception:
                gate_name, reason, status = ("OK", "payment recorded", 200)

            render_kwargs = {"status": status, "user_token": tok}
            return self._render_gate(gate_name, reason, **render_kwargs)

        if path == "/cancel_payment":
            try:
                set_paid(sub, False)
                res = gates.route_and_record("cancel_payment", "", sub)
                gate_name = _resolve_gate(res.get("gate", "OK"))
                reason = res.get("reason", "payment canceled")
                status = int(res.get("status") or 200)
            except Exception:
                gate_name, reason, status = ("OK", "payment canceled", 200)

            render_kwargs = {"status": status, "user_token": tok}
            return self._render_gate(gate_name, reason, **render_kwargs)

        if path == "/submit":
            prompt = (form.get("prompt", [""])[0] or "")
            res = gates.route_and_record("prompt", prompt, sub)

            gate_name = _resolve_gate(res.get("gate", "Labyrinth"))
            reason = res.get("reason", "ok")
            status = int(res.get("status") or 200)

            render_kwargs = {"status": status, "user_token": tok}
            return self._render_gate(gate_name, reason, **render_kwargs)
        jerr(self, 404, "not_found")

def parse_bind(url: str):
    if "://" not in url: url = "http://" + url
    p = urlparse(url)
    host = p.hostname or "127.0.0.1"
    port = p.port or 8080
    return host, int(port)

def main():
    host, port = parse_bind(BIND_URL)
    srv = ThreadingHTTPServer((host, port), Handler)
    try:
        logging.info("Server running on http://%s:%i", host, port)
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()

if __name__ == "__main__":
    main()
