"""Intentionally-vulnerable local target for ORTHRUS integration tests.

Binds to 127.0.0.1 only. Each route/behaviour simulates one vuln class so the
scanners can run end-to-end against a target we own. Do NOT deploy this.

  /search?q=     reflected XSS                 /xml (POST)    XXE (in-band file read)
  /redirect?url= open redirect                 /graphql(POST) GraphQL introspection
  /render?name=  SSTI (evaluates a*b)          /profile?id=   IDOR / object enumeration
  /sqli?id=      SQLi (MySQL error on quote)   /comment(POST) reflected XSS (body) + CSRF
  /ping?host=    OS command injection          cookies        missing flags / serialized / weak JWT
  /download?file=LFI (/etc/passwd, win.ini)    X-Forwarded-Host reflection -> cache poisoning
  /fetch?url=    SSRF (GET + POST body)         /api/users/<id> IDOR / BOLA via REST path id
  /api/account(POST) mass assignment (autobind)
  /password-reset     Host/X-Forwarded-Host reflected into reset link -> host-header injection
  /actuator/env       exposed Spring Boot Actuator env  /server-status  Apache status -> framework debug
  /account            /account/*.css returns the page verbatim -> web cache deception
  /nosql?user=        reflects a MongoServerError on operator/quote chars -> NoSQL injection
  /upload (POST)      accepts any multipart file with no validation -> unrestricted upload
  /redirect?url=      reflects url into Location verbatim -> open redirect + CRLF response split

Run: python reflecting_target.py [port]
"""

from __future__ import annotations

import json
import re
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# JWT signed with the weak secret "secret" (HS256), payload {"user":"admin","role":"user"}.
WEAK_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoidXNlciJ9."
    "50QUbI83hHJdTpsseful-jdby2eFD5UIj4wEzPfVnrU"
)
INSECURE_COOKIES = [
    "sid=abc123def456",
    'obj=O:8:"stdClass":1:{s:4:"user";s:5:"admin";}',
    f"token={WEAK_JWT}",
]

HOME = (
    "<html><body><h1>Vuln Test App</h1><ul>"
    '<li><a href="/search?q=hello">search</a></li>'
    '<li><a href="/redirect?url=/home">redirect</a></li>'
    '<li><a href="/render?name=guest">render</a></li>'
    '<li><a href="/sqli?id=1">sqli</a></li>'
    '<li><a href="/ping?host=127.0.0.1">ping</a></li>'
    '<li><a href="/download?file=readme.txt">download</a></li>'
    '<li><a href="/xml?doc=1">xml</a></li>'
    '<li><a href="/profile?id=1">profile</a></li>'
    '<li><a href="/fetch?url=http://127.0.0.1/health">fetch</a></li>'
    '<li><a href="/dom?html=hi">dom</a></li>'
    '<li><a href="/guestbook">guestbook</a></li>'
    '<li><a href="/pp?a=1">pp</a></li>'
    '<li><a href="/redeem">redeem</a></li>'
    '<li><a href="/login">login</a></li>'
    '<li><a href="/password-reset">reset</a></li>'
    '<li><a href="/account">account</a></li>'
    '<li><a href="/nosql?user=guest">nosql</a></li>'
    '<li><a href="/upload">upload</a></li>'
    '<li><a href="/items">items</a></li>'
    "</ul>"
    '<script src="/app.js"></script>'
    '<form action="/comment" method="post">'
    '<input name="text"><input name="email"><button>send</button></form>'
    '<form action="/fetch" method="post">'
    '<input name="url"><button>fetch</button></form>'
    '<form action="/api/account" method="post">'
    '<input name="name" value="guest"><button>save</button></form>'
    "</body></html>"
)

REDEEM_FORM = (
    "<html><body><h1>Redeem</h1>"
    '<form action="/redeem" method="post">'
    '<input name="coupon" value="SAVE10"><button>redeem</button></form></body></html>'
)
LOGIN_FORM = (
    "<html><body><h1>Login</h1>"
    '<form action="/login" method="post">'
    '<input name="username"><input name="password" type="password">'
    "<button>sign in</button></form></body></html>"
)
REDEEM_LOCK = threading.Lock()
REDEEM_STATE = {"granted": 0, "window": 0.0}
REDEEM_LIMIT = 3  # per ~1s window, so a concurrent burst yields partial success

GRAPHQL_SCHEMA = (
    '{"data":{"__schema":{"queryType":{"name":"Query"},'
    '"types":[{"name":"User"},{"name":"Query"}]}}}'
)
MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds to your "
    "MySQL server version for the right syntax to use near \"'\" at line 1"
)
PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
WININI = "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n"

_ARITH = re.compile(r"(\d+)\*(\d+)")
_ECHO = re.compile(r"echo\s+([A-Za-z0-9]+)")
_SHELL_META = re.compile(r"[;|&`$\n]")

# Client-side sink: writes the URL fragment / ?html param straight into innerHTML.
DOM_PAGE = (
    "<html><body><h1>DOM</h1><div id=out></div><script>"
    "var h=location.hash.slice(1);try{h=decodeURIComponent(h)}catch(e){}"
    'var q=new URLSearchParams(location.search).get("html")||"";'
    "document.getElementById('out').innerHTML=h+q;"
    "</script></body></html>"
)

# Client-side prototype pollution: a naive recursive merge of URL params with no
# __proto__/constructor guard.
PP_PAGE = (
    "<html><body><h1>PP</h1><script>"
    "function setDeep(o,path,v){for(var i=0;i<path.length-1;i++){var k=path[i];"
    "if(!(k in o))o[k]={};o=o[k];}o[path[path.length-1]]=v;}"
    "function parse(qs){var out={};(qs||'').split('&').forEach(function(p){"
    "if(!p)return;var i=p.indexOf('=');if(i<0)return;"
    "var key=decodeURIComponent(p.slice(0,i));var val=decodeURIComponent(p.slice(i+1));"
    "var path=key.replace(/\\]/g,'').split(/\\[|\\./).filter(Boolean);setDeep(out,path,val);});return out;}"
    "parse(location.search.slice(1)||location.hash.slice(1));"
    "</script></body></html>"
)

# External JS with API endpoints, a websocket URL, and a leaked key (for js-analyzer).
APP_JS = (
    "/*! jQuery v1.7.1 jquery.com | jquery.org/license */"  # outdated lib -> SCA finding
    "const API='/api/v2';"
    "fetch('/api/v2/profile').then(r=>r.json());"
    "axios.get('/api/v2/orders');"
    "const ws=new WebSocket('ws://127.0.0.1:8732/ws');"
    "const AWS_KEY='AKIAIOSFODNN7EXAMPLE';"
)
ENV_FILE = "SECRET_KEY=orthrus-prod-123\nDATABASE_URL=postgres://u:p@db/app\n"
GIT_HEAD = "ref: refs/heads/main\n"
# Spring Boot Actuator /env left exposed (framework debug / management endpoint).
ACTUATOR_ENV = (
    '{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment",'
    '"properties":{"DB_PASSWORD":{"value":"s3cr3t"},"JAVA_HOME":{"value":"/usr/lib/jvm"}}}]}'
)
SERVER_STATUS = "Apache Server Status for 127.0.0.1\nServer uptime: 3 days 4 hours\nScoreboard: __W_\n"
# Sensitive account page; any /account/* sub-path returns it verbatim -> web cache deception.
ACCOUNT_BODY = (
    "<html><body><h1>Account</h1>user=alice, email=alice@corp.example, "
    "balance=$4,200.00, card ending 1234</body></html>"
)

# Stored XSS: comments are rendered into HTML without sanitization.
GUESTBOOK_COMMENTS: list[str] = []


def fetch_url(u: str) -> str:
    """Server-side fetch of an attacker-controlled URL -> SSRF (shared GET/POST)."""
    if not u.startswith(("http://", "https://")):
        return "no url provided"
    try:  # noqa: S310 (intentionally unvalidated for the SSRF test case)
        with urllib.request.urlopen(u, timeout=3) as r:  # noqa: S310
            return f"fetched HTTP {r.status}"
    except Exception as exc:  # noqa: BLE001
        return f"error: {type(exc).__name__}"


class Handler(BaseHTTPRequestHandler):
    def _headers(
        self, length: int, status: int = 200, location: str | None = None, cookies: bool = False
    ) -> None:
        self.send_response(status)
        if location is not None:
            self.send_header("Location", location)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.send_header("X-Cache", "MISS")  # cache indicator
        origin = self.headers.get("Origin")
        if origin:  # reflect any origin with credentials -> CORS misconfig
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        if cookies:
            for cookie in INSECURE_COOKIES:
                self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _html(self, body: str, cookies: bool = False) -> None:
        xfh = self.headers.get("X-Forwarded-Host")
        if xfh:  # unkeyed header reflection -> cache poisoning
            body = body.replace("</body>", f'<link href="https://{xfh}/s.css"></body>')
        data = body.encode("utf-8")
        self._headers(len(data), cookies=cookies)
        self.wfile.write(data)

    def _raw(self, data: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj: dict) -> None:
        self._raw(json.dumps(obj).encode("utf-8"), "application/json")

    @staticmethod
    def _parse_fields(body: str) -> dict[str, str]:
        """Body fields as a flat str->str dict, accepting JSON or urlencoded."""
        text = body.strip()
        if text.startswith("{"):
            try:
                obj = json.loads(text)
            except ValueError:
                return {}
            return {k: str(v) for k, v in obj.items()} if isinstance(obj, dict) else {}
        return {k: v[0] for k, v in parse_qs(text, keep_blank_values=True).items()}

    def _body(self) -> str:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length).decode("utf-8", "ignore") if length else ""

    def _profile_body(self, pid: str) -> str:
        names = {"1": "Alice Anderson", "2": "Bob Brown", "3": "Carol Clark"}
        nm = names.get(pid, f"User {pid}")
        return (
            f"<html><body>Profile #{pid}: name={nm}, email=user{pid}@corp.example, "
            f"dept=Engineering, joined=2020-01-15, status=active account</body></html>"
        )

    def _guestbook(self) -> str:
        items = "".join(f"<div class=c>{c}</div>" for c in GUESTBOOK_COMMENTS)
        return (
            "<html><body><h1>Guestbook</h1>" + items
            + '<form action="/guestbook" method="post">'
            '<textarea name="comment"></textarea><button>post</button></form>'
            "</body></html>"
        )

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        parts = urlsplit(self.path)
        qs = parse_qs(parts.query, keep_blank_values=True)

        def first(key: str) -> str:
            return qs.get(key, [""])[0]

        if parts.path == "/search":
            self._html(f"<html><body>You searched for: {first('q')}</body></html>")
        elif parts.path == "/redirect":
            self._headers(0, status=302, location=first("url"))
        elif parts.path == "/render":
            name = first("name")
            m = _ARITH.search(name)
            out = str(int(m.group(1)) * int(m.group(2))) if m else name
            self._html(f"<html><body>Hello {out}</body></html>")
        elif parts.path == "/sqli":
            value = first("id")
            body = MYSQL_ERROR if ("'" in value or '"' in value) else f"user {value}"
            self._html(f"<html><body>{body}</body></html>")
        elif parts.path == "/ping":
            host = first("host")
            m = _ECHO.search(host)
            out = m.group(1) if (m and _SHELL_META.search(host)) else host
            self._html(f"<html><body>PING result: {out}</body></html>")
        elif parts.path == "/download":
            f = first("file")
            if "passwd" in f:
                self._html(PASSWD)
            elif "win.ini" in f.lower():
                self._html(WININI)
            else:
                self._html("<html><body>file not found</body></html>")
        elif parts.path == "/profile":
            pid = first("id") or "0"
            self._html(self._profile_body(pid))
        elif parts.path.startswith("/api/users/"):
            # REST object reference: /api/users/<id> returns a distinct object per
            # numeric id with no per-object authorization -> BOLA via PATH param.
            uid = parts.path[len("/api/users/"):].split("/", 1)[0] or "0"
            self._html(self._profile_body(uid))
        elif parts.path == "/xml":
            self._html("<html><body>XML endpoint: POST an XML document</body></html>")
        elif parts.path == "/fetch":
            self._html(f"<html><body>fetch result: {fetch_url(first('url'))}</body></html>")
        elif parts.path == "/dom":
            self._html(DOM_PAGE)
        elif parts.path == "/pp":
            self._html(PP_PAGE)
        elif parts.path == "/redeem":
            self._html(REDEEM_FORM)
        elif parts.path == "/login":
            self._html(LOGIN_FORM)
        elif parts.path == "/dashboard":
            self._html("<html><body>Welcome, admin</body></html>")
        elif parts.path == "/app.js":
            self._raw(APP_JS.encode(), "application/javascript")
        elif parts.path == "/.env":
            self._raw(ENV_FILE.encode(), "text/plain")
        elif parts.path == "/.git/HEAD":
            self._raw(GIT_HEAD.encode(), "text/plain")
        elif parts.path == "/actuator/env":
            # Spring Boot Actuator env endpoint left exposed -> leaks config/secrets.
            self._raw(ACTUATOR_ENV.encode(), "application/json")
        elif parts.path == "/server-status":
            self._raw(SERVER_STATUS.encode(), "text/plain")
        elif parts.path == "/account" or parts.path.startswith("/account/"):
            # Ignores any extra sub-path -> /account/x.css returns the page -> cache deception.
            self._html(ACCOUNT_BODY)
        elif parts.path == "/items":
            # Processes an undeclared 'debug' param (reflected) -> param mining finds it.
            dbg = first("debug")
            if dbg:
                self._html(f"<html><body>items (debug mode: {dbg})</body></html>")
            else:
                self._html("<html><body>items list</body></html>")
        elif parts.path == "/nosql":
            user = first("user")
            if any(c in user for c in ("$", "{", "'", '"', "\\")):
                self._html("<html><body>MongoServerError: unknown top level operator: $ne</body></html>")
            else:
                self._html(f"<html><body>user record: {user}</body></html>")
        elif parts.path == "/guestbook":
            self._html(self._guestbook())
        elif parts.path == "/password-reset":
            # Builds the reset link from the (attacker-controllable) host header
            # -> host header injection / password-reset poisoning.
            host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "localhost"
            link = f"https://{host}/reset?token=SECRET-RESET-TOKEN"
            self._html(
                f'<html><body>Password reset link emailed: '
                f'<a href="{link}">reset your password</a></body></html>'
            )
        else:
            self._html(HOME, cookies=True)

    def do_POST(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        body = self._body()
        if parts.path == "/xml":
            if "etc/passwd" in body:
                self._html(PASSWD)
            elif "win.ini" in body.lower():
                self._html(WININI)
            else:
                self._html("<html><body>&lt;ok/&gt;</body></html>")
        elif parts.path == "/graphql":
            self._html(GRAPHQL_SCHEMA if "__schema" in body or "query" in body else "{}")
        elif parts.path == "/guestbook":
            comment = parse_qs(body).get("comment", [""])[0]
            if comment:
                GUESTBOOK_COMMENTS.append(comment)
            self._html(self._guestbook())
        elif parts.path == "/redeem":
            with REDEEM_LOCK:  # limited stock per ~1s window -> partial success under a burst
                now = time.time()
                if now - REDEEM_STATE["window"] > 2.0:
                    REDEEM_STATE["window"] = now
                    REDEEM_STATE["granted"] = 0
                if REDEEM_STATE["granted"] < REDEEM_LIMIT:
                    REDEEM_STATE["granted"] += 1
                    self._html("<html><body>coupon redeemed</body></html>")
                else:
                    self._headers(0, status=409)
        elif parts.path == "/login":
            form = parse_qs(body)
            user = form.get("username", [""])[0]
            pwd = form.get("password", [""])[0]
            if user == "admin" and pwd == "admin":
                self._headers(0, status=302, location="/dashboard")
            else:
                self._html("<html><body>Invalid credentials</body></html>")
        elif parts.path == "/comment":
            text = parse_qs(body).get("text", [""])[0]  # reflected unencoded -> XSS (POST body)
            self._html(f"<html><body>Thanks. You said: {text}</body></html>")
        elif parts.path == "/fetch":
            url = parse_qs(body).get("url", [""])[0]  # server-side fetch of body param -> SSRF (POST)
            self._html(f"<html><body>fetch result: {fetch_url(url)}</body></html>")
        elif parts.path == "/api/account":
            # Naive autobind: every supplied field is merged onto the account
            # object, so a client can set server-controlled props -> mass assignment.
            account = {"id": "1", "name": "guest", "role": "user", "verified": "false"}
            account.update(self._parse_fields(body))
            self._json(account)
        elif parts.path == "/upload":
            # No extension/content validation -> accepts any file (unrestricted upload).
            m = re.search(r'filename="([^"]+)"', body)
            fname = m.group(1) if m else ""
            if fname:
                self._html(f"<html><body>File uploaded to /uploads/{fname}</body></html>")
            else:
                self._html("<html><body>no file provided</body></html>")
        else:
            self.do_GET()

    def log_message(self, *args: object) -> None:
        pass


def _start_ws_server(port: int) -> None:
    """A WebSocket server that accepts ANY origin (missing Origin validation)."""
    import asyncio

    try:
        import websockets
    except ImportError:
        return

    async def handler(ws):  # noqa: ANN001
        try:
            async for msg in ws:
                await ws.send(f"echo:{msg}")
        except Exception:
            pass

    async def serve() -> None:
        async with websockets.serve(handler, "127.0.0.1", port):
            await asyncio.Future()

    asyncio.run(serve())


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8731
    threading.Thread(target=_start_ws_server, args=(port + 1,), daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
