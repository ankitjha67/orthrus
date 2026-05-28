"""Intentionally-vulnerable local target for HYDRA integration tests.

Binds to 127.0.0.1 only. Each route/behaviour simulates one vuln class so the
scanners can run end-to-end against a target we own. Do NOT deploy this.

  /search?q=     reflected XSS                 /xml (POST)    XXE (in-band file read)
  /redirect?url= open redirect                 /graphql(POST) GraphQL introspection
  /render?name=  SSTI (evaluates a*b)          /profile?id=   IDOR / object enumeration
  /sqli?id=      SQLi (MySQL error on quote)   <form>         CSRF (no token)
  /ping?host=    OS command injection          cookies        missing flags / serialized / weak JWT
  /download?file=LFI (/etc/passwd, win.ini)    X-Forwarded-Host reflection -> cache poisoning

Run: python reflecting_target.py [port]
"""

from __future__ import annotations

import re
import sys
import threading
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
    "</ul>"
    '<script src="/app.js"></script>'
    '<form action="/comment" method="post">'
    '<input name="text"><input name="email"><button>send</button></form>'
    "</body></html>"
)

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
    "const API='/api/v2';"
    "fetch('/api/v2/profile').then(r=>r.json());"
    "axios.get('/api/v2/orders');"
    "const ws=new WebSocket('ws://127.0.0.1:8732/ws');"
    "const AWS_KEY='AKIAIOSFODNN7EXAMPLE';"
)
ENV_FILE = "SECRET_KEY=hydra-prod-123\nDATABASE_URL=postgres://u:p@db/app\n"
GIT_HEAD = "ref: refs/heads/main\n"

# Stored XSS: comments are rendered into HTML without sanitization.
GUESTBOOK_COMMENTS: list[str] = []


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

    def _body(self) -> str:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length).decode("utf-8", "ignore") if length else ""

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
            names = {"1": "Alice Anderson", "2": "Bob Brown", "3": "Carol Clark"}
            nm = names.get(pid, f"User {pid}")
            self._html(
                f"<html><body>Profile #{pid}: name={nm}, email=user{pid}@corp.example, "
                f"dept=Engineering, joined=2020-01-15, status=active account</body></html>"
            )
        elif parts.path == "/xml":
            self._html("<html><body>XML endpoint: POST an XML document</body></html>")
        elif parts.path == "/fetch":
            u = first("url")
            status = "no url provided"
            if u.startswith(("http://", "https://")):
                try:  # server-side fetch -> SSRF
                    with urllib.request.urlopen(u, timeout=3) as r:  # noqa: S310
                        status = f"fetched HTTP {r.status}"
                except Exception as exc:  # noqa: BLE001
                    status = f"error: {type(exc).__name__}"
            self._html(f"<html><body>fetch result: {status}</body></html>")
        elif parts.path == "/dom":
            self._html(DOM_PAGE)
        elif parts.path == "/pp":
            self._html(PP_PAGE)
        elif parts.path == "/app.js":
            self._raw(APP_JS.encode(), "application/javascript")
        elif parts.path == "/.env":
            self._raw(ENV_FILE.encode(), "text/plain")
        elif parts.path == "/.git/HEAD":
            self._raw(GIT_HEAD.encode(), "text/plain")
        elif parts.path == "/guestbook":
            self._html(self._guestbook())
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
