#!/usr/bin/env python3
"""Labeled deliberately-vulnerable app for benchmarking web scanners.

Self-contained (Python stdlib only). Backs SQLi endpoints with sqlite but emits
MySQL-style error messages and supports a SLEEP() function, so SQL-injection
tools that target MySQL/PostgreSQL/MSSQL are exercised fairly (real targets are
MySQL and emit those errors). Each route's vulnerability status is fixed and
documented in manifest.json — that is the ground truth the scorer compares to.

Routes:
  SQLi (vulnerable, string-concatenated):
    /sqli/error?id=1     numeric, error-based + UNION reachable
    /sqli/blind?id=1     numeric, boolean-blind (content differs)
    /sqli/string?name=a  single-quote string context
    /sqli/time?id=1      numeric, time-based (SLEEP available)
    /sqli/post  (POST id=1)  vulnerable via POST body
  SQLi (safe):
    /sqli/safe?id=1      parameterized query
  XSS (vulnerable, unescaped reflection):
    /xss/body?q=         HTML body context
    /xss/attr?q=         HTML attribute context
    /xss/js?q=           JavaScript string context
  XSS (safe):
    /xss/safe?q=         html.escape()
  SSRF:
    /ssrf/fetch?url=     server actually fetches the URL (vulnerable)
    /ssrf/safe?url=      allowlist-only, no fetch (safe)
  /health                readiness probe
"""

import html
import os
import sqlite3
import sys
import tempfile
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DB_PATH = os.path.join(tempfile.gettempdir(), "anvil_bench.sqlite")

# In-memory store for the stored-XSS endpoint.
STORE = []

# MySQL-style error so MySQL-targeting error-based detection is exercised.
MYSQL_ERR = (
    "You have an error in your SQL syntax; check the manual that corresponds to "
    "your MySQL server version for the right syntax to use near '{frag}' at line 1"
)


def _sleep(seconds):
    try:
        time.sleep(min(float(seconds), 6.0))  # cap to avoid runaway
    except (TypeError, ValueError):
        pass
    return 0


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT, secret TEXT)")
    conn.executemany(
        "INSERT INTO users VALUES (?,?,?)",
        [(1, "admin", "s3cr3t"), (2, "bob", "hunter2"), (3, "alice", "p@ss")],
    )
    conn.commit()
    conn.close()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.create_function("SLEEP", 1, _sleep)
    # MySQL aliases so injected payloads resolve.
    conn.create_function("VERSION", 0, lambda: "8.0.34-mysql")
    return conn


def run_query(sql):
    """Execute attacker-influenced SQL; return (rows, error_fragment|None)."""
    conn = db()
    try:
        cur = conn.execute(sql)
        return cur.fetchall(), None
    except sqlite3.Error as e:
        return None, str(e)
    finally:
        conn.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, status=200, ctype="text/html", extra_headers=None):
        data = body.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        self.route(u.path, q)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        q = parse_qs(raw)
        u = urlparse(self.path)
        self.route(u.path, q, post=True)

    def route(self, path, q, post=False):
        def p(name, default=""):
            return q.get(name, [default])[0]

        # ---------- OWASP-Benchmark-style scale corpus ----------
        # /bench/{type}/{case} — `case` (in the PATH, so it survives scanning that
        # rewrites query params) decides whether this case is genuinely vulnerable
        # (even) or safe-but-look-alike (odd) and which context. The injectable
        # parameter is `q`. Ground truth is derived from `case` in the generated
        # manifest, mirroring OWASP Benchmark's 50/50 TP/FP design.
        def _bench_case(prefix):
            try:
                return int(path[len(prefix):])
            except ValueError:
                return 0

        if path.startswith("/bench/sqli/"):
            case = _bench_case("/bench/sqli/")
            qv = p("q", "1")
            real = (case % 2 == 0)
            ctx = case % 3  # 0=numeric, 1=single-quote string, 2=error-returning
            conn = db()
            try:
                if real:
                    sql = (
                        f"SELECT name FROM users WHERE name='{qv}'"
                        if ctx == 1
                        else f"SELECT name FROM users WHERE id={qv}"
                    )
                    rows = conn.execute(sql).fetchall()
                    return self._send(f"<p>{'Welcome' if rows else 'Not found'}</p>")
                # safe: parameterized query
                if ctx == 1:
                    rows = conn.execute("SELECT name FROM users WHERE name=?", (qv,)).fetchall()
                else:
                    rows = conn.execute("SELECT name FROM users WHERE id=?", (qv,)).fetchall()
                return self._send(f"<p>{'Welcome' if rows else 'Not found'}</p>")
            except sqlite3.Error:
                # vulnerable + error context leaks a (MySQL-style) DB error
                if real:
                    return self._send(MYSQL_ERR.format(frag=qv[-8:]))
                return self._send("<p>Not found</p>")
            finally:
                conn.close()

        if path.startswith("/bench/xss/"):
            case = _bench_case("/bench/xss/")
            qv = p("q", "test")
            real = (case % 2 == 0)
            ctx = case % 4  # 0=body, 1=attribute, 2=js-string, 3=comment
            val = qv if real else html.escape(qv, quote=True)
            if ctx == 0:
                body = f"<div>{val}</div>"
            elif ctx == 1:
                body = f'<input value="{val}">'
            elif ctx == 2:
                body = f'<script>var x="{val}";</script>'
            else:
                body = f"<!-- {val} -->"
            return self._send(f"<html><body>{body}</body></html>")

        # ---------------- SQLi ----------------
        if path == "/sqli/error" or (path == "/sqli/post" and post):
            raw = p("id", "1")
            rows, err = run_query(f"SELECT name FROM users WHERE id={raw}")
            if err:
                frag = raw[-12:]
                return self._send(MYSQL_ERR.format(frag=frag), 200)
            names = ", ".join(r[0] for r in rows) if rows else "none"
            return self._send(f"<h1>User</h1><p>name: {names}</p>")

        if path == "/sqli/blind":
            raw = p("id", "1")
            rows, err = run_query(f"SELECT name FROM users WHERE id={raw}")
            if err:
                # blind: errors are swallowed (generic page), only content differs
                return self._send("<h1>Result</h1><p>Not found</p>")
            if rows:
                return self._send("<h1>Result</h1><p>Welcome back, member!</p>")
            return self._send("<h1>Result</h1><p>Not found</p>")

        if path == "/sqli/string":
            raw = p("name", "admin")
            rows, err = run_query(f"SELECT id FROM users WHERE name='{raw}'")
            if err:
                return self._send(MYSQL_ERR.format(frag=raw[-12:]), 200)
            if rows:
                return self._send("<h1>Result</h1><p>Welcome back, member!</p>")
            return self._send("<h1>Result</h1><p>Not found</p>")

        if path == "/sqli/time":
            raw = p("id", "1")
            rows, err = run_query(f"SELECT name FROM users WHERE id={raw}")
            if err:
                return self._send("<h1>Result</h1><p>err</p>")
            return self._send("<h1>Result</h1><p>ok</p>")

        if path == "/sqli/safe":
            raw = p("id", "1")
            conn = db()
            try:
                cur = conn.execute("SELECT name FROM users WHERE id=?", (raw,))
                rows = cur.fetchall()
            except sqlite3.Error:
                rows = []
            finally:
                conn.close()
            names = ", ".join(r[0] for r in rows) if rows else "none"
            return self._send(f"<h1>User</h1><p>name: {names}</p>")

        # ---------------- XSS (vulnerable) ----------------
        if path == "/xss/body":  # HTML body context
            return self._send(f"<html><body><h1>Search</h1><div>{p('q')}</div></body></html>")
        if path == "/xss/attr":  # double-quote attribute
            return self._send(f'<html><body><input type="text" value="{p("q")}"></body></html>')
        if path == "/xss/attr_sq":  # single-quote attribute
            return self._send(f"<html><body><input type='text' value='{p('q')}'></body></html>")
        if path == "/xss/js":  # JS string context
            return self._send(f'<html><body><script>var term="{p("q")}";</script></body></html>')
        if path == "/xss/comment":  # inside an HTML comment
            return self._send(f"<html><body><!-- {p('q')} --></body></html>")
        if path == "/xss/href":  # URL/href context (javascript: scheme)
            return self._send(f'<html><body><a href="{p("q")}">link</a></body></html>')
        if path == "/xss/filtered":  # strips < and > -> needs attribute event-handler breakout
            v = p("q").replace("<", "").replace(">", "")
            return self._send(f'<html><body><input value="{v}"></body></html>')
        if path == "/xss/post" and post:  # reflected via POST body
            return self._send(f"<html><body><div>{p('q')}</div></body></html>")
        if path == "/xss/dom":  # DOM XSS: client JS reads ?q= and sinks to innerHTML
            return self._send(
                "<html><body><div id=out></div><script>"
                "var u=new URLSearchParams(location.search);"
                "document.getElementById('out').innerHTML=u.get('q');"
                "</script></body></html>"
            )
        if path == "/xss/stored":  # stored: GET shows store; (POST stores then redirects)
            if post:
                STORE.append(p("q"))
                return self._send("<html><body>saved</body></html>")
            items = "".join(f"<li>{x}</li>" for x in STORE[-10:])
            return self._send(f"<html><body><h1>Comments</h1><ul>{items}</ul></body></html>")

        # ---------------- XSS (safe) ----------------
        if path == "/xss/safe":  # html.escape body
            return self._send(f"<html><body><div>{html.escape(p('q'))}</div></body></html>")
        if path == "/xss/attr_safe":  # properly escaped attribute
            return self._send(
                f'<html><body><input value="{html.escape(p("q"), quote=True)}"></body></html>'
            )
        if path == "/xss/csp":  # reflected UNescaped but CSP blocks inline execution
            return self._send(
                f"<html><body><div>{p('q')}</div></body></html>",
                extra_headers={"Content-Security-Policy": "script-src 'none'; object-src 'none'"},
            )

        # ---------------- SSRF (vulnerable) ----------------
        if path == "/ssrf/fetch" or (path == "/ssrf/post_fetch" and post):
            target = p("url")  # server fetches it and returns the content
            if not target:
                return self._send("<p>provide url</p>")
            try:
                with urllib.request.urlopen(target, timeout=3) as resp:
                    body = resp.read(4096).decode("utf-8", "replace")
                return self._send(f"<h1>Fetched</h1><pre>{body}</pre>")
            except Exception as e:  # noqa: BLE001 - vulnerable app reflects the error
                return self._send(f"<h1>Fetch error</h1><pre>{e}</pre>")
        if path == "/ssrf/blind":  # fetches but returns nothing useful (blind SSRF)
            target = p("url")
            try:
                urllib.request.urlopen(target, timeout=3).read(64)
            except Exception:
                pass
            return self._send("<h1>Request received</h1>")

        # ---------------- SSRF (safe) ----------------
        if path == "/ssrf/safe":  # strict allowlist
            target = p("url")
            allow = ("https://example.com", "http://example.com")
            if target.startswith(allow):
                return self._send("<p>allowed</p>")
            return self._send("<p>blocked: host not allowlisted</p>")
        if path == "/ssrf/reflect":  # echoes the URL but never fetches it
            return self._send(f"<h1>You requested</h1><pre>{p('url')}</pre>")  # reflection != SSRF

        if path == "/health":
            return self._send("ok")

        return self._send("<h1>404</h1>", 404)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8980
    init_db()
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"vulnapp listening on 127.0.0.1:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
