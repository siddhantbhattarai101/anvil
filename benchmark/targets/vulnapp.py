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

    def _send(self, body, status=200, ctype="text/html"):
        data = body.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
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

        # ---------------- XSS ----------------
        if path == "/xss/body":
            return self._send(f"<html><body><h1>Search</h1><div>{p('q')}</div></body></html>")
        if path == "/xss/attr":
            return self._send(f'<html><body><input type="text" value="{p("q")}"></body></html>')
        if path == "/xss/js":
            return self._send(
                f'<html><body><script>var term="{p("q")}";</script></body></html>'
            )
        if path == "/xss/safe":
            return self._send(f"<html><body><div>{html.escape(p('q'))}</div></body></html>")

        # ---------------- SSRF ----------------
        if path == "/ssrf/fetch":
            target = p("url")
            if not target:
                return self._send("<p>provide ?url=</p>")
            try:
                with urllib.request.urlopen(target, timeout=3) as resp:
                    body = resp.read(4096).decode("utf-8", "replace")
                return self._send(f"<h1>Fetched</h1><pre>{body}</pre>")
            except Exception as e:  # noqa: BLE001 - vulnerable app reflects the error
                return self._send(f"<h1>Fetch error</h1><pre>{e}</pre>")
        if path == "/ssrf/safe":
            target = p("url")
            allow = ("https://example.com", "http://example.com")
            if target.startswith(allow):
                return self._send("<p>allowed</p>")
            return self._send("<p>blocked: host not allowlisted</p>")

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
