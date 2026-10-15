"""Run the rendered nginx site for real inside a loopback-only network namespace and flood a few of its paths.

What this is
    A helper program for tests/deploy/test_deploy_nginx.py, run as
    `unshare -rn .venv/bin/python tests/deploy/nginx_live_driver.py <nginx binary> <library path> <work dir>`.
    It renders deploy/nginx/roxy.conf.template with roxy-nginx-apply's own functions for the binary's version,
    starts nginx (daemon off) on ports 80 and 443 with a trustme certificate, starts a small backend on
    127.0.0.1:8001 (the blue color's port) that counts requests per path, sends floods of TLS requests, and prints
    one JSON object: the status counts of each flood, how many requests reached the backend, and which log files
    contain the kill-switch token.

Why it exists
    Rate limits and log contents are behavior, not syntax: `nginx -t` accepts a location without `limit_req`, and
    only a running nginx shows that a flood of /health reaches Python, or that a refused kill-switch request writes
    its path (the token) to the error log. Plan 17.2 promises both "floods dropped before Python runs" and "the
    token must never be written to disk".

How it works
    Each flood comes from its own loopback source address (127.0.0.2, .3, ...), so every flood starts with a full
    per-IP bucket and no flood waits for the previous one to drain. Ten threads, each on one keep-alive TLS
    connection, send well over the 20 requests per second the `perip` zone allows. A fresh user and network
    namespace (`unshare -rn`) has only a loopback interface, so nothing here can reach another machine, and inside
    it the test may bind ports 80 and 443.

What to read next
    tests/deploy/test_deploy_nginx.py, deploy/nginx/roxy.conf.template, tests/deploy/deploy_sandbox.py (build_prefix).
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from deploy_sandbox import DEPLOY, HOST, build_prefix, load_script, ubuntu_nginx_conf

TOKEN = "KILLSWITCHtoken0123456789abcdef"
HITS: Counter[str] = Counter()
HITS_LOCK = threading.Lock()


def start_backend(port: int) -> ThreadingHTTPServer:
    """The app's stand-in: 200 for everything, counting requests per path."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            with HITS_LOCK:
                HITS[self.path.split("?")[0]] += 1
            body = b'{"Degraded":[]}\n'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # the trustme certificate; this checks nginx behavior, not the chain
    return ctx


def connect(source: str) -> http.client.HTTPConnection:
    raw = socket.create_connection(("127.0.0.1", 443), timeout=5, source_address=(source, 0))
    conn = http.client.HTTPConnection(HOST, 443, timeout=5)
    conn.sock = tls_context().wrap_socket(raw, server_hostname=HOST)
    return conn


def flood_one(path: str, count: int, source: str, statuses: Counter[str], lock: threading.Lock) -> None:
    """`count` requests over keep-alive TLS connections from `source`; a refused one may close the connection."""
    conn: http.client.HTTPConnection | None = None
    for _ in range(count):
        try:
            if conn is None:
                conn = connect(source)
            conn.request("GET", path, headers={"Host": HOST})
            response = conn.getresponse()
            response.read()
            key = str(response.status)
            if response.status == 429 or response.getheader("connection", "").lower() == "close":
                conn.close()
                conn = None
        except OSError as exc:
            key = f"error:{type(exc).__name__}"
            if conn is not None:
                conn.close()
            conn = None
        with lock:
            statuses[key] += 1
    if conn is not None:
        conn.close()


def flood(path: str, count: int, source: str, threads: int = 10) -> dict[str, Any]:
    statuses: Counter[str] = Counter()
    lock = threading.Lock()
    started = time.monotonic()
    workers = [
        threading.Thread(target=flood_one, args=(path, count // threads, source, statuses, lock))
        for _ in range(threads)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    elapsed = time.monotonic() - started
    return {"statuses": dict(statuses), "sent": count // threads * threads, "rate_per_s": round(count / elapsed, 1)}


def main() -> int:
    binary, libs, work = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    # A fresh namespace from `unshare -rn` has loopback down (and 127.0.0.0/8 with it).
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, capture_output=True)
    env = dict(os.environ, LD_LIBRARY_PATH=libs)
    apply = load_script(DEPLOY / "tools" / "roxy-nginx-apply", "roxy_nginx_apply_live")
    version = apply.parse_nginx_version(
        subprocess.run([binary, "-v"], capture_output=True, text=True, env=env, check=False).stderr
    )
    prefix = work / "nginx"
    base = Path(binary).parents[2] / "etc" / "nginx" / "nginx.conf"
    build_prefix(prefix, ubuntu_nginx_conf(base), namespaced=True)
    layout = apply.Layout(
        nginx_dir=prefix, log_dir=prefix / "logs", cert_root=prefix / "certs", releases_dir=prefix / "releases"
    )
    values = apply.site_values({"ROXY_SITE_ORIGIN": f"https://{HOST}"}, layout)
    template = (DEPLOY / "nginx" / "roxy.conf.template").read_text(encoding="utf-8")
    (prefix / "sites-enabled" / "roxy-v2.conf").write_text(apply.render_site(template, version=version, values=values))
    start_backend(8001)
    command = [binary, "-p", f"{prefix}/", "-c", str(prefix / "nginx.conf"), "-g", "daemon off;"]
    if version >= (1, 19, 5):  # -e: the startup log, before the config is read (never the system's /var/log)
        command += ["-e", str(prefix / "logs" / "startup-error.log")]
    nginx = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out: dict[str, Any] = {"version": ".".join(map(str, version))}
    try:
        for _ in range(100):
            try:
                connect("127.0.0.1").close()
                break
            except OSError:
                time.sleep(0.05)
        HITS.clear()
        out["health"] = flood("/health", 250, "127.0.0.2")
        out["static_missing"] = flood("/static/css/missing.ffffffffffff.css", 250, "127.0.0.3")
        out["kill_switch"] = flood(f"/admin/invalidate/{TOKEN}", 40, "127.0.0.4")
        time.sleep(0.3)  # let nginx finish writing its log lines
        out["backend_hits"] = dict(HITS)
        logs = {path.name: path.read_text(errors="replace") for path in (prefix / "logs").glob("*.log")}
        out["log_files"] = sorted(logs)
        out["token_in_logs"] = sorted(name for name, text in logs.items() if TOKEN in text)
        out["limit_lines"] = sum(text.count("limiting requests") for text in logs.values())
    finally:
        nginx.terminate()
        try:
            output, _ = nginx.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            nginx.kill()
            output, _ = nginx.communicate()
        out["nginx_output"] = output.decode("utf-8", "replace")[-2000:]
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
