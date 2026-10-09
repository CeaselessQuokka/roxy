"""gunicorn configuration for one Roxy color (blue or green): every setting below says why it has its value.

What this is
    The file `roxy@.service` passes to gunicorn (`gunicorn -c deploy/gunicorn.conf.py roxy.asgi:app`, run from the
    release directory). gunicorn executes it as Python and reads the module-level names (`workers`, `bind`, ...)
    as its settings. The values come from the environment systemd prepared from `/etc/roxy/roxy.env` and
    `/etc/roxy/<color>.env` (plan 15.3 L), so one file serves both colors.

Why it exists
    Plan 5.2 chose gunicorn as the process manager for its sd_notify readiness, graceful HUP reload, worker
    recycling and its event loop stall watchdog. Each setting is a decision with a reason, and the plan asks for
    every line to be commented (5.2, 18.1 item 8). Three choices matter most:
    - Two listeners: the loopback TCP port nginx proxies to, and the internal Unix socket for the deploy health
      gate (plan 5.8). Every worker opens its own TCP listener (`reuse_port`), so the kernel spreads nginx's
      connections evenly over the workers instead of piling them onto one; the Unix socket cannot be shared that
      way, so the master creates it once (`on_starting`) and hands it to every worker (`post_fork`). The socket
      must be mode 0660 so the deploy user (group roxy) can connect and nobody else can; it is created with
      `umask` applied, so the umask below sets that mode.
    - A taken port fails loudly. With `reuse_port` the master binds nothing itself, so on its own it would never
      learn that the port is in use: a second master on a served port (the other color with a copy-pasted
      ROXY_BIND, a manual start) would quietly share it, and a port another program holds would leave a READY
      master whose workers fail to bind and are respawned forever (finding mp-3). So `on_starting` first checks
      the TCP address with a plain bind (no SO_REUSEPORT, so ANY listener on it refuses us) and exits with status 1
      when it is taken, before systemd hears READY, the way gunicorn fails without `reuse_port`; and `pre_fork`
      checks again before every new worker (with SO_REUSEPORT, so only a foreign listener refuses us) and stops
      the master instead of starting a worker that cannot bind. Without ROXY_BIND each color takes its own port
      from `COLOR_PORTS` (finding mp-4), never blue's.
    - Low-memory deploy mode (DESIGN.md section 0): on the 909 MB server a deploy may start the idle color with
      one worker and add the rest after the old color stopped. deploy.sh asks for that with a small marker file;
      this file reads it.
    - gunicorn 25.1 and later open a control socket by default under `$XDG_RUNTIME_DIR` or `$HOME/.gunicorn/`.
      Both colors would share that path (same user, same home), so it is pinned per color next to the internal
      socket, with the same 0660 mode. deploy.sh uses it to add workers in low-memory mode (`worker add`, the
      same code path as gunicorn's SIGTTIN handler).

How it works
    Plain module-level assignments, computed with small helpers that validate the environment and fall back to the
    plan defaults with a warning on stderr (gunicorn would otherwise fail with a less helpful message, or worse,
    silently use its own default). Nothing here imports Roxy: the master must start even when the app cannot be
    imported, so the error is reported by the worker that fails, in the journal.

What to read next
    `src/roxy/worker.py` (the worker class and its uvicorn options), `deploy/systemd/roxy@.service` (how this file
    is started), then `deploy/deploy.sh` (low-memory mode and the health gate).
"""

from __future__ import annotations

import errno
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any

# ------------------------------------------------------------------------------------------------- helpers


def _warn(message: str) -> None:
    """A one-line warning on stderr, which systemd sends to the journal under roxy-<color>."""
    sys.stderr.write(f"gunicorn.conf.py: {message}\n")


def env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    """An integer environment variable inside [minimum, maximum], or `default` (with a warning) when it is not."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        _warn(f"{name}={raw!r} is not a whole number; using {default}")
        return default
    if not minimum <= value <= maximum:
        _warn(f"{name}={value} is outside {minimum}..{maximum}; using {default}")
        return default
    return value


def env_text(name: str, default: str) -> str:
    """A text environment variable, or `default` when unset or empty."""
    return os.environ.get(name, "").strip() or default


SHM_DIR = "/dev/shm"  # noqa: S108 (a memory filesystem for gunicorn's liveness file, not a temporary file of ours)


def memory_tmp_dir() -> str | None:
    """SHM_DIR when it exists and is writable (it is, even with PrivateDevices=yes), else None (gunicorn's default)."""
    return SHM_DIR if os.path.isdir(SHM_DIR) and os.access(SHM_DIR, os.W_OK) else None


START_WORKERS_MAX_AGE_S = 3600
"""A low-memory marker older than this is ignored: a deploy takes minutes, so an old marker is a leftover."""


def start_workers(full: int, marker: Path, *, now: float | None = None) -> int:
    """How many workers to start: `full`, unless a fresh low-memory marker from deploy.sh asks for fewer.

    The marker holds one whole number between 1 and `full`. Anything else (missing, unreadable, stale, garbage)
    means "start normally", so a broken marker can never stop the service from starting.
    """
    try:
        stat = marker.stat()
        text = marker.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return full
    age = (time.time() if now is None else now) - stat.st_mtime
    if age > START_WORKERS_MAX_AGE_S:
        _warn(f"ignoring stale low-memory marker {marker} ({int(age)} s old)")
        return full
    if not text.isdigit() or not 1 <= int(text) <= full:
        _warn(f"ignoring low-memory marker {marker} with content {text[:16]!r}")
        return full
    return int(text)


COLOR_PORTS = {"blue": 8001, "green": 8002}
"""Each color's loopback port, the same as deploy/nginx/roxy-upstream-<color>.conf (`server 127.0.0.1:800x`)."""

DEFAULT_PORT = 8001
"""The port of a color not in `COLOR_PORTS` (development, "dev")."""


def default_bind(color: str) -> str:
    """The TCP address a color listens on when ROXY_BIND is missing: its own port, never the other color's."""
    return f"127.0.0.1:{COLOR_PORTS.get(color, DEFAULT_PORT)}"


def resolve_bind(color: str) -> str:
    """ROXY_BIND, or the color's own address with a warning (a missing line in /etc/roxy/<color>.env)."""
    configured = env_text("ROXY_BIND", "")
    if configured:
        return configured
    fallback = default_bind(color)
    if color in COLOR_PORTS:
        _warn(f"ROXY_BIND is not set for color {color}; using {fallback}")
    return fallback


# --------------------------------------------------------------------------------------- derived values

_color = env_text("ROXY_COLOR", "dev")
_internal_socket = env_text("ROXY_INTERNAL_SOCKET", f"/run/roxy-{_color}/internal.sock")
_full_workers = env_int("ROXY_WORKERS", 2, minimum=1, maximum=32)
_marker = Path(env_text("ROXY_DEPLOY_STATE_DIR", "/var/lib/roxy-deploy")) / f"start-workers-{_color}"
_max_requests = env_int("ROXY_MAX_REQUESTS", 20000, minimum=0, maximum=10_000_000)
_log_levels = {"debug", "info", "warning", "error", "critical"}
_log_level = env_text("ROXY_LOG_LEVEL", "info").lower()

# -------------------------------------------------------------------------------------------- settings

# The worker class: uvicorn under gunicorn, with proxy header rewriting, the Server header and uvicorn's access
# log turned off, and keep-alive 75 s (plan 5.2; those options can only be set in the class, see roxy/worker.py).
worker_class = "roxy.worker.RoxyUvicornWorker"

# Worker processes: ROXY_WORKERS (2 on the 2 vCPU server, D2). Each worker is one asyncio event loop holding
# thousands of connections, so this is about CPU cores, not concurrency. In low-memory deploy mode deploy.sh asks
# for 1 here and adds the rest after the old color stopped (DESIGN.md section 0).
workers = start_workers(_full_workers, _marker)

# Each worker opens its own listener on the TCP address with SO_REUSEPORT, and the kernel hands every new
# connection to one of them by a hash of the client's address and port, so connections spread evenly. With one
# listener shared by all workers (gunicorn's default), the worker that went idle last accepts nearly every
# connection: 4 workers took 70/10/0/0 of 80 fresh connections and 130/30/0/0 of the requests on a 16-connection
# keep-alive pool (what nginx keeps open), against 21/21/21/17 and 60/59/36/5 with this setting. A second master
# started on a port already in use would share it silently, so on_starting and pre_fork refuse a taken port (module
# docstring). Trade-off: connections still waiting in a stopping worker's accept queue are reset (Linux moves them
# to another worker when net.ipv4.tcp_migrate_req=1), so a single-worker color briefly refuses connections while its
# worker recycles.
reuse_port = True

# The loopback TCP address nginx proxies to (ROXY_BIND; without it the color's own port, 127.0.0.1:8001 for blue
# and 127.0.0.1:8002 for green, so green never lands on blue's port), opened by every worker itself (reuse_port).
# The second listener, the internal Unix socket that only the deploy and ctl.py use (plan 5.8), is not listed here:
# SO_REUSEPORT does not apply to Unix sockets (newer kernels refuse it, and older ones would let each worker replace
# the socket file of the one before), so the master creates it once in on_starting and every worker accepts on that
# one shared socket (post_fork). The ASGI dispatcher in roxy/asgi.py sends Unix socket requests to the internal app;
# nginx never proxies to the socket.
bind = [resolve_bind(_color)]

INTERNAL_SOCKET = _internal_socket
"""The internal Unix socket path (ROXY_INTERNAL_SOCKET, /run/roxy-<color>/internal.sock by default)."""

# The master applies this umask while it creates the Unix socket, so the socket is 0777 & ~0117 = 0660: the roxy
# user and the roxy group (the deploy user is a member) may connect, everyone else is refused. The runtime
# directory around it is 0750 (RuntimeDirectoryMode), a second fence.
umask = 0o117

# The event loop stall watchdog, not a request limit (plan 5.2): an async worker heartbeats from its loop, so a
# request waiting 55 s on Roblox never trips this, while a loop frozen for 30 s by blocking work always does (and
# that is always a bug). Per-request limits are the app's request_deadline_s.
timeout = 30

# How long workers get to finish in-flight requests and SWR refreshes on a reload or stop. systemd's
# TimeoutStopSec (45) is longer, so systemd never kills a worker that gunicorn is still draining (v1 had 20 < 30).
# The worker class splits it (roxy/worker.py): uvicorn waits at most 30 - 8 - 2 = 20 s for open requests (tarpit
# holds, up to 55 s, are answered at once when shutdown starts), then the lifespan shutdown gets its 8 s budget
# (final metrics flush, leader lease release), and 2 s are left before gunicorn would kill the worker.
graceful_timeout = 30

# Idle keep-alive for nginx's upstream connections. uvicorn takes the real value from the worker class
# (timeout_keep_alive=75); this line keeps gunicorn's own view equal. It must stay above nginx's upstream
# keepalive_timeout (60 s): if the app closed first, nginx could reuse a closed socket and callers would see 502s.
keepalive = 75

# Recycle a worker after ROXY_MAX_REQUESTS requests (20000; 0 disables): insurance against slow memory growth.
# v1 hard-coded 2000 and ignored the variable (plan 2.4); v2 honors it.
max_requests = _max_requests

# Spread recycling by up to 10 percent (plan 4.7 row 110) so both workers never restart at the same moment.
max_requests_jitter = _max_requests // 10

# Load the app in each worker after forking, never in the master: httpx clients, SQLite connections and the
# event loop must not be shared across a fork (plan 5.2).
preload_app = False

# Not set on purpose: forwarded_allow_ips only matters with proxy_headers, which the worker class turns off.
# roxy/core/client_ip.py is the only reader of X-Forwarded-For (plan 9.11).

# No gunicorn access log: Roxy writes its own structured, redacted http_request line for every request, and a
# raw access line would print query strings and client addresses past the redaction (plan 9.15).
accesslog = None

# gunicorn's own messages (worker starts, exits, timeouts) go to stderr, which systemd sends to the journal.
errorlog = "-"

# Verbosity of gunicorn's own messages, following ROXY_LOG_LEVEL (the app reads the same variable).
loglevel = _log_level if _log_level in _log_levels else "info"

# Process titles (`ps`, `top`) name the color, so two masters during a deploy are easy to tell apart.
proc_name = f"roxy-{_color}"

# The control socket (gunicorn 25.1 and later), pinned next to the internal socket so blue and green never share
# one path, and 0660 like the internal socket. deploy.sh uses `gunicornc -c "worker add 1"` here in low-memory
# mode, which runs the same code as gunicorn's SIGTTIN handler; the deploy user cannot signal the roxy user's
# processes, and the sudo rules allow no extra command for it (plan 9.14).
control_socket = str(Path(_internal_socket).parent / "gunicorn.ctl")

# Owner and group may use the control socket, nobody else (gunicorn's default 0600 would shut out the deploy).
control_socket_mode = 0o660

# Workers prove they are alive by touching a temporary file. /dev/shm is memory, so a slow disk can never make a
# healthy worker look frozen; fall back to gunicorn's default (the private /tmp) where it does not exist.
worker_tmp_dir = memory_tmp_dir()


# ------------------------------------------------------------------------------------------------ hooks

BIND_CHECK_ATTEMPTS = 5
"""How often `on_starting` tries a taken port, one second apart, before giving up (gunicorn's own bind retries)."""


def tcp_addresses(server: Any) -> list[tuple[str, int]]:
    """The TCP addresses of `bind` as gunicorn parsed them (Unix and file descriptor entries are skipped)."""
    found: list[tuple[str, int]] = []
    for address in server.cfg.address:
        if isinstance(address, tuple) and len(address) >= 2:
            found.append((str(address[0]), int(address[1])))
    return found


def port_problem(host: str, port: int, *, shared: bool) -> OSError | None:
    """Try to bind `host:port` on a throwaway socket; the error, or None when the bind worked (nothing listens).

    SO_REUSEADDR is set, as gunicorn sets it, so connections of an earlier run still in TIME_WAIT never count as
    "in use". `shared=False` leaves SO_REUSEPORT off: every listener on the port then refuses the bind, the
    SO_REUSEPORT listeners of another master included (Linux allows a shared port only when every socket asks
    for it). `shared=True` sets it: our own workers' listeners are accepted, a foreign listener still refuses.
    The socket never listens and is closed at once, so it can never take a connection.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    probe = socket.socket(family, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if shared and hasattr(socket, "SO_REUSEPORT"):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        probe.bind((host, port))
    except OSError as exc:
        return exc
    finally:
        probe.close()
    return None


def check_ports_free(server: Any, *, attempts: int = BIND_CHECK_ATTEMPTS, delay_s: float = 1.0) -> None:
    """Exit with status 1 when another listener holds a TCP address of `bind` (see the module docstring).

    Runs in the master before any worker exists and before gunicorn tells systemd READY, so the unit fails, the
    deploy or roxy-boot sees it, and the OnFailure alert fires, as gunicorn behaves without `reuse_port`.
    """
    for host, port in tcp_addresses(server):
        for attempt in range(max(1, attempts)):
            problem = port_problem(host, port, shared=False)
            if problem is None:
                break
            if problem.errno == errno.EADDRINUSE and attempt + 1 < attempts:
                time.sleep(delay_s)  # a master of this color that is still stopping may hold it for a moment
                continue
            server.log.error(
                "Connection in use: %s:%d is already served by another listener (%s); refusing to share it. "
                "Check ROXY_BIND in /etc/roxy/%s.env and that no other master of this port runs.",
                host,
                port,
                problem.strerror or problem,
                _color,
            )
            sys.exit(1)


def internal_listener(server: Any) -> Any:
    """gunicorn's own Unix socket listener for `INTERNAL_SOCKET`, created with `umask` (mode 0660).

    gunicorn's socket helper sets SO_REUSEPORT whenever the config says `reuse_port`, which a Unix socket refuses,
    so it gets a settings object of its own that says no.
    """
    from types import SimpleNamespace

    from gunicorn import sock

    settings = SimpleNamespace(
        umask=umask, uid=server.cfg.uid, gid=server.cfg.gid, backlog=server.cfg.backlog, reuse_port=False
    )
    return sock.UnixSocket(INTERNAL_SOCKET, settings, server.log)


def on_starting(server: Any) -> None:
    """Refuse a taken TCP port, then create the internal Unix socket once, in the master, before any worker exists.

    The port check is skipped for a master re-executed by USR2 (`master_pid` set), whose parent legitimately still
    serves the port. gunicorn keeps the Unix socket in its listener list (logged as "Listening at", closed when the
    master stops) and, because the list is not empty, creates no other master listener; with `reuse_port` the
    workers open the TCP listener.
    """
    if not getattr(server, "master_pid", 0):
        check_ports_free(server)
    server.LISTENERS = [internal_listener(server)]


def pre_fork(server: Any, worker: Any) -> None:
    """Before each new worker: stop the master if a foreign listener took the TCP port meanwhile.

    The worker would fail to bind, exit 1 and be started again, forever, behind a master systemd believes is fine
    (finding mp-3). The check sets SO_REUSEPORT, so this master's own workers' listeners never trip it.
    """
    from gunicorn.errors import HaltServer

    for host, port in tcp_addresses(server):
        problem = port_problem(host, port, shared=True)
        if problem is not None:
            server.log.error("Cannot start a worker: %s:%d is not usable (%s)", host, port, problem.strerror or problem)
            raise HaltServer(f"{host}:{port} is held by another listener", 1)


def post_fork(server: Any, worker: Any) -> None:
    """Give each new worker the master's internal Unix socket next to its own TCP listener."""
    for listener in server.LISTENERS:
        if listener not in worker.sockets:
            worker.sockets.append(listener)


def on_exit(server: Any) -> None:
    """Remove the internal socket file (gunicorn leaves Unix socket files in place when `reuse_port` is on)."""
    path = Path(INTERNAL_SOCKET)
    try:
        if path.is_socket():
            path.unlink()
    except OSError as exc:
        _warn(f"could not remove {path}: {exc}")


def when_ready(server: Any) -> None:
    """Log the effective settings once the master listens, so the journal shows which mode this start used."""
    mode = "low-memory" if workers < _full_workers else "normal"
    server.log.info(
        "roxy master ready: color=%s workers=%d of %d (%s mode) bind=%s",
        _color,
        workers,
        _full_workers,
        mode,
        ",".join([*bind, f"unix:{INTERNAL_SOCKET}"]),
    )
