"""The gunicorn worker class: uvicorn with proxy header rewriting, the Server header and the access log turned off.

What this is
    `RoxyUvicornWorker`, a small subclass of `uvicorn_worker.UvicornWorker` named in `deploy/gunicorn.conf.py`
    (`worker_class = "roxy.worker.RoxyUvicornWorker"`), and `RoxyServer`, uvicorn's `Server` with one hook at the
    start of shutdown.

Why it exists
    Plan 5.2. Some uvicorn options cannot be set from a gunicorn config file, only through the worker's
    `CONFIG_KWARGS`:
    - `proxy_headers=False`: otherwise uvicorn's ProxyHeadersMiddleware rewrites `scope["client"]` from
      `X-Forwarded-For` BEFORE Roxy runs, and `core/client_ip.py` could no longer see that the real peer is
      nginx; trusting the header from a non-proxy peer is exactly the spoofing hole plan 9.11 closes.
    - `server_header=False`: no `Server: uvicorn` header (less fingerprinting, plan 9.3).
    - `date_header=True`: keep the standard Date header.
    - `timeout_keep_alive=75`: idle keep-alive connections must outlive nginx's upstream `keepalive_timeout 60s`,
      otherwise nginx reuses a socket the app has just closed and callers see intermittent 502s (plan 17.2).
    - `lifespan="on"`: a startup failure (for example a database below the required schema) must stop the
      worker, not be mistaken for "this app has no lifespan".
    - `access_log=False`: uvicorn's access line prints the raw path and query and the client address. Roxy's
      own `http_request` log line (core/middleware.py) already records every request with the query redacted,
      secret path segments masked and the client IP hashed when `log_hash_client_ips` is on (plan 9.15); the
      uvicorn line would bypass all three.
    It also changes one exit status. uvicorn-worker exits with gunicorn's "worker failed to boot" status (3) for
    ANY startup failure, and the gunicorn master answers that status by shutting down completely, taking every
    healthy worker of the color with it. That is right for a schema that is too old (a bad deploy must stop),
    but wrong when startup failed only because a shared database was briefly busy (`roxy.lifespan`
    `StartupUnavailable`): then the worker exits with status 1, and the master just starts a new worker.
    And it bounds shutdown. On a stop, reload or recycle gunicorn gives a worker `graceful_timeout` (30 s) and
    then kills it. uvicorn, left alone, waits WITHOUT a limit for every open request before it runs the lifespan
    shutdown, and a tarpit hold lasts up to 55 s: the kill came first, and the final metrics flush and the leader
    lease release never ran (finding SHUTDOWN-HOLD). Two changes fix it: uvicorn's `timeout_graceful_shutdown`
    is set below `graceful_timeout`, and `RoxyServer.shutdown` calls `roxy.lifespan.begin_drain` before uvicorn
    starts waiting, which answers every held refusal at once.

How it works
    `UvicornWorker.__init__` builds uvicorn's `Config` from gunicorn's settings and then applies `CONFIG_KWARGS`
    on top, so these values win over anything gunicorn would pass (including gunicorn's own `keepalive`).
    `timeout_graceful_shutdown` depends on gunicorn's settings, so it is set right after:
    `graceful_shutdown_s(graceful_timeout, timeout)` = the smaller of the two, minus the lifespan's
    `SHUTDOWN_BUDGET_S` (8 s) and `SHUTDOWN_MARGIN_S` (2 s): 20 s with the production 30 and 30. (gunicorn's
    `timeout` matters too: uvicorn stops heartbeating once it begins shutting down, so a reload or recycle that
    waited longer than `timeout` would be killed as a frozen worker.) After that wait uvicorn cancels whatever is
    still running, then runs the lifespan shutdown, which has its own budget.
    `_serve` is uvicorn-worker's, with `RoxyServer` in place of uvicorn's `Server`; when it exits with the boot
    error status and the lifespan recorded a transient failure, the status becomes `TRANSIENT_BOOT_EXIT_CODE`.

What to read next
    `deploy/gunicorn.conf.py`, `roxy/lifespan.py` (`StartupUnavailable`, `begin_drain`, `SHUTDOWN_BUDGET_S`), then
    `roxy/asgi.py`.
"""

from __future__ import annotations

import socket
import sys
from typing import Any

from gunicorn.arbiter import Arbiter
from uvicorn.server import Server
from uvicorn_worker import UvicornWorker

from roxy import lifespan

TRANSIENT_BOOT_EXIT_CODE = 1
"""Exit status for a startup that failed only on unavailable shared state: gunicorn restarts the worker."""

SHUTDOWN_MARGIN_S = 2.0
"""Kept free after the lifespan shutdown budget, for closing sockets and the process exit."""

MIN_GRACEFUL_SHUTDOWN_S = 1.0


def boot_exit_code(code: object) -> object:
    """The exit status to use instead of `code`: the boot error becomes 1 when the failure was transient."""
    if code == Arbiter.WORKER_BOOT_ERROR and lifespan.transient_startup_failure():
        return TRANSIENT_BOOT_EXIT_CODE
    return code


def graceful_shutdown_s(graceful_timeout: float, timeout: float) -> float:
    """uvicorn's `timeout_graceful_shutdown`: how long open requests may finish once shutdown began.

    What is left of gunicorn's `graceful_timeout` (and of its `timeout`, the heartbeat watchdog; 0 disables it)
    after the lifespan shutdown budget and a margin, so the lifespan shutdown always runs before gunicorn's kill.
    """
    limit = float(graceful_timeout)
    if timeout and float(timeout) > 0:
        limit = min(limit, float(timeout))
    return max(MIN_GRACEFUL_SHUTDOWN_S, limit - lifespan.SHUTDOWN_BUDGET_S - SHUTDOWN_MARGIN_S)


class RoxyServer(Server):
    """uvicorn's `Server`, which tells the app that shutdown began before it waits for open requests."""

    async def shutdown(self, sockets: list[socket.socket] | None = None) -> None:
        lifespan.begin_drain(self.config.app)
        await super().shutdown(sockets=sockets)


# uvicorn-worker ships no type information, so mypy sees its class as Any; subclassing it is still what we want.
class RoxyUvicornWorker(UvicornWorker):  # type: ignore[misc]
    """UvicornWorker with Roxy's fixed uvicorn options (plan 5.2), a bounded shutdown and the transient boot exit
    status."""

    CONFIG_KWARGS: dict[str, Any] = {
        **UvicornWorker.CONFIG_KWARGS,  # keep the base class choices (loop and http "auto": uvloop, httptools)
        "proxy_headers": False,
        "server_header": False,
        "date_header": True,
        "timeout_keep_alive": 75,
        "lifespan": "on",
        "access_log": False,
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Below gunicorn's graceful_timeout, so the lifespan shutdown runs before the master's kill (module docstring).
        self.config.timeout_graceful_shutdown = graceful_shutdown_s(self.cfg.graceful_timeout, self.cfg.timeout)

    async def _serve(self) -> None:
        try:
            await self._serve_with_drain()
        except SystemExit as exc:
            code = boot_exit_code(exc.code)
            if code is exc.code:
                raise
            raise SystemExit(code) from None

    async def _serve_with_drain(self) -> None:
        """uvicorn-worker's `_serve`, with `RoxyServer` instead of uvicorn's `Server`."""
        self.config.app = self.wsgi
        server = RoxyServer(config=self.config)
        self._install_sigquit_handler()
        await server.serve(sockets=self.sockets)
        if not server.started:
            sys.exit(Arbiter.WORKER_BOOT_ERROR)
