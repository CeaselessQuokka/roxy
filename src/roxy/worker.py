"""The gunicorn worker class: uvicorn with proxy header rewriting, the Server header and the access log turned off.

What this is
    `RoxyUvicornWorker`, a small subclass of `uvicorn_worker.UvicornWorker` named in `deploy/gunicorn.conf.py`
    (`worker_class = "roxy.worker.RoxyUvicornWorker"`).

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

How it works
    `UvicornWorker.__init__` builds uvicorn's `Config` from gunicorn's settings and then applies `CONFIG_KWARGS`
    on top, so these values win over anything gunicorn would pass (including gunicorn's own `keepalive`).
    `_serve` wraps the base class's: when it exits with the boot error status and the lifespan recorded a
    transient failure, the status becomes `TRANSIENT_BOOT_EXIT_CODE`.

What to read next
    `deploy/gunicorn.conf.py`, `roxy/lifespan.py` (`StartupUnavailable`), then `roxy/asgi.py`.
"""

from __future__ import annotations

from typing import Any

from gunicorn.arbiter import Arbiter
from uvicorn_worker import UvicornWorker

from roxy import lifespan

TRANSIENT_BOOT_EXIT_CODE = 1
"""Exit status for a startup that failed only on unavailable shared state: gunicorn restarts the worker."""


def boot_exit_code(code: object) -> object:
    """The exit status to use instead of `code`: the boot error becomes 1 when the failure was transient."""
    if code == Arbiter.WORKER_BOOT_ERROR and lifespan.transient_startup_failure():
        return TRANSIENT_BOOT_EXIT_CODE
    return code


# uvicorn-worker ships no type information, so mypy sees its class as Any; subclassing it is still what we want.
class RoxyUvicornWorker(UvicornWorker):  # type: ignore[misc]
    """UvicornWorker with Roxy's fixed uvicorn options (plan 5.2) and the transient boot exit status."""

    CONFIG_KWARGS: dict[str, Any] = {
        **UvicornWorker.CONFIG_KWARGS,  # keep the base class choices (loop and http "auto": uvloop, httptools)
        "proxy_headers": False,
        "server_header": False,
        "date_header": True,
        "timeout_keep_alive": 75,
        "lifespan": "on",
        "access_log": False,
    }

    async def _serve(self) -> None:
        try:
            await super()._serve()
        except SystemExit as exc:
            code = boot_exit_code(exc.code)
            if code is exc.code:
                raise
            raise SystemExit(code) from None
