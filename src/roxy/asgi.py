"""The ASGI entry point gunicorn loads: `gunicorn -c deploy/gunicorn.conf.py roxy.asgi:app`.

What this is
    One line of real code: `app = create_asgi_app()`, the public FastAPI app (from `create_app()`) behind the
    listener dispatcher that serves the internal endpoints on the Unix socket only (plan 5.8).

Why it exists
    gunicorn needs a module-level object to import. Keeping it in its own module means importing `roxy.main` (as
    tests do) never builds an app from the real environment by accident; only the server imports this file.
    `create_app()` itself still returns the plain public FastAPI app, which is what tests use.

How it works
    `EnvSettings()` reads `/etc/roxy/roxy.env` and `/etc/roxy/<color>.env` values from the environment that
    systemd prepared. Each gunicorn worker imports this module after forking (`preload_app = False`), so every
    worker builds its own app, clients and event loop.

What to read next
    `roxy/main.py`, then `roxy/worker.py` (the worker class) and `roxy/internal_app.py`.
"""

from __future__ import annotations

from roxy.main import create_asgi_app

app = create_asgi_app()
