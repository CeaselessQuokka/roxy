"""The admin surface: everything under `/admin`, the dashboard pages and the JSON API behind them.

What this is
    The package behind `/admin` (plan 14 and 9.5). `router.py` is the one router `roxy/main.py` includes for the
    whole surface; `auth/` decides who may use it (login, second factors, sessions, CSRF, the kill switch), and
    `gallery.py` is the development-only component gallery of the design system.

Why it exists
    v1 mixed the admin routes into the same module as the proxy and the public pages. Keeping the admin surface in
    one package with one entry router makes two rules easy to check: every `/admin` route is included before the
    proxy catch-all (which never matches `/admin` anyway), and every state-changing admin route sits behind
    `require_admin` and `require_csrf` (the security tests discover them from this router).

How it works
    `router.py` includes the sub-routers in a fixed order. The dashboard pages and the admin API (later phases)
    add their routers there; each guards its own routes with the dependencies from `auth/deps.py`.

What to read next
    `roxy/admin/router.py`, then `roxy/admin/auth/__init__.py` (the login flow) and `roxy/admin/auth/deps.py`.
"""
