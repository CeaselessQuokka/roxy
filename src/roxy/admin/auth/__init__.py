"""Admin authentication: passwords, second factors, sessions, CSRF, lockouts and the emailed kill switch.

What this is
    The package that decides who may use `/admin`. A login is two steps: the password step
    (`POST /admin/api/v1/auth/login`) opens a short server-side login transaction bound to the caller's IP and
    User-Agent, and the second factor step (`POST /admin/api/v1/auth/mfa`) finishes it with an authenticator
    code (TOTP), a passkey, a recovery code or, only when allowed, an emailed code. A finished login gets a
    server-side session; every state-changing admin request then needs that session plus a CSRF token.

Why it exists
    v1 kept the whole session in a signed cookie (readable by the client, impossible to revoke one by one), used
    an emailed code as the only second factor, counted lockouts per worker process, and had no CSRF token at all
    (plan 9.5, 9.6; parity rows 94 to 101). v2 stores sessions server side (only a SHA-256 of the cookie value),
    makes the authenticator app mandatory (owner decision D5), counts lockouts atomically in hot.db for every
    worker at once (plan C6), and adds real CSRF protection that also resists the BREACH compression attack.

How it works
    Module map, in the order a login touches them:
      `allowlist.py`        optional admin network allowlist (D6): a plain 404 for everyone else
      `lockout.py`          per (username, network) failure counting and the global slow-down guard (hot.db)
      `passwords.py`        argon2id hashing in a thread pool with its own capacity limiter
      `transactions.py`     short-lived server-side records in hot.db (login transactions, TOTP replay guard)
      `flow.py`             the login state machine (`AuthService`): password step, second factor, re-auth
      `totp.py`, `recovery_codes.py`, `email_codes.py`, `webauthn.py`   the second factors
      `sessions.py`, `csrf.py`, `trusted_devices.py`, `invalidation.py` what a finished login creates
      `enrollment.py`       first-login TOTP enrollment (D5 bootstrap), recovery code and passkey management
      `users.py`            admin account rows (used by the flow and by `scripts/create_admin.py`)
      `events.py`           audit log rows and security events for every auth event (plan 9.7)
      `deps.py`             `require_admin(scope)` and `require_csrf`, the FastAPI guards (DESIGN.md 11.7)
      `routes.py`           the HTTP endpoints and pages; `responses.py` the v1-shaped JSON answers
      `testing.py`          helpers for tests (fast hasher, test users, a software passkey)

What to read next
    `roxy/admin/auth/flow.py` (the login state machine), then `roxy/admin/auth/deps.py` (how every other admin
    route is protected), then `roxy/notify/notifier.py` (the login alert email with the kill-switch link).
"""
