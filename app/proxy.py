"""Upstream request handling.

Every proxied request is served by ONE of two methods, chosen by weighted random
among those currently available, then falling down the chain if the chosen one
fails:

  - "token":  games.roblox.com with our .ROBLOSECURITY (our STATIC IP).
              Hard global request budget so we never look like a bot burst.
  - "rotate": games.roblox.com via the rotating proxy (DataImpulse exit IPs),
              with a random realistic User-Agent.

The selection + budget are coordinated across all gunicorn workers by routing.py
(a shared, flock-guarded file), so 4 workers can't collectively burst Roblox from
our static IP.

Roxy does not support authenticated requests: a caller is never allowed to supply
their own Roblox session token, and index.py rejects any request that tries
before it ever reaches this module — see index._detect_auth_attempt.
"""

import auth
import background
import config
import diagnostics
import mail
import requests
import rotate
import routing
import runtime
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

from lockfile import LockedJSON

# Tokens are sent as a DOMAIN-SCOPED cookie jar, never a bare {name: value}
# dict. A dict becomes a cookie with no domain, which `requests` will replay to
# whatever host a redirect points at -- so a single open redirect anywhere on
# roblox.com would hand our account cookie to a third party. Scoping it to
# .roblox.com makes the cookie jar itself refuse to send it off-domain, which
# keeps redirect-following intact without the exposure.
TOKEN_COOKIE_DOMAIN = ".roblox.com"


def _token_jar(token: str):
    jar = requests.cookies.RequestsCookieJar()
    jar.set(".ROBLOSECURITY", token, domain=TOKEN_COOKIE_DOMAIN, path="/")
    return jar


def mask_token(token: str) -> str:
    """A short, non-reversible label for a token. Deliberately brief: this is
    rendered on the dashboard and lands in CSV/JSON exports, so it must not be
    enough of a live credential to matter if one leaks."""
    return f"…{(token or '')[-6:]}"


# Token list is loaded from the token file and reloaded across workers when the
# file changes (so a dashboard token update reaches every worker).
_tokens_lock = Lock()
tokens = auth.read_tokens()
_tokens_mtime = auth.tokens_mtime()

# Email send de-duplication, SHARED across workers: without this, 4 workers all
# hitting the same error would each send the "rate-limited" alert, so the admin
# gets 4x the email. The shared coordination file keeps one last-sent timestamp
# per alert key, so a cooldown applies fleet-wide, not per worker.
_coord = LockedJSON(lambda: config.COORD_FILE)


def _email_allowed(key: str, cooldown: float) -> bool:
    """True if no worker has sent the `key` alert within `cooldown` seconds; if so,
    atomically reserves the slot (records 'now') so only one worker sends."""
    now = time.time()

    def mutate(data):
        gates = data.setdefault("EmailGate", {})
        last = float(gates.get(key, 0) or 0)
        if now - last < cooldown:
            return False
        gates[key] = now
        return True

    return _coord.update(mutate)


# Per single proxied request: each method may be tried once, plus a CSRF retry
# inside a method. This bounds the work for one request across the whole chain.
MAX_METHOD_ATTEMPTS = 3

# Bounds on the admin health check, so it can never outlive a worker timeout.
MAX_TOKEN_CHECK_WORKERS = 8
TOKEN_CHECK_GRACE = 5  # Seconds allowed on top of request_timeout per probe.

for t in tokens:
    diagnostics.update_token(t)


# --- Token list (cross-worker, file-backed) ---------------------------------
def _maybe_reload_tokens():
    """Pull the latest token set from the file if another worker changed it."""
    global tokens, _tokens_mtime
    mtime = auth.tokens_mtime()
    if mtime == _tokens_mtime:
        return
    with _tokens_lock:
        if mtime == _tokens_mtime:
            return
        try:
            fresh = [t for t in (line.strip() for line in auth.read_tokens()) if t]
        except OSError:
            return
        tokens = fresh
        _tokens_mtime = mtime
        diagnostics.clear_tokens()
        for t in tokens:
            diagnostics.update_token(t)


def _first_token() -> str | None:
    with _tokens_lock:
        return tokens[0] if tokens else None


def _drop_token(token: str):
    """Remove a token (throttled/expired) and queue a revalidation."""
    global tokens
    with _tokens_lock:
        if token in tokens:
            tokens.remove(token)
    diagnostics.update_token(token, being_validated=True)
    background.schedule(
        runtime.get_setting("token_expiration_cooldown", config.TOKEN_EXPIRATION_COOLDOWN), validate_token, token
    )


def has_tokens() -> bool:
    _maybe_reload_tokens()
    with _tokens_lock:
        return bool(tokens)


def notify_error(subject: str, body: str):
    """Record a runtime error and email the admin (email rate-limited; log always)."""
    diagnostics.log_error(subject, body)
    cooldown = runtime.get_setting("error_email_cooldown", config.ERROR_EMAIL_COOLDOWN)
    if not _email_allowed("error_email", cooldown):
        return
    mail.try_send(auth.get_emails()[0], f"Roxy Error: {subject}", body)


def _notify_all_throttled(url: str):
    """Email when EVERY upstream method is unavailable, rate-limited separately."""
    cooldown = runtime.get_setting("error_email_cooldown", config.ERROR_EMAIL_COOLDOWN)
    diagnostics.log_error("All upstream methods unavailable", f"No method could serve: https://{url}")
    if not _email_allowed("all_throttled_email", cooldown):
        return
    mail.try_send(
        auth.get_emails()[0],
        "Roxy: all upstream methods unavailable",
        "Every request method (Token, Rotate) was throttled/unavailable for:\n"
        f"https://{url}\n\nCheck token validity, the rotation proxy, and cooldowns on the dashboard.",
    )


def _timeout() -> int:
    return runtime.get_setting("request_timeout", config.REQUEST_TIMEOUT)


def _rotate_headers(headers: dict) -> dict:
    """Headers for a rotated request: random realistic UA, no Chrome-only client
    hints (which would mismatch a non-Chrome UA), nothing identifying us."""
    out = dict(headers)
    out["User-Agent"] = rotate.random_user_agent()
    for hint in ("Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform"):
        out.pop(hint, None)
    return out


# --- The public entry point --------------------------------------------------
# Returns (successful, response).
def request(
    url: str, method: str = "get", headers: dict = None, params: dict = None, data: str = None
) -> tuple[bool, str]:
    headers = headers if headers is not None else {}
    _maybe_reload_tokens()

    tried: set = set()
    last_response = None
    for _ in range(MAX_METHOD_ATTEMPTS):
        choice, _token_used = routing.choose(tried, has_tokens(), rotate.is_enabled())
        if choice is None:
            if not tried:
                # Nothing was ever available → everything is throttled/unconfigured.
                _notify_all_throttled(url)
                return False, "All request methods are busy right now; please try again shortly."
            return False, last_response or "All request methods are busy right now; please try again shortly."

        if choice == "token":
            diagnostics.record_token_budget_usage(_token_used)  # feeds the 1h/24h peak
        ok, again, response = _do_method(choice, url, method, headers, params, data)
        if ok:
            return True, response
        tried.add(choice)
        if response is not None:
            last_response = response
        if not again:
            # A definitive answer from Roblox (404/403/400…) — same on any method.
            return False, response if response is not None else "Upstream request failed; please try again later."

    return False, last_response or "All request methods are busy right now; please try again shortly."


def _do_method(choice: str, url: str, method: str, headers: dict, params: dict, data):
    """Run one method (with its internal CSRF retry). Returns (ok, fallback, response)
    where fallback=True means 'this method couldn't serve — try the next one'."""
    if choice == "token":
        token = _first_token()
        if not token:
            return (False, True, None)  # token vanished between choose() and now
        return _attempt(
            "token", f"https://{url}", method, headers, params, data, cookies=_token_jar(token), token=token
        )
    if choice == "rotate":
        return _attempt(
            "rotate", f"https://{url}", method, _rotate_headers(headers), params, data, proxies=rotate.proxies()
        )
    return (False, True, None)


def _endpoint_of(full_url: str) -> str:
    """A clean endpoint label (no scheme/query) for failure diagnostics."""
    return full_url.split("://", 1)[-1].split("?", 1)[0]


def _failure_reason(status: int) -> str:
    if status == 429:
        return "Rate limited (429)"
    if 500 <= status < 600:
        return f"Upstream error ({status})"
    if status == 403:
        return "Forbidden (403)"
    if status == 404:
        return "Not found (404)"
    if 400 <= status < 500:
        return f"Client error ({status})"
    return f"HTTP {status}"


def _attempt(choice, full_url, method, headers, params, data, cookies=None, proxies=None, token=None):
    """One HTTP attempt to the upstream, with a single CSRF (403) handshake retry.

    Returns (ok, fallback, response). Every non-success outcome is recorded to the
    per-requester failure log so the admin can see exactly WHY a given requester
    (token/rotate) is being rejected.
    """
    endpoint = _endpoint_of(full_url)
    csrf = None
    headers = dict(headers)
    for _ in range(2):  # original attempt + at most one CSRF retry
        if csrf is not None:
            headers["x-csrf-token"] = csrf
        try:
            req = requests.request(
                method,
                full_url,
                headers=headers,
                params=params,
                data=data,
                cookies=cookies,
                proxies=proxies,
                timeout=_timeout(),
            )
        except requests.Timeout:
            diagnostics.log_request(method.upper(), False)
            diagnostics.log_reason(True)
            diagnostics.log_request_failure(choice, "timeout", "Upstream timed out", endpoint)
            diagnostics.log_method_timeout(choice)
            # A timeout is an attempt this method made and lost, so it counts
            # toward the method's Requests/Failed exactly like a connection
            # error does. Omitting it made those two numbers freeze during an
            # upstream outage -- precisely when they are being watched.
            diagnostics.log_method(choice, False)
            if token is not None:
                diagnostics.update_token(token, used=True)  # keep Uses in sync with method Requests
            if choice == "rotate":
                routing.record_rotate_result(False)
                diagnostics.log_rotate_health(False, "timeout")
            return (False, True, None)  # transient → fall through to next method
        except requests.RequestException as e:
            diagnostics.log_request(method.upper(), False)
            diagnostics.log_reason(True)
            diagnostics.log_request_failure(choice, "error", type(e).__name__, endpoint, f"{type(e).__name__}: {e}")
            if choice == "rotate":
                # Proxy/connection error talking to DataImpulse — count + fall back.
                routing.record_rotate_result(False)
                diagnostics.log_rotate_health(False, f"{type(e).__name__}: {e}")
            if token is not None:
                diagnostics.update_token(token, used=True)  # keep Uses in sync with method Requests
            diagnostics.log_method(choice, False)
            return (False, True, None)  # connection error → fall back to the other method

        # Got an HTTP response.
        if choice == "rotate":
            routing.record_rotate_result(True)  # the proxy itself worked
            diagnostics.log_rotate_health(True)
        if token is not None:
            diagnostics.update_token(token, used=True)
        diagnostics.log_method(choice, req.status_code == 200)
        diagnostics.log_method_timing(choice, req.elapsed.total_seconds())
        diagnostics.log_status_code(req.status_code)
        diagnostics.log_request(method.upper(), req.status_code == 200)
        diagnostics.log_proxy_request(method.upper(), req.elapsed.total_seconds())

        if req.status_code == 200:
            return (True, False, req.text)
        if req.status_code == 403 and "x-csrf-token" in req.headers and csrf is None:
            # Roblox handing us a CSRF token to retry with (required for writes).
            diagnostics.log_retry(403, "CSRF token refresh")
            csrf = req.headers.get("x-csrf-token")
            continue
        # Any non-200: record the reason so the admin can diagnose this requester.
        diagnostics.log_request_failure(choice, req.status_code, _failure_reason(req.status_code), endpoint, req.text)
        if req.status_code == 429:
            # Rate-limited. For the token, drop it for revalidation. Either way,
            # fall through and let the other method try (no user-facing retry storm).
            diagnostics.log_reason(False)
            if token is not None:
                _drop_token(token)
            return (False, True, req.text)
        if 500 <= req.status_code < 600:
            diagnostics.log_reason(False)
            return (False, True, req.text)  # transient upstream error → try the other method
        # Other 4xx (403 without CSRF, 404, 400…): a real answer from Roblox.
        diagnostics.log_reason(False)
        return (False, False, req.text)

    return (False, True, None)  # CSRF retry exhausted


# --- Token validation / management ------------------------------------------
def validate_token(token: str):
    """Re-check a token against Roblox; re-add if valid, drop + email if expired."""
    global tokens
    diagnostics.record_token_budget_usage(routing.record_token_use())  # counts toward budget + peak
    try:
        req = requests.get(
            "https://accountinformation.roblox.com/v1/birthdate",
            cookies=_token_jar(token),
            timeout=_timeout(),
        )
    except requests.RequestException:
        diagnostics.update_token(token, being_validated=True)
        background.schedule(
            runtime.get_setting("token_expiration_cooldown", config.TOKEN_EXPIRATION_COOLDOWN), validate_token, token
        )
        return
    expired = False
    with _tokens_lock:
        if req.status_code == 200:
            if token not in tokens:
                tokens.append(token)
                diagnostics.update_token(token)
        else:
            diagnostics.remove_token(token, expired=True)
            expired = True
    # Email gate is shared across workers (so only one worker emails per cooldown);
    # done outside the tokens lock so the flock'd file I/O doesn't hold it.
    if expired and _email_allowed("token_expired_email", runtime.get_setting("email_cooldown", config.EMAIL_COOLDOWN)):
        mail.try_send(
            auth.get_emails()[0],
            "Token Expired",
            f'An auth token has expired: "{mask_token(token)}".\nhttps://roxytheproxy.com/admin',
        )


def update_tokens(new_tokens: list[str]):
    global tokens
    with _tokens_lock:
        for t in new_tokens:
            if t not in tokens:
                tokens.append(t)
                diagnostics.update_token(t)


def set_tokens(new_tokens: list[str]) -> tuple[list[str], bool]:
    """Replace the active token set. Writes through to the token file so ALL
    gunicorn workers pick it up (they reload on file change) -- which is why the
    write is unconditional rather than opt-in.

    Returns (cleaned tokens, whether the file write succeeded)."""
    global tokens, _tokens_mtime
    cleaned = []
    for t in new_tokens:
        t = (t or "").strip()
        if t and t not in cleaned:
            cleaned.append(t)
    with _tokens_lock:
        tokens = cleaned
        diagnostics.clear_tokens()
        for t in tokens:
            diagnostics.update_token(t)
    persisted = auth.write_tokens(cleaned)  # propagate to other workers via the file
    _tokens_mtime = auth.tokens_mtime()
    return list(cleaned), persisted


def _revalidate_one(token: str):
    global tokens
    diagnostics.record_token_budget_usage(routing.record_token_use())
    try:
        req = requests.get(
            "https://accountinformation.roblox.com/v1/birthdate",
            cookies=_token_jar(token),
            timeout=_timeout(),
        )
    except requests.RequestException:
        return
    with _tokens_lock:
        if req.status_code == 200:
            diagnostics.update_token(token)
        else:
            if token in tokens:
                tokens.remove(token)
            diagnostics.remove_token(token, expired=True)


def _check_one_token(token: str) -> dict:
    """Probe one token against Roblox and reconcile the inventory. Never raises."""
    masked = mask_token(token)
    diagnostics.record_token_budget_usage(routing.record_token_use())
    try:
        req = requests.get(
            "https://accountinformation.roblox.com/v1/birthdate",
            cookies=_token_jar(token),
            timeout=_timeout(),
        )
    except requests.RequestException as e:
        return {"Masked": masked, "Active": None, "Error": type(e).__name__}
    active = req.status_code == 200
    with _tokens_lock:
        if active:
            if token not in tokens:
                tokens.append(token)
            diagnostics.update_token(token)
        else:
            if token in tokens:
                tokens.remove(token)
            diagnostics.remove_token(token, expired=True)
    return {"Masked": masked, "Active": active, "Error": "" if active else f"HTTP {req.status_code}"}


def check_tokens() -> list[dict]:
    """Verify each current token against Roblox and return a report
    [{Masked, Active, Error}]. Updates the inventory (drops expired, re-adds valid).

    Probes run in parallel behind a whole-call deadline. Run serially, N tokens
    against a slow upstream took N x request_timeout seconds inside a single
    admin request, which outlives gunicorn's worker timeout and gets the worker
    killed part-way through the check.

    Counts toward the token's request budget (it IS a request to Roblox) but NOT
    toward the per-requester Token stats, which track user-serving traffic only."""
    _maybe_reload_tokens()
    with _tokens_lock:
        snapshot = list(tokens)
    if not snapshot:
        return []
    deadline = _timeout() + TOKEN_CHECK_GRACE
    with ThreadPoolExecutor(max_workers=min(len(snapshot), MAX_TOKEN_CHECK_WORKERS)) as pool:
        pending = [(token, pool.submit(_check_one_token, token)) for token in snapshot]
        report = []
        for token, future in pending:
            try:
                report.append(future.result(timeout=deadline))
            except Exception as e:
                report.append({"Masked": mask_token(token), "Active": None, "Error": type(e).__name__})
    return report


def probe_rotation() -> dict:
    """Verify rotation by fetching our exit IP through the proxy; logs it on success.
    Returns the rotation status + the observed exit IP (or the error)."""
    ip, error = rotate.probe_exit_ip()
    if ip:
        diagnostics.log_rotate_ip(ip, "probe")
    return {
        "Configured": rotate.is_configured(),
        "Enabled": rotate.is_enabled(),
        "ExitIP": ip,
        "Error": error,
    }


def force_revalidate_tokens() -> list[dict]:
    """Re-check every known token, clear the routing cooldowns so traffic can flow
    again immediately, and return a report of which tokens are still active."""
    routing.reset()
    return check_tokens()
