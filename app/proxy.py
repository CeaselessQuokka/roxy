"""Upstream request handling.

A proxied request (without a user-supplied token) is served by ONE of three
methods, chosen by weighted random among those currently available, then falling
down the chain if the chosen one fails:

  - "roproxy": games.roproxy.com (RoProxy's IPs). Cooldown-limited globally.
  - "token":   games.roblox.com with our .ROBLOSECURITY (our STATIC IP).
               Hard global request budget so we never look like a bot burst.
  - "rotate":  games.roblox.com via the rotating proxy (DataImpulse exit IPs),
               with a random realistic User-Agent.

The selection + budget + cooldowns are coordinated across all gunicorn workers by
routing.py (a shared, flock-guarded file), so 4 workers can't collectively burst
Roblox/RoProxy from our static IP.

A request that supplies its OWN X-Roblox-Token is sent straight to roblox.com with
that cookie — never through RoProxy or the rotating proxy, so the caller's secret
is never exposed to a third party.
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
from threading import Lock

# Token list is loaded from the token file and reloaded across workers when the
# file changes (so a dashboard token update reaches every worker).
_tokens_lock = Lock()
tokens = auth.read_tokens()
_tokens_mtime = auth.tokens_mtime()

email_last_sent = 0
error_email_last_sent = 0
all_throttled_email_last_sent = 0

# Per single proxied request: each method may be tried once, plus a CSRF retry
# inside a method. This bounds the work for one request across the whole chain.
MAX_METHOD_ATTEMPTS = 6

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
    global error_email_last_sent
    cooldown = runtime.get_setting("error_email_cooldown", config.ERROR_EMAIL_COOLDOWN)
    if time.time() - error_email_last_sent < cooldown:
        return
    error_email_last_sent = time.time()
    mail.try_send(auth.get_emails()[0], f"Roxy Error: {subject}", body)


def _notify_all_throttled(url: str):
    """Email when EVERY upstream method is unavailable, rate-limited separately."""
    global all_throttled_email_last_sent
    cooldown = runtime.get_setting("error_email_cooldown", config.ERROR_EMAIL_COOLDOWN)
    diagnostics.log_error("All upstream methods unavailable", f"No method could serve: https://{url}")
    if time.time() - all_throttled_email_last_sent < cooldown:
        return
    all_throttled_email_last_sent = time.time()
    mail.try_send(
        auth.get_emails()[0],
        "Roxy: all upstream methods unavailable",
        "Every request method (RoProxy, Token, Rotate) was throttled/unavailable for:\n"
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
    url: str, method: str = "get", headers: dict = None, params: dict = None, data: str = None, roblox_token: str = None
) -> tuple[bool, str]:
    headers = headers if headers is not None else {}
    _maybe_reload_tokens()

    # A caller's own token: go straight to roblox.com with their cookie. Never via
    # RoProxy/Rotate — their .ROBLOSECURITY must not pass through a third party.
    if roblox_token is not None:
        ok, _again, response = _attempt(
            "user", f"https://{url}", method, headers, params, data, cookies={".ROBLOSECURITY": roblox_token}
        )
        return ok, response if response is not None else "Upstream request failed; please try again later."

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
    if choice == "roproxy":
        return _attempt("roproxy", f"https://{url.replace('roblox.com', 'roproxy.com')}", method, headers, params, data)
    if choice == "token":
        token = _first_token()
        if not token:
            return (False, True, None)  # token vanished between choose() and now
        return _attempt(
            "token", f"https://{url}", method, headers, params, data, cookies={".ROBLOSECURITY": token}, token=token
        )
    if choice == "rotate":
        return _attempt(
            "rotate", f"https://{url}", method, _rotate_headers(headers), params, data, proxies=rotate.proxies()
        )
    return (False, True, None)


def _attempt(choice, full_url, method, headers, params, data, cookies=None, proxies=None, token=None):
    """One HTTP attempt to the upstream, with a single CSRF (403) handshake retry.

    Returns (ok, fallback, response). `choice` is the method name for stats
    ("user" for caller-token requests, which aren't part of the routed methods).
    """
    is_routed = choice in ("roproxy", "token", "rotate")
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
            if is_routed:
                diagnostics.log_method_timeout(choice)
            if choice == "rotate":
                routing.record_rotate_result(False)
                diagnostics.log_rotate_health(False, "timeout")
            return (False, True, None)  # transient → fall through to next method
        except requests.RequestException as e:
            diagnostics.log_request(method.upper(), False)
            diagnostics.log_reason(True)
            if choice == "rotate":
                # Proxy/connection error talking to DataImpulse — count + fall back.
                routing.record_rotate_result(False)
                diagnostics.log_rotate_health(False, f"{type(e).__name__}: {e}")
                diagnostics.log_method(choice, False)
                return (False, True, None)
            if is_routed:
                diagnostics.log_method(choice, False)
                return (False, True, None)  # roproxy/token connection error → fall back
            # User-token request couldn't reach Roblox: report and give up.
            notify_error("Upstream request failed", f"{method.upper()} {full_url}\n\n{type(e).__name__}: {e}")
            return (False, False, "Upstream request failed; please try again later.")

        # Got an HTTP response.
        if choice == "rotate":
            routing.record_rotate_result(True)  # the proxy itself worked
            diagnostics.log_rotate_health(True)
        if token is not None:
            diagnostics.update_token(token, used=True)
        if is_routed:
            diagnostics.log_method(choice, req.status_code == 200)
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
        if req.status_code == 429:
            # Rate-limited. For the token, drop it for revalidation. Either way,
            # fall through and let another method try (no user-facing retry storm).
            diagnostics.log_reason(False)
            if token is not None:
                _drop_token(token)
            if choice == "user":
                return (False, False, req.text)  # caller's own token is throttled; report it
            return (False, True, req.text)
        if 500 <= req.status_code < 600:
            diagnostics.log_reason(False)
            return (False, True, req.text)  # transient upstream error → try another method
        # Other 4xx (403 without CSRF, 404, 400…): a real answer from Roblox.
        diagnostics.log_reason(False)
        return (False, False, req.text)

    return (False, True, None)  # CSRF retry exhausted


# --- Token validation / management ------------------------------------------
def validate_token(token: str):
    """Re-check a token against Roblox; re-add if valid, drop + email if expired."""
    global tokens, email_last_sent
    diagnostics.record_token_budget_usage(routing.record_token_use())  # counts toward budget + peak
    try:
        req = requests.get(
            "https://accountinformation.roblox.com/v1/birthdate",
            cookies={".ROBLOSECURITY": token},
            timeout=_timeout(),
        )
    except requests.RequestException:
        diagnostics.update_token(token, being_validated=True)
        background.schedule(
            runtime.get_setting("token_expiration_cooldown", config.TOKEN_EXPIRATION_COOLDOWN), validate_token, token
        )
        return
    should_email = False
    with _tokens_lock:
        if req.status_code == 200:
            if token not in tokens:
                tokens.append(token)
                diagnostics.update_token(token)
        else:
            diagnostics.remove_token(token, expired=True)
            should_email = time.time() - email_last_sent > runtime.get_setting("email_cooldown", config.EMAIL_COOLDOWN)
            if should_email:
                email_last_sent = time.time()
    if should_email:
        mail.try_send(
            auth.get_emails()[0],
            "Token Expired",
            f'An auth token has expired: "{token[-3:]}".\nhttps://roxytheproxy.com/admin',
        )


def update_tokens(new_tokens: list[str]):
    global tokens
    with _tokens_lock:
        for t in new_tokens:
            if t not in tokens:
                tokens.append(t)
                diagnostics.update_token(t)


def set_tokens(new_tokens: list[str]) -> list[str]:
    """Replace the active token set. Writes through to the token file so ALL
    gunicorn workers pick it up (they reload on file change)."""
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
    auth.write_tokens(cleaned)  # propagate to other workers via the file
    _tokens_mtime = auth.tokens_mtime()
    return list(cleaned)


def _revalidate_one(token: str):
    global tokens
    diagnostics.record_token_budget_usage(routing.record_token_use())
    try:
        req = requests.get(
            "https://accountinformation.roblox.com/v1/birthdate",
            cookies={".ROBLOSECURITY": token},
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


def force_revalidate_tokens():
    """Re-check every known token, and clear the routing cooldowns so traffic can
    flow again immediately."""
    routing.reset()
    with _tokens_lock:
        snapshot = list(tokens)
    for t in snapshot:
        background.schedule(0, _revalidate_one, t)
