import auth
import background
import config
import diagnostics
import mail
import requests
import runtime
import time
from collections import deque
from threading import Lock

tokens = auth.read_tokens()
email_last_sent = 0
error_email_last_sent = 0
is_direct_api_in_cooldown = False
is_roproxy_in_cooldown = False
request_lock = Lock()

# Hard cap on attempts for a single proxied request (CSRF refreshes + 429
# retries combined). Without it, an invalid user token can bounce 403s with
# fresh CSRF headers forever and spin a worker on one request.
MAX_REQUEST_ATTEMPTS = 10

# --- Internal token safety budget ---------------------------------------------
# Timestamps of every Roblox request made WITH the internal token (including
# validation pings). The token must never look like a bot burst to Roblox, so
# once the window's budget is spent, requests get a try-later error instead.
_token_uses = deque()

for t in tokens:
    diagnostics.update_token(t)


def _budget_limits() -> tuple[int, int]:
    limit = runtime.get_setting("token_budget_requests", config.TOKEN_BUDGET_REQUESTS)
    window = runtime.get_setting("token_budget_window", config.TOKEN_BUDGET_WINDOW)
    return int(limit), int(window)


def _prune_token_uses_unlocked(window: int, now: float):
    while _token_uses and _token_uses[0] <= now - window:
        _token_uses.popleft()


def _token_budget_has_room_unlocked() -> bool:
    """Whether the internal token may make another request right now. Caller holds request_lock."""
    limit, window = _budget_limits()
    _prune_token_uses_unlocked(window, time.time())
    return len(_token_uses) < limit


def _record_token_use_unlocked() -> int:
    """Append a token use and return the resulting sliding-window usage."""
    _token_uses.append(time.time())
    _prune_token_uses_unlocked(_budget_limits()[1], time.time())
    return len(_token_uses)


def record_token_use():
    """Count a token-authenticated request (e.g. a validation ping) against the budget."""
    with request_lock:
        usage = _record_token_use_unlocked()
    diagnostics.record_token_budget_usage(usage)


def get_token_budget_state() -> dict:
    """Live budget usage for the dashboard."""
    limit, window = _budget_limits()
    now = time.time()
    with request_lock:
        _prune_token_uses_unlocked(window, now)
        used = len(_token_uses)
        oldest = _token_uses[0] if _token_uses else None
    return {
        "Used": used,
        "Limit": limit,
        "Window": window,
        "ResetIn": int(max(0, oldest + window - now)) if oldest else 0,
    }


def notify_error(subject: str, body: str):
    """Record a runtime error and email the admin about it (email is rate-limited).

    The error is always logged to diagnostics (deduped, never lost) even when the
    email is suppressed by the cooldown — so the dashboard error log is complete.
    """
    diagnostics.log_error(subject, body)
    global error_email_last_sent
    cooldown = runtime.get_setting("error_email_cooldown", config.ERROR_EMAIL_COOLDOWN)
    if time.time() - error_email_last_sent < cooldown:
        return
    error_email_last_sent = time.time()
    mail.try_send(auth.get_emails()[0], f"Roxy Error: {subject}", body)


# Returns (successful, response)
def request(
    url: str, method: str = "get", headers: dict = None, params: dict = None, data: str = None, roblox_token: str = None
) -> tuple[bool, str]:
    successful, response, csrf_token, retries = False, None, None, 0
    for _ in range(MAX_REQUEST_ATTEMPTS):
        successful, should_request_again, response, csrf_token, retries = _request(
            url, method, headers, params, data, roblox_token, csrf_token, retries
        )
        if successful:
            return True, response
        if not should_request_again:
            return False, response or "Too many requests; please try again in ~65 seconds."

    return False, response or "Too many upstream retries; please try again later."


def validate_token(token: str):
    # Test token by using an auth-dependent endpoint. If it works, the token is not expired.
    global tokens, email_last_sent
    record_token_use()  # Validation pings count toward the safety budget too.
    try:
        req = requests.get(
            "https://accountinformation.roblox.com/v1/birthdate",
            cookies={".ROBLOSECURITY": token},
            timeout=runtime.get_setting("request_timeout", config.REQUEST_TIMEOUT),
        )
    except requests.RequestException:
        # Couldn't reach Roblox to validate; re-queue a retry rather than dropping the token.
        diagnostics.update_token(token, being_validated=True)
        background.schedule(
            runtime.get_setting("token_expiration_cooldown", config.TOKEN_EXPIRATION_COOLDOWN), validate_token, token
        )
        return
    with request_lock:
        if req.status_code == 200:
            if token not in tokens:
                tokens.append(token)
                diagnostics.update_token(token)
            should_email = False
        else:
            diagnostics.remove_token(token, expired=True)
            should_email = time.time() - email_last_sent > runtime.get_setting("email_cooldown", config.EMAIL_COOLDOWN)
            if should_email:
                email_last_sent = time.time()
    # Send outside the lock; SMTP can take seconds and must not block proxying.
    if should_email:
        mail.try_send(
            auth.get_emails()[0],
            "Token Expired",
            f'An auth token has expired: "{token[-3:]}".\nhttps://roxytheproxy.com/admin',
        )


def reset_direct_api_cooldown():
    global is_direct_api_in_cooldown
    is_direct_api_in_cooldown = False
    diagnostics.proxy_health["DirectAPI"]["IsInCooldown"] = False


def reset_roproxy_cooldown():
    global is_roproxy_in_cooldown
    is_roproxy_in_cooldown = False
    diagnostics.proxy_health["RoProxy"]["IsInCooldown"] = False


# Returns (successful, should_request_again, response, csrf_token, retries)
def _request(
    url: str,
    method: str = "get",
    headers: dict = None,
    params: dict = None,
    data: str = None,
    roblox_token: str = None,
    csrf_token: str = None,
    retries: int = 0,
) -> tuple[bool, bool, str | None, str | None, int]:
    global tokens, is_direct_api_in_cooldown, is_roproxy_in_cooldown
    headers = headers if headers is not None else {}
    if len(tokens) == 0 and is_direct_api_in_cooldown and is_roproxy_in_cooldown:
        diagnostics.log_status_code(404)
        diagnostics.log_request(method.upper(), False)
        diagnostics.log_reason(True)
        return False, False, "No available tokens or APIs to call", None, retries

    with request_lock:
        token = None
        if roblox_token is not None:
            token = roblox_token
        else:
            if not is_direct_api_in_cooldown:
                is_direct_api_in_cooldown = True
                diagnostics.proxy_health["DirectAPI"]["IsInCooldown"] = True
                diagnostics.proxy_health["DirectAPI"]["LastRequestTime"] = time.time()
                background.schedule(
                    runtime.get_setting("direct_api_cooldown", config.DIRECT_API_COOLDOWN), reset_direct_api_cooldown
                )
            elif not is_roproxy_in_cooldown:
                is_roproxy_in_cooldown = True
                url = url.replace("roblox.com", "roproxy.com")
                diagnostics.proxy_health["RoProxy"]["IsInCooldown"] = True
                diagnostics.proxy_health["RoProxy"]["LastRequestTime"] = time.time()
                background.schedule(
                    runtime.get_setting("roproxy_cooldown", config.ROPROXY_COOLDOWN), reset_roproxy_cooldown
                )
            else:
                if len(tokens) == 0:
                    diagnostics.log_status_code(404)
                    diagnostics.log_request(method.upper(), False)
                    diagnostics.log_reason(True)
                    return False, False, "No valid tokens available; please try again in ~65 seconds.", None, retries

                # NEVER exceed the token's safety budget — Roblox flags bursty
                # bot behavior, and a flagged token risks the server IP.
                if not _token_budget_has_room_unlocked():
                    limit, window = _budget_limits()
                    diagnostics.log_budget_rejection()
                    diagnostics.log_status_code(429)
                    diagnostics.log_request(method.upper(), False)
                    diagnostics.log_reason(True)
                    return (
                        False,
                        False,
                        f"Roxy is at its internal safety budget ({limit} requests per {window}s); "
                        "please try again in a few seconds.",
                        None,
                        retries,
                    )

                # Single active token only (token rotation upsets Roblox).
                token = tokens[0]
                diagnostics.record_token_budget_usage(_record_token_use_unlocked())

    if csrf_token is not None:
        headers["x-csrf-token"] = csrf_token
    cookies = {".ROBLOSECURITY": token} if token else None
    try:
        req = requests.request(
            method,
            f"https://{url}",
            headers=headers,
            params=params,
            data=data,
            cookies=cookies,
            timeout=runtime.get_setting("request_timeout", config.REQUEST_TIMEOUT),
        )
    except requests.Timeout:
        # Upstream timeouts are an expected, transient condition (RoProxy/Cloudflare
        # are slow under load). They must NOT email the admin. Instead, count them
        # and — for the direct/RoProxy routes, which are now in cooldown — fall
        # through to the next available route so the caller still gets served.
        diagnostics.log_request(method.upper(), False)
        diagnostics.log_reason(True)
        if token is None:
            diagnostics.log_route_timeout("roproxy" in url)
            return False, True, None, csrf_token, retries  # retry → next route
        diagnostics.log_token_timeout()
        return False, False, "Upstream timed out; please try again shortly.", None, retries
    except requests.RequestException as e:
        diagnostics.log_request(method.upper(), False)
        diagnostics.log_reason(True)
        if token is None:
            # A connection error on direct/RoProxy: fall through to the next route.
            diagnostics.log_route_result("roproxy" in url, False)
            return False, True, None, csrf_token, retries
        notify_error("Upstream request failed", f"{method.upper()} https://{url}\n\n{type(e).__name__}: {e}")
        return False, False, "Upstream request failed; please try again later.", None, retries
    if token:
        diagnostics.update_token(token, used=True)
        diagnostics.log_token_result(req.status_code == 200)
    else:
        # Direct-API or RoProxy call: count it and whether it was rejected (non-200).
        diagnostics.log_route_result("roproxy" in url, req.status_code == 200)
    diagnostics.log_status_code(req.status_code)
    diagnostics.log_request(method.upper(), req.status_code == 200)
    diagnostics.log_proxy_request(method.upper(), req.elapsed.total_seconds())
    if req.status_code == 200:
        return True, False, req.text, None, retries
    elif req.status_code == 429:
        # The token is throttled (or the endpoint is). Put the token in cooldown
        # for revalidation, but do NOT retry the user's request — fail it
        # immediately so callers can't drive a retry storm.
        with request_lock:
            if token in tokens:
                tokens.remove(token)
                diagnostics.update_token(token, being_validated=True)
                background.schedule(
                    runtime.get_setting("token_expiration_cooldown", config.TOKEN_EXPIRATION_COOLDOWN),
                    validate_token,
                    token,
                )
        diagnostics.log_reason(False)
        return False, False, req.text, None, retries
    elif req.status_code == 403 and "x-csrf-token" in req.headers and csrf_token is None:
        # First 403 with a CSRF header is Roblox handing us the token to retry with.
        diagnostics.log_retry(403, "CSRF token refresh")
        return False, True, None, req.headers.get("x-csrf-token"), retries
    elif req.status_code == 403:
        # Either no CSRF header, or we already retried with one — the request is
        # genuinely forbidden (e.g. an invalid/expired user token). Never loop on it.
        diagnostics.log_reason(False)
        return False, False, req.text, None, retries
    else:
        diagnostics.log_reason(False)
        return False, False, f"Unexpected error {req.status_code}\n\n{req.text}", None, retries


def update_tokens(new_tokens: list[str]):
    global tokens
    with request_lock:
        for t in new_tokens:
            if t not in tokens:
                tokens.append(t)
                diagnostics.update_token(t)


def set_tokens(new_tokens: list[str]) -> list[str]:
    """Replace the active token set (single active token; rotation is disabled).

    Used by the dashboard to update the token when it expires.
    Returns the cleaned list that is now active.
    """
    global tokens
    cleaned = []
    for t in new_tokens:
        t = (t or "").strip()
        if t and t not in cleaned:
            cleaned.append(t)
    with request_lock:
        tokens = cleaned
        diagnostics.clear_tokens()
        for t in tokens:
            diagnostics.update_token(t)
    return list(cleaned)


def _revalidate_one(token: str):
    global tokens
    record_token_use()  # Validation pings count toward the safety budget too.
    try:
        req = requests.get(
            "https://accountinformation.roblox.com/v1/birthdate",
            cookies={".ROBLOSECURITY": token},
            timeout=runtime.get_setting("request_timeout", config.REQUEST_TIMEOUT),
        )
    except requests.RequestException:
        return  # Couldn't reach Roblox; leave the token as-is.
    with request_lock:
        if req.status_code == 200:
            diagnostics.update_token(token)
        else:
            if token in tokens:
                tokens.remove(token)
            diagnostics.remove_token(token, expired=True)


def force_revalidate_tokens():
    """Re-check every known token against Roblox; drop any that are no longer valid."""
    global is_direct_api_in_cooldown, is_roproxy_in_cooldown
    # Clear API cooldowns so traffic can flow again immediately after revalidation.
    is_direct_api_in_cooldown = False
    is_roproxy_in_cooldown = False
    diagnostics.proxy_health["DirectAPI"]["IsInCooldown"] = False
    diagnostics.proxy_health["RoProxy"]["IsInCooldown"] = False
    with request_lock:
        snapshot = list(tokens)
    for t in snapshot:
        background.schedule(0, _revalidate_one, t)
