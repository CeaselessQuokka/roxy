import auth
import config
import diagnostics
import mail
import requests
import runtime
import time
from threading import Timer as delay
from threading import Lock

tokens = auth.read_tokens()
email_last_sent = 0
error_email_last_sent = 0
is_direct_api_in_cooldown = False
is_roproxy_in_cooldown = False
request_lock = Lock()

for t in tokens:
    diagnostics.update_token(t)


def notify_error(subject: str, body: str):
    """Email the admin about a runtime error, rate-limited to avoid spam."""
    global error_email_last_sent
    if time.time() - error_email_last_sent < (runtime.get_setting("error_email_cooldown") or config.ERROR_EMAIL_COOLDOWN):
        return
    error_email_last_sent = time.time()
    try:
        mail.send(auth.get_emails()[0], f"Roxy Error: {subject}", body)
    except Exception:
        pass  # Never let error reporting raise.


# Returns (successful, response)
def request(
    url: str, method: str = "get", headers: dict = None, params: dict = None, data: str = None, roblox_token: str = None
) -> tuple[bool, str]:
    successful, should_request_again, response, csrf_token, retries = False, True, None, None, 0
    while should_request_again:
        successful, should_request_again, response, csrf_token, retries = _request(
            url, method, headers, params, data, roblox_token, csrf_token, retries
        )
        if successful:
            return True, response
        elif should_request_again:
            pass
        else:
            return False, response or "Too many requests; please try again in ~65 seconds."

    return False, "Major error; please notify the developer, and try again later."


def validate_token(token: str):
    # Test token by using an auth-dependent endpoint. If it works, the token is not expired.
    global tokens, email_last_sent
    try:
        req = requests.get(
            "https://accountinformation.roblox.com/v1/birthdate",
            cookies={".ROBLOSECURITY": token},
            timeout=runtime.get_setting("request_timeout") or config.REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        # Couldn't reach Roblox to validate; re-queue a retry rather than dropping the token.
        diagnostics.update_token(token, being_validated=True)
        delay(runtime.get_setting("token_expiration_cooldown") or config.TOKEN_EXPIRATION_COOLDOWN, lambda: validate_token(token)).start()
        return
    with request_lock:
        if req.status_code == 200:
            if token not in tokens:
                tokens.append(token)
                diagnostics.update_token(token)
        else:
            diagnostics.remove_token(token, expired=True)
            if time.time() - email_last_sent > (runtime.get_setting("email_cooldown") or config.EMAIL_COOLDOWN):
                email_last_sent = time.time()
                mail.send(
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


# Returns (successful, should_request_again, response)
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
                delay(runtime.get_setting("direct_api_cooldown"), lambda: reset_direct_api_cooldown()).start()
            elif not is_roproxy_in_cooldown:
                is_roproxy_in_cooldown = True
                url = url.replace("roblox.com", "roproxy.com")
                diagnostics.proxy_health["RoProxy"]["IsInCooldown"] = True
                diagnostics.proxy_health["RoProxy"]["LastRequestTime"] = time.time()
                delay(runtime.get_setting("roproxy_cooldown"), lambda: reset_roproxy_cooldown()).start()
            else:
                if len(tokens) == 0:
                    diagnostics.log_status_code(404)
                    diagnostics.log_request(method.upper(), False)
                    diagnostics.log_reason(True)
                    return False, False, "No valid tokens available; please try again in ~65 seconds.", None, retries

                # Single active token only (token rotation upsets Roblox).
                token = tokens[0]

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
            timeout=runtime.get_setting("request_timeout") or config.REQUEST_TIMEOUT,
        )
    except requests.RequestException as e:
        diagnostics.log_request(method.upper(), False)
        diagnostics.log_reason(True)
        notify_error("Upstream request failed", f"{method.upper()} https://{url}\n\n{type(e).__name__}: {e}")
        return False, False, "Upstream request failed; please try again later.", None, retries
    if token:
        diagnostics.update_token(token, used=True)
    elif "roproxy" in url:
        diagnostics.proxy_health["RoProxy"]["Count"] += 1
    else:
        diagnostics.proxy_health["DirectAPI"]["Count"] += 1
    diagnostics.log_status_code(req.status_code)
    diagnostics.log_request(method.upper(), req.status_code == 200)
    diagnostics.log_proxy_request(method.upper(), req.elapsed.total_seconds())
    if req.status_code == 200:
        return True, False, req.text, None, retries
    elif req.status_code == 429:
        with request_lock:
            if token in tokens:
                # Token may be throttled instead of expired; put it in cooldown to try again later.
                tokens.remove(token)
                diagnostics.update_token(token, being_validated=True)
                delay(runtime.get_setting("token_expiration_cooldown") or config.TOKEN_EXPIRATION_COOLDOWN, lambda: validate_token(token)).start()
        retries += 1
        if retries > runtime.get_setting("max_retries_per_request") - 1:
            diagnostics.log_reason(False)
            return False, False, req.text, None, retries
        else:
            diagnostics.log_retry(429, "Rate limited (429); retrying")
            return False, True, None, None, retries
    elif req.status_code == 403 and "x-csrf-token" in req.headers:
        diagnostics.log_retry(403, "CSRF token refresh")
        return False, True, None, req.headers.get("x-csrf-token"), retries
    elif req.status_code == 403 and "x-csrf-token" not in req.headers:
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


def set_tokens(new_tokens: list[str]) -> int:
    """Replace the active token set (single active token; rotation is disabled).

    Used by the dashboard to update the token when it expires.
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
    return len(tokens)


def _revalidate_one(token: str):
    global tokens
    try:
        req = requests.get(
            "https://accountinformation.roblox.com/v1/birthdate",
            cookies={".ROBLOSECURITY": token},
            timeout=runtime.get_setting("request_timeout") or config.REQUEST_TIMEOUT,
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
        delay(0, lambda tok=t: _revalidate_one(tok)).start()
