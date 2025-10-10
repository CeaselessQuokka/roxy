import auth
import diagnostics
import mail
import requests
import time
from config import *
from threading import Timer as delay
from threading import Lock

tokens = auth.read_tokens()
current_token_index = 0
email_last_sent = 0
is_direct_api_in_cooldown = False
is_roproxy_in_cooldown = False
request_lock = Lock()

for t in tokens:
    diagnostics.update_token(t)


# Returns (successful, response)
def request(
    url: str, method: str = "get", headers: dict = None, params: dict = None, data: str = None, roblox_token: str = None
) -> tuple[bool, str]:
    successful, should_request_again, response, csrf_token = False, True, None, None
    while should_request_again:
        successful, should_request_again, response, csrf_token = _request(
            url, method, headers, params, data, roblox_token, csrf_token
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
    req = requests.get("https://accountinformation.roblox.com/v1/birthdate", cookies={".ROBLOSECURITY": token})
    with request_lock:
        if req.status_code == 200:
            if token not in tokens:
                tokens.append(token)
                diagnostics.update_token(token)
        else:
            diagnostics.proxy_health["Tokens"]["ExpiredCount"] += 1
            if token in diagnostics.tokens:
                diagnostics.tokens.pop(token, None)
                diagnostics.proxy_health["Tokens"]["Count"] = len(diagnostics.tokens)
            if time.time() - email_last_sent > EMAIL_COOLDOWN:
                email_last_sent = time.time()
                mail.send(
                    "hurricanedavensb+proxy@gmail.com",
                    "Token Expired",
                    f'An auth token has expired: "{token[-3:]}".\nhttp://127.0.0.1:5000/admin',
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
) -> tuple[bool, bool, str | None, str | None]:
    global tokens, current_token_index, is_direct_api_in_cooldown, is_roproxy_in_cooldown
    if len(tokens) == 0 and is_direct_api_in_cooldown and is_roproxy_in_cooldown:
        diagnostics.log_status_code(404)
        diagnostics.log_request(method.upper(), False)
        return False, False, "No available tokens or APIs to call", None

    with request_lock:
        token = None
        if roblox_token is not None:
            token = roblox_token
        else:
            if not is_direct_api_in_cooldown:
                is_direct_api_in_cooldown = True
                diagnostics.proxy_health["DirectAPI"]["IsInCooldown"] = True
                diagnostics.proxy_health["DirectAPI"]["LastRequestTime"] = time.time()
                delay(DIRECT_API_COOLDOWN, lambda: reset_direct_api_cooldown()).start()
            elif not is_roproxy_in_cooldown:
                is_roproxy_in_cooldown = True
                url = url.replace("roblox.com", "roproxy.com")
                diagnostics.proxy_health["RoProxy"]["IsInCooldown"] = True
                diagnostics.proxy_health["RoProxy"]["LastRequestTime"] = time.time()
                delay(ROPROXY_COOLDOWN, lambda: reset_roproxy_cooldown()).start()
            else:
                if len(tokens) == 0:
                    diagnostics.log_status_code(404)
                    diagnostics.log_request(method.upper(), False)
                    return False, False, "No valid tokens available; please try again in ~65 seconds.", None

                current_token_index %= len(tokens)
                token = tokens[current_token_index]
                current_token_index += 1

    if csrf_token is not None:
        headers["x-csrf-token"] = csrf_token
    cookies = {".ROBLOSECURITY": token} if token else None
    req = requests.request(method, f"https://{url}", headers=headers, params=params, data=data, cookies=cookies)
    diagnostics.log_status_code(req.status_code)
    diagnostics.log_request(method.upper(), req.status_code == 200)
    diagnostics.log_proxy_request(method.upper(), req.elapsed.total_seconds())
    if req.status_code == 200:
        return True, False, req.text, None
    elif req.status_code == 429:
        with request_lock:
            if token in tokens:
                # Token may be throttled instead of expired; put it in cooldown to try again later.
                tokens.remove(token)
                diagnostics.update_token(token, being_validated=True)
                delay(TOKEN_EXPIRATION_COOLDOWN, lambda: validate_token(token)).start()
        return False, True, None, None
    elif req.status_code == 403:
        return False, True, None, req.headers.get("x-csrf-token")
    else:
        return False, False, f"Unexpected error {req.status_code}\n\n{req.text}", None


def update_tokens(new_tokens: list[str]):
    global tokens
    with request_lock:
        print("TOKENS UPDATED", len(new_tokens))
        for t in new_tokens:
            if t not in tokens:
                tokens.append(t)
                diagnostics.update_token(t)
                print("New token added:", t[-5:])
