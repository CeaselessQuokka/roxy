import auth
import challenge
import config
import diagnostics
import functools
import json
import mail
import os
import proxy
import re
import runtime
import throttle
import time
import two_fa
from flask import Flask, request, render_template, session, redirect, url_for, send_from_directory, jsonify
from markupsafe import escape

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = auth.read_admin_credentials()[3]

app.config.update(
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_SECURE=True,  # TODO: Set to True if using HTTPS.
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800 if config.DEBUG else 300,
)


## Handle web pages.
# Handle home page.
@app.route("/", methods=["GET"])
def home_page():
    diagnostics.log_page_visit("home")
    diagnostics.log_visitor(request.user_agent.string)
    return render_template("home_page.html")


@app.route("/robots.txt", methods=["GET"])
def robots_txt():
    diagnostics.log_crawl(request.access_route[0])
    diagnostics.log_page_visit("robots")
    return send_from_directory(os.path.join(app.root_path), "robots.txt")


# Handle admin page.
def validate_login(data: dict) -> bool:
    if not all(k in data for k in ("Username", "Password")):
        return False

    username = data["Username"]
    password = data["Password"]
    admin_username, admin_password, *_ = auth.read_admin_credentials()
    return username == admin_username and password == admin_password


def send_login_notification(ip: str, user_agent: str):
    """Email the admin that someone logged in, with a one-click session-invalidation link."""
    try:
        token = runtime.create_invalidation_token()
        invalidate_url = url_for("admin_invalidate", token=token, _external=True)
        body = (
            "A successful login to the Roxy admin panel just occurred.\n\n"
            f"IP: {ip}\n"
            f"User-Agent: {user_agent}\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n"
            "If this was not you, invalidate all admin sessions immediately:\n"
            f"{invalidate_url}\n"
        )
        mail.send(auth.get_emails()[0], "Roxy Admin Login", body)
    except Exception:
        pass  # A failed notification must never block login.


def requires_admin(fn: callable):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("IsAdmin", False):
            return redirect(url_for("home_page"))
        # Server-side kill switch: a stale session epoch means the session was invalidated.
        if session.get("Epoch") != runtime.get_session_epoch():
            session.clear()
            return redirect(url_for("home_page"))
        return fn(*args, **kwargs)

    return wrapper


@app.route("/admin", methods=["GET", "POST"])
def admin_page():
    ip = request.access_route[0]
    user_agent = request.user_agent.string
    if request.method == "POST":
        data = request.json
        if "IsLogin" in data:
            if validate_login(request.json):
                session["Challenge"] = dict(
                    {"Challenge": challenge.generate_challenge(ip, user_agent), "IP": ip, "UserAgent": user_agent}
                )
                two_fa.send_2fa(auth.get_emails()[0])
                return "Success", 200
            diagnostics.log_login_attempt(ip, False)
            return "Invalid credentials", 403
        elif "Is2FA" in data:
            # Returns 404 on failure to avoid revealing whether the challenge or code was wrong.
            is_2fa_valid = two_fa.is_code_valid(data.get("TwoFA", ""))  # Remove to avoid reuse on precondition failure.
            if not "Challenge" in session:
                diagnostics.log_exploit_attempt(ip, "Missing challenge", user_agent)
                return "Not Found", 404
            if session["Challenge"].get("IP", "") != ip:
                diagnostics.log_exploit_attempt(ip, "IP mismatch on challenge", user_agent)
                return "Not Found", 404
            if session["Challenge"].get("UserAgent", "") != user_agent:
                diagnostics.log_exploit_attempt(ip, "User-Agent mismatch on challenge", user_agent)
                return "Not Found", 404
            if not challenge.is_challenge_valid(session["Challenge"].get("Challenge", "")):
                diagnostics.log_exploit_attempt(ip, "Invalid or expired challenge", user_agent)
                return "Not Found", 404
            if not is_2fa_valid:
                diagnostics.log_exploit_attempt(ip, "Invalid 2FA code", user_agent)
                return "Not Found", 404

            diagnostics.log_login_attempt(ip, True)
            diagnostics.decrement_admin_visit()  # Don't count the admin's own visit before logging in.
            session.pop("Challenge", None)
            session["IsAdmin"] = True
            session["Epoch"] = runtime.get_session_epoch()
            send_login_notification(ip, user_agent)
            return "Success", 200
        else:
            return "Invalid request", 400
    elif request.method == "GET":
        if session.get("IsAdmin"):
            return redirect(url_for("admin_dashboard"))
        diagnostics.log_page_visit("admin")
        return render_template("admin.html")
    else:
        diagnostics.log_exploit_attempt(ip, "Invalid method on /admin", user_agent)
        return "Method not allowed", 405


@app.route("/admin/dashboard", methods=["GET"], endpoint="admin_dashboard")
@requires_admin
def admin_dashboard():
    return render_template("dashboard.html")


@app.route("/admin/diagnostics", methods=["GET"], endpoint="admin_diagnostics")
@requires_admin
def admin_diagnostics():
    data = diagnostics.get_diagnostics()
    data["Pause"] = runtime.get_pause_state()
    data["Settings"] = runtime.get_settings()
    return jsonify(data)


@app.route("/admin/tokens", methods=["POST"], endpoint="admin_set_tokens")
@requires_admin
def admin_set_tokens():
    data = request.json
    if not "tokens" in data:
        return "Missing tokens", 400
    proxy.update_tokens(data["tokens"])
    return "Success", 200


@app.route("/admin/logout", methods=["POST"], endpoint="admin_logout")
@requires_admin
def admin_logout():
    session.clear()
    return redirect(url_for("home_page"))


@app.route("/admin/proxy/toggle", methods=["POST"], endpoint="admin_proxy_toggle")
@requires_admin
def admin_proxy_toggle():
    data = request.json if request.is_json else {}
    if isinstance(data, dict) and "paused" in data:
        runtime.set_paused(bool(data["paused"]))
    else:
        runtime.toggle_paused()
    return jsonify(runtime.get_pause_state()), 200


@app.route("/admin/settings", methods=["GET", "POST"], endpoint="admin_settings")
@requires_admin
def admin_settings():
    if request.method == "GET":
        return jsonify({"Settings": runtime.get_settings(), "Pause": runtime.get_pause_state()}), 200
    data = request.json if request.is_json else None
    if not isinstance(data, dict):
        return "Invalid request", 400
    updates = data.get("settings", data)  # Accept {settings:{...}} or a bare mapping.
    if not isinstance(updates, dict) or not updates:
        return "No settings provided", 400
    results = {}
    for key, value in updates.items():
        ok, message = runtime.set_setting(key, value)
        results[key] = message
    return jsonify({"Results": results, "Settings": runtime.get_settings()}), 200


@app.route("/admin/tokens/force_revalidate", methods=["POST"], endpoint="admin_force_revalidate")
@requires_admin
def admin_force_revalidate():
    proxy.force_revalidate_tokens()
    return jsonify("Revalidation queued"), 200


@app.route("/admin/invalidate/<token>", methods=["GET"], endpoint="admin_invalidate")
def admin_invalidate(token: str):
    # Reachable from the emailed login alert; protected by a single-use random token.
    if runtime.consume_invalidation_token(token):
        runtime.bump_session_epoch()
        return "All admin sessions have been invalidated.", 200
    return "Invalid or expired invalidation link.", 404


@app.route("/health", methods=["GET"], endpoint="health")
def health():
    return jsonify({"Status": "ok", "Paused": runtime.is_paused()}), 200


## Handle proxying requests.
path_ignore_set = set(
    [
        ".well-known/appspecific/com.chrome.devtools.json",  # Chrome DevTools related.
    ]
)


def validate_url(url: str) -> bool:
    return re.match(r"^[a-z]+\.roblox\.com/", url, re.IGNORECASE) != None


def is_browser(user_agent: str) -> bool:
    user_agent = user_agent.lower()
    browsers = [
        "gecko",
        "webkit",
        "blink",
        "trident",
        "edgehtml",
        "chrome",
        "safari",
        "firefox",
        "edge",
        "opera",
        "opr",
        "msie",
        "ucbrowser",
        "vivaldi",
        "brave",
        "yandex",
        "samsungbrowser",
        "mozilla",
    ]
    return any(browser in user_agent for browser in browsers)


def get_fake_headers() -> dict:
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
        "Cache-Control": "max-age=0",
        "Priority": "u=0, i",
        "Sec-Ch-Ua": '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    }


_SENSITIVE_HEADERS = {"x-roblox-token", "cookie", "authorization", "x-csrf-token"}


def log_live_request(ip, user_agent, method, url, headers, body, status_code):
    """Record a sanitized snapshot of a proxied request for the dashboard live feed."""
    safe_headers = {}
    for key, value in dict(headers).items():
        safe_headers[key] = "[redacted]" if key.lower() in _SENSITIVE_HEADERS else value
    body_text = ""
    if body:
        try:
            body_text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
        except Exception:
            body_text = "[unreadable body]"
        if len(body_text) > config.MAX_LIVE_BODY_LENGTH:
            body_text = body_text[: config.MAX_LIVE_BODY_LENGTH] + "… [truncated]"
    diagnostics.log_live_request(
        dict(
            Date=time.time(),
            IP=ip,
            UserAgent=user_agent,
            Method=method,
            URL=url,
            Headers=safe_headers,
            Body=body_text,
            StatusCode=status_code,
        )
    )


# Handle proxying.
@app.route("/<path:dst>", methods=["GET", "POST", "PATCH", "PUT", "DELETE"])
def proxy_page(dst: str):
    ip = request.access_route[0]
    user_agent = request.user_agent.string
    if runtime.is_paused():
        resp = jsonify("The proxy is temporarily paused; please try again later.")
        resp.headers["Roxy-Requests-Left"] = throttle.get_requests_left(ip)
        resp.headers["Roxy-Throttle-Reset"] = throttle.get_throttle_reset_time_left(ip)
        resp.headers["Roxy-Throttled"] = "False"
        resp.headers["Roxy-Paused"] = "True"
        return resp, 503

    if throttle.is_throttled(ip):
        resp = jsonify(
            f"You have been throttled; try again in {throttle.get_throttle_reset_time_left(ip)} seconds (you get ~{config.ALLOWED_REQUESTS_PER_MINUTE} requests per ~minute)."
        )
        resp.headers["Roxy-Requests-Left"] = 0
        resp.headers["Roxy-Throttle-Reset"] = throttle.get_throttle_reset_time_left(ip)
        resp.headers["Roxy-Throttled"] = "True"
        return resp, 429

    if dst in path_ignore_set:
        resp = jsonify("Not Found")
        resp.headers["Roxy-Requests-Left"] = throttle.get_requests_left(ip)
        resp.headers["Roxy-Throttle-Reset"] = throttle.get_throttle_reset_time_left(ip)
        resp.headers["Roxy-Throttled"] = "False"
        return resp, 404

    if dst != escape(dst):
        diagnostics.log_exploit_attempt(ip, f'Invalid URL: "{dst}"', user_agent)
        resp = jsonify("Invalid URL")
        resp.headers["Roxy-Requests-Left"] = throttle.get_requests_left(ip)
        resp.headers["Roxy-Throttle-Reset"] = throttle.get_throttle_reset_time_left(ip)
        resp.headers["Roxy-Throttled"] = "False"
        return resp, 404

    if not validate_url(dst):
        diagnostics.log_exploit_attempt(ip, f'Non-Roblox URL: "{dst}"', user_agent)
        resp = jsonify("Not a Roblox URL")
        resp.headers["Roxy-Requests-Left"] = throttle.get_requests_left(ip)
        resp.headers["Roxy-Throttle-Reset"] = throttle.get_throttle_reset_time_left(ip)
        resp.headers["Roxy-Throttled"] = "False"
        return resp, 404

    throttle.update_throttling(ip, made_request=True)
    diagnostics.log_endpoint(dst, request.method)
    params = dict(request.args)
    data = request.data if request.method in ("POST", "PATCH", "PUT", "DELETE") else None

    # Remove/overwrite headers that could cause issues.
    headers = dict(request.headers)
    headers.pop("Host", None)
    headers.pop("Accept", None)
    headers.pop("Accept-Encoding", None)
    headers.pop("Cache-Control", None)
    headers.pop("Connection", None)
    headers.pop("User-Agent", None)
    headers.pop("Roblox-Id", None)
    headers.pop("Traceparent", None)
    headers.update(get_fake_headers())

    roblox_token = headers.pop("X-Roblox-Token", None)
    if roblox_token is not None and not config.TOKEN_PREFIX in roblox_token:
        roblox_token = f"{config.TOKEN_PREFIX}{roblox_token}"

    # Handle proxying the request.
    successful, response = proxy.request(
        escape(dst),
        method=request.method,
        headers=headers,
        params=params,
        data=data,
        roblox_token=roblox_token,
    )
    pretty_print = params.pop("prettyprint", "false").lower() == "true"
    if successful and response is not None and pretty_print:
        try:
            response = json.dumps(json.loads(response), indent=4)
        except:
            pass
    response = f"<pre>{response}</pre>" if is_browser(user_agent) else response
    response = response if response is not None else "Internal Server Error"
    resp = jsonify(response)
    resp.headers["Roxy-Requests-Left"] = throttle.get_requests_left(ip)
    resp.headers["Roxy-Throttle-Reset"] = throttle.get_throttle_reset_time_left(ip)
    resp.headers["Roxy-Throttled"] = str(throttle.is_throttled(ip))
    resp.data = response
    log_live_request(ip, user_agent, request.method, dst, request.headers, data, 200 if successful else 500)
    return resp, 200 if successful else 500


@app.errorhandler(500)
@app.errorhandler(Exception)
def handle_unexpected_error(error):
    # Email the admin about unexpected server errors (rate-limited inside proxy.notify_error).
    try:
        proxy.notify_error(
            "Unhandled server error",
            f"{request.method} {request.path}\n"
            f"IP: {request.access_route[0] if request.access_route else '?'}\n\n"
            f"{type(error).__name__}: {error}",
        )
    except Exception:
        pass
    return jsonify("Internal Server Error"), 500


if __name__ == "__main__":
    app.run(debug=False)
