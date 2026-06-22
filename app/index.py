import auth
import challenge
import config
import diagnostics
import functools
import hmac
import json
import mail
import os
import proxy
import re
import runtime
import storage
import throttle
import time
import traceback
import two_fa
from flask import Flask, request, render_template, session, redirect, url_for, send_from_directory, jsonify
from markupsafe import escape
from werkzeug.exceptions import HTTPException

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = auth.read_admin_credentials()[3]

app.config.update(
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_SECURE=not config.DEBUG,  # The cookie must only travel over HTTPS in production.
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # Roblox API bodies are small; cap uploads so memory can't be flooded.
)


# --- Request helpers ----------------------------------------------------------
def get_client_ip() -> str:
    """The client IP, preferring the proxy chain. Never raises."""
    try:
        route = request.access_route
        if route:
            return route[0]
        return request.remote_addr or "unknown"
    except Exception:
        return "unknown"


def get_json_dict() -> dict | None:
    """The request body parsed as a JSON object, or None. Never raises on bad input."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def wants_json() -> bool:
    """Whether this request came from the dashboard's fetch() calls (vs. browser navigation)."""
    return "application/json" in (request.headers.get("Accept") or "")


@app.after_request
def add_security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


@app.template_global()
def static_url(filename: str) -> str:
    """url_for('static', ...) with a version query so browsers never serve a
    stale cached copy of the dashboard JS/CSS after a deploy."""
    try:
        version = int(os.path.getmtime(os.path.join(app.static_folder, filename)))
    except OSError:
        version = 0
    return url_for("static", filename=filename, v=version)


## Handle web pages.
# Handle home page.
@app.route("/", methods=["GET"])
def home_page():
    diagnostics.log_page_visit("home")
    diagnostics.log_visitor(request.user_agent.string)
    return render_template("home_page.html")


@app.route("/robots.txt", methods=["GET"])
def robots_txt():
    diagnostics.log_crawl(get_client_ip())
    diagnostics.log_page_visit("robots")
    return send_from_directory(os.path.join(app.root_path), "robots.txt")


@app.route("/sitemap.xml", methods=["GET"])
def sitemap_xml():
    diagnostics.log_crawl(get_client_ip())
    return send_from_directory(os.path.join(app.root_path), "sitemap.xml", mimetype="application/xml")


@app.route("/favicon.ico", methods=["GET"])
def favicon():
    # Browsers request this automatically; without a route it would fall into the
    # proxy catch-all and pollute the probe log with innocent visitors.
    return send_from_directory(os.path.join(app.root_path, "static"), "roxy_favicon.png")


# Handle admin page.
def validate_login(data: dict) -> bool:
    username = data.get("Username")
    password = data.get("Password")
    if not isinstance(username, str) or not isinstance(password, str):
        return False

    admin_username, admin_password, *_ = auth.read_admin_credentials()
    # Constant-time comparison so the check doesn't leak how much of a guess matched.
    username_ok = hmac.compare_digest(username.encode(), admin_username.encode())
    password_ok = hmac.compare_digest(password.encode(), admin_password.encode())
    return username_ok and password_ok


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
        mail.try_send(auth.get_emails()[0], "Roxy Admin Login", body)
    except Exception:
        pass  # A failed notification must never block login.


def _reject_session():
    """End the current admin session and send the caller back to the login screen."""
    session.clear()
    if wants_json():
        return jsonify("Session expired"), 401
    return redirect(url_for("admin_page"))


def requires_admin(fn: callable):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("IsAdmin", False):
            return _reject_session()
        # Server-side kill switch: a stale session epoch means the session was invalidated.
        if session.get("Epoch") != runtime.get_session_epoch():
            return _reject_session()
        # Presence check: the dashboard heartbeats while it is open. Once the admin
        # leaves the page, the session dies ADMIN_SESSION_IDLE_TIMEOUT seconds later.
        last_seen = session.get("LastSeen", 0)
        if time.time() - last_seen > config.ADMIN_SESSION_IDLE_TIMEOUT:
            return _reject_session()
        session["LastSeen"] = time.time()
        return fn(*args, **kwargs)

    return wrapper


# Marks a browser that has successfully logged in before, so the dev's own
# visits to the login page stop inflating the "admin page visits" counter.
ADMIN_SEEN_COOKIE = "roxy_admin_seen"
# A trusted device may skip the 2FA step on future logins (see runtime).
TRUSTED_DEVICE_COOKIE = "roxy_trusted_device"


def _complete_login(ip: str, user_agent: str, trust_device: bool):
    """Finish a successful login: mark the session, notify, set cookies. Returns the response."""
    diagnostics.log_login_attempt(ip, True)
    if not request.cookies.get(ADMIN_SEEN_COOKIE):
        diagnostics.decrement_admin_visit()  # Don't count the admin's own visit before logging in.
    throttle.reset_login_failures(ip)
    session.pop("Challenge", None)
    session["IsAdmin"] = True
    session["Epoch"] = runtime.get_session_epoch()
    session["LastSeen"] = time.time()
    send_login_notification(ip, user_agent)
    resp = jsonify({"Status": "Success", "LoggedIn": True})
    resp.set_cookie(
        ADMIN_SEEN_COOKIE, "1", max_age=180 * 24 * 3600, secure=not config.DEBUG, httponly=True, samesite="Lax"
    )
    if trust_device:
        token = runtime.create_trusted_device(ip, user_agent)
        resp.set_cookie(
            TRUSTED_DEVICE_COOKIE,
            token,
            max_age=config.TRUSTED_DEVICE_DURATION,
            secure=not config.DEBUG,
            httponly=True,
            samesite="Lax",
        )
    return resp


@app.route("/admin", methods=["GET", "POST"])
def admin_page():
    ip = get_client_ip()
    user_agent = request.user_agent.string
    if request.method == "POST":
        blocked, retry_after = throttle.is_login_blocked(ip)
        if blocked:
            diagnostics.log_exploit_attempt(ip, "Login attempts rate-limited", user_agent)
            return jsonify(f"Too many attempts; try again in {retry_after} seconds."), 429
        data = get_json_dict()
        if data is None:
            diagnostics.log_exploit_attempt(ip, "Malformed login payload", user_agent)
            return jsonify("Invalid request"), 400
        if "IsLogin" in data:
            if validate_login(data):
                # A trusted device skips the 2FA step entirely.
                if runtime.is_trusted_device(request.cookies.get(TRUSTED_DEVICE_COOKIE, "")):
                    return _complete_login(ip, user_agent, trust_device=False), 200
                session["Challenge"] = dict(
                    {
                        "Challenge": challenge.generate_challenge(ip, user_agent),
                        "IP": ip,
                        "UserAgent": user_agent,
                        "TrustDevice": bool(data.get("TrustDevice")),
                    }
                )
                try:
                    two_fa.send_2fa(auth.get_emails()[0])
                except Exception:
                    session.pop("Challenge", None)
                    return jsonify("Could not send the 2FA email; please try again shortly."), 503
                return jsonify({"Status": "Success", "TwoFA": True}), 200
            throttle.register_login_failure(ip)
            diagnostics.log_login_attempt(ip, False)
            return jsonify("Invalid credentials"), 403
        elif "Is2FA" in data:
            # Returns 404 on failure to avoid revealing whether the challenge or code was wrong.
            code = data.get("TwoFA", "")
            # Consume first so the code can't be replayed after a precondition failure.
            is_2fa_valid = two_fa.is_code_valid(code if isinstance(code, str) else "")
            stored = session.get("Challenge")
            if not isinstance(stored, dict):
                diagnostics.log_exploit_attempt(ip, "Missing challenge", user_agent)
                throttle.register_login_failure(ip)
                return jsonify("Not Found"), 404
            if stored.get("IP", "") != ip:
                diagnostics.log_exploit_attempt(ip, "IP mismatch on challenge", user_agent)
                throttle.register_login_failure(ip)
                return jsonify("Not Found"), 404
            if stored.get("UserAgent", "") != user_agent:
                diagnostics.log_exploit_attempt(ip, "User-Agent mismatch on challenge", user_agent)
                throttle.register_login_failure(ip)
                return jsonify("Not Found"), 404
            if not challenge.is_challenge_valid(stored.get("Challenge", "")):
                diagnostics.log_exploit_attempt(ip, "Invalid or expired challenge", user_agent)
                throttle.register_login_failure(ip)
                return jsonify("Not Found"), 404
            if not is_2fa_valid:
                diagnostics.log_exploit_attempt(ip, "Invalid 2FA code", user_agent)
                throttle.register_login_failure(ip)
                return jsonify("Not Found"), 404

            trust_device = bool(stored.get("TrustDevice"))
            return _complete_login(ip, user_agent, trust_device=trust_device), 200
        else:
            return jsonify("Invalid request"), 400
    # GET
    if session.get("IsAdmin"):
        return redirect(url_for("admin_dashboard"))
    if not request.cookies.get(ADMIN_SEEN_COOKIE):
        # Known-admin browsers don't count toward the visit stats.
        diagnostics.log_page_visit("admin")
    return render_template("admin.html")


@app.route("/admin/dashboard", methods=["GET"], endpoint="admin_dashboard")
@requires_admin
def admin_dashboard():
    return render_template("dashboard.html")


@app.route("/admin/heartbeat", methods=["POST"], endpoint="admin_heartbeat")
@requires_admin
def admin_heartbeat():
    # requires_admin already refreshed LastSeen; report the policy so the UI can show it.
    return (
        jsonify(
            {
                "OK": True,
                "IdleTimeout": config.ADMIN_SESSION_IDLE_TIMEOUT,
                "HeartbeatInterval": config.ADMIN_HEARTBEAT_INTERVAL,
            }
        ),
        200,
    )


@app.route("/admin/diagnostics", methods=["GET"], endpoint="admin_diagnostics")
@requires_admin
def admin_diagnostics():
    data = diagnostics.get_diagnostics()
    data["Pause"] = runtime.get_pause_state()
    data["Settings"] = runtime.get_settings()
    data["EndpointBlocks"] = runtime.get_endpoint_blocks()
    data["EndpointRules"] = runtime.get_endpoint_rules()
    data["HeaderRules"] = runtime.get_header_rules()
    data["ThrottleAll"] = runtime.get_throttle_all_state()
    # Token budget for the dashboard, sourced from the shared routing state that
    # get_diagnostics already fetched (no extra file read).
    rs = data.get("Routing", {})
    data["TokenBudget"] = {
        "Used": rs.get("TokenUsed", 0),
        "Limit": rs.get("TokenLimit", 0),
        "Window": rs.get("TokenWindow", 0),
        "ResetIn": rs.get("TokenResetIn", 0),
    }
    data["Persistence"] = storage.get_status()
    data["TrustedDevices"] = runtime.get_trusted_device_count()
    data["TrustedThisDevice"] = runtime.is_trusted_device(request.cookies.get(TRUSTED_DEVICE_COOKIE, ""))
    return jsonify(data)


@app.route("/admin/tokens", methods=["POST"], endpoint="admin_set_tokens")
@requires_admin
def admin_set_tokens():
    data = get_json_dict()
    if data is None or "tokens" not in data:
        return jsonify("Missing tokens"), 400
    raw = data["tokens"]
    if not isinstance(raw, list) or not all(isinstance(t, str) for t in raw):
        return jsonify("Tokens must be a list of strings"), 400
    cleaned = proxy.set_tokens(raw)
    persisted = None
    if data.get("persist"):
        persisted = auth.write_tokens(cleaned)
    return jsonify({"Count": len(cleaned), "Persisted": persisted}), 200


@app.route("/admin/logout", methods=["POST"], endpoint="admin_logout")
@requires_admin
def admin_logout():
    session.clear()
    if wants_json():
        return jsonify("Logged out"), 200
    return redirect(url_for("home_page"))


@app.route("/admin/proxy/toggle", methods=["POST"], endpoint="admin_proxy_toggle")
@requires_admin
def admin_proxy_toggle():
    data = get_json_dict() or {}
    reason = data.get("reason") if isinstance(data.get("reason"), str) else None
    target = bool(data["paused"]) if "paused" in data else not runtime.is_paused()
    if target:
        diagnostics.clear_stats(("pause_drops",))  # Fresh drop count for this downtime.
    runtime.set_paused(target, reason=reason)
    return jsonify(runtime.get_pause_state()), 200


@app.route("/admin/proxy/throttle_all", methods=["POST"], endpoint="admin_throttle_all")
@requires_admin
def admin_throttle_all():
    data = get_json_dict() or {}
    reason = data.get("reason") if isinstance(data.get("reason"), str) else None
    # Optionally update the configurable per-IP limit/period in the same call.
    if "limit" in data:
        runtime.set_setting("global_throttle_limit", data.get("limit"))
    if "period" in data:
        runtime.set_setting("global_throttle_period", data.get("period"))
    target = bool(data["enabled"]) if "enabled" in data else not runtime.is_throttle_all()
    if target:
        diagnostics.clear_stats(("throttle_drops",))  # Fresh drop count for this downtime.
    runtime.set_throttle_all(target, reason=reason)
    return jsonify(runtime.get_throttle_all_state()), 200


@app.route("/admin/settings", methods=["GET", "POST"], endpoint="admin_settings")
@requires_admin
def admin_settings():
    if request.method == "GET":
        return jsonify({"Settings": runtime.get_settings(), "Pause": runtime.get_pause_state()}), 200
    data = get_json_dict()
    if data is None:
        return jsonify("Invalid request"), 400
    updates = data.get("settings", data)  # Accept {settings:{...}} or a bare mapping.
    if not isinstance(updates, dict) or not updates:
        return jsonify("No settings provided"), 400
    results = {}
    for key, value in updates.items():
        ok, message = runtime.set_setting(key, value)
        results[key] = message
    return jsonify({"Results": results, "Settings": runtime.get_settings()}), 200


@app.route("/admin/tokens/force_revalidate", methods=["POST"], endpoint="admin_force_revalidate")
@requires_admin
def admin_force_revalidate():
    # Synchronously re-checks each token against Roblox and reports which are live.
    report = proxy.force_revalidate_tokens()
    active = sum(1 for t in report if t.get("Active") is True)
    return jsonify({"Tokens": report, "Active": active, "Total": len(report)}), 200


@app.route("/admin/health_check", methods=["POST"], endpoint="admin_health_check")
@requires_admin
def admin_health_check():
    """Active health probe for the dashboard's Run Health Check: verifies the
    server is up, each token is still live (real request to Roblox), and that the
    rotation proxy hands out a working exit IP."""
    tokens_report = proxy.check_tokens()
    rotation = proxy.probe_rotation()
    return (
        jsonify(
            {
                "Status": "ok",
                "Paused": runtime.is_paused(),
                "Tokens": tokens_report,
                "TokensActive": sum(1 for t in tokens_report if t.get("Active") is True),
                "TokensTotal": len(tokens_report),
                "Rotation": rotation,
            }
        ),
        200,
    )


@app.route("/admin/rotation/verify", methods=["POST"], endpoint="admin_verify_rotation")
@requires_admin
def admin_verify_rotation():
    # Fetches our exit IP THROUGH the rotation proxy and logs it (rotation only —
    # does not touch the tokens, to avoid spending token budget on a quick check).
    return jsonify(proxy.probe_rotation()), 200


@app.route("/admin/fingerprints/clear_header", methods=["POST"], endpoint="admin_clear_fingerprint_header")
@requires_admin
def admin_clear_fingerprint_header():
    data = get_json_dict()
    if data is None or not data.get("name"):
        return jsonify("Missing header name"), 400
    ok = diagnostics.clear_fingerprint_header(bool(data.get("blocked")), str(data["name"]))
    return jsonify("Cleared" if ok else "Cleared in memory, but the data file could not be written"), 200


@app.route("/admin/trusted_devices/revoke", methods=["POST"], endpoint="admin_revoke_trusted")
@requires_admin
def admin_revoke_trusted():
    # Revoke every trusted device (e.g. if one is lost); they'll need full 2FA again.
    count = runtime.revoke_trusted_devices()
    resp = jsonify({"Revoked": count})
    resp.delete_cookie(TRUSTED_DEVICE_COOKIE)  # Also drop this browser's trust cookie.
    return resp, 200


@app.route("/admin/data/clear", methods=["POST"], endpoint="admin_clear_data")
@requires_admin
def admin_clear_data():
    data = get_json_dict()
    target = (data or {}).get("target")
    if target == "all":
        names = diagnostics.CLEAR_ALL_NAMES  # Every section, each exactly once.
    else:
        names = diagnostics.CLEAR_TARGETS.get(target)
    if not names:
        return jsonify(f"Unknown clear target: {target}"), 400
    ok = diagnostics.clear_stats(names)
    if ok:
        return jsonify("Cleared everything" if target == "all" else "Cleared"), 200
    return jsonify("Cleared in memory, but the data file could not be written"), 200


@app.route("/admin/probes/clear", methods=["POST"], endpoint="admin_clear_probes")
@requires_admin
def admin_clear_probes():
    diagnostics.clear_stats(diagnostics.CLEAR_TARGETS["probes"])
    return jsonify("Probe records cleared"), 200


@app.route("/admin/endpoints/block", methods=["POST"], endpoint="admin_block_endpoint")
@requires_admin
def admin_block_endpoint():
    data = get_json_dict()
    if data is None or not data.get("pattern"):
        return jsonify({"Message": "Missing pattern"}), 400
    ok, message = runtime.block_endpoint(
        str(data["pattern"]), str(data.get("note", "")), str(data.get("type", "glob"))
    )
    status = 200 if ok else 400
    return jsonify({"Message": message, "EndpointBlocks": runtime.get_endpoint_blocks()}), status


@app.route("/admin/endpoints/unblock", methods=["POST"], endpoint="admin_unblock_endpoint")
@requires_admin
def admin_unblock_endpoint():
    data = get_json_dict()
    if data is None or not data.get("pattern"):
        return jsonify({"Message": "Missing pattern"}), 400
    ok, message = runtime.unblock_endpoint(str(data["pattern"]))
    status = 200 if ok else 400
    return jsonify({"Message": message, "EndpointBlocks": runtime.get_endpoint_blocks()}), status


@app.route("/admin/endpoints/rule", methods=["POST"], endpoint="admin_set_endpoint_rule")
@requires_admin
def admin_set_endpoint_rule():
    data = get_json_dict()
    if data is None or not data.get("pattern"):
        return jsonify({"Message": "Missing pattern"}), 400
    ok, message = runtime.set_endpoint_rule(
        str(data["pattern"]),
        data.get("limit"),
        data.get("period", config.DEFAULT_ENDPOINT_RULE_PERIOD),
        str(data.get("type", "glob")),
    )
    status = 200 if ok else 400
    return jsonify({"Message": message, "EndpointRules": runtime.get_endpoint_rules()}), status


@app.route("/admin/endpoints/rule/clear", methods=["POST"], endpoint="admin_clear_endpoint_rule")
@requires_admin
def admin_clear_endpoint_rule():
    data = get_json_dict()
    if data is None or not data.get("pattern"):
        return jsonify({"Message": "Missing pattern"}), 400
    ok, message = runtime.clear_endpoint_rule(str(data["pattern"]))
    status = 200 if ok else 400
    return jsonify({"Message": message, "EndpointRules": runtime.get_endpoint_rules()}), status


@app.route("/admin/headers/rule", methods=["POST"], endpoint="admin_add_header_rule")
@requires_admin
def admin_add_header_rule():
    data = get_json_dict()
    if data is None or not data.get("needle"):
        return jsonify({"Message": "Missing match text"}), 400
    ok, message = runtime.add_header_rule(
        str(data.get("scope", "either")),
        str(data.get("mode", "contains")),
        str(data["needle"]),
        str(data.get("note", "")),
        str(data.get("header", "")),
    )
    status = 200 if ok else 400
    return jsonify({"Message": message, "HeaderRules": runtime.get_header_rules()}), status


@app.route("/admin/headers/rule/clear", methods=["POST"], endpoint="admin_clear_header_rule")
@requires_admin
def admin_clear_header_rule():
    data = get_json_dict()
    if data is None or not data.get("id"):
        return jsonify({"Message": "Missing rule id"}), 400
    ok, message = runtime.remove_header_rule(str(data["id"]))
    status = 200 if ok else 400
    return jsonify({"Message": message, "HeaderRules": runtime.get_header_rules()}), status


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
        "favicon.ico",  # Served by its own route; kept here as a guard.
    ]
)

# Hop-by-hop / environment headers that must never be forwarded to Roblox.
# Exact header names to drop before forwarding to Roblox. Anything that could
# reveal our server, our domain, or the visitor's IP must go (so Roblox can't
# fingerprint us as a proxy / flag bot behavior).
_STRIPPED_REQUEST_HEADERS = (
    "Host",
    "Accept",
    "Accept-Encoding",
    "Cache-Control",
    "Connection",
    "User-Agent",
    "Roblox-Id",
    "Traceparent",
    "Cookie",  # Never forward visitor cookies upstream.
    "Transfer-Encoding",
    "Forwarded",
    "Via",
    "Referer",  # Would reveal roxytheproxy.com.
    "Origin",  # Same.
    "True-Client-Ip",
    "X-Real-Ip",
    "X-Client-Ip",
    "X-Cluster-Client-Ip",
    "X-Original-Forwarded-For",
)

# Any header whose lowercased name starts with one of these prefixes is dropped
# too — covers X-Forwarded-*, all Cloudflare CF-* headers, and our own Roxy-*.
_STRIPPED_HEADER_PREFIXES = ("x-forwarded", "cf-", "roxy-", "x-real", "fly-", "x-vercel", "x-amzn")


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
        # Only advertise encodings `requests` can ALWAYS decode. Advertising
        # br/zstd without the optional decoder packages installed makes
        # upstream (especially Cloudflare/RoProxy) reply compressed and the
        # client receives raw binary gibberish.
        "Accept-Encoding": "gzip, deflate",
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


def sanitize_headers(headers) -> dict:
    """A copy of the incoming headers with secret values redacted."""
    safe = {}
    for key, value in dict(headers).items():
        safe[key] = "[redacted]" if key.lower() in _SENSITIVE_HEADERS else value
    return safe


def log_live_request(ip, user_agent, method, url, headers, body, status_code):
    """Record a sanitized snapshot of a proxied request for the dashboard live feed."""
    try:
        safe_headers = sanitize_headers(headers)
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
    except Exception:
        pass  # The live feed is best-effort; never let it break a proxied response.


def _with_throttle_headers(resp, ip: str, **extra):
    # One shared-store read for all three header values (cheaper than three).
    snap = throttle.headers_snapshot(ip)
    resp.headers["Roxy-Requests-Left"] = snap["RequestsLeft"]
    resp.headers["Roxy-Throttle-Reset"] = snap["ResetIn"]
    resp.headers["Roxy-Throttled"] = str(snap["Throttled"])
    for key, value in extra.items():
        resp.headers[key.replace("_", "-")] = value
    return resp


def throttled_response(ip: str, reset_in=None):
    """The standard 'you've been throttled' 429. Reused for header-rule blocks so a
    blocked exploiter sees an ordinary rate-limit message and can't tell they were
    filtered (it's indistinguishable from a real throttle)."""
    if reset_in is None:
        reset_in = throttle.get_throttle_reset_time_left(ip)
    allowed = runtime.get_setting("allowed_requests_per_minute", config.ALLOWED_REQUESTS_PER_MINUTE)
    resp = jsonify(
        f"You have been throttled; try again in {reset_in} seconds (you get ~{allowed} requests per ~minute)."
    )
    return _with_throttle_headers(resp, ip, Roxy_Throttle_Reset=reset_in, Roxy_Throttled="True"), 429


# Handle proxying.
@app.route("/<path:dst>", methods=["GET", "POST", "PATCH", "PUT", "DELETE"])
def proxy_page(dst: str):
    ip = get_client_ip()
    user_agent = request.user_agent.string
    if runtime.is_paused():
        diagnostics.log_pause_drop()
        resp = jsonify(runtime.pause_message())
        return _with_throttle_headers(resp, ip, Roxy_Paused="True"), 503

    # Global throttle-all: a softer alternative to a full pause. Every IP is
    # rate-limited to a configurable N requests per P seconds; requests within
    # that budget proceed normally (still subject to the regular per-IP and
    # per-endpoint limits), the rest get a friendly 429.
    if runtime.is_throttle_all():
        allowed, retry_in = throttle.check_global_throttle(ip)
        if not allowed:
            diagnostics.log_throttle_all_drop()
            resp = jsonify(runtime.throttle_all_message())
            return _with_throttle_headers(resp, ip, Roxy_Throttle_Reset=retry_in, Roxy_Global_Throttled="True"), 429

    if throttle.is_throttled(ip):
        return throttled_response(ip)

    if dst in path_ignore_set:
        resp = jsonify("Not Found")
        return _with_throttle_headers(resp, ip), 404

    if dst != escape(dst):
        diagnostics.log_exploit_attempt(ip, f'Invalid URL: "{dst}"', user_agent)
        resp = jsonify("Invalid URL")
        return _with_throttle_headers(resp, ip), 404

    if not validate_url(dst):
        diagnostics.log_exploit_attempt(ip, f'Non-Roblox URL: "{dst}"', user_agent)
        resp = jsonify("Not a Roblox URL")
        return _with_throttle_headers(resp, ip), 404

    # Header rules deny abusive clients (e.g. exploit fingerprints) outright.
    # The blocked caller gets a normal-looking THROTTLE 429 — indistinguishable
    # from a real rate-limit — so the exploiter thinks they're requesting too much
    # rather than realizing they're filtered. The admin sees the real detail (and
    # the blocked request's full fingerprint, for false-positive review).
    header_rule = runtime.match_header_rule(request.headers)
    if header_rule:
        diagnostics.log_header_blocked(header_rule, dst, request.method, ip)
        diagnostics.log_request_fingerprint(
            request.headers.items(),
            user_agent,
            blocked=True,
            last_headers=json.dumps(sanitize_headers(request.headers)),
            last_path=dst,
            last_ip=ip,
        )
        reset_in = runtime.get_setting("throttle_reset_duration", config.THROTTLE_RESET_DURATION)
        return throttled_response(ip, reset_in=reset_in)

    if runtime.is_endpoint_blocked(dst):
        diagnostics.log_blocked_endpoint(dst, request.method, ip, runtime.get_matching_block(dst))
        resp = jsonify("This endpoint is currently blocked.")
        return _with_throttle_headers(resp, ip, Roxy_Blocked="True"), 403

    endpoint_allowed, endpoint_retry, endpoint_pattern = throttle.check_endpoint_limit(ip, dst)
    if not endpoint_allowed:
        diagnostics.log_rate_limited_endpoint(dst, request.method, ip, endpoint_pattern)
        resp = jsonify(f"This endpoint is rate-limited for you; try again in {endpoint_retry} seconds.")
        resp.headers["Roxy-Requests-Left"] = throttle.get_requests_left(ip)
        resp.headers["Roxy-Throttle-Reset"] = endpoint_retry
        resp.headers["Roxy-Throttled"] = "True"
        resp.headers["Roxy-Endpoint-Limited"] = "True"
        return resp, 429

    throttle.update_throttling(ip, made_request=True)
    safe_headers = sanitize_headers(request.headers)
    safe_headers_json = json.dumps(safe_headers)
    diagnostics.log_endpoint(dst, request.method, safe_headers_json, ip)
    # Track distinct header names + their values + user-agents (secret values are
    # fingerprinted, not stored raw) to help spot abusive clients. The UA record
    # also keeps the last headers/endpoint so a UA can be drilled into.
    diagnostics.log_request_fingerprint(
        request.headers.items(), user_agent, last_headers=safe_headers_json, last_path=dst, last_ip=ip
    )

    # Preserve repeated query params (e.g. ?ids=1&ids=2); requests encodes lists.
    params = request.args.to_dict(flat=False)
    # Strip Roxy's own option BEFORE proxying so it never reaches Roblox.
    pretty_values = params.pop("prettyprint", None)
    pretty_print = bool(pretty_values) and str(pretty_values[-1]).lower() == "true"

    data = request.get_data() if request.method in ("POST", "PATCH", "PUT", "DELETE") else None

    # Remove/overwrite headers that could cause issues or identify us/the visitor.
    headers = {}
    stripped = {name.lower() for name in _STRIPPED_REQUEST_HEADERS}
    for key, value in request.headers.items():
        kl = key.lower()
        if kl in stripped or any(kl.startswith(p) for p in _STRIPPED_HEADER_PREFIXES):
            continue
        headers[key] = value
    headers.update(get_fake_headers())

    roblox_token = headers.pop("X-Roblox-Token", None)
    if roblox_token is not None and not config.TOKEN_PREFIX in roblox_token:
        roblox_token = f"{config.TOKEN_PREFIX}{roblox_token}"

    # Handle proxying the request.
    successful, response = proxy.request(
        str(escape(dst)),
        method=request.method,
        headers=headers,
        params=params,
        data=data,
        roblox_token=roblox_token,
    )
    if successful and response is not None and pretty_print:
        try:
            response = json.dumps(json.loads(response), indent=4)
        except (ValueError, TypeError):
            pass
    response = response if response is not None else "Internal Server Error"
    status = 200 if successful else 500
    if is_browser(user_agent):
        # Humans get readable, HTML-escaped output (escaping also blocks any
        # script content in an upstream body from executing on Roxy's origin).
        resp = app.response_class(f"<pre>{escape(response)}</pre>", mimetype="text/html")
    else:
        # API consumers get the raw upstream body passed through untouched.
        resp = app.response_class(response, mimetype="application/json")
    _with_throttle_headers(resp, ip)
    log_live_request(ip, user_agent, request.method, dst, request.headers, data, status)
    return resp, status


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, HTTPException) and error.code and error.code < 500:
        # Expected client-level errors (405s from bots probing POST /, 404s, bad
        # payloads...). These are routine: record them as probes, return the real
        # status — and never email about them.
        try:
            diagnostics.log_exploit_attempt(
                get_client_ip(),
                f"HTTP {error.code} via {request.method} {request.path}"[:200],
                request.user_agent.string,
            )
        except Exception:
            pass
        response = error.get_response()  # Keeps spec headers like Allow on a 405.
        response.data = json.dumps(error.description)
        response.content_type = "application/json"
        return response

    # Genuine server-side failure: log it (deduped per exception type+message) and
    # email the admin (rate-limited in notify_error).
    try:
        signature = f"{type(error).__name__}: {error}"
        proxy.notify_error(
            signature,
            f"{request.method} {request.path}\n"
            f"IP: {get_client_ip()}\n\n"
            f"{traceback.format_exc()}",
        )
    except Exception:
        pass
    return jsonify("Internal Server Error"), 500


if __name__ == "__main__":
    app.run(debug=False)
