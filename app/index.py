import logging
import logging.handlers

import auth
import capture
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
import tarpit
import throttle
import time
import traceback
import two_fa
import workers
from flask import Flask, request, render_template, session, redirect, url_for, send_from_directory, jsonify
from markupsafe import escape
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix


def _configure_logging():
    """Send the app's log records somewhere a human can find them.

    Modules log failures (a bounced email, a crashed background task) via the
    standard logging module, but nothing ever configured a handler, so under
    gunicorn those records fell through to the last-resort handler and were
    effectively discarded. stderr is inherited by gunicorn and captured by
    journald, so this is all it takes to make them readable with journalctl.
    """
    root = logging.getLogger()
    if root.handlers:
        return  # Respect a host-provided configuration (gunicorn --log-config).
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)


_configure_logging()
_logger = logging.getLogger("roxy.app")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = auth.read_admin_credentials()[3]

# Trust exactly config.TRUSTED_PROXY_HOPS proxy hops. ProxyFix rewrites
# REMOTE_ADDR from the RIGHTMOST end of X-Forwarded-For, skipping that many
# entries -- the hops our own infrastructure appended. Anything further left was
# written by the caller and is not evidence of anything.
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=config.TRUSTED_PROXY_HOPS, x_proto=config.TRUSTED_PROXY_HOPS, x_host=config.TRUSTED_PROXY_HOPS
)

app.config.update(
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_SECURE=not config.DEBUG,  # The cookie must only travel over HTTPS in production.
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # Roblox API bodies are small; cap uploads so memory can't be flooded.
)


# --- Request helpers ----------------------------------------------------------
def get_client_ip() -> str:
    """The client IP. Never raises.

    Reads remote_addr, which ProxyFix (above) has already resolved to the last
    hop our own proxies vouch for. It must NOT read access_route[0]: with the
    conventional nginx `X-Forwarded-For $proxy_add_x_forwarded_for`, which
    appends rather than replaces, the leftmost entry is whatever the caller
    typed. Everything keyed on this value -- per-IP throttling, the admin login
    lockout, the 2FA challenge binding, the bypass allowlist -- is only as
    trustworthy as this function.
    """
    try:
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


# Everything the pages need is served from our own /static, so the policy can be
# strict with no exceptions. The dashboard renders attacker-supplied header
# values and user-agents by design; it escapes them all today, and this is the
# net for the day a refactor forgets one. `data:` is for the favicon only.
_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; object-src 'none'"
)


@app.after_request
def add_security_headers(resp):
    workers.count_request()  # Feeds the fleet view (a worker recycles at max_requests).
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Content-Security-Policy", _CSP)
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=(), interest-cohort=()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if config.SEND_HSTS and not config.DEBUG:
        # Off by default: nginx terminates TLS and already adds this, and
        # nginx's add_header appends rather than replaces, so emitting it here
        # too would send the browser two Strict-Transport-Security headers.
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
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
                # Tell the page how long the code lives so it can show a countdown
                # instead of letting it expire silently.
                return (
                    jsonify(
                        {
                            "Status": "Success",
                            "TwoFA": True,
                            "ExpiresIn": runtime.get_setting("two_fa_expiration", config.TWO_FA_EXPIRATION),
                        }
                    ),
                    200,
                )
            throttle.register_login_failure(ip)
            diagnostics.log_login_attempt(ip, False)
            return jsonify("Invalid credentials"), 403
        elif "IsResend2FA" in data:
            # Send a fresh code for a login already past the password step.
            # Rate-limited like any other attempt, and it re-mints the challenge
            # so an abandoned one can't be reused.
            stored = session.get("Challenge")
            if not isinstance(stored, dict) or stored.get("IP", "") != ip or stored.get("UserAgent", "") != user_agent:
                return jsonify("Start the login again."), 403
            session["Challenge"] = dict(stored, Challenge=challenge.generate_challenge(ip, user_agent))
            try:
                two_fa.send_2fa(auth.get_emails()[0])
            except Exception:
                return jsonify("Could not send the 2FA email; please try again shortly."), 503
            return (
                jsonify(
                    {
                        "Status": "Success",
                        "TwoFA": True,
                        "ExpiresIn": runtime.get_setting("two_fa_expiration", config.TWO_FA_EXPIRATION),
                    }
                ),
                200,
            )
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
    # The frequent auto-poll accepts slightly-stale cross-worker totals; an
    # explicit Refresh asks for the current truth and pays for the merge.
    data = diagnostics.get_diagnostics(force_flush=request.args.get("flush") == "1")
    data["Pause"] = runtime.get_pause_state()
    data["Settings"] = runtime.get_settings()
    data["EndpointBlocks"] = runtime.get_endpoint_blocks()
    data["EndpointRules"] = runtime.get_endpoint_rules()
    data["HeaderRules"] = runtime.get_header_rules()
    data["ThrottleBypassIps"] = runtime.get_throttle_bypass_ips()
    data["YourIP"] = get_client_ip()  # so the admin can one-click bypass their own IP for testing
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
    data["Capture"] = capture.get_state()
    data["InternalEndpoints"] = proxy.internal_endpoints()
    data["IgnoredValueHeaders"] = runtime.get_ignored_value_headers()
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
    # set_tokens writes the token file itself -- it has to, because that file is
    # how the other gunicorn workers learn about the change. Persistence is
    # therefore not optional and never was; the old "persist" flag just wrote the
    # same file a second time while the UI implied it was a choice.
    cleaned, persisted = proxy.set_tokens(raw)
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
        return jsonify({"Message": "Missing header name"}), 400
    values_only = bool(data.get("values_only"))
    ok, removed = diagnostics.clear_fingerprint_header(
        bool(data.get("blocked")), str(data["name"]), values_only=values_only
    )
    what = "values" if values_only else "header"
    message = f"Cleared {what} for \"{data['name']}\" ({removed} value{'' if removed == 1 else 's'} removed)"
    if not ok:
        message += " — cleared in memory, but the data file could not be written"
    return jsonify({"Message": message, "Removed": removed}), 200


@app.route("/admin/fingerprints/values", methods=["GET"], endpoint="admin_fingerprint_values")
@requires_admin
def admin_fingerprint_values():
    """One header's distinct values. Fetched only when the admin expands a row,
    so the dashboard's frequent poll never has to carry them."""
    name = request.args.get("name", "")
    if not name:
        return jsonify("Missing header name"), 400
    blocked = request.args.get("blocked") == "1"
    limit = max(1, min(1000, request.args.get("limit", type=int) or 200))
    return jsonify(diagnostics.get_header_values(blocked, name, limit)), 200


@app.route("/admin/fingerprints/user_agent", methods=["GET"], endpoint="admin_fingerprint_user_agent")
@requires_admin
def admin_fingerprint_user_agent():
    """The last headers/path/IP recorded for one user-agent (lazy drill-down)."""
    ua = request.args.get("ua", "")
    if not ua:
        return jsonify("Missing user agent"), 400
    return jsonify(diagnostics.get_user_agent_detail(request.args.get("blocked") == "1", ua)), 200


@app.route("/admin/endpoints/concrete", methods=["GET"], endpoint="admin_endpoint_concrete")
@requires_admin
def admin_endpoint_concrete():
    """One endpoint's drill-down: concrete paths, callers, and its recent requests.

    Everything bulky about an endpoint lives here rather than in the poll — the
    recent-request ring carries headers, query strings and body previews, which
    would multiply the dashboard's poll payload by the endpoint count if it
    travelled with it.
    """
    template = request.args.get("template", "")
    if not template:
        return jsonify("Missing template"), 400
    limit = max(1, min(500, request.args.get("limit", type=int) or 100))
    return jsonify(diagnostics.get_endpoint_detail(template, limit, request.args.get("path", ""))), 200


@app.route("/admin/activity/detail", methods=["GET"], endpoint="admin_activity_detail")
@requires_admin
def admin_activity_detail():
    """The full breakdown for one client IP or one calling Roblox place."""
    kind = "caller" if request.args.get("kind") == "caller" else "ip"
    key = request.args.get("key", "")
    if not key:
        return jsonify("Missing key"), 400
    return jsonify(diagnostics.get_activity_detail(kind, key)), 200


@app.route("/admin/live/detail", methods=["GET"], endpoint="admin_live_detail")
@requires_admin
def admin_live_detail():
    """The captured request + response bodies behind one live-feed entry.

    404 rather than an error when it's gone: captures expire by design, and an
    admin scrolling back past the window should be told the bytes aged out, not
    that something broke.
    """
    entry = capture.get(request.args.get("id", ""))
    if entry is None:
        return jsonify({"Message": "That capture has expired or was evicted.", "Expired": True}), 404
    return jsonify(entry), 200


@app.route("/admin/live/clear", methods=["POST"], endpoint="admin_clear_captures")
@requires_admin
def admin_clear_captures():
    capture.reset()
    diagnostics.clear_stats(diagnostics.CLEAR_TARGETS["live"])
    return jsonify({"Message": "Live feed and captured bodies cleared"}), 200


@app.route("/admin/workers/reset", methods=["POST"], endpoint="admin_reset_workers")
@requires_admin
def admin_reset_workers():
    """Zero the fleet's request counters (reaches every worker, not just this one)."""
    at = workers.reset_counts()
    return jsonify({"Message": "Worker request counts reset", "ResetAt": at}), 200


# Roblox's own public lookup chain, walked through our own proxy so it uses the
# same routing/budget as everything else and needs no extra credentials:
#   place id  -> universe id  -> the experience, including its creator.
# Open Cloud (apis.roblox.com/cloud/v2/universes/...) can return richer data but
# only for experiences the API key's owner controls, which makes it useless for
# the question actually being asked here — "who is this stranger hammering me?"
_PLACE_UNIVERSE_URL = "apis.roblox.com/universes/v1/places/{id}/universe"
_UNIVERSE_DETAIL_URL = "games.roblox.com/v1/games"


def _lookup_json(url: str, params: dict = None):
    """Fetch one public Roblox JSON endpoint for the admin lookup. Returns (data, error).

    Tries the proxy stack first, so the request goes out through rotation when
    that is available and our own IP stays out of it. Falls back to a direct
    call if routing has nothing to offer — which is precisely the situation this
    tool is used in: you want to identify whoever is hammering you at the moment
    the token budget is spent and every method is busy, and a lookup that only
    works when nothing is wrong is a lookup that never works when it matters.

    The fallback is safe to make directly: these endpoints are public, take no
    credentials, and are called once per admin click, so they cost the token
    budget nothing and cannot look like bot traffic.
    """
    ok, body = proxy.request(url, method="get", headers={}, params=params or {})
    if not ok:
        body, error = _lookup_direct(url, params)
        if error:
            return None, error
    try:
        return json.loads(body), ""
    except (ValueError, TypeError):
        return None, "Upstream returned a non-JSON body"


def _lookup_direct(url: str, params: dict = None):
    """Last-resort direct fetch for the admin lookup. Returns (body, error)."""
    started = time.monotonic()
    try:
        resp = proxy.requests.get(f"https://{url}", params=params or {}, timeout=proxy._timeout())
    except Exception as error:
        diagnostics.log_internal_request(
            "admin_lookup", False, "error", time.monotonic() - started, url, f"{type(error).__name__}: {error}"
        )
        return "", f"{type(error).__name__}: {error}"[:300]
    ok = resp.status_code == 200
    diagnostics.log_internal_request("admin_lookup", ok, resp.status_code, time.monotonic() - started, url)
    diagnostics.log_status_code(resp.status_code, source="Internal")
    if not ok:
        return "", f"Roblox returned HTTP {resp.status_code}"
    return resp.text, ""


@app.route("/admin/lookup/place", methods=["POST"], endpoint="admin_lookup_place")
@requires_admin
def admin_lookup_place():
    """Identify the experience (and its owner) behind a place or universe id.

    The Roblox-Id header on an inbound request is a PLACE id, so this is the
    step that turns "something called 75227619283955 is hammering me" into a
    named experience with a named owner — which is what a report, a block, or a
    conversation with the developer all need.
    """
    data = get_json_dict() or {}
    raw = str(data.get("id", "")).strip()
    if not raw.isdigit():
        return jsonify({"Message": "Enter a numeric place or universe ID"}), 400
    kind = "universe" if data.get("kind") == "universe" else "place"
    result = {"Query": raw, "Kind": kind, "PlaceId": raw if kind == "place" else "", "UniverseId": ""}

    universe_id = raw
    if kind == "place":
        payload, error = _lookup_json(_PLACE_UNIVERSE_URL.format(id=raw))
        if error:
            return jsonify({"Message": f"Could not resolve that place: {error}", **result}), 502
        universe_id = str((payload or {}).get("universeId", "") or "")
        if not universe_id:
            return jsonify({"Message": "Roblox did not return a universe for that place", **result}), 404
    result["UniverseId"] = universe_id

    payload, error = _lookup_json(_UNIVERSE_DETAIL_URL, {"universeIds": universe_id})
    if error:
        return jsonify({"Message": f"Could not load that experience: {error}", **result}), 502
    entries = (payload or {}).get("data") or []
    if not entries:
        return jsonify({"Message": "Roblox returned no experience for that ID", **result}), 404
    game = entries[0]
    creator = game.get("creator") or {}
    result.update(
        {
            "Name": game.get("name", ""),
            "Description": str(game.get("description", ""))[:600],
            "RootPlaceId": game.get("rootPlaceId", ""),
            "Created": game.get("created", ""),
            "Updated": game.get("updated", ""),
            "Playing": game.get("playing", 0),
            "Visits": game.get("visits", 0),
            "MaxPlayers": game.get("maxPlayers", 0),
            "FavoritedCount": game.get("favoritedCount", 0),
            "CreatorId": creator.get("id", ""),
            "CreatorName": creator.get("name", ""),
            "CreatorType": creator.get("type", ""),
            "CreatorVerified": bool(creator.get("hasVerifiedBadge")),
            "Url": f"https://www.roblox.com/games/{game.get('rootPlaceId', '')}",
            "CreatorUrl": _creator_url(creator),
        }
    )
    return jsonify(result), 200


def _creator_url(creator: dict) -> str:
    kind = str(creator.get("type", "")).lower()
    ident = creator.get("id", "")
    if not ident:
        return ""
    if kind == "group":
        return f"https://www.roblox.com/groups/{ident}"
    return f"https://www.roblox.com/users/{ident}/profile"


@app.route("/admin/internal/endpoints", methods=["GET"], endpoint="admin_internal_endpoints")
@requires_admin
def admin_internal_endpoints():
    """Every upstream call Roxy makes on its OWN behalf, and their live health.

    Exists to settle a specific worry: that adding a block or rate rule could cut
    the token health check off at the knees. It cannot — internal probes never
    enter the proxy route, so no rule on it applies to them — and this endpoint
    is how that is checked rather than trusted.
    """
    return (
        jsonify(
            {
                "Endpoints": proxy.internal_endpoints(),
                "Stats": diagnostics.get_diagnostics().get("InternalRequests", {}),
                "Note": (
                    "Internal probes call Roblox directly and never pass through the proxy route, "
                    "so endpoint blocks, rate rules, request filters, throttling and pause cannot "
                    "affect them. Client traffic to a similarly-named endpoint is unrelated."
                ),
            }
        ),
        200,
    )


@app.route("/admin/fingerprints/ignore", methods=["POST"], endpoint="admin_ignore_header_values")
@requires_admin
def admin_ignore_header_values():
    """Stop (or resume) enumerating one header's distinct values.

    For headers that carry a unique value per request there is nothing to learn
    from the list and building it is what used to fill the data file."""
    data = get_json_dict()
    if data is None or not data.get("name"):
        return jsonify({"Message": "Missing header name"}), 400
    name = str(data["name"])
    if data.get("ignore", True):
        ok, message = runtime.add_ignored_value_header(name, str(data.get("note", "")))
        if ok:
            # Drop what was already collected, everywhere, so the setting takes
            # effect immediately instead of at the next eviction.
            diagnostics.clear_fingerprint_header(bool(data.get("blocked")), name, values_only=True)
            message = f'No longer recording values for "{name}"'
    else:
        ok, message = runtime.remove_ignored_value_header(name)
        if ok:
            message = f'Recording values for "{name}" again'
    return jsonify({"Message": message, "IgnoredValueHeaders": runtime.get_ignored_value_headers()}), 200 if ok else 400


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
    # Must be a string before it reaches the lookup: dict.get() raises TypeError
    # on an unhashable key, so a JSON body of {"target": []} became a 500 (and an
    # error email) instead of a 400.
    if not isinstance(target, str):
        return jsonify("Clear target must be a string"), 400
    if target == "all":
        names = diagnostics.CLEAR_ALL_NAMES  # Every section, each exactly once.
    else:
        names = diagnostics.CLEAR_TARGETS.get(target)
    if not names:
        return jsonify(f"Unknown clear target: {target}"), 400
    if target in ("tarpit", "all"):
        # The per-IP arrival times live in the shared tarpit file, not in the
        # stats. Leaving them behind would make the first request after a clear
        # report a gap measured from before it.
        tarpit.reset()
    if target in ("live", "all"):
        capture.reset()  # Captured bodies live in their own file, so clear_stats can't reach them.
    if target == "all":
        # Same story for the worker registry: the fleet's request counts are
        # kept per worker process, so "Clear all data" left them standing and
        # the totals afterwards looked like the clear had partly failed.
        workers.reset_counts()
    ok = diagnostics.clear_stats(names)
    if ok:
        return jsonify("Cleared everything" if target == "all" else "Cleared"), 200
    return jsonify("Cleared in memory, but the data file could not be written"), 200


@app.route("/admin/probes/clear", methods=["POST"], endpoint="admin_clear_probes")
@requires_admin
def admin_clear_probes():
    diagnostics.clear_stats(diagnostics.CLEAR_TARGETS["probes"])
    return jsonify("Probe records cleared"), 200


@app.route("/admin/throttle/bypass", methods=["POST"], endpoint="admin_add_throttle_bypass")
@requires_admin
def admin_add_throttle_bypass():
    data = get_json_dict()
    if data is None or not str(data.get("ip", "")).strip():
        return jsonify({"Message": "Missing IP"}), 400
    ok, message = runtime.add_throttle_bypass(str(data["ip"]), data.get("expires_in", 0), str(data.get("note", "")))
    status = 200 if ok else 400
    return jsonify({"Message": message, "ThrottleBypassIps": runtime.get_throttle_bypass_ips()}), status


@app.route("/admin/throttle/bypass/remove", methods=["POST"], endpoint="admin_remove_throttle_bypass")
@requires_admin
def admin_remove_throttle_bypass():
    data = get_json_dict()
    if data is None or not str(data.get("ip", "")).strip():
        return jsonify({"Message": "Missing IP"}), 400
    ok, message = runtime.remove_throttle_bypass(str(data["ip"]))
    status = 200 if ok else 400
    return jsonify({"Message": message, "ThrottleBypassIps": runtime.get_throttle_bypass_ips()}), status


@app.route("/admin/endpoints/block", methods=["POST"], endpoint="admin_block_endpoint")
@requires_admin
def admin_block_endpoint():
    data = get_json_dict()
    if data is None or not data.get("pattern"):
        return jsonify({"Message": "Missing pattern"}), 400
    ok, message = runtime.block_endpoint(
        str(data["pattern"]),
        str(data.get("note", "")),
        str(data.get("type", "glob")),
        str(data.get("message", "")),
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
        str(data.get("message", "")),
        str(data.get("note", "")),
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
        str(data.get("message", "")),
    )
    status = 200 if ok else 400
    return jsonify({"Message": message, "HeaderRules": runtime.get_header_rules()}), status


def _parse_header_text(raw: str) -> list:
    """Parse pasted "Name: Value" lines into (name, value) pairs.

    Deliberately forgiving — this is a scratchpad the admin pastes real captured
    headers into, so a leading "GET /path HTTP/1.1" request line, blank lines and
    stray whitespace are skipped rather than rejected.
    """
    pairs = []
    for line in str(raw or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue  # Request line / junk.
        name, _, value = line.partition(":")
        name = name.strip()
        if name:
            pairs.append((name[:200], value.strip()[:2000]))
    return pairs


MAX_TEST_HEADERS = 200


@app.route("/admin/headers/test", methods=["POST"], endpoint="admin_test_header_rule")
@requires_admin
def admin_test_header_rule():
    """Dry-run the request filters against sample headers, changing nothing.

    Runs runtime.explain_header_rules, which evaluates through the very function
    the proxy uses on every request — so "would this be blocked?" is answered by
    the real decision, not by a description of it. A draft rule can be tested
    before it is saved, which is the point: you find out whether a filter works
    (and what else it would catch) while you can still change it.
    """
    data = get_json_dict()
    if data is None:
        return jsonify({"Message": "Invalid request"}), 400
    raw = data.get("headers")
    if isinstance(raw, dict):
        pairs = [(str(k)[:200], str(v)[:2000]) for k, v in raw.items()]
    elif isinstance(raw, list):
        pairs = [(str(p[0])[:200], str(p[1])[:2000]) for p in raw if isinstance(p, (list, tuple)) and len(p) >= 2]
    else:
        pairs = _parse_header_text(raw)
    if not pairs:
        return jsonify({"Message": "Add at least one header to test against"}), 400
    if len(pairs) > MAX_TEST_HEADERS:
        return jsonify({"Message": f"Too many headers (max {MAX_TEST_HEADERS})"}), 400
    draft = data.get("draft") if isinstance(data.get("draft"), dict) else None
    result = runtime.explain_header_rules(pairs, draft=draft)
    result["Headers"] = [{"Name": name, "Value": value} for name, value in pairs]
    return jsonify(result), 200


@app.route("/admin/headers/rule/clear", methods=["POST"], endpoint="admin_clear_header_rule")
@requires_admin
def admin_clear_header_rule():
    data = get_json_dict()
    if data is None or not data.get("id"):
        return jsonify({"Message": "Missing rule id"}), 400
    ok, message = runtime.remove_header_rule(str(data["id"]))
    status = 200 if ok else 400
    return jsonify({"Message": message, "HeaderRules": runtime.get_header_rules()}), status


@app.route("/admin/invalidate/<token>", methods=["GET", "POST"], endpoint="admin_invalidate")
def admin_invalidate(token: str):
    """The emergency kill switch from the emailed login alert.

    GET only renders a confirmation page; the token is consumed by the POST. It
    used to be consumed on GET, which meant Gmail's and every mail gateway's
    link prefetcher burned the single-use token before the admin ever clicked
    it -- so the one link that exists for an emergency was reliably dead during
    the emergency.
    """
    if request.method == "GET":
        return render_template("invalidate.html", token=token), 200
    if runtime.consume_invalidation_token(token):
        runtime.bump_session_epoch()
        return render_template("invalidate.html", token="", done=True), 200
    return render_template("invalidate.html", token="", failed=True), 404


@app.route("/health", methods=["GET"], endpoint="health")
def health():
    # Includes the stats-file size so an external monitor can alarm on the one
    # metric that predicts trouble, without needing a session.
    persistence = storage.get_status()
    return (
        jsonify(
            {
                "Status": "ok",
                "Paused": runtime.is_paused(),
                "DataBytes": persistence["DataBytes"],
                "DataLimitBytes": persistence["DataLimitBytes"],
                "PersistenceOK": persistence["Writable"] and not persistence["Oversize"],
            }
        ),
        200,
    )


@app.route("/admin/<path:unknown>", methods=["GET", "POST", "PATCH", "PUT", "DELETE"], endpoint="admin_not_found")
def admin_not_found(unknown: str):
    """Catch mistyped or stale admin URLs.

    Without this they fall through to the proxy catch-all below and get logged
    as "Non-Roblox URL" probe attempts, so every typo and every old bookmark
    shows up in the security log as an attack.
    """
    return jsonify("Not Found"), 404


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
    "X-Roblox-Token",  # Roxy doesn't support authenticated requests; also rejected outright (see _detect_auth_attempt).
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


def _detect_auth_attempt(headers) -> str | None:
    """Roxy does not support authenticated (ROBLOSECURITY) requests. Detect an
    attempt to send one — via the documented X-Roblox-Token header, or any header
    whose value carries an actual Roblox session cookie (identified by the
    literal warning prefix Roblox itself bakes into every real cookie value, so
    this catches one smuggled in via any other header too). Returns a short
    reason for the probe log, or None if the request is clean."""
    for name, value in headers.items():
        if name.lower() == "x-roblox-token":
            return "X-Roblox-Token header"
        if config.TOKEN_PREFIX in (value or ""):
            return f'"{name}" header carried a ROBLOSECURITY-shaped value'
    return None


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
        # br/zstd without the optional decoder packages installed makes a
        # Cloudflare-fronted upstream reply compressed and the client
        # receives raw binary gibberish.
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


def _body_text(body) -> str:
    """A decoded, length-capped view of a request body for the live feed."""
    if not body:
        return ""
    try:
        text = body.decode("utf-8", errors="replace") if isinstance(body, (bytes, bytearray)) else str(body)
    except Exception:
        return "[unreadable body]"
    if len(text) > config.MAX_LIVE_BODY_LENGTH:
        return text[: config.MAX_LIVE_BODY_LENGTH] + "… [truncated]"
    return text


class RequestContext:
    """Everything about one inbound proxy request that the bookkeeping needs.

    Gathered once at the top of proxy_page so that every exit path — served,
    throttled, blocked, filtered, paused, probed — can be recorded identically.
    Previously only the SUCCESSFUL path was recorded to the live feed, which
    meant the one view built for watching traffic in real time was blind to
    exactly the traffic worth watching: an attack that is being refused produced
    a counter going up and nothing else. Refusals are now first-class events.
    """

    __slots__ = ("ip", "path", "method", "user_agent", "caller_id", "headers", "query", "started", "bypass", "_body")

    def __init__(self):
        self.ip = get_client_ip()
        self.path = ""
        self.method = request.method
        self.user_agent = request.user_agent.string
        # Roblox stamps the calling PLACE id on every HttpService request. It is
        # self-reported and therefore not proof of anything, but it is the only
        # identifier that survives a game's server IPs churning — which makes it
        # the one that actually names a caller.
        self.caller_id = (request.headers.get("Roblox-Id") or "").strip()[:64]
        self.headers = request.headers
        self.query = request.query_string.decode("utf-8", "replace")[:2000]
        self.started = time.monotonic()
        self.bypass = False
        self._body = None

    @property
    def body(self) -> bytes:
        """The raw request body, read at most once.

        Werkzeug has already buffered it (MAX_CONTENT_LENGTH caps it at 2 MB), so
        this is a memory read rather than I/O — but it is only touched when
        something is going to record it.
        """
        if self._body is None:
            try:
                self._body = request.get_data() or b""
            except Exception:
                self._body = b""
        return self._body

    def elapsed(self) -> float:
        return time.monotonic() - self.started


def _record_outcome(ctx: RequestContext, status: int, outcome: str, **extra):
    """Record one completed proxy request in every view that should show it.

    Single funnel on purpose. The alternative — each branch remembering to call
    the four or five right loggers — is how the endpoint table ended up able to
    show the last caller for some paths and not others, and how refusals ended
    up missing from the live feed entirely. One call site cannot drift.

    Best-effort throughout: diagnostics must never be able to fail a request it
    is only describing.
    """
    try:
        reason = extra.get("reason", "")
        source = extra.get("source", "Roxy")
        trace = extra.get("trace") or {}
        served = outcome == "served"
        # Which status code we ANSWERED with, and who decided it. For a refusal
        # that is us; for a served request the upstream status is recorded
        # separately by proxy.py, so this one is not double-counted as Roblox's.
        diagnostics.log_status_code(status, source=source)
        if not served:
            diagnostics.log_refusal(
                reason or outcome,
                status,
                ip=ctx.ip,
                path=ctx.path,
                category=extra.get("category", ""),
                detail=extra.get("detail", ""),
            )
        if runtime.get_setting("activity_tracking", 1):
            diagnostics.log_traffic(
                ctx.ip, ctx.caller_id, ctx.method, ctx.path, status, outcome, user_agent=ctx.user_agent
            )
        capture_id = _capture(ctx, status, outcome, trace, extra.get("response_body"))
        diagnostics.log_live_request(
            dict(
                Date=time.time(),
                IP=ctx.ip,
                UserAgent=ctx.user_agent,
                Method=ctx.method,
                URL=ctx.path,
                Query=ctx.query,
                Headers=sanitize_headers(ctx.headers),
                Body=_body_text(ctx.body),
                StatusCode=status,
                # The three fields that make the feed diagnostic rather than
                # decorative: what we did, why, and what Roblox actually said.
                Outcome=outcome,
                Reason=reason,
                Source=source,
                CallerId=ctx.caller_id,
                UpstreamStatus=trace.get("UpstreamStatus", ""),
                UpstreamMethod=trace.get("Method", ""),
                UpstreamError=trace.get("UpstreamError", ""),
                Attempts=trace.get("Attempts", 0),
                Retries=trace.get("Retries", 0),
                Duration=round(ctx.elapsed(), 4),
                Bypass=ctx.bypass,
                CaptureId=capture_id,
            )
        )
    except Exception:
        pass


def _capture(ctx: RequestContext, status: int, outcome: str, trace: dict, response_body) -> str:
    """Stash the full request/response bodies for this request, if capture is on.

    Kept out of the diagnostics stores deliberately — see capture.py for why the
    bytes live under their own byte budget and TTL rather than in the stats file.
    Returns the capture id to hang off the live-feed entry, or "".
    """
    try:
        if not capture.is_enabled():
            return ""
        return capture.record(
            {
                "Date": time.time(),
                "IP": ctx.ip,
                "Method": ctx.method,
                "URL": ctx.path,
                "Query": ctx.query,
                "CallerId": ctx.caller_id,
                "UserAgent": ctx.user_agent,
                "Outcome": outcome,
                "Status": status,
                "UpstreamStatus": trace.get("UpstreamStatus", ""),
                "UpstreamMethod": trace.get("Method", ""),
                "RequestHeaders": capture.redact_headers(ctx.headers),
                "RequestBody": ctx.body,
                "ResponseHeaders": capture.redact_headers(trace.get("UpstreamHeaders") or {}),
                "ResponseBody": response_body,
            }
        )
    except Exception:
        return ""


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
    ctx = RequestContext()
    ctx.path = dst
    ip, user_agent = ctx.ip, ctx.user_agent
    # Counted before any decision, so refusals count too: this is "traffic aimed
    # at the proxy", the number that distinguishes an idle service from a busy
    # one. The fleet's other counter includes the dashboard's own polling and so
    # keeps climbing even when nobody is using the proxy at all.
    workers.count_proxied()

    def refuse(resp, status, outcome, reason="", **extra):
        """Answer a refusal and record it everywhere at once."""
        response_headers = extra.pop("headers", {})
        _record_outcome(ctx, status, outcome, reason=reason or outcome, **extra)
        return _with_throttle_headers(resp, ip, **response_headers), status

    if runtime.is_paused():
        diagnostics.log_pause_drop()
        return refuse(jsonify(runtime.pause_message()), 503, "paused", headers={"Roxy_Paused": "True"})

    # Throttle-bypass allowlist: an admin-listed IP skips the rate-limit 429s
    # (per-IP throttle, throttle-all, per-endpoint rate rules) for load/spam
    # testing. It does NOT bypass pause, endpoint blocks, header rules, or the
    # Token safety budget — so the real routing behavior is still exercised.
    bypass = ctx.bypass = runtime.is_throttle_bypassed(ip)

    def hold(category: str, reason: str = ""):
        """Sit on a refusal before answering it (see tarpit.py).

        Placed immediately before the error is built, so the caller receives the
        byte-identical response they always did — just later. Bypass IPs are
        never held: that allowlist is how the admin tests against their own
        server, and a 20-second wait per probe would make that useless.

        `reason` identifies the SPECIFIC rule, not just its kind: with several
        filters armed, "a filter caught something" is not an answer to "which
        one is doing this?".
        """
        if not bypass:
            tarpit.hold(ip, category, reason)

    # Global throttle-all: a softer alternative to a full pause. Every IP is
    # rate-limited to a configurable N requests per P seconds; requests within
    # that budget proceed normally (still subject to the regular per-IP and
    # per-endpoint limits), the rest get a friendly 429.
    if not bypass and runtime.is_throttle_all():
        allowed, retry_in = throttle.check_global_throttle(ip)
        if not allowed:
            diagnostics.log_throttle_all_drop()
            limits = runtime.get_throttle_all_state()
            hold("throttle_all", f"Global limit {limits.get('Limit')} per {limits.get('Period')}s")
            return refuse(
                jsonify(runtime.throttle_all_message()),
                429,
                "throttle_all",
                headers={"Roxy_Throttle_Reset": retry_in, "Roxy_Global_Throttled": "True"},
            )

    if not bypass and throttle.is_throttled(ip):
        hold(
            "throttle",
            f"Per-IP limit {runtime.get_setting('allowed_requests_per_minute', config.ALLOWED_REQUESTS_PER_MINUTE)} "
            f"per {runtime.get_setting('throttle_reset_duration', config.THROTTLE_RESET_DURATION)}s",
        )
        resp, status = throttled_response(ip)
        _record_outcome(ctx, status, "throttled", reason="Per-IP rate limit")
        return resp, status

    if dst in path_ignore_set:
        return refuse(jsonify("Not Found"), 404, "ignored_path")

    if dst != escape(dst):
        diagnostics.log_exploit_attempt(ip, f'Invalid URL: "{dst}"', user_agent)
        hold("probe", "Invalid URL (unsafe characters)")
        return refuse(jsonify("Invalid URL"), 404, "probe", reason="Invalid URL", category="probe")

    if not validate_url(dst):
        diagnostics.log_exploit_attempt(ip, f'Non-Roblox URL: "{dst}"', user_agent)
        hold("probe", f"Non-Roblox URL: {dst.split('/', 1)[0][:60]}")
        return refuse(jsonify("Not a Roblox URL"), 404, "probe", reason="Non-Roblox URL", category="probe")

    # Roxy does not support authenticated requests: reject and log any attempt to
    # send a Roblox session token/cookie, before anything upstream is touched.
    auth_attempt = _detect_auth_attempt(request.headers)
    if auth_attempt:
        diagnostics.log_exploit_attempt(ip, f"Sent a ROBLOSECURITY token ({auth_attempt})", user_agent)
        hold("auth_attempt", auth_attempt)
        return refuse(
            jsonify("Requests requiring authentication are not allowed with this proxy."),
            400,
            "auth_attempt",
            reason="Sent a ROBLOSECURITY token",
            detail=auth_attempt,
        )

    # Header rules deny abusive clients (e.g. exploit fingerprints) outright.
    # By default the blocked caller gets a normal-looking THROTTLE 429 —
    # indistinguishable from a real rate-limit — so the exploiter concludes
    # they're sending too much rather than realizing they're filtered. A rule may
    # override that with its own message, which is useful for redirecting a
    # legitimate integration and a giveaway against a hostile one; that trade-off
    # is the admin's to make, per rule.
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
        # Name the filter AND what it matched on, so a row in the tarpit table is
        # actionable without cross-referencing the Request Filters list.
        matched = header_rule.get("MatchedHeader", "?")
        hold("header_rule", f"Filter {header_rule.get('Id', '?')} (matched {matched})")
        custom = str(header_rule.get("Message", "")).strip()
        if custom:
            resp, status = jsonify(custom), 429
            _with_throttle_headers(resp, ip, Roxy_Throttle_Reset=reset_in, Roxy_Throttled="True")
        else:
            resp, status = throttled_response(ip, reset_in=reset_in)
        _record_outcome(
            ctx, status, "header_rule", reason=f"Request filter: {header_rule.get('Id', '?')}", category="header_rule"
        )
        return resp, status

    block = runtime.match_endpoint_block(dst)
    if block:
        diagnostics.log_blocked_endpoint(dst, request.method, ip, block.get("Pattern", ""))
        hold("blocked_endpoint", f"Block rule: {block.get('Pattern', '?')}")
        message = str(block.get("Message", "")).strip() or "This endpoint is currently blocked."
        return refuse(
            jsonify(message),
            403,
            "blocked_endpoint",
            reason=f"Blocked endpoint: {block.get('Pattern', '')}",
            category="blocked_endpoint",
            headers={"Roxy_Blocked": "True"},
        )

    if not bypass:
        endpoint_allowed, endpoint_retry, endpoint_pattern = throttle.check_endpoint_limit(ip, dst)
        if not endpoint_allowed:
            diagnostics.log_rate_limited_endpoint(dst, request.method, ip, endpoint_pattern)
            hold("endpoint_rule", f"Rate rule: {endpoint_pattern}")
            rule = runtime.match_endpoint_rule(dst) or {}
            custom = str(rule.get("Message", "")).strip()
            message = custom or f"This endpoint is rate-limited for you; try again in {endpoint_retry} seconds."
            resp = jsonify(message)
            resp.headers["Roxy-Requests-Left"] = throttle.get_requests_left(ip)
            resp.headers["Roxy-Throttle-Reset"] = endpoint_retry
            resp.headers["Roxy-Throttled"] = "True"
            resp.headers["Roxy-Endpoint-Limited"] = "True"
            _record_outcome(
                ctx,
                429,
                "endpoint_rule",
                reason=f"Endpoint rate rule: {endpoint_pattern}",
                category="endpoint_rule",
            )
            return resp, 429
        # Count the request toward the per-IP limit (skipped for bypass IPs so
        # their spam testing doesn't mark them throttled in the dashboard).
        throttle.update_throttling(ip, made_request=True)
    safe_headers = sanitize_headers(request.headers)
    safe_headers_json = json.dumps(safe_headers)
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

    data = ctx.body if request.method in ("POST", "PATCH", "PUT", "DELETE") else None

    # Remove/overwrite headers that could cause issues or identify us/the visitor.
    headers = {}
    stripped = {name.lower() for name in _STRIPPED_REQUEST_HEADERS}
    for key, value in request.headers.items():
        kl = key.lower()
        if kl in stripped or any(kl.startswith(p) for p in _STRIPPED_HEADER_PREFIXES):
            continue
        headers[key] = value
    headers.update(get_fake_headers())

    # Handle proxying the request. `trace` comes back describing what actually
    # happened upstream — which method served it, Roblox's own status, how many
    # attempts — none of which the (successful, response) pair can express.
    trace = {}
    successful, response = proxy.request(
        str(escape(dst)),
        method=request.method,
        headers=headers,
        params=params,
        data=data,
        trace=trace,
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
    outcome = "served" if successful else "upstream_failed"
    # Recorded AFTER the upstream call so the endpoint row carries what came back,
    # not just what went out — the answer is usually the interesting half.
    diagnostics.log_endpoint(
        dst,
        request.method,
        safe_headers_json,
        ip,
        Query=ctx.query,
        Body=_body_text(data),
        Status=status,
        UpstreamStatus=trace.get("UpstreamStatus", ""),
        UpstreamMethod=trace.get("Method", ""),
        Outcome=outcome,
        UserAgent=user_agent,
        CallerId=ctx.caller_id,
    )
    _record_outcome(
        ctx,
        status,
        outcome,
        reason="" if successful else (trace.get("Outcome") or "upstream failure"),
        # A served response is Roblox's answer relayed; only its FAILURE modes are
        # ours. proxy.py already counted the real upstream status, so counting a
        # relayed 200 again as "Roblox" would double it.
        source="Roxy" if not successful else "Relay",
        trace=trace,
        response_body=response,
    )
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
            f"{request.method} {request.path}\n" f"IP: {get_client_ip()}\n\n" f"{traceback.format_exc()}",
        )
    except Exception:
        pass
    return jsonify("Internal Server Error"), 500


if __name__ == "__main__":
    app.run(debug=False)
