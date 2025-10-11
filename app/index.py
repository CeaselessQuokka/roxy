import auth
import diagnostics
import config
import file_watcher
import proxy
import json
import requests
import urllib
import re
import two_fa
from flask import Flask, request, render_template, session, redirect, url_for
from markupsafe import escape

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = auth.read_admin_credentials()[3]

app.config.update(
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_SECURE=False,  # Set to True if using HTTPS.
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800 if config.DEBUG else 300,
)


## Handle web pages.
# Handle home page.
@app.route("/", methods=["GET", "POST"])
def home_page():
    return render_template("home.html")


# @app.route("/credits")
# def credits_page():
#     return render_template("credits.html")


# Handle admin page.
def validate_login(data: dict) -> bool:
    if not all(k in data for k in ("Username", "Password")):
        return False

    username = data["Username"]
    password = data["Password"]
    admin_username, admin_password, *_ = auth.read_admin_credentials()
    return username == admin_username and password == admin_password


def requires_admin(fn: callable):
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("home_page"))
        return fn(*args, **kwargs)

    return wrapper


# TODO: generate better challenge, use secrets hash and use ua + ip to get encoded from hmac using the secrets hash as key, that result is now the hash for the challenge or something
# TODO: test every way to input and make sure no errors occur
@app.route("/admin", methods=["GET", "POST"])
def admin_page():
    if request.method == "POST":
        data = request.json
        if "IsLogin" in data:
            if validate_login(request.json):
                two_fa.send_2fa("hurricanedavensb+proxy@gmail.com")
                return "Success", 200
            diagnostics.log_login_attempt(request.access_route[0], False)
            return "Invalid credentials", 403
        elif "Is2FA" in data:
            if not two_fa.is_code_valid(data.get("TwoFA", "")):
                diagnostics.log_exploit_attempt(request.access_route[0], "Invalid 2FA code", request.user_agent.string)
                return "2FA code expired", 401  # Give false impression that code expired instead of 2FA being wrong.
            diagnostics.log_login_attempt(request.access_route[0], True)
            session["is_admin"] = True
            return "Success", 200
        else:
            return "Invalid request", 400
    elif request.method == "GET":
        if session.get("is_admin"):
            return redirect(url_for("admin_dashboard"))
        return render_template("admin.html")
    else:
        diagnostics.log_exploit_attempt(request.access_route[0], "Invalid method on /admin", request.user_agent.string)
        return "Method not allowed", 405


@app.route("/admin/dashboard", methods=["GET"], endpoint="admin_dashboard")
@requires_admin
def admin_dashboard():
    return render_template("dashboard.html")


@app.route("/admin/diagnostics", methods=["GET"], endpoint="admin_diagnostics")
@requires_admin
def admin_diagnostics():
    return diagnostics.get_diagnostics()


@app.route("/admin/tokens", methods=["POST"], endpoint="admin_set_tokens")
@requires_admin
def admin_set_tokens():
    data = request.json
    if not "tokens" in data:
        return "Missing tokens", 400
    proxy.update_tokens(data["tokens"])
    return "Success", 200


## Handle proxying requests.
def validate_url(url: str) -> bool:
    return re.match(r"^[a-z]+\.roblox\.com/", url, re.IGNORECASE) != None


# Handle Get proxying.
@app.route("/<path:dst>", methods=["GET", "POST", "PATCH", "PUT", "DELETE"])
def proxy_page(dst: str):
    if dst != escape(dst):
        diagnostics.log_exploit_attempt(request.access_route[0], f'Invalid URL: "{dst}"', request.user_agent.string)
        return "Invalid URL", 404

    if not validate_url(dst):
        diagnostics.log_exploit_attempt(request.access_route[0], f'Non-Roblox URL: "{dst}"', request.user_agent.string)
        return "Not a Roblox URL", 404

    params = dict(request.args)
    data = request.data if request.method in ("POST", "PATCH", "PUT", "DELETE") else None

    # Remove/overwrite headers that could cause issues.
    headers = dict(request.headers)
    headers.pop("Host", None)
    headers.pop("Roblox-Id", None)
    headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
    )

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
    return f"<pre>{response}</pre>" if successful and response is not None else (response, 500)


if __name__ == "__main__":
    app.run(debug=False)  # TODO: MAKE DEBUG = FALSE WHEN DEPLOYING
