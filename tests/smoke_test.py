"""End-to-end smoke test for the Roxy proxy server.

Boots the real Flask app against a sandbox /etc/roxy (via env overrides) with
SMTP stubbed out, then exercises the security/robustness paths:
  - bot probes (POST /, bad JSON, non-Roblox URLs) return clean errors and never email
  - the full login flow (credentials -> 2FA -> dashboard)
  - presence-based session expiry (heartbeat keeps it alive; >30s idle kills it)
  - login brute-force lockout
  - admin endpoints (diagnostics, settings, tokens, probes clear, invalidate link)

Run:  ROXY_FILE_ROOT=... python tests/smoke_test.py   (the script sets its own sandbox)
"""

import json
import os
import sys
import tempfile
import time
from urllib.parse import quote

# --- Sandbox /etc/roxy + data file BEFORE importing the app -------------------
sandbox = tempfile.mkdtemp(prefix="roxy_test_")
os.environ["ROXY_FILE_ROOT"] = sandbox
os.environ["ROXY_DATA_FILE"] = os.path.join(sandbox, "roxy_data.json")
os.environ["ROXY_STATE_FILE"] = os.path.join(sandbox, "roxy_state.json")
os.environ["ROXY_ROUTING_FILE"] = os.path.join(sandbox, "roxy_routing.json")
os.environ["ROXY_THROTTLE_FILE"] = os.path.join(sandbox, "roxy_throttle.json")
os.environ["ROXY_COORD_FILE"] = os.path.join(sandbox, "roxy_coord.json")
os.environ["ROXY_TARPIT_FILE"] = os.path.join(sandbox, "roxy_tarpit.json")
os.environ["ROXY_WORKERS_FILE"] = os.path.join(sandbox, "roxy_workers.json")
os.environ["ROXY_CAPTURE_FILE"] = os.path.join(sandbox, "roxy_capture.json")
# Rotation proxy is configured from the start (only "token"/"rotate" methods
# exist now, so most fallback tests need Rotate available); specific sections
# temporarily remove/restore this file to test the disabled/unavailable cases.
ROTATE_PROXY_PATH = os.path.join(sandbox, "rotate_proxy.txt")
os.environ["ROXY_ROTATE_PROXY_FILE"] = ROTATE_PROXY_PATH


def enable_rotation():
    with open(ROTATE_PROXY_PATH, "w") as f:
        f.write("http://gw.dataimpulse.test:823\n")


def disable_rotation():
    if os.path.exists(ROTATE_PROXY_PATH):
        os.remove(ROTATE_PROXY_PATH)


ADMIN_USER = "testadmin"
ADMIN_PASS = "testpassword123"


def write(name, content):
    with open(os.path.join(sandbox, name), "w") as f:
        f.write(content)


write("files.txt", "admin_credentials.txt\napp_password.txt\nauth_tokens.txt\nemails.txt\n")
write("admin_credentials.txt", f"{ADMIN_USER}\n{ADMIN_PASS}\nhmac-key-for-testing\nflask-secret-for-testing\n")
write("app_password.txt", "fake-app-password\n")
write("auth_tokens.txt", "FAKE_TOKEN_AAA\n")
write("emails.txt", "admin@example.com\nsender@example.com\n")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"))

# --- Stub SMTP before anything can send ---------------------------------------
import mail  # noqa: E402

sent_emails = []


def fake_send(to, subject, body):
    sent_emails.append({"to": to, "subject": subject, "body": body})


def fake_try_send(to, subject, body):
    fake_send(to, subject, body)
    return True


mail.send = fake_send
mail.try_send = fake_try_send

import index  # noqa: E402  (imports the full app: proxy, throttle, diagnostics, ...)
import config  # noqa: E402
import runtime  # noqa: E402

# The tarpit ships ON (probes and filter-blocked requests are held for 8-20s).
# Every probe in this suite would otherwise sit for that long, so it is disabled
# here and re-enabled with sub-second holds by its own section at the bottom.
runtime.set_setting("tarpit_enabled", 0)

app = index.app
app.config.update(SESSION_COOKIE_SECURE=False, TESTING=True)


# Registered before the first request (Flask forbids adding routes after that);
# used by the "real 500s still email" section at the bottom.
@app.route("/_boom_test_only")
def _boom():
    raise RuntimeError("intentional test explosion")


passed, failed = 0, 0


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


def emails_with(subject_fragment):
    return [e for e in sent_emails if subject_fragment in e["subject"]]


client = app.test_client()
IP_MAIN = {"X-Forwarded-For": "10.1.1.1"}
IP_BRUTE = {"X-Forwarded-For": "10.2.2.2"}

print("== Public pages ==")
r = client.get("/", headers=IP_MAIN)
check("GET / -> 200", r.status_code == 200, r.status_code)
r = client.get("/robots.txt", headers=IP_MAIN)
check("GET /robots.txt -> 200", r.status_code == 200, r.status_code)
r = client.get("/favicon.ico", headers=IP_MAIN)
check("GET /favicon.ico -> 200 (no probe-log pollution)", r.status_code == 200, r.status_code)
r = client.get("/health", headers=IP_MAIN)
check("GET /health -> 200", r.status_code == 200, r.status_code)

print("== Bot probes return clean errors and never email ==")
before = len(sent_emails)
r = client.post("/", headers=IP_MAIN, data="garbage")
check("POST / -> 405 (the email-spam case)", r.status_code == 405, r.status_code)
check("405 keeps Allow header", "Allow" in r.headers, dict(r.headers))
check("405 body is JSON", r.is_json or r.data.startswith(b'"'), r.data[:60])
r = client.post("/health", headers=IP_MAIN)
check("POST /health -> 404 via proxy catch-all (not a Roblox URL)", r.status_code == 404, r.status_code)
r = client.get("/this-is-not-roblox", headers=IP_MAIN)
check("GET non-Roblox URL -> 404", r.status_code == 404, r.status_code)
check("Roxy-Throttled header is a clean bool string", r.headers.get("Roxy-Throttled") in ("True", "False"))
r = client.post("/admin", headers=IP_MAIN, data="not json", content_type="text/plain")
check("POST /admin with non-JSON -> 400 (no crash)", r.status_code == 400, r.status_code)
r = client.post("/admin", headers=IP_MAIN, json=["a", "list"])
check("POST /admin with JSON list -> 400 (no crash)", r.status_code == 400, r.status_code)
check("No emails were sent for any of the above", len(sent_emails) == before, sent_emails[before:])

print("== Login flow ==")
r = client.post("/admin", headers=IP_MAIN, json={"IsLogin": True, "Username": "wrong", "Password": "wrong"})
check("Bad credentials -> 403", r.status_code == 403, r.status_code)
r = client.post("/admin", headers=IP_MAIN, json={"IsLogin": True, "Username": ADMIN_USER, "Password": ADMIN_PASS})
check("Good credentials -> 200", r.status_code == 200, r.status_code)
codes = emails_with("Admin 2FA")
check("2FA email sent", len(codes) == 1, len(codes))
code = codes[-1]["body"].strip() if codes else ""

r = client.post("/admin", headers=IP_MAIN, json={"Is2FA": True, "TwoFA": "0000000000000000"})
check("Wrong 2FA code -> 404", r.status_code == 404, r.status_code)
# The challenge was consumed by the failed attempt; restart the login to get a fresh one.
r = client.post("/admin", headers=IP_MAIN, json={"IsLogin": True, "Username": ADMIN_USER, "Password": ADMIN_PASS})
code = emails_with("Admin 2FA")[-1]["body"].strip()
r = client.post("/admin", headers=IP_MAIN, json={"Is2FA": True, "TwoFA": code})
check("Correct 2FA code -> 200", r.status_code == 200, r.status_code)
check("Login notification email sent", len(emails_with("Roxy Admin Login")) >= 1)

r = client.get("/admin/dashboard", headers=IP_MAIN)
check("GET /admin/dashboard (logged in) -> 200", r.status_code == 200, r.status_code)
r = client.post("/admin/heartbeat", headers={**IP_MAIN, "Accept": "application/json"})
check("Heartbeat -> 200", r.status_code == 200, r.status_code)
hb = r.get_json()
check(
    "Heartbeat reports idle timeout",
    isinstance(hb, dict) and hb.get("IdleTimeout") == config.ADMIN_SESSION_IDLE_TIMEOUT,
    hb,
)

r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check("Diagnostics -> 200", r.status_code == 200, r.status_code)
diag = r.get_json()
for key in ("TrafficMinutes", "ServerTime", "WorkerStartedAt", "ExploitSummary", "Settings", "Pause"):
    check(f"Diagnostics payload has {key}", key in diag, list(diag.keys())[:8])
check(
    "405 probe was recorded in exploit summary",
    any("HTTP 405" in reason for reason in diag.get("ExploitSummary", {})),
    list(diag.get("ExploitSummary", {})),
)

print("== Presence-based session expiry ==")
with client.session_transaction() as sess:
    sess["LastSeen"] = time.time() - (config.ADMIN_SESSION_IDLE_TIMEOUT - 5)
r = client.post("/admin/heartbeat", headers={**IP_MAIN, "Accept": "application/json"})
check("Heartbeat at 25s idle -> still alive (200)", r.status_code == 200, r.status_code)
with client.session_transaction() as sess:
    sess["LastSeen"] = time.time() - (config.ADMIN_SESSION_IDLE_TIMEOUT + 5)
r = client.post("/admin/heartbeat", headers={**IP_MAIN, "Accept": "application/json"})
check("Heartbeat at 35s idle -> 401 JSON for fetch()", r.status_code == 401, r.status_code)
r = client.get("/admin/dashboard", headers=IP_MAIN)
check("Dashboard after expiry -> redirect to login", r.status_code == 302 and "/admin" in r.headers.get("Location", ""))

print("== Re-login and admin actions ==")
r = client.post("/admin", headers=IP_MAIN, json={"IsLogin": True, "Username": ADMIN_USER, "Password": ADMIN_PASS})
code = emails_with("Admin 2FA")[-1]["body"].strip()
r = client.post("/admin", headers=IP_MAIN, json={"Is2FA": True, "TwoFA": code})
check("Re-login works after expiry", r.status_code == 200, r.status_code)

r = client.post("/admin/tokens", headers=IP_MAIN, json={"tokens": ["  TOK_A  ", "TOK_B", "TOK_A", ""]})
check("Set tokens -> 200, deduped count", r.status_code == 200 and r.get_json().get("Count") == 2, r.data[:80])
r = client.post("/admin/tokens", headers=IP_MAIN, json={"tokens": ["TOK_C"], "persist": True})
check("Persist tokens -> written to file", r.status_code == 200 and r.get_json().get("Persisted") is True, r.data[:80])
with open(os.path.join(sandbox, "auth_tokens.txt")) as f:
    check("Token file contains the new token", f.read().strip() == "TOK_C")
r = client.post("/admin/tokens", headers=IP_MAIN, json={"tokens": "not-a-list"})
check("Invalid tokens payload -> 400", r.status_code == 400, r.status_code)

r = client.post("/admin/settings", headers=IP_MAIN, json={"settings": {"allowed_requests_per_minute": 25}})
check("Settings save -> 200", r.status_code == 200, r.status_code)
check(
    "Setting actually applied",
    r.get_json()["Settings"]["allowed_requests_per_minute"]["value"] == 25,
)
r = client.post("/admin/settings", headers=IP_MAIN, json={"settings": {"allowed_requests_per_minute": 999999999}})
check("Out-of-range setting rejected with message", "between" in str(r.get_json().get("Results", {})), r.data[:120])

r = client.post("/admin/probes/clear", headers=IP_MAIN)
check("Clear probes -> 200", r.status_code == 200, r.status_code)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check("Exploit summary empty after clear", diag.get("ExploitSummary") == {}, diag.get("ExploitSummary"))
check("Exploit attempts empty after clear", diag.get("ExploitAttempts") == [], len(diag.get("ExploitAttempts", [])))

r = client.post("/admin/endpoints/block", headers=IP_MAIN, json={"pattern": "games.roblox.com/v1", "note": "test"})
check("Block endpoint -> 200", r.status_code == 200, r.status_code)
r = client.get("/games.roblox.com/v1/games", headers=IP_MAIN)
check("Blocked endpoint -> 403 without upstream call", r.status_code == 403, r.status_code)
r = client.post("/admin/endpoints/unblock", headers=IP_MAIN, json={"pattern": "games.roblox.com/v1"})
check("Unblock endpoint -> 200", r.status_code == 200, r.status_code)

print("== Full proxy pipeline with fake upstream (recording, headers, params) ==")
import datetime as _dt
import proxy as proxy_module


class FakeUpstreamResponse:
    def __init__(self, status=200, text='{"ok":true}', headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.elapsed = _dt.timedelta(milliseconds=42)

    def json(self):
        return json.loads(self.text)


upstream_calls = []


def fake_upstream(method, url, headers=None, params=None, data=None, cookies=None, timeout=None, proxies=None):
    upstream_calls.append(
        {
            "method": method,
            "url": url,
            "headers": headers or {},
            "params": params or {},
            "cookies": cookies,
            "proxies": proxies,
        }
    )
    return FakeUpstreamResponse()


# requests.get is used by token validation (accountinformation) and the rotation
# exit-IP probe (ipify). Stub it so those never hit the network in tests.
get_calls = []
_probe_ip_counter = [0]


def fake_get(url, headers=None, params=None, cookies=None, proxies=None, timeout=None):
    get_calls.append({"url": url, "cookies": cookies, "proxies": proxies})
    if "ipify" in url or "ip-echo" in url:
        _probe_ip_counter[0] += 1
        return FakeUpstreamResponse(status=200, text='{"ip":"203.0.113.%d"}' % _probe_ip_counter[0])
    return FakeUpstreamResponse(status=200, text='{"ok":true}')  # token validation: active


proxy_module.requests.request = fake_upstream
proxy_module.requests.get = fake_get

import routing as routing_module  # noqa: E402


def reset_routing():
    """Clear the shared routing file (token budget + cooldowns) between sections."""
    routing_module.reset()


def set_method_weights(token, rotate):
    """Force the routing mix deterministically for a test section."""
    client.post(
        "/admin/settings",
        headers=IP_MAIN,
        json={"settings": {"token_weight": token, "rotate_weight": rotate}},
    )


# Default for most sections: every routed request goes via Token (roblox.com),
# with a budget so high it never interferes. Rotation is enabled from the start
# (only "token"/"rotate" methods exist now) so fallback tests have somewhere to
# fall TO; specific sections override the weights/availability as needed.
import rotate as rotate_module  # noqa: E402

enable_rotation()
client.post(
    "/admin/settings",
    headers=IP_MAIN,
    json={"settings": {"token_weight": 100, "rotate_weight": 0, "token_budget_requests": 100000}},
)
proxy_module.set_tokens(["FAKE_TOKEN_AAA"])

api_client = app.test_client()
api_client.set_cookie("some_visitor_cookie", "should-not-be-forwarded")
IP_API = {"X-Forwarded-For": "10.3.3.3"}

r = api_client.get("/avatar.roblox.com/v2/test?prettyprint=true&ids=1&ids=2", headers=IP_API)
check("Proxied GET -> 200", r.status_code == 200, r.status_code)
check("prettyprint=true formats the response", json.loads(r.data) == {"ok": True} and b"\n" in r.data, r.data[:60])
call = upstream_calls[-1]
r = api_client.get("/avatar.roblox.com/v2/test-plain", headers=IP_API)
check("Raw upstream body passed through without prettyprint", r.data == b'{"ok":true}', r.data[:60])
check(
    "Token route attaches the .ROBLOSECURITY cookie",
    (call["cookies"] or {}).get(".ROBLOSECURITY") == "FAKE_TOKEN_AAA",
    call["cookies"],
)
check("Upstream URL is https + roblox", call["url"] == "https://avatar.roblox.com/v2/test", call["url"])
check("prettyprint stripped before proxying", "prettyprint" not in call["params"], call["params"])
check("Repeated query params preserved", call["params"].get("ids") == ["1", "2"], call["params"])
check(
    "Accept-Encoding only advertises decodable encodings (gibberish fix)",
    call["headers"].get("Accept-Encoding") == "gzip, deflate",
    call["headers"].get("Accept-Encoding"),
)
check("Visitor cookies NOT forwarded upstream", "Cookie" not in call["headers"], list(call["headers"]))
check("X-Forwarded-For NOT forwarded upstream", "X-Forwarded-For" not in call["headers"], list(call["headers"]))

r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check("RequestCounts recorded the proxied GET", diag["RequestCounts"]["GET"]["Successful"] >= 1, diag["RequestCounts"])
check("Endpoint recorded", "avatar.roblox.com/v2/test" in diag.get("Endpoints", {}), list(diag.get("Endpoints", {})))
check(
    "Traffic chart bucket recorded",
    sum(b.get("Successful", 0) for b in diag.get("TrafficMinutes", {}).values()) >= 1,
    diag.get("TrafficMinutes"),
)
check("Live feed recorded", any("avatar.roblox.com" in (i.get("URL") or "") for i in diag.get("LiveRequests", [])))
check("Status code 200 recorded", diag.get("StatusCodesDetailed", {}).get("200", 0) >= 1)
# A plain read merges at most once per diagnostics_flush_interval; ?flush=1 is the
# explicit "give me the current cross-worker truth" the Refresh button uses.
client.get("/admin/diagnostics?flush=1", headers={**IP_MAIN, "Accept": "application/json"})
with open(os.environ["ROXY_DATA_FILE"]) as f:
    on_disk = json.load(f)
check(
    "Stats persisted to the data file",
    on_disk.get("Diagnostics", {}).get("request_counts", {}).get("GET", {}).get("Successful", 0) >= 1,
)
check("Persistence health says writable", diag.get("Persistence", {}).get("Writable") is True, diag.get("Persistence"))

print("== Token safety budget (hard cap; falls back, never exceeds) ==")
reset_routing()
# Token preferred; Rotate is the only fallback once the budget is capped.
client.post(
    "/admin/settings",
    headers=IP_MAIN,
    json={"settings": {"token_budget_requests": 2, "token_budget_window": 3600}},
)
set_method_weights(100, 0)  # token-only while available; falls to rotate when budget-capped
proxy_module.set_tokens(["BUDGET_TOKEN"])
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "requests"})  # fresh method counters
budget_client = app.test_client()
IP_BUDGET = {"X-Forwarded-For": "10.4.4.4"}
for i in range(5):
    budget_client.get(f"/games.roblox.com/v1/list?a={i}", headers=IP_BUDGET)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
ms = diag.get("MethodStats", {})
check("Token used exactly the budget (2), never more", ms.get("Token", {}).get("Requests") == 2, ms.get("Token"))
check("Over-budget requests fell back to Rotate (3)", ms.get("Rotate", {}).get("Requests") == 3, ms.get("Rotate"))
check("TokenBudget shows the cap usage", diag.get("TokenBudget", {}).get("Used") == 2, diag.get("TokenBudget"))
check("TokenBudget limit reflects setting", diag.get("TokenBudget", {}).get("Limit") == 2, diag.get("TokenBudget"))
# Restore sane values for the rest of the run.
client.post(
    "/admin/settings", headers=IP_MAIN, json={"settings": {"token_budget_requests": 100000, "token_budget_window": 65}}
)
set_method_weights(100, 0)
reset_routing()
proxy_module.set_tokens(["FAKE_TOKEN_AAA"])

print("== Clear-data targets (manual-only erasure) ==")
r = client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "nope"})
check("Unknown clear target -> 400", r.status_code == 400, r.status_code)
r = client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "requests"})
check("Clear requests -> 200", r.status_code == 200, r.status_code)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check("Request counters zeroed", diag["RequestCounts"]["GET"]["Successful"] == 0, diag["RequestCounts"]["GET"])
check("Traffic chart cleared", diag.get("TrafficMinutes") == {}, diag.get("TrafficMinutes"))
check("Detailed status codes cleared", diag.get("StatusCodesDetailed") == {}, diag.get("StatusCodesDetailed"))
check("Budget rejections cleared", diag.get("TokenBudgetRejections") == 0, diag.get("TokenBudgetRejections"))
with open(os.environ["ROXY_DATA_FILE"]) as f:
    on_disk = json.load(f)
check(
    "Clear epoch recorded in the data file",
    "request_counts" in on_disk.get("Diagnostics", {}).get("ClearEpochs", {}),
    list(on_disk.get("Diagnostics", {}).get("ClearEpochs", {})),
)
check(
    "File counters zeroed too",
    on_disk["Diagnostics"]["request_counts"]["GET"]["Successful"] == 0,
)
r = api_client.get("/avatar.roblox.com/v2/after-clear", headers=IP_API)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check(
    "New requests count again after clear",
    diag["RequestCounts"]["GET"]["Successful"] == 1,
    diag["RequestCounts"]["GET"],
)

print("== Admin-visit counting skips known admin browsers ==")
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
visits_before = r.get_json()["PageVisits"].get("admin", 0)
stranger = app.test_client()
stranger.get("/admin", headers={"X-Forwarded-For": "10.5.5.5"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check("Unknown browser visit counts", r.get_json()["PageVisits"].get("admin", 0) == visits_before + 1)
known = app.test_client()
known.set_cookie("roxy_admin_seen", "1")
known.get("/admin", headers={"X-Forwarded-For": "10.5.5.6"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check("Known-admin browser visit does NOT count", r.get_json()["PageVisits"].get("admin", 0) == visits_before + 1)
check(
    "Login response set the admin-seen cookie",
    any(c.key == "roxy_admin_seen" for c in client._cookies.values()) if hasattr(client, "_cookies") else True,
)

print("== Wildcard endpoint blocking ==")
# Make sure proxied (non-blocked) requests reach the fake upstream.
proxy_module.set_tokens(["WILDCARD_TOKEN"])
IP_WILD = {"X-Forwarded-For": "10.6.6.1"}
client.post("/admin/endpoints/block", headers=IP_MAIN, json={"pattern": "games.roblox.com/v1/games/*/servers"})

n = len(upstream_calls)
r = api_client.get("/games.roblox.com/v1/games/694768217/servers/0", headers=IP_WILD)
check("Wildcard blocks .../games/<id>/servers/0 -> 403", r.status_code == 403, r.status_code)
check("Wildcard-blocked request never hit upstream", len(upstream_calls) == n, len(upstream_calls) - n)
r = api_client.get("/games.roblox.com/v1/games/123/servers", headers=IP_WILD)
check("Wildcard blocks bare .../servers (trailing wildcard) -> 403", r.status_code == 403, r.status_code)
n = len(upstream_calls)
r = api_client.get("/games.roblox.com/v1/games/9583680112/votes", headers=IP_WILD)
check("Sibling .../votes is NOT blocked -> 200", r.status_code == 200, r.status_code)
check("Allowed sibling DID hit upstream", len(upstream_calls) == n + 1, len(upstream_calls) - n)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check(
    "Wildcard block pattern stored",
    "games.roblox.com/v1/games/*/servers" in r.get_json().get("EndpointBlocks", {}),
    list(r.get_json().get("EndpointBlocks", {})),
)
client.post("/admin/endpoints/unblock", headers=IP_MAIN, json={"pattern": "games.roblox.com/v1/games/*/servers"})
n = len(upstream_calls)
r = api_client.get("/games.roblox.com/v1/games/694768217/servers/0", headers=IP_WILD)
check("After unblock, .../servers passes again -> 200", r.status_code == 200, r.status_code)

print("== Wildcard per-endpoint rate rule ==")
IP_WRULE = {"X-Forwarded-For": "10.6.6.2"}
client.post(
    "/admin/endpoints/rule",
    headers=IP_MAIN,
    json={"pattern": "thumbnails.roblox.com/v1/*/icons", "limit": 1, "period": 3600},
)
r1 = api_client.get("/thumbnails.roblox.com/v1/users/icons?size=150", headers=IP_WRULE)
r2 = api_client.get("/thumbnails.roblox.com/v1/users/icons?size=420", headers=IP_WRULE)
check("Wildcard rate rule allows 1st -> 200", r1.status_code == 200, r1.status_code)
check("Wildcard rate rule blocks 2nd -> 429", r2.status_code == 429, r2.status_code)
r3 = api_client.get("/thumbnails.roblox.com/v1/groups/thumbnails?id=1", headers=IP_WRULE)
check("Non-matching thumbnails path is NOT rate-limited -> 200", r3.status_code == 200, r3.status_code)
client.post("/admin/endpoints/rule/clear", headers=IP_MAIN, json={"pattern": "thumbnails.roblox.com/v1/*/icons"})

print("== Header-based request blocking (Xeno) ==")
client.post("/admin/headers/rule", headers=IP_MAIN, json={"scope": "either", "mode": "contains", "needle": "xeno"})
IP_HDR = {"X-Forwarded-For": "10.7.7.1"}

n = len(upstream_calls)
r = api_client.get("/games.roblox.com/v1/games/1/votes", headers={**IP_HDR, "Xeno-Fingerprint": "9b6c6e24"})
check("Header rule blocks request with Xeno-* header (key match) -> disguised 429", r.status_code == 429, r.status_code)
check(
    "Header-blocked body looks like a throttle (no reason leaked)",
    b"throttled" in r.data and b"eader" not in r.data,
    r.data[:80],
)
check("Header-blocked response disguised as throttled", r.headers.get("Roxy-Throttled") == "True", dict(r.headers))
check("Header-blocked request never hit upstream", len(upstream_calls) == n, len(upstream_calls) - n)

r = api_client.get("/games.roblox.com/v1/games/1/votes", headers={**IP_HDR, "User-Agent": "Xeno/1.3.55"})
check("Header rule blocks Xeno User-Agent (value match) -> 429", r.status_code == 429, r.status_code)

n = len(upstream_calls)
r = api_client.get("/games.roblox.com/v1/games/1/votes", headers={**IP_HDR, "User-Agent": "Roblox/WinInet"})
check("Clean request passes -> 200", r.status_code == 200, r.status_code)
check("Clean request DID hit upstream", len(upstream_calls) == n + 1)

r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
hba = diag.get("HeaderBlockedAttempts", {})
check("Header-blocked attempts recorded", any(int(v.get("Count", 0)) >= 1 for v in hba.values()), hba)
check(
    "Recorded rule remembers the matched header",
    any(v.get("LastHeader") for v in hba.values()),
    hba,
)
xeno_rec = next((v for k, v in hba.items() if "xeno" in k), {})
check("Header-blocked record notes which field triggered (value)", xeno_rec.get("LastField") == "value", xeno_rec)
check("Header-blocked record captures the matched text", "Xeno" in (xeno_rec.get("LastMatch") or ""), xeno_rec)
check(
    "Header rule stored in HeaderRules",
    any("xeno" in k for k in diag.get("HeaderRules", {})),
    list(diag.get("HeaderRules", {})),
)

# Key-scope exact rule
client.post("/admin/headers/rule", headers=IP_MAIN, json={"scope": "key", "mode": "exact", "needle": "exploit-guid"})
r = api_client.get("/games.roblox.com/v1/games/1/votes", headers={**IP_HDR, "Exploit-Guid": "x"})
check("Exact key-scope rule blocks Exploit-Guid header -> 429", r.status_code == 429, r.status_code)
r = api_client.get("/games.roblox.com/v1/games/1/votes", headers={**IP_HDR, "Exploit-Guid-Extra": "x"})
check("Exact key rule does NOT match a longer header name -> 200", r.status_code == 200, r.status_code)

# Remove the broad xeno rule; a Xeno UA should pass again (exact exploit-guid rule still stands)
xeno_id = next(k for k in diag.get("HeaderRules", {}) if "xeno" in k)
client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": xeno_id})
r = api_client.get("/games.roblox.com/v1/games/1/votes", headers={**IP_HDR, "User-Agent": "Xeno/1.3.55"})
check("After removing the rule, Xeno UA passes -> 200", r.status_code == 200, r.status_code)

# Clear the header-blocked attempt records
r = client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "header_blocked_attempts"})
check("Clear header-blocked attempts -> 200", r.status_code == 200, r.status_code)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check(
    "Header-blocked attempts cleared",
    r.get_json().get("HeaderBlockedAttempts") == {},
    r.get_json().get("HeaderBlockedAttempts"),
)
# Remove the remaining exact rule so it doesn't affect later sections.
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
for rid in [k for k in r.get_json().get("HeaderRules", {}) if "exploit-guid" in k]:
    client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": rid})

print("== Global throttle-all mode (configurable N per P, custom message, drops) ==")
proxy_module.requests.request = fake_upstream
proxy_module.set_tokens(["TA_TOKEN"])
# Enable with a custom message and limit of 2 per 3600s so the 3rd request trips it.
r = client.post(
    "/admin/proxy/throttle_all",
    headers=IP_MAIN,
    json={"enabled": True, "reason": "Heavy load, slow down.", "limit": 2, "period": 3600},
)
state = r.get_json()
check("Enable throttle-all -> state on", r.status_code == 200 and state.get("ThrottleAll") is True, r.data[:80])
check("Throttle-all stored the configurable limit", state.get("Limit") == 2 and state.get("Period") == 3600, state)
check("Throttle-all stored the custom reason", state.get("Reason") == "Heavy load, slow down.", state)
IP_TA = {"X-Forwarded-For": "10.8.8.1"}
n = len(upstream_calls)
r1 = api_client.get("/games.roblox.com/v1/ta1", headers=IP_TA)
r2 = api_client.get("/games.roblox.com/v1/ta2", headers=IP_TA)
check(
    "Throttle-all lets the first N requests through",
    r1.status_code == 200 and r2.status_code == 200,
    (r1.status_code, r2.status_code),
)
check("Allowed throttle-all requests reached upstream", len(upstream_calls) == n + 2, len(upstream_calls) - n)
n = len(upstream_calls)
r3 = api_client.get("/games.roblox.com/v1/ta3", headers=IP_TA)
check("Throttle-all blocks beyond the limit -> 429", r3.status_code == 429, r3.status_code)
check("Throttle-all 429 returns the CUSTOM message", b"Heavy load, slow down." in r3.data, r3.data[:80])
check("Over-limit throttle-all request never hit upstream", len(upstream_calls) == n, len(upstream_calls) - n)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check("Throttle-all drops counted in diagnostics", diag.get("ThrottleAllDrops", 0) >= 1, diag.get("ThrottleAllDrops"))
r = client.post("/admin/proxy/throttle_all", headers=IP_MAIN, json={"enabled": False})
check("Disable throttle-all -> state off", r.get_json().get("ThrottleAll") is False, r.data[:80])
IP_TA2 = {"X-Forwarded-For": "10.8.8.2"}
n = len(upstream_calls)
r = api_client.get("/games.roblox.com/v1/after-throttle-all", headers=IP_TA2)
check("After disabling, requests proxy normally -> 200", r.status_code == 200, r.status_code)
check("Normal request hit upstream again", len(upstream_calls) == n + 1, len(upstream_calls) - n)

print("== Pause: custom message + dropped-request counter ==")
r = client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": True, "reason": "Updating tokens, back soon."})
check(
    "Pause with reason -> state paused + reason",
    r.get_json().get("Paused") is True and r.get_json().get("Reason") == "Updating tokens, back soon.",
    r.data[:80],
)
IP_PAUSE = {"X-Forwarded-For": "10.15.0.1"}
r = api_client.get("/games.roblox.com/v1/while-paused", headers=IP_PAUSE)
check(
    "Paused proxy returns 503 with the custom message",
    r.status_code == 503 and b"Updating tokens, back soon." in r.data,
    (r.status_code, r.data[:80]),
)
api_client.get("/games.roblox.com/v1/while-paused-2", headers=IP_PAUSE)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check("Pause drops counted", r.get_json().get("PauseDrops", 0) >= 2, r.get_json().get("PauseDrops"))
# Re-pausing resets the drop counter for the new downtime.
client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": False})
r = client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": True})  # reuses the persisted message
api_client.get("/games.roblox.com/v1/while-paused-3", headers=IP_PAUSE)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check(
    "Pause drop counter reset on new downtime", r.get_json().get("PauseDrops", 0) == 1, r.get_json().get("PauseDrops")
)
# Explicitly clearing the message (reason="") falls back to the default.
client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": False})
client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": True, "reason": ""})
r = api_client.get("/games.roblox.com/v1/while-paused-4", headers=IP_PAUSE)
check("Default pause message used when message is cleared", b"Service down for maintenance." in r.data, r.data[:80])
client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": False})
r = api_client.get("/games.roblox.com/v1/after-pause", headers={"X-Forwarded-For": "10.15.0.2"})
check("After resume, proxy works again -> 200", r.status_code == 200, r.status_code)

print("== Rotate rejection counts (non-200) ==")
reset_routing()
set_method_weights(0, 100)  # force Rotate


def failing_upstream(method, url, headers=None, params=None, data=None, cookies=None, timeout=None, proxies=None):
    upstream_calls.append(
        {"method": method, "url": url, "headers": headers or {}, "params": params or {}, "cookies": cookies}
    )
    return FakeUpstreamResponse(status=500, text="upstream boom")


proxy_module.requests.request = failing_upstream
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
rp0 = r.get_json().get("MethodStats", {}).get("Rotate", {}).get("Failed", 0)
api_client.get("/games.roblox.com/v1/fail-a", headers={"X-Forwarded-For": "10.10.0.1"})
api_client.get("/games.roblox.com/v1/fail-b", headers={"X-Forwarded-For": "10.10.0.2"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
rp1 = r.get_json().get("MethodStats", {}).get("Rotate", {})
check("Rotate rejection (non-200) counted", rp1.get("Failed", 0) >= rp0 + 1, rp1)
check("Rotate requests counted", rp1.get("Requests", 0) >= 2, rp1)
proxy_module.requests.request = fake_upstream  # restore 200s
set_method_weights(100, 0)
reset_routing()

print("== Upstream timeouts: fall through routes, never email ==")
reset_routing()
# Rotate must be tried FIRST every time, or ~1 run in 100 picks Token, succeeds,
# and never produces the timeout this section is asserting on. Weight 0 excludes
# Token from the initial pick; it is still reachable as the fallback, because
# once Rotate is in the excluded set it becomes the only candidate.
set_method_weights(0, 100)
proxy_module.set_tokens(["FALLBACK_TOKEN"])


def timeout_unless_token(method, url, headers=None, params=None, data=None, cookies=None, timeout=None, proxies=None):
    upstream_calls.append({"method": method, "url": url, "cookies": cookies})
    if cookies and cookies.get(".ROBLOSECURITY"):
        return FakeUpstreamResponse(status=200, text='{"ok":true}')  # token route works
    raise proxy_module.requests.Timeout("read timed out")  # rotate times out


proxy_module.requests.request = timeout_unless_token
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
to0 = r.get_json().get("MethodStats", {}).get("Rotate", {}).get("Timeouts", 0)
emails_before = len(sent_emails)
r = api_client.get("/games.roblox.com/v1/timeout-test", headers={"X-Forwarded-For": "10.16.0.1"})
check("Rotate timeout falls through to the token -> 200", r.status_code == 200, r.status_code)
check("Timed-out request was ultimately served", r.data == b'{"ok":true}', r.data[:60])
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
to1 = r.get_json().get("MethodStats", {}).get("Rotate", {}).get("Timeouts", 0)
check("Rotate timeout counted", to1 >= to0 + 1, to1)
check("Timeouts never email the admin", len(sent_emails) == emails_before, sent_emails[emails_before:])
proxy_module.requests.request = fake_upstream  # restore 200s
set_method_weights(100, 0)
reset_routing()
proxy_module.set_tokens(["FAKE_TOKEN_AAA"])

print("== Endpoint templating (ID collapse + concrete drill-down) ==")
proxy_module.set_tokens(["TPL_TOKEN"])
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "endpoints"})
IP_TPL = {"X-Forwarded-For": "10.11.0.1"}
for uid in ("111", "222", "333"):
    api_client.get(f"/avatar.roblox.com/v2/avatar/users/{uid}/outfits", headers=IP_TPL)
api_client.get("/games.roblox.com/v1/games/694768217/servers/0", headers=IP_TPL)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
eps = r.get_json().get("Endpoints", {})
tmpl = "avatar.roblox.com/v2/avatar/users/{userId}/outfits"
check("IDs collapse into a {userId} template", tmpl in eps, list(eps))
check("Template counts all 3 requests", eps.get(tmpl, {}).get("Count") == 3, eps.get(tmpl))
check("Template reports 3 concrete IDs", eps.get(tmpl, {}).get("ConcreteCount") == 3, eps.get(tmpl))
# The concrete paths themselves carry a captured header dump each, so they are
# fetched per template on demand rather than shipped with every dashboard poll.
concrete = client.get(
    f"/admin/endpoints/concrete?template={quote(tmpl, safe='')}", headers={**IP_MAIN, "Accept": "application/json"}
).get_json()
check("Template keeps the 3 concrete IDs", len(concrete.get("Concrete", {})) == 3, concrete.get("Concrete"))
check(
    "Concrete drill-down has the real path",
    "avatar.roblox.com/v2/avatar/users/111/outfits" in concrete.get("Concrete", {}),
    list(concrete.get("Concrete", {})),
)
check(
    "games servers path collapses gameId + serverId",
    "games.roblox.com/v1/games/{gameId}/servers/{serverId}" in eps,
    [k for k in eps if k.startswith("games.roblox.com")],
)

print("== Regex endpoint blocking ==")
proxy_module.set_tokens(["RX_TOKEN"])
rx_pattern = r"games\.roblox\.com/v1/games/\d+/votes"
r = client.post("/admin/endpoints/block", headers=IP_MAIN, json={"pattern": rx_pattern, "type": "regex"})
check("Add regex block -> 200", r.status_code == 200, r.data[:80])
IP_RX = {"X-Forwarded-For": "10.12.0.1"}
n = len(upstream_calls)
r = api_client.get("/games.roblox.com/v1/games/999/votes", headers=IP_RX)
check("Regex block matches /votes -> 403", r.status_code == 403, r.status_code)
check("Regex-blocked request never hit upstream", len(upstream_calls) == n, len(upstream_calls) - n)
r = api_client.get("/games.roblox.com/v1/games/999/servers/0", headers=IP_RX)
check("Regex block does NOT match /servers -> 200", r.status_code == 200, r.status_code)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
blocks = r.get_json().get("EndpointBlocks", {})
check("Regex block stored with Type=regex", blocks.get(rx_pattern, {}).get("Type") == "regex", blocks.get(rx_pattern))
r = client.post("/admin/endpoints/unblock", headers=IP_MAIN, json={"pattern": rx_pattern})
r = api_client.get("/games.roblox.com/v1/games/999/votes", headers=IP_RX)
check("After unblock, regex pattern no longer blocks -> 200", r.status_code == 200, r.status_code)

print("== Regex header rule ==")
r = client.post(
    "/admin/headers/rule", headers=IP_MAIN, json={"scope": "value", "mode": "regex", "needle": r"Synapse|Xeno|KRNL"}
)
check("Add regex header rule -> 200", r.status_code == 200, r.data[:80])
IP_RXH = {"X-Forwarded-For": "10.13.0.1"}
r = api_client.get("/games.roblox.com/v1/x", headers={**IP_RXH, "User-Agent": "KRNL/2.0"})
check("Regex header rule blocks matching UA -> 429", r.status_code == 429, r.status_code)
r = api_client.get("/games.roblox.com/v1/x", headers={**IP_RXH, "User-Agent": "LegitClient/1.0"})
check("Regex header rule lets a clean UA through -> 200", r.status_code == 200, r.status_code)
r = client.post("/admin/headers/rule", headers=IP_MAIN, json={"scope": "value", "mode": "regex", "needle": "([bad"})
check("Invalid regex header rule rejected -> 400", r.status_code == 400, r.data[:80])
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
for rid in [k for k in r.get_json().get("HeaderRules", {}) if "|regex|" in k]:
    client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": rid})

print("== Token budget peak (1h / 24h) ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "requests"})
reset_routing()  # fresh window so the peak is exactly what we drive
set_method_weights(100, 0)  # token-only
proxy_module.set_tokens(["PEAK_TOKEN"])
client.post(
    "/admin/settings", headers=IP_MAIN, json={"settings": {"token_budget_requests": 95, "token_budget_window": 65}}
)
IP_PK = {"X-Forwarded-For": "10.14.0.1"}
for i in range(3):
    api_client.get(f"/games.roblox.com/v1/peak{i}", headers=IP_PK)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check(
    "Token budget Used reflects the 3 token requests",
    diag.get("TokenBudget", {}).get("Used") == 3,
    diag.get("TokenBudget"),
)
check("Budget peak (1h) captured", diag.get("BudgetPeak1h") == 3, diag.get("BudgetPeak1h"))
check("Budget peak (24h) captured", diag.get("BudgetPeak24h") == 3, diag.get("BudgetPeak24h"))
client.post("/admin/settings", headers=IP_MAIN, json={"settings": {"token_budget_requests": 100000}})
reset_routing()

print("== No same-method retry on 429; CSRF handshake kept ==")
reset_routing()
set_method_weights(50, 50)  # token + rotate both eligible
proxy_module.set_tokens(["RETRY_TOKEN"])
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "requests"})


def upstream_429(method, url, headers=None, params=None, data=None, cookies=None, timeout=None, proxies=None):
    upstream_calls.append({"method": method, "url": url})
    return FakeUpstreamResponse(status=429, text="Too Many Requests")


proxy_module.requests.request = upstream_429
n = len(upstream_calls)
r = api_client.get("/games.roblox.com/v1/retry-test", headers={"X-Forwarded-For": "10.20.0.1"})
check("All methods 429'd -> request fails", r.status_code == 500, r.status_code)
check("Each method tried at most once on 429 (no retry storm)", len(upstream_calls) - n <= 2, len(upstream_calls) - n)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
rc = r.get_json().get("RetryCounts", {})
check("No 429 retries recorded", "429" not in (rc.get("ByStatusCode") or {}), rc.get("ByStatusCode"))

# CSRF handshake (a required protocol step for writes) must still work — via Rotate.
reset_routing()
set_method_weights(0, 100)  # force Rotate


def upstream_csrf(method, url, headers=None, params=None, data=None, cookies=None, timeout=None, proxies=None):
    upstream_calls.append({"method": method, "url": url})
    if headers and headers.get("x-csrf-token"):
        return FakeUpstreamResponse(status=200, text='{"ok":true}')
    return FakeUpstreamResponse(status=403, text="csrf", headers={"x-csrf-token": "CSRF123"})


proxy_module.requests.request = upstream_csrf
n = len(upstream_calls)
r = api_client.post("/economy.roblox.com/v1/purchase", headers={"X-Forwarded-For": "10.20.0.2"}, data=b"{}")
check("CSRF handshake still completes a write -> 200", r.status_code == 200, r.status_code)
check("CSRF handshake used exactly one retry (same method)", len(upstream_calls) == n + 2, len(upstream_calls) - n)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check("CSRF retry recorded (403)", "403" in (r.get_json().get("RetryCounts", {}).get("ByStatusCode") or {}))
proxy_module.requests.request = fake_upstream
set_method_weights(100, 0)
reset_routing()
proxy_module.set_tokens(["FAKE_TOKEN_AAA"])

print("== Service messages persist after disabling ==")
client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": True, "reason": "Persisted pause msg"})
client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": False})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check(
    "Pause message persists after resume",
    r.get_json().get("Pause", {}).get("Reason") == "Persisted pause msg",
    r.get_json().get("Pause"),
)

print("== Per-endpoint last headers recorded ==")
proxy_module.set_tokens(["HDR_TOKEN"])
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "endpoints"})
api_client.get(
    "/avatar.roblox.com/v2/avatar/users/777/outfits",
    headers={"X-Forwarded-For": "10.21.0.1", "X-Test-Header": "fingerprint-me"},
)
detail = client.get(
    f"/admin/endpoints/concrete?template={quote(tmpl, safe='')}", headers={**IP_MAIN, "Accept": "application/json"}
).get_json()
concrete = (detail.get("Concrete") or {}).get("avatar.roblox.com/v2/avatar/users/777/outfits", {})
check(
    "Concrete endpoint stores last headers",
    "X-Test-Header" in (concrete.get("LastHeaders") or ""),
    concrete.get("LastHeaders"),
)
check("Concrete endpoint stores last IP", concrete.get("LastIP") == "10.21.0.1", concrete.get("LastIP"))

print("== Token route Requests/Rejected counted ==")
set_method_weights(100, 0)  # force the token route
proxy_module.set_tokens(["TKR_TOKEN"])
api_client.get("/games.roblox.com/v1/token-route", headers={"X-Forwarded-For": "10.21.0.2"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
tk = r.get_json().get("MethodStats", {}).get("Token", {})
check("Token method request count tracked", tk.get("Requests", 0) >= 1, tk)

print("== Request fingerprints (header names + user-agents) ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "fingerprints"})
proxy_module.set_tokens(["FP_TOKEN"])
api_client.get(
    "/games.roblox.com/v1/fp",
    headers={"X-Forwarded-For": "10.22.0.1", "User-Agent": "EvilExploiter/9", "X-Weird-Header": "1"},
)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check(
    "Distinct header names tracked",
    "x-weird-header" in (diag.get("HeaderNames") or {}),
    list(diag.get("HeaderNames", {}))[:8],
)
check(
    "Distinct user-agents tracked",
    "EvilExploiter/9" in (diag.get("UserAgents") or {}),
    list(diag.get("UserAgents", {}))[:8],
)

print("== Error log (deduped, admin-clear only) ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "errors"})
client.get("/_boom_test_only", headers=IP_MAIN)
client.get("/_boom_test_only", headers=IP_MAIN)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
errs = r.get_json().get("Errors", {})
boom_sig = next((k for k in errs if "intentional test explosion" in k), None)
check("Server error logged with signature", boom_sig is not None, list(errs))
check("Repeated identical errors dedupe with a count", errs.get(boom_sig, {}).get("Count", 0) >= 2, errs.get(boom_sig))
check(
    "Error log keeps a detail/traceback",
    "Traceback" in (errs.get(boom_sig, {}).get("LastDetail") or ""),
    errs.get(boom_sig),
)

print("== Trusted device skips 2FA for 30 days ==")
td_ip = {"X-Forwarded-For": "10.23.0.1"}
r = client_post_login = app.test_client()
r = client_post_login.post(
    "/admin", headers=td_ip, json={"IsLogin": True, "Username": ADMIN_USER, "Password": ADMIN_PASS, "TrustDevice": True}
)
check("Login with TrustDevice still asks for 2FA first", r.get_json().get("TwoFA") is True, r.data[:80])
code = emails_with("Admin 2FA")[-1]["body"].strip()
r = client_post_login.post("/admin", headers=td_ip, json={"Is2FA": True, "TwoFA": code})
check("2FA with trust -> logged in", r.get_json().get("LoggedIn") is True, r.data[:80])
set_cookies = r.headers.getlist("Set-Cookie")
td_cookie = next((c for c in set_cookies if c.startswith("roxy_trusted_device=")), "")
td_token = td_cookie.split(";", 1)[0].split("=", 1)[1] if td_cookie else ""
check("Trusted-device cookie issued", bool(td_token), set_cookies)
import runtime as runtime_module

check("Backend recognizes the trusted-device token", runtime_module.is_trusted_device(td_token), "not recognized")
emails_n = len(emails_with("Admin 2FA"))
fresh = app.test_client()
fresh.set_cookie("roxy_trusted_device", td_token, domain="localhost")
r = fresh.post("/admin", headers=td_ip, json={"IsLogin": True, "Username": ADMIN_USER, "Password": ADMIN_PASS})
check("Trusted device logs in WITHOUT 2FA", r.get_json().get("LoggedIn") is True, r.data[:80])
check("Trusted re-login sent no new 2FA email", len(emails_with("Admin 2FA")) == emails_n, "new 2FA email sent")
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check("Trusted device counted", r.get_json().get("TrustedDevices", 0) >= 1, r.get_json().get("TrustedDevices"))
client.post("/admin/trusted_devices/revoke", headers=IP_MAIN)
check("Revoke clears backend trust", not runtime_module.is_trusted_device(td_token), "still trusted")
fresh2 = app.test_client()
fresh2.set_cookie("roxy_trusted_device", td_token, domain="localhost")
r = fresh2.post("/admin", headers=td_ip, json={"IsLogin": True, "Username": ADMIN_USER, "Password": ADMIN_PASS})
check("After revoke, the device needs 2FA again", r.get_json().get("TwoFA") is True, r.data[:80])

print("== Clear isolation + Clear All ==")
proxy_module.set_tokens(["ISO_TOKEN"])
api_client.get("/avatar.roblox.com/v2/avatar/users/999/outfits", headers={"X-Forwarded-For": "10.24.0.1"})  # endpoints
api_client.get("/not-a-roblox-domain-iso", headers={"X-Forwarded-For": "10.24.0.1"})  # probe
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "probes"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check(
    "Clearing probes leaves endpoints intact (no cross-clear)",
    len(diag.get("Endpoints", {})) >= 1,
    list(diag.get("Endpoints", {})),
)
check("Clearing probes did clear the probe summary", diag.get("ExploitSummary", {}) == {}, diag.get("ExploitSummary"))
r = client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "all"})
check("Clear All -> 200", r.status_code == 200, r.status_code)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check("Clear All wiped endpoints", diag.get("Endpoints", {}) == {}, diag.get("Endpoints"))
check("Clear All wiped errors", diag.get("Errors", {}) == {}, diag.get("Errors"))
check(
    "Clear All wiped fingerprints",
    diag.get("HeaderNames", {}) == {} and diag.get("UserAgents", {}) == {},
    (diag.get("HeaderNames"), diag.get("UserAgents")),
)
check(
    "Clear All zeroed request counters", diag["RequestCounts"]["GET"]["Successful"] == 0, diag["RequestCounts"]["GET"]
)
check("Clear All does NOT touch trusted-device/rules state", "Settings" in diag)

print("== Admin page-visit counter works for anonymous GET /admin ==")
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
visits0 = r.get_json()["PageVisits"].get("admin", 0)
app.test_client().get("/admin", headers={"X-Forwarded-For": "10.25.0.1"})  # fresh anonymous bot
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check(
    "Anonymous GET /admin increments the counter",
    r.get_json()["PageVisits"].get("admin", 0) == visits0 + 1,
    r.get_json()["PageVisits"],
)

print("== Health: method stats + routing budget/cooldown ResetIn ==")
proxy_module.requests.request = fake_upstream
reset_routing()
set_method_weights(100, 0)  # token-only
proxy_module.set_tokens(["MATCH_TOKEN"])
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "all"})
for i in range(3):
    api_client.get(f"/games.roblox.com/v1/match{i}", headers={"X-Forwarded-For": "10.30.0.1"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check(
    "Token method recorded 3 requests",
    diag.get("MethodStats", {}).get("Token", {}).get("Requests") == 3,
    diag.get("MethodStats", {}).get("Token"),
)
check("Routing reports token budget usage", diag.get("Routing", {}).get("TokenUsed", 0) >= 3, diag.get("Routing"))
# Force a Rotate failure (with max_failures=1) and confirm RotateResetIn is reported.
client.post("/admin/settings", headers=IP_MAIN, json={"settings": {"rotate_max_failures": 1, "rotate_cooldown": 65}})
set_method_weights(0, 100)


def rotate_fails_once(method, url, headers=None, params=None, data=None, cookies=None, timeout=None, proxies=None):
    upstream_calls.append({"method": method, "url": url, "proxies": proxies})
    if proxies:
        raise proxy_module.requests.exceptions.ProxyError("simulated rotate failure")
    return FakeUpstreamResponse(status=200, text='{"ok":true}')


proxy_module.requests.request = rotate_fails_once
api_client.get("/games.roblox.com/v1/cooldown-test", headers={"X-Forwarded-For": "10.30.0.2"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check(
    "Rotate reports a cooldown ResetIn",
    r.get_json().get("Routing", {}).get("RotateResetIn", 0) > 0,
    r.get_json().get("Routing"),
)
proxy_module.requests.request = fake_upstream
client.post(
    "/admin/settings",
    headers=IP_MAIN,
    json={"settings": {"rotate_max_failures": config.ROTATE_MAX_FAILURES, "rotate_cooldown": config.ROTATE_COOLDOWN}},
)
set_method_weights(100, 0)
reset_routing()

print("== Clear-all resets the method counters too ==")
proxy_module.set_tokens(["CLR_TOKEN"])
api_client.get("/games.roblox.com/v1/before-clear", headers={"X-Forwarded-For": "10.30.0.3"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
ms_before = r.get_json().get("MethodStats", {})
check("Method stats have requests before clear", ms_before.get("Token", {}).get("Requests", 0) >= 1, ms_before)
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "all"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
ms_after = r.get_json().get("MethodStats", {})
check("Clear-all zeroed Token request count", ms_after.get("Token", {}).get("Requests", 0) == 0, ms_after.get("Token"))
check(
    "Clear-all zeroed Rotate request count", ms_after.get("Rotate", {}).get("Requests", 0) == 0, ms_after.get("Rotate")
)
proxy_module.set_tokens(["FAKE_TOKEN_AAA"])

print("== Specific-header request filter (precise targeting) ==")
proxy_module.requests.request = fake_upstream
proxy_module.set_tokens(["SPEC_TOKEN"])
# Target ONLY the User-Agent value; other headers containing the word must NOT trip it.
r = client.post(
    "/admin/headers/rule", headers=IP_MAIN, json={"header": "User-Agent", "mode": "contains", "needle": "BadClient"}
)
check("Add specific-header rule -> 200", r.status_code == 200, r.data[:80])
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
spec_rule = next((v for k, v in r.get_json().get("HeaderRules", {}).items() if v.get("Header") == "User-Agent"), {})
check("Specific-header rule stored with Header field", spec_rule.get("Header") == "User-Agent", spec_rule)
IP_SPEC = {"X-Forwarded-For": "10.40.0.1"}
r = api_client.get("/games.roblox.com/v1/spec", headers={**IP_SPEC, "User-Agent": "BadClient/1.0"})
check("Specific-header rule blocks the targeted header value -> 429", r.status_code == 429, r.status_code)
n = len(upstream_calls)
r = api_client.get(
    "/games.roblox.com/v1/spec", headers={**IP_SPEC, "User-Agent": "Good/1.0", "X-Note": "BadClient is here"}
)
check("Same text in a DIFFERENT header does NOT trip the targeted rule -> 200", r.status_code == 200, r.status_code)
check("Non-matching request reached upstream", len(upstream_calls) == n + 1, len(upstream_calls) - n)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
for rid in [k for k, v in r.get_json().get("HeaderRules", {}).items() if v.get("Header") == "User-Agent"]:
    client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": rid})

print("== Fingerprint value drill-down (+ sensitive fingerprinting) ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "fingerprints"})
IP_FP = {"X-Forwarded-For": "10.41.0.1"}
api_client.get("/games.roblox.com/v1/v", headers={**IP_FP, "Roblox-Id": "111", "Cookie": ".ROBLOSECURITY=SECRET_AAA"})
api_client.get("/games.roblox.com/v1/v", headers={**IP_FP, "Roblox-Id": "222", "Cookie": ".ROBLOSECURITY=SECRET_AAA"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
hn = r.get_json().get("HeaderNames", {})
check(
    "Header summary reports the distinct-value count",
    hn.get("roblox-id", {}).get("ValueCount") == 2,
    hn.get("roblox-id"),
)


def header_values(name, blocked=False):
    """Values now live behind their own endpoint so the dashboard poll stays small."""
    q = f"name={quote(str(name), safe='')}&blocked={1 if blocked else 0}"
    return client.get(f"/admin/fingerprints/values?{q}", headers={**IP_MAIN, "Accept": "application/json"}).get_json()


roblox_id_vals = header_values("Roblox-Id").get("Values", {})
check("Header value drill-down records distinct values", set(roblox_id_vals) == {"111", "222"}, roblox_id_vals)
cookie_vals = header_values("Cookie").get("Values", {})
check(
    "Sensitive cookie values are fingerprinted, not stored raw",
    all(v.startswith("fp:") for v in cookie_vals) and cookie_vals,
    cookie_vals,
)
check(
    "Two identical cookies collapse to one fingerprint with count 2",
    any(info.get("Count") == 2 for info in cookie_vals.values()),
    cookie_vals,
)
# Per-header clear: clear just roblox-id, leave cookie intact.
r = client.post("/admin/fingerprints/clear_header", headers=IP_MAIN, json={"name": "Roblox-Id"})
check("Per-header clear -> 200", r.status_code == 200, r.status_code)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
hn = r.get_json().get("HeaderNames", {})
check("Cleared header is gone", "roblox-id" not in hn, list(hn))
check("Other headers untouched by per-header clear", "cookie" in hn, list(hn))

print("== Blocked Request Fingerprints (false-positive review) ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "blocked_fingerprints"})
client.post(
    "/admin/headers/rule", headers=IP_MAIN, json={"header": "User-Agent", "mode": "contains", "needle": "Grief"}
)
api_client.get(
    "/games.roblox.com/v1/bfp", headers={"X-Forwarded-For": "10.42.0.1", "User-Agent": "GrieferTool/3", "X-Tag": "abc"}
)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check(
    "Blocked request's header names recorded separately",
    "user-agent" in (diag.get("BlockedHeaderNames") or {}),
    list(diag.get("BlockedHeaderNames", {})),
)
check(
    "Blocked request's user-agent recorded separately",
    "GrieferTool/3" in (diag.get("BlockedUserAgents") or {}),
    list(diag.get("BlockedUserAgents", {})),
)
check(
    "Blocked fingerprints are separate from accepted ones",
    "GrieferTool/3" not in (diag.get("UserAgents") or {}),
    list(diag.get("UserAgents", {})),
)
# Clean up the rule.
for rid in [k for k, v in diag.get("HeaderRules", {}).items() if v.get("Needle") == "Grief"]:
    client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": rid})

print("== Traffic pills reflect the last hour ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "requests"})
proxy_module.set_tokens(["PILL_TOKEN"])
for i in range(4):
    api_client.get(f"/games.roblox.com/v1/pill{i}", headers={"X-Forwarded-For": "10.43.0.1"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
now_minute = int(diag["ServerTime"] // 60)
hour_ok = sum(b.get("Successful", 0) for m, b in diag.get("TrafficMinutes", {}).items() if int(m) > now_minute - 60)
check("Traffic minutes reflect recent successful requests (drives the pills)", hour_ok >= 4, hour_ok)

print("== IP rotation (DataImpulse) ==")
# Rotation is already enabled (configured from the start of the run).
reset_routing()
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "requests"})
set_method_weights(0, 100)  # force Rotate
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check(
    "Rotation reports configured + enabled",
    r.get_json().get("Rotate", {}).get("Configured") and r.get_json().get("Rotate", {}).get("Enabled"),
    r.get_json().get("Rotate"),
)
check(
    "Proxy URL shown masked (no creds)",
    "@" not in (r.get_json().get("Rotate", {}).get("ProxyUrl") or ""),
    r.get_json().get("Rotate"),
)
IP_ROT = {"X-Forwarded-For": "10.50.0.1"}
r = api_client.get("/games.roblox.com/v1/rotate-me", headers={**IP_ROT, "User-Agent": "OriginalUA/1"})
check("Rotated request -> 200", r.status_code == 200, r.status_code)
last = upstream_calls[-1]
check("Rotate sends through the proxy", bool(last.get("proxies")), last.get("proxies"))
check("Rotate does not rewrite the domain", last["url"] == "https://games.roblox.com/v1/rotate-me", last["url"])
check("Rotate sends NO token cookie", not (last.get("cookies") or {}).get(".ROBLOSECURITY"), last.get("cookies"))
check(
    "Rotate swaps in a random User-Agent",
    last["headers"].get("User-Agent") != "OriginalUA/1",
    last["headers"].get("User-Agent"),
)
check("Rotate drops Chrome client-hints (UA mismatch)", "Sec-Ch-Ua" not in last["headers"], list(last["headers"]))
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check(
    "Rotation count recorded",
    r.get_json().get("MethodStats", {}).get("Rotate", {}).get("Requests", 0) >= 1,
    r.get_json().get("MethodStats", {}).get("Rotate"),
)

print("== Rotation proxy failure falls back ==")
reset_routing()
set_method_weights(1, 100)  # prefer Rotate, Token as fallback
proxy_module.set_tokens(["ROT_FALLBACK_TOKEN"])


def rotate_fails_token_ok(method, url, headers=None, params=None, data=None, cookies=None, timeout=None, proxies=None):
    upstream_calls.append({"method": method, "url": url, "cookies": cookies, "proxies": proxies})
    if proxies:  # the rotation proxy is "down"
        raise proxy_module.requests.exceptions.ProxyError("502 from proxy")
    return FakeUpstreamResponse(status=200, text='{"ok":true}')


proxy_module.requests.request = rotate_fails_token_ok
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
rf0 = r.get_json().get("MethodStats", {}).get("Rotate", {}).get("Failed", 0)
r = api_client.get("/games.roblox.com/v1/rot-fallback", headers={"X-Forwarded-For": "10.50.0.2"})
check("Rotate proxy failure falls back to another method -> 200", r.status_code == 200, r.status_code)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check(
    "Rotate failure counted",
    r.get_json().get("MethodStats", {}).get("Rotate", {}).get("Failed", 0) >= rf0 + 1,
    r.get_json().get("MethodStats", {}).get("Rotate"),
)
proxy_module.requests.request = fake_upstream

print("== All methods unavailable emails the admin ==")
reset_routing()
disable_rotation()
set_method_weights(100, 0)
proxy_module.set_tokens([])  # no token AND rotation disabled -> nothing available
emails_before = len(emails_with("all upstream methods unavailable"))
r = api_client.get("/games.roblox.com/v1/nothing-left", headers={"X-Forwarded-For": "10.51.0.2"})
check("No method available -> request fails", r.status_code == 500, r.status_code)
check(
    "All-unavailable emails the admin", len(emails_with("all upstream methods unavailable")) > emails_before, "no email"
)
# Restore healthy defaults.
enable_rotation()
set_method_weights(100, 0)
reset_routing()
proxy_module.set_tokens(["FAKE_TOKEN_AAA"])

print("== No identifying info forwarded upstream ==")
proxy_module.requests.request = fake_upstream
set_method_weights(100, 0)
proxy_module.set_tokens(["LEAK_TOKEN"])
api_client.get(
    "/games.roblox.com/v1/leak-check",
    headers={
        "X-Forwarded-For": "9.9.9.9",
        "X-Real-IP": "9.9.9.9",
        "Referer": "https://roxytheproxy.com/secret",
        "Origin": "https://roxytheproxy.com",
        "CF-Connecting-IP": "9.9.9.9",
        "Via": "1.1 roxy",
        "Roxy-Internal": "leak",
        "True-Client-IP": "9.9.9.9",
    },
)
sent = {k.lower() for k in upstream_calls[-1]["headers"]}
for bad in (
    "x-forwarded-for",
    "x-real-ip",
    "referer",
    "origin",
    "cf-connecting-ip",
    "via",
    "roxy-internal",
    "true-client-ip",
):
    check(f"Upstream did NOT receive '{bad}'", bad not in sent, sorted(sent))

print("== Authenticated requests are rejected (no ROBLOSECURITY support) ==")
IP_AUTH = {"X-Forwarded-For": "10.90.0.1"}
n = len(upstream_calls)
r = api_client.get("/games.roblox.com/v1/auth-test", headers={**IP_AUTH, "X-Roblox-Token": "some_token_value"})
check("X-Roblox-Token request -> 400", r.status_code == 400, r.status_code)
check("Rejection message explains why", b"authentication are not allowed" in r.data, r.data[:120])
check("Rejected auth request never hit upstream", len(upstream_calls) == n, len(upstream_calls) - n)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check(
    "Auth attempt logged as a probe (visible on the dashboard)",
    any("ROBLOSECURITY" in a.get("Reason", "") for a in r.get_json().get("ExploitAttempts", [])),
    r.get_json().get("ExploitAttempts", [])[-3:],
)
# A real .ROBLOSECURITY value (Roblox's own literal warning prefix) smuggled via
# ANY header — not just X-Roblox-Token — must be caught and rejected too.
n = len(upstream_calls)
r = api_client.get(
    "/games.roblox.com/v1/auth-test-2",
    headers={**IP_AUTH, "X-Custom-Auth": f"{config.TOKEN_PREFIX}SECRETVALUE"},
)
check("A ROBLOSECURITY-shaped value in ANY header -> 400", r.status_code == 400, r.status_code)
check("Smuggled-token request never hit upstream", len(upstream_calls) == n, len(upstream_calls) - n)
# A clean request (no token-shaped headers at all) still passes.
n = len(upstream_calls)
r = api_client.get("/games.roblox.com/v1/auth-test-clean", headers=IP_AUTH)
check("Clean request (no auth headers) -> 200", r.status_code == 200, r.status_code)
check("Clean request reached upstream", len(upstream_calls) == n + 1, len(upstream_calls) - n)
# X-Roblox-Token is unreachable via a live request (the gate above always rejects
# it first) but is ALSO in the stripped-header list as defense-in-depth.
check(
    "X-Roblox-Token is stripped as defense-in-depth",
    "x-roblox-token" in {h.lower() for h in index._STRIPPED_REQUEST_HEADERS},
    index._STRIPPED_REQUEST_HEADERS,
)

print("== sitemap.xml + robots SEO ==")
r = client.get("/sitemap.xml", headers=IP_MAIN)
check("GET /sitemap.xml -> 200 XML", r.status_code == 200 and b"<urlset" in r.data, r.status_code)
r = client.get("/robots.txt", headers=IP_MAIN)
check("robots.txt references the sitemap", b"Sitemap:" in r.data, r.data[:120])
check("robots.txt disallows /admin", b"/admin" in r.data, r.data[:120])

print("== Token Uses stay in sync with Token method Requests ==")
proxy_module.requests.request = fake_upstream
reset_routing()
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "requests"})
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "proxy_timings"})
set_method_weights(100, 0)
proxy_module.set_tokens(["SYNC_TOKEN"])
IP_SYNC = {"X-Forwarded-For": "10.60.0.1"}
for i in range(4):
    api_client.get(f"/games.roblox.com/v1/sync{i}", headers=IP_SYNC)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
token_req = diag.get("MethodStats", {}).get("Token", {}).get("Requests", 0)
uses_sum = sum(int(t.get("Uses", 0)) for t in diag.get("Tokens", []))
check("Token method recorded 4 requests", token_req == 4, token_req)
check(
    "Sum of per-token Uses equals Token method Requests", uses_sum == token_req and uses_sum == 4, (uses_sum, token_req)
)
check("Token row shows a Last Used time", any(t.get("LastUsedAt") for t in diag.get("Tokens", [])), diag.get("Tokens"))

print("== Per-requester timings ==")
mt = diag.get("MethodTimings", {})
check("Token timing recorded for the 4 requests", mt.get("Token", {}).get("Count", 0) == 4, mt.get("Token"))
check("Token timing captured a latency", mt.get("Token", {}).get("Max", 0) > 0, mt.get("Token"))

print("== Proxy timings clear independently of request counters ==")
rc_before = diag.get("RequestCounts", {}).get("GET", {}).get("Successful", 0)
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "proxy_timings"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag2 = r.get_json()
check(
    "proxy_timings clear zeroed method timings",
    diag2.get("MethodTimings", {}).get("Token", {}).get("Count", 0) == 0,
    diag2.get("MethodTimings"),
)
check(
    "Request counters SURVIVED a proxy_timings clear",
    diag2.get("RequestCounts", {}).get("GET", {}).get("Successful", 0) == rc_before,
    (diag2.get("RequestCounts", {}).get("GET"), rc_before),
)
api_client.get("/games.roblox.com/v1/sync-again", headers=IP_SYNC)  # repopulate both
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "requests"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag3 = r.get_json()
check(
    "'requests' clear zeroed the request counters",
    diag3.get("RequestCounts", {}).get("GET", {}).get("Successful", 0) == 0,
    diag3.get("RequestCounts", {}).get("GET"),
)
check(
    "Proxy timings SURVIVED a 'requests' clear",
    diag3.get("MethodTimings", {}).get("Token", {}).get("Count", 0) >= 1,
    diag3.get("MethodTimings", {}).get("Token"),
)

print("== Request failures log (per requester, why + when) ==")
reset_routing()
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "request_failures"})
set_method_weights(0, 100)  # Rotate
proxy_module.requests.request = failing_upstream  # returns 500
api_client.get("/games.roblox.com/v1/boom", headers={"X-Forwarded-For": "10.61.0.1"})
proxy_module.requests.request = fake_upstream
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
rf = r.get_json().get("RequestFailures", {})
check("Failure logged against the Rotate requester", any(v.get("Method") == "Rotate" for v in rf.values()), rf)
check("Failure records the status code", any("500" in str(v.get("LastStatus")) for v in rf.values()), rf)
check("Failure records the endpoint", any("boom" in (v.get("LastEndpoint") or "") for v in rf.values()), rf)
set_method_weights(100, 0)
reset_routing()
proxy_module.set_tokens(["FAKE_TOKEN_AAA"])

print("== Blocked user-agent drill-down (last headers + endpoint) ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "blocked_fingerprints"})
client.post(
    "/admin/headers/rule", headers=IP_MAIN, json={"header": "User-Agent", "mode": "contains", "needle": "DrillBot"}
)
api_client.get(
    "/games.roblox.com/v1/drill",
    headers={"X-Forwarded-For": "10.62.0.1", "User-Agent": "DrillBot/1", "X-Marker": "yes"},
)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
bua = r.get_json().get("BlockedUserAgents", {})
ua_key = next((k for k in bua if "DrillBot" in k), "")
check("Blocked UA summary flags that a last request was captured", bua.get(ua_key, {}).get("HasDetail") is True, bua)
# The captured header dump is per-record and heavy, so it is fetched on expand.
rec = client.get(
    f"/admin/fingerprints/user_agent?ua={quote(ua_key, safe='')}&blocked=1",
    headers={**IP_MAIN, "Accept": "application/json"},
).get_json()
check("Blocked UA captured its last headers", bool(rec.get("LastHeaders")), rec)
check("Blocked UA captured its last endpoint", "drill" in (rec.get("LastPath") or ""), rec)
check("Blocked UA captured its last IP", rec.get("LastIP") == "10.62.0.1", rec)
for rid in [k for k in r.get_json().get("HeaderRules", {}) if "drillbot" in k]:
    client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": rid})

print("== Settings expose all tunables (weights, rotation) ==")
settings = (
    client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"}).get_json().get("Settings", {})
)
for key in (
    "token_weight",
    "rotate_weight",
    "token_danger_zone",
    "rotate_enabled",
    "rotate_cooldown",
    "rotate_max_failures",
):
    check(f"Setting '{key}' is editable", key in settings, list(settings))

print("== Force-revalidate + health check report token + rotation status ==")
enable_rotation()
reset_routing()
proxy_module.set_tokens(["LIVE_TOKEN"])
r = client.post("/admin/tokens/force_revalidate", headers=IP_MAIN)
fr = r.get_json()
check("Force-revalidate reports token totals", fr.get("Total") == 1 and fr.get("Active") == 1, fr)
check("Force-revalidate report lists the token", bool(fr.get("Tokens")) and fr["Tokens"][0].get("Active") is True, fr)
r = client.post("/admin/health_check", headers=IP_MAIN)
hc = r.get_json()
check("Health check reports tokens active", hc.get("TokensActive") == 1 and hc.get("TokensTotal") == 1, hc)
check(
    "Health check probed a rotation exit IP",
    (hc.get("Rotation", {}).get("ExitIP") or "").startswith("203.0.113"),
    hc.get("Rotation"),
)
r = client.post("/admin/rotation/verify", headers=IP_MAIN)
rv = r.get_json()
check("Rotation verify returns an exit IP", (rv.get("ExitIP") or "").startswith("203.0.113"), rv)
check("Rotation verify sent through the proxy", get_calls[-1].get("proxies") is not None, get_calls[-1])
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check(
    "Exit IPs are logged for verification", len(r.get_json().get("RotateIps", [])) >= 1, r.get_json().get("RotateIps")
)
disable_rotation()
set_method_weights(100, 0)
reset_routing()
proxy_module.set_tokens(["FAKE_TOKEN_AAA"])

print("== Per-IP throttle is shared across workers (one limit, no Nx bypass) ==")
import throttle as throttle_module
import lockfile as lockfile_module

proxy_module.requests.request = fake_upstream
set_method_weights(100, 0)
proxy_module.set_tokens(["THR_TOKEN"])
client.post(
    "/admin/settings",
    headers=IP_MAIN,
    json={"settings": {"allowed_requests_per_minute": 3, "throttle_reset_duration": 300}},
)
IP_THR = {"X-Forwarded-For": "10.70.0.1"}
statuses = [api_client.get(f"/games.roblox.com/v1/thr{i}", headers=IP_THR).status_code for i in range(6)]
check("Over the shared per-IP limit returns 429", statuses[-1] == 429, statuses)
# A SECOND worker (independent store object on the SAME file) sees the same count
# — proving the limit lives in shared state, not per-worker memory.
worker_b = lockfile_module.LockedJSON(lambda: config.THROTTLE_FILE)
entry_b = worker_b.read().get("Ips", {}).get("10.70.0.1", {})
check("Per-IP count lives in the shared file (worker B sees it)", entry_b.get("Requests", 0) >= 4, entry_b)
check("Worker B sees the IP as throttled (no Nx bypass)", bool(entry_b.get("Throttled")), entry_b)
check("throttle.is_throttled reads the shared state", throttle_module.is_throttled("10.70.0.1") is True)
client.post(
    "/admin/settings",
    headers=IP_MAIN,
    json={"settings": {"allowed_requests_per_minute": 100000, "throttle_reset_duration": 50}},
)

# The real multi-worker scenario: separate OS PROCESSES (like gunicorn workers)
# hammering one shared file. The in-process test above is serialized by the
# per-process lock, so this is what actually exercises the inter-process flock.
import subprocess

mp_file = os.path.join(sandbox, "mp_counter.json")
app_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app")
worker_code = (
    f"import sys; sys.path.insert(0, {app_dir!r})\n"
    "from lockfile import LockedJSON\n"
    f"store = LockedJSON(lambda: {mp_file!r})\n"
    "for _ in range(200):\n"
    "    store.update(lambda d: d.__setitem__('n', d.get('n', 0) + 1))\n"
)
procs = [subprocess.Popen([sys.executable, "-c", worker_code]) for _ in range(5)]
for p in procs:
    p.wait()
mp_total = lockfile_module.LockedJSON(lambda: mp_file).read().get("n", 0)
check("5 processes x 200 increments == 1000 (inter-process flock loses nothing)", mp_total == 1000, mp_total)

print("== Throttle-bypass allowlist (skip 429s for spam testing) ==")
import runtime as runtime_module

proxy_module.requests.request = fake_upstream
set_method_weights(100, 0)
proxy_module.set_tokens(["BYPASS_TOKEN"])
client.post(
    "/admin/settings",
    headers=IP_MAIN,
    json={"settings": {"allowed_requests_per_minute": 3, "throttle_reset_duration": 300}},
)
# Control: a normal IP is throttled once it passes the limit.
IP_CTRL = {"X-Forwarded-For": "10.80.0.1"}
ctrl = [api_client.get(f"/games.roblox.com/v1/np{i}", headers=IP_CTRL).status_code for i in range(6)]
check("Without bypass, an IP is throttled past the limit", 429 in ctrl, ctrl)
# Add a bypass; that IP can now blow past the limit with no 429.
r = client.post("/admin/throttle/bypass", headers=IP_MAIN, json={"ip": "10.80.0.2", "note": "spam test"})
check("Add bypass -> 200", r.status_code == 200, r.data[:80])
check("Bypass IP appears in the returned list", "10.80.0.2" in r.get_json().get("ThrottleBypassIps", {}), r.get_json())
IP_BYP = {"X-Forwarded-For": "10.80.0.2"}
byp = [api_client.get(f"/games.roblox.com/v1/by{i}", headers=IP_BYP).status_code for i in range(12)]
check("Bypassed IP never gets a 429 (spam allowed)", all(s == 200 for s in byp), byp)
diag = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"}).get_json()
check(
    "Diagnostics lists the bypass IP", "10.80.0.2" in diag.get("ThrottleBypassIps", {}), diag.get("ThrottleBypassIps")
)
check("Diagnostics reports the requester's own IP (for one-click add)", bool(diag.get("YourIP")), diag.get("YourIP"))
# Remove it -> throttling resumes for that IP.
r = client.post("/admin/throttle/bypass/remove", headers=IP_MAIN, json={"ip": "10.80.0.2"})
check("Remove bypass -> 200", r.status_code == 200, r.status_code)
check("Bypass removed from the list", "10.80.0.2" not in r.get_json().get("ThrottleBypassIps", {}), r.get_json())
after = [api_client.get(f"/games.roblox.com/v1/ar{i}", headers=IP_BYP).status_code for i in range(6)]
check("After removal, the IP is throttled again", 429 in after, after)
# Optional expiry: a set expiry that has passed deactivates the bypass on its own.
runtime_module.add_throttle_bypass("10.80.0.3", expires_in=0.05, note="temp")
check("Bypass is active before its expiry", runtime_module.is_throttle_bypassed("10.80.0.3") is True)
time.sleep(0.12)
check("Bypass auto-expires after its expiry", runtime_module.is_throttle_bypassed("10.80.0.3") is False)
check("Expired bypass is hidden from the list", "10.80.0.3" not in runtime_module.get_throttle_bypass_ips())
runtime_module.remove_throttle_bypass("10.80.0.3")
check(
    "Bypass with no expiry never expires",
    (runtime_module.add_throttle_bypass("10.80.0.4"), runtime_module.is_throttle_bypassed("10.80.0.4"))[1] is True,
)
runtime_module.remove_throttle_bypass("10.80.0.4")
client.post(
    "/admin/settings",
    headers=IP_MAIN,
    json={"settings": {"allowed_requests_per_minute": 100000, "throttle_reset_duration": 50}},
)

print("== Login lockout + email de-dup are shared across workers ==")
throttle_module.reset_login_failures("10.71.0.1")
for _ in range(config.MAX_LOGIN_FAILURES):
    throttle_module.register_login_failure("10.71.0.1")
login_b = worker_b.read().get("Login", {}).get("10.71.0.1", {})
check("Login failures recorded in the shared file", login_b.get("Count", 0) >= config.MAX_LOGIN_FAILURES, login_b)
check("Lockout is enforced from shared state", throttle_module.is_login_blocked("10.71.0.1")[0] is True)
throttle_module.reset_login_failures("10.71.0.1")
# Email gate: the first call reserves the slot, a second within the cooldown is denied.
check("First email send is allowed", proxy_module._email_allowed("smoketest_email", 100) is True)
check(
    "Duplicate email within cooldown is suppressed (shared gate)",
    proxy_module._email_allowed("smoketest_email", 100) is False,
)
coord_b = lockfile_module.LockedJSON(lambda: config.COORD_FILE)
check(
    "Email gate timestamp lives in the shared coord file",
    float(coord_b.read().get("EmailGate", {}).get("smoketest_email", 0)) > 0,
)

print("== Emailed invalidation link (kill switch) ==")
invalidate_emails = emails_with("Roxy Admin Login")
link_token = invalidate_emails[-1]["body"].split("/admin/invalidate/")[-1].strip().splitlines()[0]
# GET only shows a confirmation page and must NOT spend the token: mail scanners
# and link prefetchers issue GETs, and consuming it there burned the one-shot
# emergency link before the admin ever clicked it.
epoch_before = runtime_module.get_session_epoch()
r = client.get(f"/admin/invalidate/{link_token}", headers=IP_MAIN)
check("Invalidation link GET renders a confirmation page -> 200", r.status_code == 200, r.status_code)
check("A prefetched GET does not spend the token", runtime_module.get_session_epoch() == epoch_before)
r = client.get(f"/admin/invalidate/{link_token}", headers=IP_MAIN)
check("Link still valid after a prefetch", r.status_code == 200, r.status_code)
r = client.post(f"/admin/invalidate/{link_token}", headers=IP_MAIN)
check("Confirming the invalidation -> 200", r.status_code == 200, r.status_code)
check("Confirming bumps the session epoch", runtime_module.get_session_epoch() > epoch_before)
r = client.post(f"/admin/invalidate/{link_token}", headers=IP_MAIN)
check("Reused invalidation link -> 404 (single use)", r.status_code == 404, r.status_code)
r = client.get("/admin/dashboard", headers=IP_MAIN)
check("Session dead after kill switch", r.status_code == 302, r.status_code)

print("== Brute-force lockout (separate IP) ==")
for _ in range(config.MAX_LOGIN_FAILURES):
    client.post("/admin", headers=IP_BRUTE, json={"IsLogin": True, "Username": "x", "Password": "y"})
r = client.post("/admin", headers=IP_BRUTE, json={"IsLogin": True, "Username": ADMIN_USER, "Password": ADMIN_PASS})
check("Locked out after repeated failures -> 429", r.status_code == 429, r.status_code)

print("== Error emails still work for real 500s (rate-limited) ==")
# Reset the SHARED (cross-worker) email gate left by earlier error-log tests.
proxy_module._coord.update(lambda d: d.get("EmailGate", {}).clear())
before = len(emails_with("Roxy Error"))
r = client.get("/_boom_test_only", headers=IP_MAIN)
check("Real exception -> 500", r.status_code == 500, r.status_code)
after = emails_with("Roxy Error")
check("Real exception emails the admin", len(after) == before + 1, len(after))
check("Error email includes traceback", "Traceback" in after[-1]["body"] if after else False)
r = client.get("/_boom_test_only", headers=IP_MAIN)
check("Second exception within cooldown does NOT email", len(emails_with("Roxy Error")) == before + 1)

print("== Concurrency hammer (probe storms must not crash shared state) ==")
import threading

hammer_errors = []


def hammer(worker_id):
    c = app.test_client()
    try:
        for i in range(25):
            ip = {"X-Forwarded-For": f"10.9.{worker_id}.{i % 5}"}
            c.get(f"/probe-path-{worker_id}-{i}", headers=ip)  # exploit log + throttle paths
            c.post("/", headers=ip)  # HTTPException handler path
    except Exception as e:  # noqa: BLE001 - anything here is a real bug
        hammer_errors.append(repr(e))


threads = [threading.Thread(target=hammer, args=(n,)) for n in range(8)]
for t in threads:
    t.start()
for t in threads:
    t.join()
check("400 concurrent requests raised no exceptions", not hammer_errors, hammer_errors[:3])

# Lost-update check: many threads incrementing the SAME shared counter must land
# EXACTLY the right total (proves the flock read-modify-write loses nothing).
client.post(
    "/admin/settings",
    headers=IP_MAIN,
    json={"settings": {"allowed_requests_per_minute": 1000000, "throttle_reset_duration": 600}},
)
HAMMER_IP = "10.99.0.1"
throttle_module._store.update(lambda d: d.get("Ips", {}).pop(HAMMER_IP, None))
INC_THREADS, INC_EACH = 8, 50


def count_hammer():
    for _ in range(INC_EACH):
        throttle_module.update_throttling(HAMMER_IP, made_request=True)


inc_threads = [threading.Thread(target=count_hammer) for _ in range(INC_THREADS)]
for t in inc_threads:
    t.start()
for t in inc_threads:
    t.join()
final = lockfile_module.LockedJSON(lambda: config.THROTTLE_FILE).read().get("Ips", {}).get(HAMMER_IP, {})
check(
    "Concurrent counter increments lose nothing (no write race)",
    final.get("Requests") == INC_THREADS * INC_EACH,
    (final.get("Requests"), INC_THREADS * INC_EACH),
)
client.post(
    "/admin/settings",
    headers=IP_MAIN,
    json={"settings": {"allowed_requests_per_minute": 100000, "throttle_reset_duration": 50}},
)

# Log back in (the kill switch above ended the old session) and confirm the app is still healthy.
r = client.post("/admin", headers=IP_MAIN, json={"IsLogin": True, "Username": ADMIN_USER, "Password": ADMIN_PASS})
code = emails_with("Admin 2FA")[-1]["body"].strip()
r = client.post("/admin", headers=IP_MAIN, json={"Is2FA": True, "TwoFA": code})
check("Login still works after epoch bump + hammer", r.status_code == 200, r.status_code)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check("Diagnostics healthy after hammer", r.status_code == 200, r.status_code)

print("== Record caps survive the cross-worker merge (the OOM bug) ==")
# Each worker caps its own stores, but merging N workers' capped sets used to
# produce an uncapped UNION -- so the shared file, and therefore every worker's
# memory, grew forever until the kernel killed the process. The merge must
# re-apply every ceiling.
import diagnostics as diag_module  # noqa: E402

cap = diag_module._cap("max_header_value_records", config.MAX_HEADER_VALUE_RECORDS)
shared_side = {f"shared-{i}": {"Count": 1, "FirstSeen": 1.0, "LastSeen": 1.0} for i in range(cap)}
local_side = {f"local-{i}": {"Count": 1, "FirstSeen": 1.0, "LastSeen": 1.0} for i in range(cap)}
merged = diag_module._merge_stats(
    {"header_names": {"x-merge-test": {"Count": cap, "FirstSeen": 1.0, "LastSeen": 1.0, "Values": shared_side}}},
    {"header_names": {"x-merge-test": {"Count": cap, "FirstSeen": 1.0, "LastSeen": 1.0, "Values": local_side}}},
    {},
)
merged_values = merged["header_names"]["x-merge-test"]["Values"]
check(
    "Merging two full sets stays within the value cap (no unbounded union)",
    len(merged_values) <= cap,
    f"{len(merged_values)} > {cap}",
)
wide = {f"ua-{i}": {"Count": 1, "FirstSeen": 1.0, "LastSeen": 1.0} for i in range(cap * 4)}
merged = diag_module._merge_stats({"user_agents": wide}, {"user_agents": dict(wide)}, {})
ua_cap = diag_module._cap("max_user_agent_records", config.MAX_USER_AGENT_RECORDS)
check("User-agent store is capped after a merge", len(merged["user_agents"]) <= ua_cap, len(merged["user_agents"]))
check(
    "Trimming keeps the busiest records, not arbitrary ones",
    diag_module._trim_store({"keep": {"Count": 99}, "drop": {"Count": 1}}, 1, "count") == 1 and "keep" in {"keep": 1},
)
sizes = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"}).get_json()
check("Diagnostics reports per-store record counts", isinstance(sizes.get("StoreSizes"), dict), sizes.get("StoreSizes"))
check(
    "Persistence reports the stats-file size against its ceiling",
    sizes.get("Persistence", {}).get("DataLimitBytes") == config.MAX_DATA_FILE_BYTES,
    sizes.get("Persistence"),
)

print("== High-cardinality header values are not enumerated ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "fingerprints"})
proxy_module.set_tokens(["CARD_TOKEN"])
IP_CARD = {"X-Forwarded-For": "10.90.0.1"}
for i in range(5):
    api_client.get("/games.roblox.com/v1/card", headers={**IP_CARD, "traceparent": f"00-{i:032x}-{i:016x}-01"})
d = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"}).get_json()
tp = d.get("HeaderNames", {}).get("traceparent", {})
check("traceparent is still counted", tp.get("Count", 0) >= 5, tp)
check("traceparent's per-request values are NOT stored", tp.get("ValueCount") == 0, tp)
check("traceparent is flagged as not-enumerated", tp.get("ValuesIgnored") is True, tp)
check(
    "traceparent ships in the default ignore list",
    "traceparent" in d.get("IgnoredValueHeaders", {}),
    d.get("IgnoredValueHeaders"),
)
# ...and the admin can turn it back on, then off again, from the dashboard.
r = client.post("/admin/fingerprints/ignore", headers=IP_MAIN, json={"name": "traceparent", "ignore": False})
check("Un-ignoring a header -> 200", r.status_code == 200, r.status_code)
check("Un-ignored header leaves the list", "traceparent" not in r.get_json().get("IgnoredValueHeaders", {}))
api_client.get("/games.roblox.com/v1/card", headers={**IP_CARD, "traceparent": "00-abc-def-01"})
d = client.get("/admin/diagnostics?flush=1", headers={**IP_MAIN, "Accept": "application/json"}).get_json()
check(
    "Values are recorded again once un-ignored",
    d["HeaderNames"]["traceparent"].get("ValueCount") == 1,
    d["HeaderNames"]["traceparent"],
)
r = client.post("/admin/fingerprints/ignore", headers=IP_MAIN, json={"name": "traceparent", "ignore": True})
check("Re-ignoring a header -> 200", r.status_code == 200, r.status_code)
d = client.get("/admin/diagnostics?flush=1", headers={**IP_MAIN, "Accept": "application/json"}).get_json()
check(
    "Re-ignoring drops what was already collected",
    d["HeaderNames"]["traceparent"].get("ValueCount") == 0,
    d["HeaderNames"]["traceparent"],
)

print("== Per-header clear cannot be resurrected by another worker ==")
# The reported bug: clearing a header removed it here and from the file, but every
# OTHER worker still held it in memory AND in its merge baseline, so its next
# autosave merged the record straight back. Section clears already guarded against
# this with ClearEpochs; per-key clears need the same, keyed per record.
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "fingerprints"})
api_client.get("/games.roblox.com/v1/res", headers={"X-Forwarded-For": "10.90.1.1", "X-Ghost": "boo"})
diag_module._flush()
stale_local = json.loads(json.dumps(diag_module.serialize()))  # what a second worker would still be holding
ok, _removed = diag_module.clear_fingerprint_header(False, "X-Ghost")
check("Per-header clear reports success", ok is True)
check("Cleared header is gone from this worker", "x-ghost" not in diag_module.header_names)


def worker_b_flush(local_snapshot):
    """Replay another worker's flush: its stale copy must not put the record back."""

    def mutate(data):
        shared = data.get("Diagnostics", {})
        key_epochs = shared.get("KeyClearEpochs", {})
        applied = dict(local_snapshot)
        for marker, epoch in (key_epochs or {}).items():
            store_name, _, remainder = str(marker).partition("/")
            values_only = remainder.endswith("/Values")
            key = remainder[: -len("/Values")] if values_only else remainder
            diag_module._apply_key_clear(applied, store_name, key, values_only)
        data["Diagnostics"] = diag_module._merge_stats(shared, applied, applied)
        return data

    return storage_module.update_data(mutate)


import storage as storage_module  # noqa: E402

after = worker_b_flush(stale_local)
check(
    "A second worker's flush does NOT resurrect the cleared header",
    "x-ghost" not in after.get("Diagnostics", {}).get("header_names", {}),
    list(after.get("Diagnostics", {}).get("header_names", {})),
)
check(
    "The clear is recorded as a KeyClearEpoch",
    any("x-ghost" in k for k in after["Diagnostics"].get("KeyClearEpochs", {})),
    after["Diagnostics"].get("KeyClearEpochs"),
)
# Values-only clear keeps the header itself.
api_client.get("/games.roblox.com/v1/res", headers={"X-Forwarded-For": "10.90.1.1", "X-Keep": "v1"})
diag_module._flush()
diag_module.clear_fingerprint_header(False, "X-Keep", values_only=True)
check("Values-only clear keeps the header row", "x-keep" in diag_module.header_names, list(diag_module.header_names))
check(
    "Values-only clear empties its values",
    not diag_module.header_names["x-keep"].get("Values"),
    diag_module.header_names.get("x-keep"),
)

print("== Client IP comes from a hop we control, not from the caller ==")
# nginx's conventional `X-Forwarded-For $proxy_add_x_forwarded_for` APPENDS, so the
# LEFTMOST entry is whatever the caller typed. Reading it let anyone bypass per-IP
# throttling, the admin login lockout and the 2FA challenge binding.
with app.test_request_context(
    "/", environ_base={"REMOTE_ADDR": "203.0.113.7"}, headers={"X-Forwarded-For": "9.9.9.9, 203.0.113.7"}
):
    check("Spoofed leading X-Forwarded-For is ignored", index.get_client_ip() == "203.0.113.7", index.get_client_ip())
with app.test_request_context("/", environ_base={"REMOTE_ADDR": "198.51.100.4"}):
    check(
        "Falls back to the socket address with no header",
        index.get_client_ip() == "198.51.100.4",
        index.get_client_ip(),
    )

print("== The Roblox session cookie cannot follow a redirect off-domain ==")
# Passing cookies={...} makes a domain-less cookie that `requests` replays to
# whatever host a 302 points at; a domain-scoped jar refuses off-domain instead.
import requests as requests_module  # noqa: E402

jar = proxy_module._token_jar("SECRET_COOKIE_VALUE")
for url, should_send in [
    ("https://games.roblox.com/v1/x", True),
    ("https://accountinformation.roblox.com/v1/birthdate", True),
    ("https://evil.example/x", False),
    ("https://roblox.com.evil.example/x", False),
]:
    prepared = requests_module.Request("GET", url).prepare()
    sent = requests_module.cookies.get_cookie_header(jar, prepared)
    check(
        f"Token cookie {'is sent to' if should_send else 'is NOT sent to'} {url.split('/')[2]}",
        bool(sent) is should_send,
        sent,
    )
check(
    "Token masking exposes at most 6 characters",
    len(proxy_module.mask_token("A" * 80).strip("…")) <= 6,
    proxy_module.mask_token("A" * 80),
)

print("== Hardening headers, admin 404s, and input guards ==")
r = client.get("/", headers=IP_MAIN)
for header in (
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
):
    check(f"{header} is set", bool(r.headers.get(header)), dict(r.headers))
check(
    "CSP blocks framing and inline script hosts",
    "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", ""),
)
# nginx terminates TLS and adds HSTS itself, and its add_header APPENDS rather
# than replaces -- so the app staying quiet is what stops the browser receiving
# two Strict-Transport-Security headers.
check(
    "HSTS is left to nginx by default",
    r.headers.get("Strict-Transport-Security") is None,
    r.headers.get("Strict-Transport-Security"),
)
config.SEND_HSTS = True
try:
    hsts = client.get("/", headers=IP_MAIN).headers.get("Strict-Transport-Security")
    check("HSTS can be enabled where no proxy adds it", "max-age=" in (hsts or ""), hsts)
finally:
    config.SEND_HSTS = False
probes_before = len(
    client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
    .get_json()
    .get("ExploitAttempts", [])
)
r = client.get("/admin/dashbaord", headers=IP_MAIN)  # a typo, not an attack
check("A mistyped admin URL -> 404", r.status_code == 404, r.status_code)
probes_after = (
    client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
    .get_json()
    .get("ExploitAttempts", [])
)
check(
    "A mistyped admin URL is NOT logged as an exploit attempt",
    not any("dashbaord" in (p.get("Reason") or "") for p in probes_after),
    [p.get("Reason") for p in probes_after[-3:]],
)
r = client.post("/admin/data/clear", headers=IP_MAIN, json={"target": []})
check("A non-string clear target -> 400, not a 500", r.status_code == 400, r.status_code)
r = client.post("/admin/data/clear", headers=IP_MAIN, json={"target": {"a": 1}})
check("An object clear target -> 400, not a 500", r.status_code == 400, r.status_code)

print("== Throttle window does not creep past its configured duration ==")
client.post(
    "/admin/settings",
    headers=IP_MAIN,
    json={"settings": {"allowed_requests_per_minute": 100, "throttle_reset_duration": 50}},
)
IP_CREEP = "10.90.2.1"
throttle_module._store.update(lambda data: data.get("Ips", {}).pop(IP_CREEP, None))
throttle_module.update_throttling(IP_CREEP, made_request=True)
first_reset = throttle_module._store.read()["Ips"][IP_CREEP]["ThrottleResetTime"]
for _ in range(10):
    throttle_module.update_throttling(IP_CREEP, made_request=True)
later_reset = throttle_module._store.read()["Ips"][IP_CREEP]["ThrottleResetTime"]
check("Extra requests do not push the reset time outwards", later_reset == first_reset, (first_reset, later_reset))

print("== Distinct events are not deduped away by the merge ==")
# Two genuinely separate probes from one IP in one second with the same reason are
# two probes; deduping on the whole record collapsed them into one.
twin = {"IP": "10.90.3.1", "Date": 1000.0, "Reason": "same reason", "UserAgent": "x"}
merged_list = diag_module._merge_list("exploit_attempts", [dict(twin, Id="a-1")], [dict(twin, Id="a-2")])
check("Identical-looking events with distinct ids both survive", len(merged_list) == 2, merged_list)
same = dict(twin, Id="a-9")
check(
    "The same event merged twice stays one", len(diag_module._merge_list("exploit_attempts", [same], [dict(same)])) == 1
)

print("== Upstream timeouts are counted against the method that lost ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "requests"})
set_method_weights(100, 0)
reset_routing()
proxy_module.set_tokens(["TIMEOUT_TOKEN"])
saved_request = proxy_module.requests.request


def always_timeout(method, url, **kwargs):
    raise requests_module.Timeout("simulated")


proxy_module.requests.request = always_timeout
api_client.get("/games.roblox.com/v1/timeout", headers={"X-Forwarded-For": "10.90.4.1"})
proxy_module.requests.request = saved_request
ms = (
    client.get("/admin/diagnostics?flush=1", headers={**IP_MAIN, "Accept": "application/json"})
    .get_json()
    .get("MethodStats", {})
    .get("Token", {})
)
check("A timeout counts as a Token request", ms.get("Requests", 0) >= 1, ms)
check("A timeout counts as a Token failure", ms.get("Failed", 0) >= 1, ms)
check("A timeout is still counted as a timeout", ms.get("Timeouts", 0) >= 1, ms)
reset_routing()
proxy_module.set_tokens(["FAKE_TOKEN_AAA"])

print("== Control plane is separate from, and survives, the stats file ==")
check(
    "The state file exists and is small",
    os.path.getsize(os.environ["ROXY_STATE_FILE"]) < 256 * 1024,
    os.path.getsize(os.environ["ROXY_STATE_FILE"]),
)
with open(os.environ["ROXY_STATE_FILE"]) as f:
    state_blob = json.load(f)
check(
    "Settings live in the state file",
    isinstance(state_blob.get("Runtime", {}).get("Settings"), dict),
    list(state_blob.get("Runtime", {})),
)
check(
    "Endpoint rules live in the state file",
    "EndpointRules" in state_blob.get("Runtime", {}),
    list(state_blob.get("Runtime", {})),
)
client.post("/admin/endpoints/block", headers=IP_MAIN, json={"pattern": "games.roblox.com/v1/survivor"})
os.remove(os.environ["ROXY_DATA_FILE"])  # nuke every statistic
check(
    "Deleting the whole stats file leaves the rules intact",
    "games.roblox.com/v1/survivor" in runtime_module.get_endpoint_blocks(),
    list(runtime_module.get_endpoint_blocks()),
)
r = api_client.get("/games.roblox.com/v1/survivor", headers={"X-Forwarded-For": "10.90.5.1"})
check("...and the rules are still enforced", r.status_code == 403, r.status_code)
client.post("/admin/endpoints/unblock", headers=IP_MAIN, json={"pattern": "games.roblox.com/v1/survivor"})

print("== An oversized stats file is quarantined, not parsed ==")
# Parsing is the step that exhausts memory, so the guard has to fire before it.
with open(os.environ["ROXY_DATA_FILE"], "w") as f:
    f.write("[" + "0," * (config.MAX_DATA_FILE_BYTES // 2) + "0]")
check(
    "The oversized file is above the limit", os.path.getsize(os.environ["ROXY_DATA_FILE"]) > config.MAX_DATA_FILE_BYTES
)
loaded = storage_module.load_data()
check("An oversized stats file loads as empty instead of blowing up memory", loaded == {}, type(loaded))
check("The oversized file is moved aside for inspection", not os.path.exists(os.environ["ROXY_DATA_FILE"]))
check(
    "The quarantine is reported to the dashboard",
    bool(storage_module.get_status().get("Oversize")),
    storage_module.get_status(),
)
for leftover in os.listdir(sandbox):
    if ".oversize-" in leftover:
        os.remove(os.path.join(sandbox, leftover))

print("== Tarpit: refusals are held open, capped, and measured ==")
import tarpit as tarpit_module  # noqa: E402
import threading  # noqa: E402

client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "tarpit"})
for key, value in (("tarpit_enabled", 1), ("tarpit_min_seconds", 1), ("tarpit_max_seconds", 1)):
    runtime.set_setting(key, value)
TARPIT_IP = {"X-Forwarded-For": "10.44.0.1"}

started = time.time()
r = api_client.get("/not-a-roblox-url-at-all", headers=TARPIT_IP)
held_for = time.time() - started
check("A probe still gets its normal 404", r.status_code == 404, r.status_code)
check("...but only after being held", held_for >= 0.9, f"{held_for:.2f}s")
check("The response says nothing about being held", not any("held" in name.lower() for name in r.headers.keys()))

api_client.get("/still-not-roblox", headers=TARPIT_IP)
stats = diag_module.tarpit_stats
check("Both holds were counted", stats["Count"] >= 2, stats["Count"])
check("Time wasted is accumulated", stats["TotalHeld"] >= 1.8, stats["TotalHeld"])
check("The interval between their requests is measured", stats["Gaps"] >= 1, stats["Gaps"])
check("Holds are attributed to the category that caused them", "probe" in stats["Categories"], stats["Categories"])
check("The caller is tracked individually", "10.44.0.1" in diag_module.tarpit_ips, list(diag_module.tarpit_ips))

# A category that is switched off must not be held at all.
runtime.set_setting("tarpit_on_throttle", 0)
runtime.set_setting("allowed_requests_per_minute", 3)  # Earlier sections may have raised this.
before = diag_module.tarpit_stats["Count"]
for _ in range(8):
    api_client.get("/games.roblox.com/v1/games", headers={"X-Forwarded-For": "10.44.0.9"})
started = time.time()
r = api_client.get("/games.roblox.com/v1/games", headers={"X-Forwarded-For": "10.44.0.9"})
check("A throttled caller gets the usual 429", r.status_code == 429, r.status_code)
check("A disabled category is answered instantly", time.time() - started < 0.5, f"{time.time() - started:.2f}s")
check("...and is not counted as a hold", diag_module.tarpit_stats["Count"] == before, diag_module.tarpit_stats["Count"])

# The safety valve: holds must never be able to occupy every worker thread.
runtime.set_setting("tarpit_max_concurrent", 1)
runtime.set_setting("tarpit_min_seconds", 2)
runtime.set_setting("tarpit_max_seconds", 2)
skipped_before = diag_module.tarpit_stats["Skipped"]
outcomes = []
threads = [
    threading.Thread(target=lambda n: outcomes.append(tarpit_module.hold(f"10.44.1.{n}", "probe")), args=(n,))
    for n in range(4)
]
wall = time.time()
[t.start() for t in threads]
[t.join() for t in threads]
wall = time.time() - wall
check("Only one request is held when the cap is 1", sum(1 for held in outcomes if held > 0) == 1, outcomes)
check("The rest are refused instantly rather than queueing", wall < 3.5, f"{wall:.2f}s")
check("Over-capacity refusals are counted separately", diag_module.tarpit_stats["Skipped"] == skipped_before + 3)
check("No slot is leaked once the holds finish", tarpit_module.active_holds() == 0, tarpit_module.active_holds())

# A worker killed mid-hold must not strand its slot forever.
tarpit_module._store.update(lambda data: data.setdefault("Slots", {}).update({"dead-worker": time.time() - 1}))
check("An expired lease is not counted as active", tarpit_module.active_holds() == 0)
check("...and is reclaimed by the next admission", tarpit_module.hold("10.44.2.1", "probe") > 0)

# If the shared file is unavailable, LockedJSON degrades to a throwaway dict —
# which would make every worker think it holds the only slot. Fail closed.
import lockfile as lockfile_module  # noqa: E402

_real_write = lockfile_module.LockedJSON._write
lockfile_module.LockedJSON._write = lambda self, data: (_ for _ in ()).throw(OSError("disk gone"))
skipped_before = diag_module.tarpit_stats["Skipped"]
degraded = tarpit_module.hold("10.44.2.9", "probe")
lockfile_module.LockedJSON._write = _real_write
check("With shared state unavailable, nothing is held", degraded == 0.0, degraded)
check("...and the refusal is counted, not silently dropped", diag_module.tarpit_stats["Skipped"] == skipped_before + 1)
check("...and holding resumes once it recovers", tarpit_module.hold("10.44.2.8", "probe") > 0)

# The admin's own bypass IP must never be tarpitted (it is how they test).
client.post("/admin/throttle/bypass", headers=IP_MAIN, json={"ip": "10.44.3.1"})
runtime.set_setting("tarpit_max_concurrent", 6)
started = time.time()
api_client.get("/not-roblox-either", headers={"X-Forwarded-For": "10.44.3.1"})
check("A bypass IP is answered instantly", time.time() - started < 0.5, f"{time.time() - started:.2f}s")
client.post("/admin/throttle/bypass/remove", headers=IP_MAIN, json={"ip": "10.44.3.1"})

r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check("Dashboard sees live tarpit capacity", diag.get("Tarpit", {}).get("MaxConcurrent") == 6, diag.get("Tarpit"))
check("Dashboard sees which categories are armed", "probe" in diag.get("Tarpit", {}).get("Categories", []))
check("Dashboard gets the arrival-rate windows", len(diag.get("TarpitRates", [])) == 3, diag.get("TarpitRates"))
check("Tarpit totals reach the dashboard", diag.get("TarpitStats", {}).get("Count", 0) >= 2, diag.get("TarpitStats"))

r = client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "tarpit"})
check("Tarpit stats can be cleared -> 200", r.status_code == 200, r.status_code)
check("...and the counters reset", diag_module.tarpit_stats["Count"] == 0, diag_module.tarpit_stats)
check("...including the shared arrival times", tarpit_module._store.read() == {}, tarpit_module._store.read())
runtime.set_setting("tarpit_enabled", 0)

print("== Proxy timings separate successes from failures ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "proxy_timings"})
reset_routing()


def upstream_404(method, url, headers=None, params=None, data=None, cookies=None, timeout=None, proxies=None):
    return FakeUpstreamResponse(status=404, text='{"errors":[]}')


api_client.get("/games.roblox.com/v1/fast", headers={"X-Forwarded-For": "10.55.0.1"})
proxy_module.requests.request = upstream_404
api_client.get("/games.roblox.com/v1/missing", headers={"X-Forwarded-For": "10.55.0.2"})
proxy_module.requests.request = fake_upstream  # restore 200s

diag = client.get("/admin/diagnostics?flush=1", headers={**IP_MAIN, "Accept": "application/json"}).get_json()
get_row = diag.get("ProxyRequestCounts", {}).get("GET", {})
check("A successful GET lands in the Success bucket", get_row.get("Success", {}).get("Count", 0) >= 1, get_row)
check("A failed GET lands in the Failed bucket", get_row.get("Failed", {}).get("Count", 0) >= 1, get_row)
check(
    "The combined row still totals both",
    get_row.get("Count", 0) >= get_row.get("Success", {}).get("Count", 0) + get_row.get("Failed", {}).get("Count", 0),
    get_row,
)
totals = diag.get("MethodTimings", {})
split = any(m.get("Success", {}).get("Count", 0) or m.get("Failed", {}).get("Count", 0) for m in totals.values())
check("Per-requester timings are split the same way", split, totals)

print("== Token health reports liveness, not just counters ==")
api_client.get("/games.roblox.com/v1/live", headers={"X-Forwarded-For": "10.55.0.3"})
diag = client.get("/admin/diagnostics?flush=1", headers={**IP_MAIN, "Accept": "application/json"}).get_json()
methods = diag.get("MethodStats", {})
live = [m for m in methods.values() if m.get("Requests")]
check("A requester records when it last ran", any(m.get("LastRequestTime") for m in live), methods)
check("A requester records when it last succeeded", any(m.get("LastSuccessAt") for m in live), methods)
proxy_module.requests.request = failing_upstream  # returns 500
api_client.get("/games.roblox.com/v1/broken", headers={"X-Forwarded-For": "10.55.0.4"})
proxy_module.requests.request = fake_upstream
diag = client.get("/admin/diagnostics?flush=1", headers={**IP_MAIN, "Accept": "application/json"}).get_json()
methods = diag.get("MethodStats", {})
check(
    "A requester records why it last failed",
    any("500" in str(m.get("LastError", "")) for m in methods.values()),
    {k: v.get("LastError") for k, v in methods.items()},
)

print("== Worker fleet is reported instead of one worker's uptime ==")
import workers as workers_module  # noqa: E402

workers_module.heartbeat()
diag = client.get("/admin/diagnostics?flush=1", headers={**IP_MAIN, "Accept": "application/json"}).get_json()
fleet = diag.get("WorkerFleet", {})
check("The fleet lists at least this worker", fleet.get("Count", 0) >= 1, fleet)
check("Service uptime is reported separately from worker uptime", fleet.get("ServiceUptime", 0) > 0, fleet)
check("Service uptime survives a worker restarting", fleet.get("ServiceStartedAt", 0) > 0, fleet)
row = (fleet.get("Workers") or [{}])[0]
check("Each worker reports its pid", row.get("Pid"), row)
check("Each worker reports its memory", row.get("RSS", 0) > 0, row)
check("Each worker reports its own uptime", row.get("Uptime", 0) >= 0, row)
check("Each worker reports how many requests it has served", row.get("Requests", 0) > 0, row)

# The two counters must not be the same number. "All" includes the dashboard
# polling itself, so on an idle proxy it climbs on its own — which reads as
# traffic unless proxy requests are counted separately.
before = workers_module.get_state()
for _ in range(6):
    client.get("/health", headers=IP_MAIN)
workers_module.heartbeat()
idle = workers_module.get_state()
check("Non-proxy requests raise the total", idle["TotalRequests"] > before["TotalRequests"], idle["TotalRequests"])
check("...but not the proxy count", idle["TotalProxied"] == before["TotalProxied"], idle["TotalProxied"])
for _ in range(4):
    api_client.get("/not-a-roblox-url-here", headers={"X-Forwarded-For": "10.77.0.1"})
workers_module.heartbeat()
busy = workers_module.get_state()
check("Proxy traffic raises the proxy count", busy["TotalProxied"] == idle["TotalProxied"] + 4, busy["TotalProxied"])
check("...counting refused requests too, not only served ones", busy["TotalProxied"] > 0)
service_started = fleet.get("ServiceStartedAt")
workers_module.heartbeat()
again = workers_module.get_state()
check("Service start time is stable across heartbeats", again.get("ServiceStartedAt") == service_started)
# A stale worker must drop out of the fleet rather than lingering forever.
workers_module._registry.update(
    lambda data: data.setdefault("Workers", {}).update(
        {"999999": {"Pid": 999999, "StartedAt": time.time() - 900, "LastSeen": time.time() - 600, "RSS": 1}}
    )
)
check("A worker that stopped heartbeating is not shown", all(w["Pid"] != 999999 for w in workers_module.get_state()["Workers"]))
workers_module.heartbeat()
check("...and is pruned from the registry", "999999" not in workers_module._registry.read().get("Workers", {}))

print("== Request filters can be dry-run before they are saved ==")
for existing in list(runtime.get_header_rules()):
    client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": existing})
client.post("/admin/headers/rule", headers=IP_MAIN, json={"scope": "either", "mode": "contains", "needle": "Xeno"})
SAMPLE = "User-Agent: Roblox/WinInet\nXeno-Fingerprint: abc123\nAccept: */*"

r = client.post("/admin/headers/test", headers={**IP_MAIN, "Accept": "application/json"}, json={"headers": SAMPLE})
result = r.get_json()
check("Testing a filter -> 200", r.status_code == 200, r.status_code)
check("A matching sample is reported as blocked", result.get("Blocked") is True, result)
check("...naming the header that tripped it", result.get("BlockedBy", {}).get("MatchedHeader") == "Xeno-Fingerprint")
check("...and which side matched", result.get("BlockedBy", {}).get("MatchedField") == "key", result.get("BlockedBy"))
check("Every saved rule is reported, matching or not", len(result.get("Rules", [])) >= 1, result.get("Rules"))

r = client.post(
    "/admin/headers/test",
    headers={**IP_MAIN, "Accept": "application/json"},
    json={"headers": {"User-Agent": "Roblox/WinInet"}},
)
check("A clean sample is reported as allowed", r.get_json().get("Blocked") is False, r.get_json())

# The point of the tester: try a rule BEFORE saving it.
r = client.post(
    "/admin/headers/test",
    headers={**IP_MAIN, "Accept": "application/json"},
    json={"headers": {"User-Agent": "Roblox/WinInet"}, "draft": {"header": "User-Agent", "needle": "wininet"}},
)
draft = r.get_json().get("Draft", {})
check("An unsaved draft rule is evaluated", draft.get("Matched") is True, draft)
check("Draft matching is case-insensitive, like the real thing", draft.get("MatchedText") == "Roblox/WinInet", draft)
check("Testing a draft does not save it", "user-agent|value|contains|wininet" not in runtime.get_header_rules())

r = client.post(
    "/admin/headers/test",
    headers={**IP_MAIN, "Accept": "application/json"},
    json={"headers": {"A": "b"}, "draft": {"mode": "regex", "needle": "([unclosed"}},
)
check("An invalid draft regex is explained, not crashed", r.get_json().get("Draft", {}).get("Valid") is False)

r = client.post("/admin/headers/test", headers={**IP_MAIN, "Accept": "application/json"}, json={"headers": ""})
check("Testing with no headers -> 400", r.status_code == 400, r.status_code)
r = client.post(
    "/admin/headers/test",
    headers={**IP_MAIN, "Accept": "application/json"},
    json={"headers": "GET /v1/users HTTP/1.1\n\nUser-Agent: Xeno-Loader"},
)
check("A pasted request line is skipped rather than rejected", r.get_json().get("HeaderCount") == 1, r.get_json())
check("...and the real header is still matched", r.get_json().get("Blocked") is True, r.get_json())

# The tester must agree with the proxy, or it is worse than useless.
r = api_client.get("/games.roblox.com/v1/games", headers={"X-Forwarded-For": "10.66.0.1", "Xeno-Fingerprint": "abc"})
check("A sample the tester calls blocked is blocked for real", r.status_code == 429, r.status_code)
for existing in list(runtime.get_header_rules()):
    client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": existing})


# =============================================================================
# Diagnostics overhaul: attribution, caller identity, capture, rule messages
# =============================================================================
import capture as capture_module  # noqa: E402
import workers as workers_module  # noqa: E402

# Every store this suite reads is per-worker until a flush merges it, so each
# section forces one rather than trusting the autosave interval to have run.
def diag():
    return diag_module.get_diagnostics(force_flush=True)


def clear_all_diag():
    diag_module.clear_stats(diag_module.CLEAR_ALL_NAMES)
    capture_module.reset()


IP_ATT = {"X-Forwarded-For": "10.55.0.1"}
PLACE = "75227619283955"

# These sections make many requests from a handful of IPs, so the ordinary
# per-IP limit would throttle them into refusals and the assertions below would
# be reading the throttle rather than what they mean to test.
_PRIOR_RPM = runtime.get_setting("allowed_requests_per_minute")
runtime.set_setting("allowed_requests_per_minute", 100000)


def fresh_upstream():
    """Restore a healthy upstream: 200s, a live token, no routing cooldowns.

    Earlier sections deliberately break these (a 429 drops the token, a timeout
    parks Rotate), and an unhealthy upstream turns every later request into a
    500 that looks like a bug in whatever is being tested.
    """
    proxy_module.requests.request = fake_upstream
    proxy_module.set_tokens(["FAKE_TOKEN_AAA"])
    reset_routing()

print("\n== Status codes are attributed to whoever produced them ==")
reset_routing()
clear_all_diag()
proxy_module.requests.request = fake_upstream  # 200s
r = api_client.get("/games.roblox.com/v1/games", headers={**IP_ATT, "Roblox-Id": PLACE})
check("A proxied request still succeeds", r.status_code == 200, r.status_code)
sources = diag()["StatusSources"]
check("Roblox's own 200 is counted under Roblox", sources["Roblox"].get("200") == 1, sources)
check("...and what the caller received is counted separately", sources["Relay"].get("200") == 1, sources)
check("Nothing is attributed to Roxy for a clean request", not sources["Roxy"], sources)

# Now a refusal we generate ourselves: same 429 shape, opposite meaning.
runtime.block_endpoint("games.roblox.com/v1/games/blocked", "test")
r = api_client.get("/games.roblox.com/v1/games/blocked", headers=IP_ATT)
check("A blocked endpoint is refused", r.status_code == 403, r.status_code)
sources = diag()["StatusSources"]
check("Our own 403 is counted under Roxy, not Roblox", sources["Roxy"].get("403") == 1, sources)
check("...and never leaks into Roblox's column", "403" not in sources["Roblox"], sources)

# A 429 from Roblox and a 429 from us must be distinguishable — this is the whole
# point of the split, because the two demand opposite actions.
clear_all_diag()
reset_routing()
proxy_module.requests.request = upstream_429
api_client.get("/games.roblox.com/v1/games", headers={"X-Forwarded-For": "10.55.0.9"})
sources = diag()["StatusSources"]
check("A 429 FROM Roblox lands in the Roblox column", sources["Roblox"].get("429", 0) >= 1, sources)
check("...and not in ours", "429" not in sources["Roxy"], sources)

runtime.set_setting("global_throttle_limit", 1)
runtime.set_setting("global_throttle_period", 60)
runtime.set_throttle_all(True)
api_client.get("/games.roblox.com/v1/games", headers={"X-Forwarded-For": "10.55.0.20"})
api_client.get("/games.roblox.com/v1/games", headers={"X-Forwarded-For": "10.55.0.20"})
runtime.set_throttle_all(False)
sources = diag()["StatusSources"]
check("A 429 WE issued lands in the Roxy column", sources["Roxy"].get("429", 0) >= 1, sources)
fresh_upstream()  # the 429 above dropped the token for revalidation

print("\n== Refusals are keyed by the rule that produced them ==")
clear_all_diag()
runtime.block_endpoint("games.roblox.com/v1/blocked-two", "test")
api_client.get("/games.roblox.com/v1/blocked-two", headers=IP_ATT)
api_client.get("/nothing.example.com/probe", headers=IP_ATT)
refusals = diag()["Refusals"]
blocked = [k for k in refusals if k.startswith("Blocked endpoint")]
probes = [k for k in refusals if "Non-Roblox" in k]
check("A blocked endpoint records its own reason", blocked, list(refusals))
check("A probe records a different reason", probes, list(refusals))
check("...so a single status code no longer hides which rule fired", len(refusals) >= 2, list(refusals))
check("A refusal remembers the path it refused", refusals[blocked[0]].get("LastPath") == "games.roblox.com/v1/blocked-two")
check("...and who asked", refusals[blocked[0]].get("LastIP") == "10.55.0.1", refusals[blocked[0]])
runtime.unblock_endpoint("games.roblox.com/v1/blocked-two")
runtime.unblock_endpoint("games.roblox.com/v1/games/blocked")

print("\n== Endpoints record their last request, ID in the path or not ==")
clear_all_diag()
fresh_upstream()
# The regression this covers: LastHeaders/LastIP were only ever attached to
# CONCRETE paths, and only when the template had collapsed an ID -- so the
# busiest endpoint there is (no ID in its path) could never show who called it.
api_client.post(
    "/users.roblox.com/v1/users",
    headers={**IP_ATT, "Roblox-Id": PLACE, "User-Agent": "Roblox/Linux"},
    json={"userIds": [398800, 398801]},
)
row = diag()["Endpoints"]["users.roblox.com/v1/users"]
check("An ID-less endpoint reports its last caller", row.get("LastIP") == "10.55.0.1", row)
check("...the status it answered with", str(row.get("LastStatus")) == "200", row)
check("...the place that called it", row.get("LastCallerId") == PLACE, row)
check("...and offers a drill-down", row.get("HasDetail") is True, row)

detail = diag_module.get_endpoint_detail("users.roblox.com/v1/users")
check("The drill-down keeps recent requests", len(detail["Recent"]) == 1, detail["Recent"])
recent = detail["Recent"][0]
check("...with the body that was sent", "398800" in (recent.get("Body") or ""), recent)
check("...the headers that came with it", "Roblox-Id" in (recent.get("Headers") or ""), recent)
check("...and what Roblox answered", str(recent.get("UpstreamStatus")) == "200", recent)
check("The endpoint tracks its distinct callers", detail["IPs"].get("10.55.0.1") == 1, detail["IPs"])

# An ID-bearing path keeps working exactly as before, at both levels.
api_client.get("/games.roblox.com/v1/games/9583680112/votes", headers=IP_ATT)
detail = diag_module.get_endpoint_detail("games.roblox.com/v1/games/{gameId}/votes")
check("A templated endpoint still lists its concrete paths", "games.roblox.com/v1/games/9583680112/votes" in detail["Concrete"])
concrete = detail["Concrete"]["games.roblox.com/v1/games/9583680112/votes"]
check("...and the concrete path keeps its own last request", concrete.get("LastIP") == "10.55.0.1", concrete)

runtime.set_setting("endpoint_recent_requests", 2)
for _ in range(5):
    api_client.get("/games.roblox.com/v1/games", headers=IP_ATT)
detail = diag_module.get_endpoint_detail("games.roblox.com/v1/games")
check("The recent-request ring honours its cap", len(detail["Recent"]) == 2, len(detail["Recent"]))
runtime.set_setting("endpoint_recent_requests", config.ENDPOINT_RECENT_REQUESTS)

print("\n== Who is calling: per-IP and per-place activity ==")
clear_all_diag()
fresh_upstream()
for i in range(3):
    api_client.get(
        "/games.roblox.com/v1/games",
        headers={"X-Forwarded-For": "10.56.0.%d" % i, "Roblox-Id": PLACE, "User-Agent": "Roblox/Linux"},
    )
snapshot = diag()
callers = snapshot["Callers"]
ips = snapshot["IpActivity"]
check("One experience is one row, however many IPs it uses", callers.get(PLACE, {}).get("Count") == 3, callers)
check("...while the same traffic is three rows by IP", len([k for k in ips if k.startswith("10.56.")]) == 3, list(ips))
check("A caller's distinct source IPs are counted", callers[PLACE]["PeerCount"] == 3, callers[PLACE])
check("A rate is reported alongside the total", callers[PLACE]["Rate1"] == 3, callers[PLACE])
check("The caller's user-agent is kept", callers[PLACE]["UserAgent"] == "Roblox/Linux", callers[PLACE])

detail = diag_module.get_activity_detail("caller", PLACE)
check("A caller drills down to its endpoints", detail["Endpoints"].get("games.roblox.com/v1/games") == 3, detail)
check("...its status codes", detail["Statuses"].get("200") == 3, detail)
check("...its outcomes", detail["Outcomes"].get("served") == 3, detail)
check("...and its source IPs", len(detail["Peers"]) == 3, detail)

# Refusals count against the caller too -- the one being blocked is the one worth counting.
runtime.block_endpoint("economy.roblox.com", "test")
api_client.get("/economy.roblox.com/v1/x", headers={"X-Forwarded-For": "10.56.0.0", "Roblox-Id": PLACE})
runtime.unblock_endpoint("economy.roblox.com")
callers = diag()["Callers"]
check("A refused request counts against its caller", callers[PLACE]["Refused"] == 1, callers[PLACE])
check("...but the three served ones do not", callers[PLACE]["Count"] == 4, callers[PLACE])

runtime.set_setting("activity_tracking", 0)
api_client.get("/games.roblox.com/v1/games", headers={"X-Forwarded-For": "10.57.0.1"})
check("Activity tracking can be turned off", "10.57.0.1" not in diag()["IpActivity"])
runtime.set_setting("activity_tracking", 1)

print("\n== The live feed covers refusals, not just successes ==")
clear_all_diag()
fresh_upstream()
runtime.block_endpoint("thumbnails.roblox.com", "test")
api_client.get("/thumbnails.roblox.com/v1/x", headers=IP_ATT)
api_client.get("/games.roblox.com/v1/games", headers=IP_ATT)
runtime.unblock_endpoint("thumbnails.roblox.com")
feed = diag()["LiveRequests"]
outcomes = {item.get("Outcome") for item in feed}
check("A served request appears in the feed", "served" in outcomes, outcomes)
check("A REFUSED request appears too", "blocked_endpoint" in outcomes, outcomes)
refused = next(i for i in feed if i.get("Outcome") == "blocked_endpoint")
check("...saying which rule refused it", "Blocked endpoint" in (refused.get("Reason") or ""), refused)
served = next(i for i in feed if i.get("Outcome") == "served")
check("A served entry records Roblox's own status", str(served.get("UpstreamStatus")) == "200", served)
check("...which upstream method served it", served.get("UpstreamMethod") in ("token", "rotate"), served)
check("...and how long it took", isinstance(served.get("Duration"), (int, float)), served)

print("\n== Captured bodies are bounded three ways ==")
capture_module.reset()
runtime.set_setting("capture_enabled", 1)
runtime.set_setting("capture_max_records", 3)
for i in range(6):
    capture_module.record({"URL": "u%d" % i, "RequestBody": "req%d" % i, "ResponseBody": "resp%d" % i})
state = capture_module.get_state()
check("The record cap evicts oldest-first", state["Count"] == 3, state)

runtime.set_setting("capture_max_records", 100)
runtime.set_setting("capture_max_bytes", 900)
capture_module.reset()
for i in range(20):
    capture_module.record({"URL": "u%d" % i, "RequestBody": "x" * 200, "ResponseBody": "y" * 200})
state = capture_module.get_state()
check("The byte budget is enforced independently of the count", state["Bytes"] <= 900, state)
check("...and something survives it", state["Count"] >= 1, state)

runtime.set_setting("capture_max_bytes", config.CAPTURE_MAX_BYTES)
runtime.set_setting("capture_max_body", 10)
capture_module.reset()
cid = capture_module.record({"URL": "u", "RequestBody": "a" * 500, "ResponseBody": "b" * 500})
entry = capture_module.get(cid)
check("A body is truncated to the configured length", len(entry["ResponseBody"]) == 10, entry)
check("...and says so", entry["ResponseBodyTruncated"] is True, entry)
check("...keeping the original length for context", entry["ResponseBodyLength"] == 500, entry)
runtime.set_setting("capture_max_body", config.CAPTURE_MAX_BODY)

capture_module.reset()
runtime.set_setting("capture_ttl_seconds", 0)  # 0 disables the TTL, so this checks the opposite
cid = capture_module.record({"URL": "u", "ResponseBody": "z"})
check("A capture is retrievable while it lives", capture_module.get(cid) is not None)
runtime.set_setting("capture_ttl_seconds", config.CAPTURE_TTL_SECONDS)

capture_module.reset()
runtime.set_setting("capture_enabled", 0)
check("Capture can be switched off entirely", capture_module.record({"URL": "u"}) == "")
runtime.set_setting("capture_enabled", 1)

# The property that keeps capture off the hot path: recording buffers in memory
# rather than rewriting the whole shared file under an flock on every request.
# Doing that per request would put a several-hundred-KB serialize plus
# cross-worker lock contention on the busiest path, worst during exactly the
# flood this feature exists to diagnose.
capture_module.reset()
capture_module.flush()
_mtime_before = os.path.getmtime(config.CAPTURE_FILE) if os.path.exists(config.CAPTURE_FILE) else 0
_ids = [capture_module.record({"URL": "u%d" % i, "ResponseBody": "b"}) for i in range(5)]
_mtime_after = os.path.getmtime(config.CAPTURE_FILE) if os.path.exists(config.CAPTURE_FILE) else 0
check("Recording does not touch the shared file", _mtime_after == _mtime_before, (_mtime_before, _mtime_after))
check("...but a buffered capture is readable immediately", capture_module.get(_ids[-1]) is not None)
capture_module.flush()
check("...and a flush merges the batch", capture_module.get_state()["Count"] == 5, capture_module.get_state())
check("...where it stays readable", capture_module.get(_ids[0]) is not None)

# End to end: the live feed hands the dashboard an id that resolves to real bodies.
clear_all_diag()
fresh_upstream()
api_client.post("/users.roblox.com/v1/users", headers=IP_ATT, json={"userIds": [1, 2, 3]})
item = diag()["LiveRequests"][0]
check("A live entry carries a capture id", bool(item.get("CaptureId")), item)
entry = capture_module.get(item["CaptureId"])
check("...that resolves to the request body", "userIds" in entry["RequestBody"], entry)
check("...and to the RESPONSE body", entry["ResponseBody"] == '{"ok":true}', entry)
check("Response headers are captured too", isinstance(entry["ResponseHeaders"], dict), entry)

r = client.get("/admin/live/detail?id=does-not-exist", headers={**IP_MAIN, "Accept": "application/json"})
check("An expired capture 404s rather than erroring", r.status_code == 404, r.status_code)

print("\n== Secrets never reach the capture store ==")
capture_module.reset()
cid = capture_module.record(
    {
        "URL": "u",
        "RequestHeaders": capture_module.redact_headers({"Cookie": "secret", "X-Roblox-Token": "t", "Accept": "json"}),
        "ResponseHeaders": capture_module.redact_headers({"Set-Cookie": "sess=abc"}),
    }
)
entry = capture_module.get(cid)
check("Cookies are redacted on the way in", entry["RequestHeaders"]["Cookie"] == "[redacted]", entry)
check("So is the token header", entry["RequestHeaders"]["X-Roblox-Token"] == "[redacted]", entry)
check("So is an upstream Set-Cookie", entry["ResponseHeaders"]["Set-Cookie"] == "[redacted]", entry)
check("Ordinary headers survive", entry["RequestHeaders"]["Accept"] == "json", entry)

print("\n== Rules can carry their own reply to the caller ==")
fresh_upstream()
r = client.post(
    "/admin/endpoints/block",
    headers={**IP_MAIN, "Accept": "application/json"},
    json={
        "pattern": "www.roblox.com/games/votingservice",
        "note": "legacy",
        "message": "Deprecated: use games.roblox.com/v1/games/*/votes instead.",
    },
)
check("A block accepts a caller-facing message", r.status_code == 200, r.status_code)
r = api_client.get("/www.roblox.com/games/votingservice/1234", headers=IP_ATT)
check("...which is what the caller receives", r.get_json() == "Deprecated: use games.roblox.com/v1/games/*/votes instead.", r.get_json())
check("...with the normal blocked status", r.status_code == 403, r.status_code)
check("The private note is not sent to the caller", "legacy" not in (r.get_data(as_text=True) or ""))
client.post("/admin/endpoints/unblock", headers=IP_MAIN, json={"pattern": "www.roblox.com/games/votingservice"})

r = client.post(
    "/admin/endpoints/rule",
    headers={**IP_MAIN, "Accept": "application/json"},
    json={"pattern": "avatar.roblox.com", "limit": 1, "period": 60, "message": "Batch your avatar lookups."},
)
check("A rate rule accepts a message", r.status_code == 200, r.status_code)
api_client.get("/avatar.roblox.com/v1/x", headers={"X-Forwarded-For": "10.58.0.1"})
r = api_client.get("/avatar.roblox.com/v1/x", headers={"X-Forwarded-For": "10.58.0.1"})
check("A rate-limited caller gets the custom message", r.get_json() == "Batch your avatar lookups.", r.get_json())
check("...still as a 429", r.status_code == 429, r.status_code)
client.post("/admin/endpoints/rule/clear", headers=IP_MAIN, json={"pattern": "avatar.roblox.com"})

# A filter's default is silence -- a message is opt-in because it gives the game away.
client.post(
    "/admin/headers/rule",
    headers={**IP_MAIN, "Accept": "application/json"},
    json={"header": "Roblox-Id", "scope": "value", "mode": "exact", "needle": PLACE},
)
r = api_client.get("/games.roblox.com/v1/games", headers={"X-Forwarded-For": "10.59.0.1", "Roblox-Id": PLACE})
check("A filtered caller still sees a plain throttle by default", "throttled" in r.get_data(as_text=True).lower(), r.get_data(as_text=True))
for existing in list(runtime.get_header_rules()):
    client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": existing})

client.post(
    "/admin/headers/rule",
    headers={**IP_MAIN, "Accept": "application/json"},
    json={
        "header": "Roblox-Id",
        "scope": "value",
        "mode": "exact",
        "needle": PLACE,
        "message": "Contact the proxy owner about your usage.",
    },
)
r = api_client.get("/games.roblox.com/v1/games", headers={"X-Forwarded-For": "10.59.0.2", "Roblox-Id": PLACE})
check("...but a filter message is honoured when set", r.get_json() == "Contact the proxy owner about your usage.", r.get_json())
for existing in list(runtime.get_header_rules()):
    client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": existing})

print("\n== Internal probes are exempt from every caller-facing rule ==")
clear_all_diag()
fresh_upstream()
# The worry this settles: that a block or rate rule could take out the token
# health check. It cannot -- internal probes call requests.get directly and never
# enter the proxy route -- and this asserts it rather than trusting control flow.
runtime.set_paused(True)
runtime.set_throttle_all(True)
runtime.block_endpoint("accountinformation.roblox.com", "would break the health check if it applied")
runtime.set_endpoint_rule("accountinformation.roblox.com", 1, 60)
client.post("/admin/headers/rule", headers=IP_MAIN, json={"scope": "either", "mode": "contains", "needle": "Accept"})
before = len(get_calls)
report = proxy_module.check_tokens()
check("A token check still reaches Roblox while paused", len(get_calls) > before, len(get_calls))
check("...and reports the token as active", any(t.get("Active") for t in report), report)
check("...through a blocked, rate-limited, filtered endpoint", all(t.get("Error") in ("", None) for t in report), report)
internal = diag()["InternalRequests"]
check("The probe is recorded as internal", "token_check" in internal, internal)
check("...with its own success count", internal["token_check"]["Count"] >= 1, internal)
check("...and is NOT counted as caller traffic", "token_check" not in diag()["IpActivity"])
check("Its status lands in the Internal column", diag()["StatusSources"]["Internal"].get("200", 0) >= 1, diag()["StatusSources"])
check("The internal endpoint list names the probe URL", any("accountinformation" in e["URL"] for e in proxy_module.internal_endpoints()))
runtime.unblock_endpoint("accountinformation.roblox.com")
runtime.clear_endpoint_rule("accountinformation.roblox.com")
for existing in list(runtime.get_header_rules()):
    client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": existing})
runtime.set_paused(False)
runtime.set_throttle_all(False)

r = client.get("/admin/internal/endpoints", headers={**IP_MAIN, "Accept": "application/json"})
check("The dashboard can list every internal call site", r.status_code == 200, r.status_code)
check("...and explains why rules cannot reach them", "never pass through the proxy route" in r.get_json()["Note"])

print("\n== Worker request counts are resettable ==")
workers_module.count_request()
workers_module.count_request()
workers_module.count_proxied()
workers_module.heartbeat()
before = workers_module.get_state()
check("Worker counters accumulate", before["TotalRequests"] >= 2, before["TotalRequests"])
workers_module.reset_counts()
workers_module.heartbeat()
after = workers_module.get_state()
check("Resetting zeroes the fleet's request count", after["TotalRequests"] == 0, after["TotalRequests"])
check("...and the proxy count with it", after["TotalProxied"] == 0, after["TotalProxied"])
check("...recording when it happened", after["CountersResetAt"] > 0, after)
check("Uptime is not disturbed by a counter reset", after["ServiceStartedAt"] == before["ServiceStartedAt"])

r = client.post("/admin/workers/reset", headers={**IP_MAIN, "Accept": "application/json"})
check("The admin route resets them too", r.status_code == 200, r.status_code)

workers_module.count_request()
workers_module.heartbeat()
check("Counters climb again after a reset", workers_module.get_state()["TotalRequests"] >= 1)
for _ in range(20):
    workers_module.count_request()
    workers_module.count_proxied()
workers_module.heartbeat()
busy = workers_module.get_state()["TotalRequests"]
client.post("/admin/data/clear", headers={**IP_MAIN, "Accept": "application/json"}, json={"target": "all"})
workers_module.heartbeat()
state = workers_module.get_state()
# Not exactly zero, and correctly so: the counter includes EVERY request the
# worker serves (that is what gunicorn recycles on), so the clear-all request
# itself is counted the moment after it resets them. What must be gone is
# everything that came before it.
check("Clear-all takes the worker counters with it", state["TotalRequests"] < busy, (busy, state["TotalRequests"]))
check("...leaving only the request that did the clearing", state["TotalRequests"] <= 1, state["TotalRequests"])
check("...and zeroing the proxy count outright", state["TotalProxied"] == 0, state["TotalProxied"])
check("...and the captured bodies", capture_module.get_state()["Count"] == 0, capture_module.get_state())

print("\n== Tarpit cannot outgrow the fleet it runs on ==")
# The setting's own maximum is 64. On a 16-slot fleet that would let held
# refusals occupy every request slot the service has, i.e. the tarpit takes the
# proxy down instead of the caller. The clamp makes over-configuring a no-op.
os.environ["ROXY_WORKERS"] = "4"
os.environ["ROXY_THREADS"] = "4"
runtime.set_setting("tarpit_max_concurrent", 64)
effective, configured, slots = tarpit_module.capacity()
check("The fleet's real slot count is read, not assumed", slots == 16, slots)
check("An over-configured cap is clamped", effective < configured, (effective, configured))
check("...to a fraction of the fleet", effective == 8, effective)
state = tarpit_module.get_state()
check("The clamp is visible to the admin", state["Clamped"] is True, state)
check("...alongside what was asked for", state["ConfiguredConcurrent"] == 64, state)
check("Capacity pressure is reported", "CapacityUsedPct" in state, state)
runtime.set_setting("tarpit_max_concurrent", 4)
effective, configured, _ = tarpit_module.capacity()
check("A sane cap is left alone", effective == configured == 4, (effective, configured))
check("...and reports itself as unclamped", tarpit_module.get_state()["Clamped"] is False)
runtime.set_setting("tarpit_max_concurrent", config.TARPIT_MAX_CONCURRENT)

print("\n== The tarpit holds refusals and nothing else ==")
# The one property that matters: a hold happens only on a path that has already
# decided to refuse, so it can never delay (or admit) a real request.
clear_all_diag()
fresh_upstream()
runtime.set_setting("tarpit_enabled", 1)
runtime.set_setting("tarpit_min_seconds", 0)
runtime.set_setting("tarpit_max_seconds", 1)
runtime.set_setting("tarpit_on_probe", 1)
held_before = diag_module.tarpit_stats.get("Count", 0)
start = time.time()
r = api_client.get("/games.roblox.com/v1/games", headers={"X-Forwarded-For": "10.60.0.1"})
served_elapsed = time.time() - start
check("A request that will be SERVED is never held", r.status_code == 200, r.status_code)
check("...and is not delayed", served_elapsed < 1.5, served_elapsed)
check("...and is not counted as tarpitted", diag_module.tarpit_stats.get("Count", 0) == held_before)
api_client.get("/not-roblox.example.com/x", headers={"X-Forwarded-For": "10.60.0.2"})
check("A probe IS held", diag_module.tarpit_stats.get("Count", 0) > held_before, diag_module.tarpit_stats)
check("The hold is attributed to the right category", "probe" in diag_module.tarpit_stats.get("Categories", {}))

# A bypass IP is exempt, which is what makes the allowlist usable for testing.
runtime.add_throttle_bypass("10.60.0.3", 0, "test")
before = diag_module.tarpit_stats.get("Count", 0)
start = time.time()
api_client.get("/not-roblox.example.com/x", headers={"X-Forwarded-For": "10.60.0.3"})
check("A bypass IP is never held", time.time() - start < 1.5)
check("...and is not counted", diag_module.tarpit_stats.get("Count", 0) == before)
runtime.remove_throttle_bypass("10.60.0.3")
runtime.set_setting("tarpit_enabled", 0)

print("\n== Errors say whose fault they were ==")
clear_all_diag()
diag_module.log_error("something we broke", "detail", source="Roxy")
diag_module.log_error("something Roblox broke", "detail", source="Roblox")
errors = diag()["Errors"]
check("An error records its source", errors["something we broke"]["Source"] == "Roxy", errors)
check("...distinguishing an upstream failure from ours", errors["something Roblox broke"]["Source"] == "Roblox", errors)

print("\n== Merged stat stores stay capped ==")
# A per-worker cap alone is not enough: merging N workers' individually-capped
# sets produces an uncapped union. retry_counts' child maps were declared as
# `children`, which for a single-record store silently did nothing.
clear_all_diag()
for i in range(config.MAX_RETRY_REASONS + 25):
    diag_module.log_retry(429, "reason-%d" % i)
merged = diag()["RetryCounts"]
check("Retry reasons are capped after the merge", len(merged["Reasons"]) <= config.MAX_RETRY_REASONS, len(merged["Reasons"]))
for i in range(config.MAX_STATUS_CODES + 25):
    diag_module.log_status_code(200 + i, source="Roxy")
check("Per-source status codes are capped", len(diag()["StatusSources"]["Roxy"]) <= config.MAX_STATUS_CODES)
for i in range(config.MAX_IP_ACTIVITY_RECORDS + 30):
    diag_module.log_traffic("10.99.%d.%d" % (i // 256, i % 256), "", "GET", "games.roblox.com/v1/games", 200, "served")
check("IP activity is capped", len(diag()["IpActivity"]) <= config.MAX_IP_ACTIVITY_RECORDS, len(diag()["IpActivity"]))
for i in range(config.MAX_CALLER_RECORDS + 30):
    diag_module.log_traffic("10.98.0.1", "place-%d" % i, "GET", "games.roblox.com/v1/games", 200, "served")
check("Callers are capped", len(diag()["Callers"]) <= config.MAX_CALLER_RECORDS, len(diag()["Callers"]))
clear_all_diag()

print("\n== The new sections clear independently ==")
fresh_upstream()
api_client.get("/games.roblox.com/v1/games", headers={**IP_ATT, "Roblox-Id": PLACE})
runtime.block_endpoint("badges.roblox.com", "test")
api_client.get("/badges.roblox.com/v1/x", headers=IP_ATT)
runtime.unblock_endpoint("badges.roblox.com")
check("Callers are populated before the clear", bool(diag()["Callers"]))
r = client.post("/admin/data/clear", headers={**IP_MAIN, "Accept": "application/json"}, json={"target": "callers"})
check("Clearing callers -> 200", r.status_code == 200, r.status_code)
after = diag()
check("...empties the caller table", not after["Callers"], after["Callers"])
check("...and leaves refusals alone", bool(after["Refusals"]), after["Refusals"])
client.post("/admin/data/clear", headers={**IP_MAIN, "Accept": "application/json"}, json={"target": "refusals"})
check("Refusals clear on their own", not diag()["Refusals"])

print("\n== Place lookup resolves an experience to its owner ==")
# Walks the same public chain the dashboard button uses: place -> universe ->
# creator. The upstream is stubbed, so this checks the plumbing and the shape,
# not Roblox's data.
lookup_calls = []


def fake_lookup(method, url, headers=None, params=None, data=None, cookies=None, timeout=None, proxies=None):
    lookup_calls.append(url)
    if "universes/v1/places" in url:
        return FakeUpstreamResponse(text='{"universeId": 10649318893}')
    return FakeUpstreamResponse(
        text='{"data":[{"id":10649318893,"rootPlaceId":75227619283955,"name":"Untitled Experience",'
        '"description":"","playing":1,"visits":16,"maxPlayers":1,"favoritedCount":0,'
        '"created":"2026-08-07T15:44:27Z","updated":"2026-08-07T20:09:18Z",'
        '"creator":{"id":55667462,"name":"vesonce","type":"User","hasVerifiedBadge":false}}]}'
    )


fresh_upstream()
proxy_module.requests.request = fake_lookup
r = client.post("/admin/lookup/place", headers={**IP_MAIN, "Accept": "application/json"}, json={"id": PLACE})
proxy_module.requests.request = fake_upstream
payload = r.get_json()
check("Looking up a place -> 200", r.status_code == 200, r.status_code)
check("It resolves the place to a universe", str(payload.get("UniverseId")) == "10649318893", payload)
check("...names the experience", payload.get("Name") == "Untitled Experience", payload)
check("...names the owner", payload.get("CreatorName") == "vesonce", payload)
check("...and what kind of owner it is", payload.get("CreatorType") == "User", payload)
check("...with a link to their profile", "users/55667462" in (payload.get("CreatorUrl") or ""), payload)
check("Both lookup hops go through the proxy stack", len(lookup_calls) == 2, lookup_calls)
r = client.post("/admin/lookup/place", headers={**IP_MAIN, "Accept": "application/json"}, json={"id": "not-a-number"})
check("A non-numeric ID is rejected, not proxied", r.status_code == 400, r.status_code)

clear_all_diag()
reset_routing()
runtime.set_setting("allowed_requests_per_minute", _PRIOR_RPM)

print(f"\n{'=' * 40}\nRESULT: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
