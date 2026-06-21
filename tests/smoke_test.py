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

# --- Sandbox /etc/roxy + data file BEFORE importing the app -------------------
sandbox = tempfile.mkdtemp(prefix="roxy_test_")
os.environ["ROXY_FILE_ROOT"] = sandbox
os.environ["ROXY_DATA_FILE"] = os.path.join(sandbox, "roxy_data.json")

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


upstream_calls = []


def fake_upstream(method, url, headers=None, params=None, data=None, cookies=None, timeout=None):
    upstream_calls.append(
        {"method": method, "url": url, "headers": headers or {}, "params": params or {}, "cookies": cookies}
    )
    return FakeUpstreamResponse()


proxy_module.requests.request = fake_upstream

api_client = app.test_client()
api_client.set_cookie("some_visitor_cookie", "should-not-be-forwarded")
IP_API = {"X-Forwarded-For": "10.3.3.3"}

r = api_client.get("/avatar.roblox.com/v2/test?prettyprint=true&ids=1&ids=2", headers=IP_API)
check("Proxied GET -> 200", r.status_code == 200, r.status_code)
check("prettyprint=true formats the response", json.loads(r.data) == {"ok": True} and b"\n" in r.data, r.data[:60])
call = upstream_calls[-1]  # The first request, before cooldown reroutes the next one to RoProxy.
r = api_client.get("/avatar.roblox.com/v2/test-plain", headers=IP_API)
check("Raw upstream body passed through without prettyprint", r.data == b'{"ok":true}', r.data[:60])
check(
    "Second request fell back to RoProxy (direct API in cooldown)",
    upstream_calls[-1]["url"] == "https://avatar.roproxy.com/v2/test-plain",
    upstream_calls[-1]["url"],
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
with open(os.environ["ROXY_DATA_FILE"]) as f:
    on_disk = json.load(f)
check(
    "Stats persisted to the data file",
    on_disk.get("Diagnostics", {}).get("request_counts", {}).get("GET", {}).get("Successful", 0) >= 1,
)
check("Persistence health says writable", diag.get("Persistence", {}).get("Writable") is True, diag.get("Persistence"))

print("== Token safety budget (never exceeds the configured cap) ==")
client.post(
    "/admin/settings",
    headers=IP_MAIN,
    json={"settings": {"token_budget_requests": 2, "token_budget_window": 3600}},
)
proxy_module.is_direct_api_in_cooldown = True
proxy_module.is_roproxy_in_cooldown = True
proxy_module.set_tokens(["BUDGET_TOKEN"])
budget_client = app.test_client()
IP_BUDGET = {"X-Forwarded-For": "10.4.4.4"}
r1 = budget_client.get("/games.roblox.com/v1/list?a=1", headers=IP_BUDGET)
r2 = budget_client.get("/games.roblox.com/v1/list?a=2", headers=IP_BUDGET)
check("Token requests 1-2 within budget -> 200", r1.status_code == 200 and r2.status_code == 200)
check(
    "Internal token attached upstream",
    (upstream_calls[-1]["cookies"] or {}).get(".ROBLOSECURITY") == "BUDGET_TOKEN",
    upstream_calls[-1]["cookies"],
)
r3 = budget_client.get("/games.roblox.com/v1/list?a=3", headers=IP_BUDGET)
check("Request 3 rejected by budget (no upstream call)", r3.status_code == 500 and b"safety budget" in r3.data, r3.data[:90])
check("Budget rejection did not hit Roblox", (upstream_calls[-1]["params"] or {}).get("a") == ["2"], upstream_calls[-1])
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check("TokenBudget shows usage", diag.get("TokenBudget", {}).get("Used") == 2, diag.get("TokenBudget"))
check("TokenBudget limit reflects setting", diag.get("TokenBudget", {}).get("Limit") == 2, diag.get("TokenBudget"))
check("Budget rejections counted", diag.get("TokenBudgetRejections", 0) >= 1, diag.get("TokenBudgetRejections"))
# Restore sane values for the rest of the run.
client.post(
    "/admin/settings",
    headers=IP_MAIN,
    json={"settings": {"token_budget_requests": 95, "token_budget_window": 65}},
)
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False

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
check("New requests count again after clear", diag["RequestCounts"]["GET"]["Successful"] == 1, diag["RequestCounts"]["GET"])

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
check("Login response set the admin-seen cookie", any(c.key == "roxy_admin_seen" for c in client._cookies.values()) if hasattr(client, "_cookies") else True)

print("== Wildcard endpoint blocking ==")
# Make sure proxied (non-blocked) requests reach the fake upstream.
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
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
check("Header rule blocks request with Xeno-* header (key match) -> 404", r.status_code == 404, r.status_code)
check("Header-blocked body is a GENERIC error (no reason leaked)", b"Not Found" in r.data and b"eader" not in r.data, r.data[:80])
check("Header-blocked request never hit upstream", len(upstream_calls) == n, len(upstream_calls) - n)

r = api_client.get("/games.roblox.com/v1/games/1/votes", headers={**IP_HDR, "User-Agent": "Xeno/1.3.55"})
check("Header rule blocks Xeno User-Agent (value match) -> 404", r.status_code == 404, r.status_code)

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
check("Header rule stored in HeaderRules", any("xeno" in k for k in diag.get("HeaderRules", {})), list(diag.get("HeaderRules", {})))

# Key-scope exact rule
client.post("/admin/headers/rule", headers=IP_MAIN, json={"scope": "key", "mode": "exact", "needle": "exploit-guid"})
r = api_client.get("/games.roblox.com/v1/games/1/votes", headers={**IP_HDR, "Exploit-Guid": "x"})
check("Exact key-scope rule blocks Exploit-Guid header -> 404", r.status_code == 404, r.status_code)
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
check("Header-blocked attempts cleared", r.get_json().get("HeaderBlockedAttempts") == {}, r.get_json().get("HeaderBlockedAttempts"))
# Remove the remaining exact rule so it doesn't affect later sections.
client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": "key|exact|exploit-guid"})

print("== Emailed invalidation link (kill switch) ==")
invalidate_emails = emails_with("Roxy Admin Login")
link_token = invalidate_emails[-1]["body"].split("/admin/invalidate/")[-1].strip().splitlines()[0]
r = client.get(f"/admin/invalidate/{link_token}", headers=IP_MAIN)
check("Valid invalidation link -> 200", r.status_code == 200, r.status_code)
r = client.get(f"/admin/invalidate/{link_token}", headers=IP_MAIN)
check("Reused invalidation link -> 404 (single use)", r.status_code == 404, r.status_code)
r = client.get("/admin/dashboard", headers=IP_MAIN)
check("Session dead after kill switch", r.status_code == 302, r.status_code)

print("== Brute-force lockout (separate IP) ==")
for _ in range(config.MAX_LOGIN_FAILURES):
    client.post("/admin", headers=IP_BRUTE, json={"IsLogin": True, "Username": "x", "Password": "y"})
r = client.post("/admin", headers=IP_BRUTE, json={"IsLogin": True, "Username": ADMIN_USER, "Password": ADMIN_PASS})
check("Locked out after repeated failures -> 429", r.status_code == 429, r.status_code)

print("== Error emails still work for real 500s (rate-limited) ==")
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

# Log back in (the kill switch above ended the old session) and confirm the app is still healthy.
r = client.post("/admin", headers=IP_MAIN, json={"IsLogin": True, "Username": ADMIN_USER, "Password": ADMIN_PASS})
code = emails_with("Admin 2FA")[-1]["body"].strip()
r = client.post("/admin", headers=IP_MAIN, json={"Is2FA": True, "TwoFA": code})
check("Login still works after epoch bump + hammer", r.status_code == 200, r.status_code)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check("Diagnostics healthy after hammer", r.status_code == 200, r.status_code)

print(f"\n{'=' * 40}\nRESULT: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
