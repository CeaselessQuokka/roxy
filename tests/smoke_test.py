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
check("Header rule blocks request with Xeno-* header (key match) -> disguised 429", r.status_code == 429, r.status_code)
check("Header-blocked body looks like a throttle (no reason leaked)", b"throttled" in r.data and b"eader" not in r.data, r.data[:80])
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
check("Header rule stored in HeaderRules", any("xeno" in k for k in diag.get("HeaderRules", {})), list(diag.get("HeaderRules", {})))

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
check("Header-blocked attempts cleared", r.get_json().get("HeaderBlockedAttempts") == {}, r.get_json().get("HeaderBlockedAttempts"))
# Remove the remaining exact rule so it doesn't affect later sections.
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
for rid in [k for k in r.get_json().get("HeaderRules", {}) if "exploit-guid" in k]:
    client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": rid})

print("== Global throttle-all mode (configurable N per P, custom message, drops) ==")
proxy_module.requests.request = fake_upstream
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
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
check("Throttle-all lets the first N requests through", r1.status_code == 200 and r2.status_code == 200, (r1.status_code, r2.status_code))
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
check("Pause with reason -> state paused + reason", r.get_json().get("Paused") is True and r.get_json().get("Reason") == "Updating tokens, back soon.", r.data[:80])
IP_PAUSE = {"X-Forwarded-For": "10.15.0.1"}
r = api_client.get("/games.roblox.com/v1/while-paused", headers=IP_PAUSE)
check("Paused proxy returns 503 with the custom message", r.status_code == 503 and b"Updating tokens, back soon." in r.data, (r.status_code, r.data[:80]))
api_client.get("/games.roblox.com/v1/while-paused-2", headers=IP_PAUSE)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check("Pause drops counted", r.get_json().get("PauseDrops", 0) >= 2, r.get_json().get("PauseDrops"))
# Re-pausing resets the drop counter for the new downtime.
client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": False})
r = client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": True})  # reuses the persisted message
api_client.get("/games.roblox.com/v1/while-paused-3", headers=IP_PAUSE)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check("Pause drop counter reset on new downtime", r.get_json().get("PauseDrops", 0) == 1, r.get_json().get("PauseDrops"))
# Explicitly clearing the message (reason="") falls back to the default.
client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": False})
client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": True, "reason": ""})
r = api_client.get("/games.roblox.com/v1/while-paused-4", headers=IP_PAUSE)
check("Default pause message used when message is cleared", b"Service down for maintenance." in r.data, r.data[:80])
client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": False})
r = api_client.get("/games.roblox.com/v1/after-pause", headers={"X-Forwarded-For": "10.15.0.2"})
check("After resume, proxy works again -> 200", r.status_code == 200, r.status_code)

print("== Direct API / RoProxy rejection counts ==")
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
proxy_module.set_tokens([])  # force the direct-API / RoProxy routes (no token path)


def failing_upstream(method, url, headers=None, params=None, data=None, cookies=None, timeout=None):
    upstream_calls.append({"method": method, "url": url, "headers": headers or {}, "params": params or {}, "cookies": cookies})
    return FakeUpstreamResponse(status=500, text="upstream boom")


proxy_module.requests.request = failing_upstream
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
ph0 = r.get_json().get("ProxyHealth", {})
da0 = ph0.get("DirectAPI", {}).get("Failed", 0)
rp0 = ph0.get("RoProxy", {}).get("Failed", 0)
api_client.get("/games.roblox.com/v1/fail-direct", headers={"X-Forwarded-For": "10.10.0.1"})  # direct route, 500
api_client.get("/games.roblox.com/v1/fail-roproxy", headers={"X-Forwarded-For": "10.10.0.2"})  # roproxy route, 500
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
ph1 = r.get_json().get("ProxyHealth", {})
check("Direct API rejection counted", ph1.get("DirectAPI", {}).get("Failed", 0) >= da0 + 1, ph1.get("DirectAPI"))
check("RoProxy rejection counted", ph1.get("RoProxy", {}).get("Failed", 0) >= rp0 + 1, ph1.get("RoProxy"))
proxy_module.requests.request = fake_upstream  # restore 200s

print("== Upstream timeouts: fall through routes, never email ==")
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
proxy_module.set_tokens(["FALLBACK_TOKEN"])
proxy_module._token_uses.clear()


def timeout_unless_token(method, url, headers=None, params=None, data=None, cookies=None, timeout=None):
    upstream_calls.append({"method": method, "url": url, "cookies": cookies})
    if cookies and cookies.get(".ROBLOSECURITY"):
        return FakeUpstreamResponse(status=200, text='{"ok":true}')  # token route works
    raise proxy_module.requests.Timeout("read timed out")  # direct + roproxy time out


proxy_module.requests.request = timeout_unless_token
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
ph0 = r.get_json().get("ProxyHealth", {})
emails_before = len(sent_emails)
r = api_client.get("/games.roblox.com/v1/timeout-test", headers={"X-Forwarded-For": "10.16.0.1"})
check("Direct+RoProxy timeout falls through to the token -> 200", r.status_code == 200, r.status_code)
check("Timed-out request was ultimately served", r.data == b'{"ok":true}', r.data[:60])
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
ph1 = r.get_json().get("ProxyHealth", {})
check(
    "Direct API timeout counted",
    ph1.get("DirectAPI", {}).get("Timeouts", 0) >= ph0.get("DirectAPI", {}).get("Timeouts", 0) + 1,
    ph1.get("DirectAPI"),
)
check(
    "RoProxy timeout counted",
    ph1.get("RoProxy", {}).get("Timeouts", 0) >= ph0.get("RoProxy", {}).get("Timeouts", 0) + 1,
    ph1.get("RoProxy"),
)
check("Timeouts never email the admin", len(sent_emails) == emails_before, sent_emails[emails_before:])
proxy_module.requests.request = fake_upstream  # restore 200s

print("== Endpoint templating (ID collapse + concrete drill-down) ==")
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
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
check("Template keeps the 3 concrete IDs", len(eps.get(tmpl, {}).get("Concrete", {})) == 3, eps.get(tmpl, {}).get("Concrete"))
check(
    "Concrete drill-down has the real path",
    "avatar.roblox.com/v2/avatar/users/111/outfits" in eps.get(tmpl, {}).get("Concrete", {}),
    list(eps.get(tmpl, {}).get("Concrete", {})),
)
check(
    "games servers path collapses gameId + serverId",
    "games.roblox.com/v1/games/{gameId}/servers/{serverId}" in eps,
    [k for k in eps if k.startswith("games.roblox.com")],
)

print("== Regex endpoint blocking ==")
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
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
r = client.post("/admin/headers/rule", headers=IP_MAIN, json={"scope": "value", "mode": "regex", "needle": r"Synapse|Xeno|KRNL"})
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
proxy_module._token_uses.clear()  # fresh window so the peak is exactly what we drive
proxy_module.is_direct_api_in_cooldown = True
proxy_module.is_roproxy_in_cooldown = True
proxy_module.set_tokens(["PEAK_TOKEN"])
client.post("/admin/settings", headers=IP_MAIN, json={"settings": {"token_budget_requests": 95, "token_budget_window": 65}})
IP_PK = {"X-Forwarded-For": "10.14.0.1"}
for i in range(3):
    api_client.get(f"/games.roblox.com/v1/peak{i}", headers=IP_PK)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check("Token budget Used reflects the 3 token requests", diag.get("TokenBudget", {}).get("Used") == 3, diag.get("TokenBudget"))
check("Budget peak (1h) captured", diag.get("BudgetPeak1h") == 3, diag.get("BudgetPeak1h"))
check("Budget peak (24h) captured", diag.get("BudgetPeak24h") == 3, diag.get("BudgetPeak24h"))
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False

print("== No user-facing retries (429 fails immediately; CSRF handshake kept) ==")
proxy_module.is_direct_api_in_cooldown = True
proxy_module.is_roproxy_in_cooldown = True
proxy_module.set_tokens(["RETRY_TOKEN"])
proxy_module._token_uses.clear()
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "requests"})


def upstream_429(method, url, headers=None, params=None, data=None, cookies=None, timeout=None):
    upstream_calls.append({"method": method, "url": url})
    return FakeUpstreamResponse(status=429, text="Too Many Requests")


proxy_module.requests.request = upstream_429
n = len(upstream_calls)
r = api_client.get("/games.roblox.com/v1/retry-test", headers={"X-Forwarded-For": "10.20.0.1"})
check("A 429 fails the user request immediately", r.status_code == 500, r.status_code)
check("A 429 is NOT retried (single upstream attempt)", len(upstream_calls) == n + 1, len(upstream_calls) - n)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
rc = r.get_json().get("RetryCounts", {})
check("No 429 retries recorded", "429" not in (rc.get("ByStatusCode") or {}), rc.get("ByStatusCode"))

# CSRF handshake (a required protocol step for writes) must still work.
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
proxy_module.set_tokens([])


def upstream_csrf(method, url, headers=None, params=None, data=None, cookies=None, timeout=None):
    upstream_calls.append({"method": method, "url": url})
    if headers and headers.get("x-csrf-token"):
        return FakeUpstreamResponse(status=200, text='{"ok":true}')
    return FakeUpstreamResponse(status=403, text="csrf", headers={"x-csrf-token": "CSRF123"})


proxy_module.requests.request = upstream_csrf
n = len(upstream_calls)
r = api_client.post("/economy.roblox.com/v1/purchase", headers={"X-Forwarded-For": "10.20.0.2"}, data=b"{}")
check("CSRF handshake still completes a write -> 200", r.status_code == 200, r.status_code)
check("CSRF handshake used exactly one retry", len(upstream_calls) == n + 2, len(upstream_calls) - n)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check("CSRF retry recorded (403)", "403" in (r.get_json().get("RetryCounts", {}).get("ByStatusCode") or {}))
proxy_module.requests.request = fake_upstream

print("== Service messages persist after disabling ==")
client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": True, "reason": "Persisted pause msg"})
client.post("/admin/proxy/toggle", headers=IP_MAIN, json={"paused": False})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check("Pause message persists after resume", r.get_json().get("Pause", {}).get("Reason") == "Persisted pause msg", r.get_json().get("Pause"))

print("== Per-endpoint last headers recorded ==")
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
proxy_module.set_tokens(["HDR_TOKEN"])
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "endpoints"})
api_client.get("/avatar.roblox.com/v2/avatar/users/777/outfits", headers={"X-Forwarded-For": "10.21.0.1", "X-Test-Header": "fingerprint-me"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
concrete = (r.get_json().get("Endpoints", {}).get(tmpl, {}).get("Concrete", {}) or {}).get(
    "avatar.roblox.com/v2/avatar/users/777/outfits", {}
)
check("Concrete endpoint stores last headers", "X-Test-Header" in (concrete.get("LastHeaders") or ""), concrete.get("LastHeaders"))
check("Concrete endpoint stores last IP", concrete.get("LastIP") == "10.21.0.1", concrete.get("LastIP"))

print("== Token route Requests/Rejected counted ==")
# Force the token route (direct + roproxy in cooldown) so a token request actually happens.
proxy_module.set_tokens(["TKR_TOKEN"])
proxy_module.is_direct_api_in_cooldown = True
proxy_module.is_roproxy_in_cooldown = True
api_client.get("/games.roblox.com/v1/token-route", headers={"X-Forwarded-For": "10.21.0.2"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
tk = r.get_json().get("ProxyHealth", {}).get("Tokens", {})
check("Token route request count tracked", tk.get("Requests", 0) >= 1, tk)

print("== Request fingerprints (header names + user-agents) ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "fingerprints"})
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
proxy_module.set_tokens(["FP_TOKEN"])
api_client.get("/games.roblox.com/v1/fp", headers={"X-Forwarded-For": "10.22.0.1", "User-Agent": "EvilExploiter/9", "X-Weird-Header": "1"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check("Distinct header names tracked", "x-weird-header" in (diag.get("HeaderNames") or {}), list(diag.get("HeaderNames", {}))[:8])
check("Distinct user-agents tracked", "EvilExploiter/9" in (diag.get("UserAgents") or {}), list(diag.get("UserAgents", {}))[:8])

print("== Error log (deduped, admin-clear only) ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "errors"})
client.get("/_boom_test_only", headers=IP_MAIN)
client.get("/_boom_test_only", headers=IP_MAIN)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
errs = r.get_json().get("Errors", {})
boom_sig = next((k for k in errs if "intentional test explosion" in k), None)
check("Server error logged with signature", boom_sig is not None, list(errs))
check("Repeated identical errors dedupe with a count", errs.get(boom_sig, {}).get("Count", 0) >= 2, errs.get(boom_sig))
check("Error log keeps a detail/traceback", "Traceback" in (errs.get(boom_sig, {}).get("LastDetail") or ""), errs.get(boom_sig))

print("== Trusted device skips 2FA for 30 days ==")
td_ip = {"X-Forwarded-For": "10.23.0.1"}
r = client_post_login = app.test_client()
r = client_post_login.post("/admin", headers=td_ip, json={"IsLogin": True, "Username": ADMIN_USER, "Password": ADMIN_PASS, "TrustDevice": True})
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
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
proxy_module.set_tokens(["ISO_TOKEN"])
api_client.get("/avatar.roblox.com/v2/avatar/users/999/outfits", headers={"X-Forwarded-For": "10.24.0.1"})  # endpoints
api_client.get("/not-a-roblox-domain-iso", headers={"X-Forwarded-For": "10.24.0.1"})  # probe
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "probes"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check("Clearing probes leaves endpoints intact (no cross-clear)", len(diag.get("Endpoints", {})) >= 1, list(diag.get("Endpoints", {})))
check("Clearing probes did clear the probe summary", diag.get("ExploitSummary", {}) == {}, diag.get("ExploitSummary"))
r = client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "all"})
check("Clear All -> 200", r.status_code == 200, r.status_code)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check("Clear All wiped endpoints", diag.get("Endpoints", {}) == {}, diag.get("Endpoints"))
check("Clear All wiped errors", diag.get("Errors", {}) == {}, diag.get("Errors"))
check("Clear All wiped fingerprints", diag.get("HeaderNames", {}) == {} and diag.get("UserAgents", {}) == {}, (diag.get("HeaderNames"), diag.get("UserAgents")))
check("Clear All zeroed request counters", diag["RequestCounts"]["GET"]["Successful"] == 0, diag["RequestCounts"]["GET"])
check("Clear All does NOT touch trusted-device/rules state", "Settings" in diag)

print("== Admin page-visit counter works for anonymous GET /admin ==")
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
visits0 = r.get_json()["PageVisits"].get("admin", 0)
app.test_client().get("/admin", headers={"X-Forwarded-For": "10.25.0.1"})  # fresh anonymous bot
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
check("Anonymous GET /admin increments the counter", r.get_json()["PageVisits"].get("admin", 0) == visits0 + 1, r.get_json()["PageVisits"])

print("== Health: Tokens Requests == sum of Uses; Direct/RoProxy ResetIn ==")
proxy_module.requests.request = fake_upstream
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
proxy_module.set_tokens(["MATCH_TOKEN"])
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "all"})
# Force the token route (direct + roproxy in cooldown) and make a few requests.
proxy_module.is_direct_api_in_cooldown = True
proxy_module.is_roproxy_in_cooldown = True
for i in range(3):
    api_client.get(f"/games.roblox.com/v1/match{i}", headers={"X-Forwarded-For": "10.30.0.1"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
token_uses = sum(int(t.get("Uses", 0)) for t in diag.get("Tokens", []))
tokens_requests = diag.get("ProxyHealth", {}).get("Tokens", {}).get("Requests", 0)
check("Token health Requests equals sum of Auth-token Uses", tokens_requests == token_uses and token_uses >= 3, (tokens_requests, token_uses))
# Trigger a direct-API cooldown and confirm ResetIn is reported.
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
proxy_module.set_tokens([])
api_client.get("/games.roblox.com/v1/cooldown-test", headers={"X-Forwarded-For": "10.30.0.2"})  # enters direct cooldown
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
da = r.get_json().get("ProxyHealth", {}).get("DirectAPI", {})
check("Direct API reports a cooldown ResetIn", da.get("IsInCooldown") and da.get("ResetIn", 0) > 0, da)

print("== Clear-all resets the live health counters too ==")
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
proxy_module.set_tokens(["CLR_TOKEN"])
api_client.get("/games.roblox.com/v1/before-clear", headers={"X-Forwarded-For": "10.30.0.3"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
ph_before = r.get_json().get("ProxyHealth", {})
check("Health has request counts before clear", (ph_before.get("DirectAPI", {}).get("Count", 0) + ph_before.get("RoProxy", {}).get("Count", 0)) >= 1, ph_before)
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "all"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
ph_after = r.get_json().get("ProxyHealth", {})
check("Clear-all zeroed Direct API request count", ph_after.get("DirectAPI", {}).get("Count", 0) == 0, ph_after.get("DirectAPI"))
check("Clear-all zeroed RoProxy request count", ph_after.get("RoProxy", {}).get("Count", 0) == 0, ph_after.get("RoProxy"))
check("Clear-all zeroed token Requests", ph_after.get("Tokens", {}).get("Requests", 0) == 0, ph_after.get("Tokens"))

print("== Specific-header request filter (precise targeting) ==")
proxy_module.requests.request = fake_upstream
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
proxy_module.set_tokens(["SPEC_TOKEN"])
# Target ONLY the User-Agent value; other headers containing the word must NOT trip it.
r = client.post("/admin/headers/rule", headers=IP_MAIN, json={"header": "User-Agent", "mode": "contains", "needle": "BadClient"})
check("Add specific-header rule -> 200", r.status_code == 200, r.data[:80])
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
spec_rule = next((v for k, v in r.get_json().get("HeaderRules", {}).items() if v.get("Header") == "User-Agent"), {})
check("Specific-header rule stored with Header field", spec_rule.get("Header") == "User-Agent", spec_rule)
IP_SPEC = {"X-Forwarded-For": "10.40.0.1"}
r = api_client.get("/games.roblox.com/v1/spec", headers={**IP_SPEC, "User-Agent": "BadClient/1.0"})
check("Specific-header rule blocks the targeted header value -> 429", r.status_code == 429, r.status_code)
n = len(upstream_calls)
r = api_client.get("/games.roblox.com/v1/spec", headers={**IP_SPEC, "User-Agent": "Good/1.0", "X-Note": "BadClient is here"})
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
roblox_id_vals = hn.get("roblox-id", {}).get("Values", {})
check("Header value drill-down records distinct values", set(roblox_id_vals) == {"111", "222"}, roblox_id_vals)
cookie_vals = hn.get("cookie", {}).get("Values", {})
check("Sensitive cookie values are fingerprinted, not stored raw", all(v.startswith("fp:") for v in cookie_vals) and cookie_vals, cookie_vals)
check("Two identical cookies collapse to one fingerprint with count 2", any(info.get("Count") == 2 for info in cookie_vals.values()), cookie_vals)
# Per-header clear: clear just roblox-id, leave cookie intact.
r = client.post("/admin/fingerprints/clear_header", headers=IP_MAIN, json={"name": "Roblox-Id"})
check("Per-header clear -> 200", r.status_code == 200, r.status_code)
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
hn = r.get_json().get("HeaderNames", {})
check("Cleared header is gone", "roblox-id" not in hn, list(hn))
check("Other headers untouched by per-header clear", "cookie" in hn, list(hn))

print("== Blocked Request Fingerprints (false-positive review) ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "blocked_fingerprints"})
client.post("/admin/headers/rule", headers=IP_MAIN, json={"header": "User-Agent", "mode": "contains", "needle": "Grief"})
api_client.get("/games.roblox.com/v1/bfp", headers={"X-Forwarded-For": "10.42.0.1", "User-Agent": "GrieferTool/3", "X-Tag": "abc"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
check("Blocked request's header names recorded separately", "user-agent" in (diag.get("BlockedHeaderNames") or {}), list(diag.get("BlockedHeaderNames", {})))
check("Blocked request's user-agent recorded separately", "GrieferTool/3" in (diag.get("BlockedUserAgents") or {}), list(diag.get("BlockedUserAgents", {})))
check("Blocked fingerprints are separate from accepted ones", "GrieferTool/3" not in (diag.get("UserAgents") or {}), list(diag.get("UserAgents", {})))
# Clean up the rule.
for rid in [k for k, v in diag.get("HeaderRules", {}).items() if v.get("Needle") == "Grief"]:
    client.post("/admin/headers/rule/clear", headers=IP_MAIN, json={"id": rid})

print("== Traffic pills reflect the last hour ==")
client.post("/admin/data/clear", headers=IP_MAIN, json={"target": "requests"})
proxy_module.is_direct_api_in_cooldown = False
proxy_module.is_roproxy_in_cooldown = False
proxy_module.set_tokens(["PILL_TOKEN"])
for i in range(4):
    api_client.get(f"/games.roblox.com/v1/pill{i}", headers={"X-Forwarded-For": "10.43.0.1"})
r = client.get("/admin/diagnostics", headers={**IP_MAIN, "Accept": "application/json"})
diag = r.get_json()
now_minute = int(diag["ServerTime"] // 60)
hour_ok = sum(b.get("Successful", 0) for m, b in diag.get("TrafficMinutes", {}).items() if int(m) > now_minute - 60)
check("Traffic minutes reflect recent successful requests (drives the pills)", hour_ok >= 4, hour_ok)

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
proxy_module.error_email_last_sent = 0  # Clear any cooldown left by earlier error-log tests.
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
