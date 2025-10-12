import config
import copy
import time

exploit_attempts = list()
login_attempts = list()

request_counts = dict(
    {
        "GET": dict({"Successful": 0, "Failed": 0}),
        "POST": dict({"Successful": 0, "Failed": 0}),
        "PATCH": dict({"Successful": 0, "Failed": 0}),
        "PUT": dict({"Successful": 0, "Failed": 0}),
        "DELETE": dict({"Successful": 0, "Failed": 0}),
    }
)

status_code_counts = dict(
    {
        "2xx": 0,
        "4xx": 0,
    }
)

crawls = dict(
    {
        # [IP]: {LastRequestTime: float, Count: int},
    }
)

proxy_request_counts = dict(
    {
        "GET": dict({"TotalTime": 0, "Count": 0, "Min": 0, "Max": 0, "LastRequestTime": 0}),  # Count = nRequests.
        "POST": dict({"TotalTime": 0, "Count": 0, "Min": 0, "Max": 0, "LastRequestTime": 0}),  # Count = nRequests.
        "PATCH": dict({"TotalTime": 0, "Count": 0, "Min": 0, "Max": 0, "LastRequestTime": 0}),  # Count = nRequests.
        "PUT": dict({"TotalTime": 0, "Count": 0, "Min": 0, "Max": 0, "LastRequestTime": 0}),  # Count = nRequests.
        "DELETE": dict({"TotalTime": 0, "Count": 0, "Min": 0, "Max": 0, "LastRequestTime": 0}),  # Count = nRequests.
    }
)

proxy_health = dict(
    {
        "DirectAPI": dict({"Count": 0, "LastRequestTime": 0, "IsInCooldown": False}),  # Count = nRequests.
        "RoProxy": dict({"Count": 0, "LastRequestTime": 0, "IsInCooldown": False}),  # Count = nRequests.
        "Tokens": dict({"Count": 0, "ExpiredCount": 0, "BeingValidatedCount": 0}),  # Count = nTokens.
    }
)

tokens = dict(
    {
        # [full_token]: {Masked: str, BeingValidated: bool, Uses: int}
    }
)


def log_crawl(ip: str):
    global crawls
    now = time.time()
    if ip in crawls:
        crawls[ip]["Count"] += 1
        crawls[ip]["LastRequestTime"] = now
    else:
        crawls[ip] = dict(LastRequestTime=now, Count=1)


def log_exploit_attempt(ip: str, reason: str, user_agent: str):
    exploit_attempts.append(dict(IP=ip, Date=time.time(), Reason=reason, UserAgent=user_agent))
    if len(exploit_attempts) > config.MAX_EXPLOIT_RECORDS:
        exploit_attempts.pop(0)


def log_login_attempt(ip: str, successful: bool):
    login_attempts.append(dict(IP=ip, Date=time.time(), Successful=successful))
    if len(login_attempts) > config.MAX_LOGIN_RECORDS:
        login_attempts.pop(0)


def log_request(method: str, successful: bool):
    if method in request_counts:
        if successful:
            request_counts[method]["Successful"] += 1
        else:
            request_counts[method]["Failed"] += 1


def log_status_code(status_code: int):
    if 200 <= status_code < 300:
        status_code_counts["2xx"] += 1
    elif 400 <= status_code < 500:
        status_code_counts["4xx"] += 1


def log_proxy_request(method: str, duration: float):
    if method in proxy_request_counts:
        proxy_request_counts[method]["TotalTime"] += duration
        proxy_request_counts[method]["Count"] += 1
        proxy_request_counts[method]["LastRequestTime"] = time.time()
        if duration < proxy_request_counts[method]["Min"] or proxy_request_counts[method]["Min"] == 0:
            proxy_request_counts[method]["Min"] = duration
        if duration > proxy_request_counts[method]["Max"]:
            proxy_request_counts[method]["Max"] = duration


def update_token(token: str, being_validated: bool = False, used: bool = False):
    global tokens
    masked = f"...{token[-20:]}"
    if token in tokens:
        tokens[token]["BeingValidated"] = being_validated
        if used:
            tokens[token]["Uses"] += 1
    else:
        tokens[token] = dict(
            Masked=masked,
            BeingValidated=being_validated,
            Uses=tokens.get(token, {}).get("Uses", 0) + (1 if used else 0),
        )
    proxy_health["Tokens"]["Count"] = len(tokens)
    proxy_health["Tokens"]["BeingValidatedCount"] = sum(1 for t in tokens.values() if t["BeingValidated"])


def get_diagnostics() -> dict:
    global tokens
    return dict(
        {
            "ExploitAttempts": exploit_attempts,
            "LoginAttempts": login_attempts,
            "RequestCounts": request_counts,
            "StatusCodeCounts": status_code_counts,
            "ProxyRequestCounts": proxy_request_counts,
            "ProxyHealth": proxy_health,
            "Crawls": crawls,
            "Tokens": copy.deepcopy(list(tokens.values())),
        }
    )
