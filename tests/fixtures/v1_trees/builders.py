"""Builders for fake v1 `/etc/roxy` trees, for the migration tests (plan 19.6).

What this is
    `V1TreeBuilder` writes a directory shaped exactly like a v1 `/etc/roxy` (files.txt, the four secret files,
    rotate_proxy.txt, roxy_state.json, roxy_data.json, the per-worker coordination files and a cache directory),
    plus ready-made trees: `small_tree`, `large_tree`, and the knobs the tests turn (a corrupt data file, a
    multi-line token file, out-of-range settings, the legacy `Runtime` blob inside roxy_data.json, dashes in admin
    text).

Why it exists
    The migrator must be tested against v1 files without ever reading the real `/etc/roxy`. The shapes come from
    the v1 code (`app/runtime.py _serialize_unlocked`, `app/diagnostics.py`, `app/auth.py`) and the v1 notes; every
    secret is an obviously fake value generated at runtime, every IP address is from the documentation ranges
    (RFC 5737), and the v1 setting defaults are a second, independent copy of `app/runtime.py`, so a mistake in
    the migrator's own table cannot hide itself.

How it works
    A builder holds the `Runtime` blob, the `Diagnostics` stores and the secret values as plain dicts; tests change
    them, then call `write()`. Dash characters are built with `chr()`, so this file holds none (plan C5).

What to read next
    `tests/migration/conftest.py` (how the tests use these) and `src/roxy/migration/v1_tree.py` (the reader).
"""

from __future__ import annotations

import copy
import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

EM = chr(0x2014)
EN = chr(0x2013)
TOKEN_PREFIX = (
    "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-"
    "items.|_"
)
"""The public warning text every Roblox cookie starts with (v1 config.TOKEN_PREFIX); not a secret."""

V1_TIME = 1_750_000_000  # a fixed "v1 era" timestamp, before the tests' FakeClock start (1_760_000_000)

# v1 setting defaults (app/runtime.py lines 155-298, DEBUG off), written out independently of the migrator.
V1_SETTING_DEFAULTS: dict[str, int] = {
    "allowed_requests_per_minute": 10,
    "throttle_reset_duration": 50,
    "stale_ip_duration": 60,
    "max_retries_per_request": 3,
    "two_fa_expiration": 60,
    "challenge_expiration": 60,
    "token_expiration_cooldown": 15,
    "request_timeout": 15,
    "email_cooldown": 600,
    "error_email_cooldown": 300,
    "autosave_interval": 30,
    "max_live_requests": 150,
    "max_exploit_records": 20,
    "max_login_records": 20,
    "max_crawl_records": 20,
    "max_throttle_records": 20,
    "max_endpoint_records": 200,
    "max_header_name_records": 300,
    "max_header_value_records": 200,
    "max_user_agent_records": 1000,
    "max_error_records": 1000,
    "endpoint_recent_requests": 5,
    "activity_tracking": 1,
    "max_ip_activity_records": 400,
    "max_caller_records": 200,
    "capture_enabled": 1,
    "capture_max_records": 250,
    "capture_max_bytes": 4194304,
    "capture_max_body": 16384,
    "capture_ttl_seconds": 900,
    "throttle_escalation_enabled": 1,
    "throttle_strike_decay_seconds": 1800,
    "user_agent_rules_enabled": 1,
    "cache_enabled": 1,
    "cache_ttl_seconds": 60,
    "cache_error_ttl_seconds": 0,
    "cache_disk_enabled": 1,
    "cache_max_entries": 3000,
    "cache_max_bytes": 33554432,
    "cache_max_body": 262144,
    "cache_memory_entries": 400,
    "cache_memory_bytes": 8388608,
    "cache_stale_seconds": 600,
    "cache_serve_throttled": 0,
    "cache_coalesce": 1,
    "cache_coalesce_wait_ms": 1500,
    "cache_post_requests": 0,
    "cache_respect_no_cache": 0,
    "auto_ignore_high_cardinality": 1,
    "diagnostics_flush_interval": 10,
    "token_budget_requests": 95,
    "token_budget_window": 65,
    "global_throttle_limit": 1,
    "global_throttle_period": 60,
    "token_weight": 75,
    "rotate_weight": 25,
    "token_danger_zone": 60,
    "rotate_enabled": 1,
    "rotate_cooldown": 60,
    "rotate_max_failures": 3,
    "tarpit_enabled": 1,
    "tarpit_min_seconds": 8,
    "tarpit_max_seconds": 20,
    "tarpit_max_concurrent": 6,
    "tarpit_on_header_rule": 1,
    "tarpit_on_probe": 1,
    "tarpit_on_throttle": 0,
    "tarpit_on_throttle_all": 0,
    "tarpit_on_endpoint_rule": 0,
    "tarpit_on_blocked_endpoint": 0,
    "tarpit_on_auth_attempt": 0,
}

V1_DEFAULT_TIERS: list[dict[str, Any]] = [
    {
        "Multiplier": 1.0,
        "Message": f"Too many requests {EM} please slow down.",
        "Note": "First strike: probably just fast.",
    },
    {
        "Multiplier": 2.0,
        "Message": "You are about to be severely throttled. Please respect the proxy's limits.",
        "Note": "Second strike: a warning they can still act on.",
    },
    {
        "Multiplier": 4.0,
        "Message": "You have been harshly throttled due to bot behavior. The proxy is happy for you to scrape data, "
        "but please respect its limits. If you need more request bandwidth, contact CeaselessQuokka.",
        "Note": "Third strike: says what to do about it.",
    },
    {
        "Multiplier": 8.0,
        "Message": "You are still ignoring the proxy's limits, so the wait has been extended again. Contact "
        "CeaselessQuokka if you need more request bandwidth.",
        "Note": "Fourth strike and beyond: the last rung repeats.",
    },
]
"""v1 config.DEFAULT_THROTTLE_TIERS, rung 1 with its original em dash."""

V1_DEFAULT_IGNORED_VALUE_HEADERS = (
    "traceparent",
    "tracestate",
    "x-request-id",
    "request-id",
    "x-correlation-id",
    "x-amzn-trace-id",
    "x-b3-traceid",
    "x-b3-spanid",
    "x-b3-parentspanid",
)


def fake_token() -> str:
    """An obviously fake `.ROBLOSECURITY` value: the public prefix, a FAKE marker, random hex."""
    return TOKEN_PREFIX + "FAKEV1TESTTOKEN" + secrets.token_hex(96).upper()


@dataclass
class FakeV1Secrets:
    """The secret values of one fake tree (generated at runtime, never committed)."""

    tokens: list[str]
    username: str = "owner-test"
    password: str = field(default_factory=lambda: "fake-v1-password-" + secrets.token_hex(8))
    hmac_key: str = field(default_factory=lambda: "fake-hmac-" + secrets.token_hex(16))
    session_secret: str = field(default_factory=lambda: "fake-session-" + secrets.token_hex(16))
    app_password: str = field(default_factory=lambda: "fakeapppw" + secrets.token_hex(8))
    rotator_url: str = field(default_factory=lambda: f"http://fakeuser:fakepw{secrets.token_hex(6)}@127.0.0.1:9")
    email_to: str = "owner@example.invalid"
    email_from: str = "sender@example.invalid"

    def values(self) -> list[str]:
        """Every secret value (the username and the addresses are not secrets)."""
        return [*self.tokens, self.password, self.hmac_key, self.session_secret, self.app_password, self.rotator_url]


def make_secrets(token_count: int = 1) -> FakeV1Secrets:
    return FakeV1Secrets(tokens=[fake_token() for _ in range(token_count)])


def default_runtime() -> dict[str, Any]:
    """A `Runtime` blob exactly as v1 writes it for an untouched install (all 71 settings at their defaults)."""
    return {
        "Paused": False,
        "PausedSince": 0.0,
        "PauseReason": "",
        "ThrottleAll": False,
        "ThrottleAllSince": 0.0,
        "ThrottleAllReason": "",
        "SessionEpoch": 1,
        "Settings": dict(V1_SETTING_DEFAULTS),
        "SettingsUpdated": dict.fromkeys(V1_SETTING_DEFAULTS, 0.0),
        "ThrottleBypassIps": {},
        "EndpointBlocks": {},
        "EndpointRules": {},
        "CacheRules": {},
        "UserAgentRules": {},
        "CacheIgnoredParams": {},
        "ThrottleTiers": copy.deepcopy(V1_DEFAULT_TIERS),
        "HeaderRules": {},
        "IgnoredValueHeaders": {
            name: {"Added": 0.0, "Auto": False, "Note": "default"} for name in V1_DEFAULT_IGNORED_VALUE_HEADERS
        },
        "InvalidationTokens": {},
        "TwoFACodes": {},
        "Challenges": {},
        "TrustedDevices": {},
    }


def set_setting(runtime: dict[str, Any], key: str, value: Any) -> None:
    runtime["Settings"][key] = value
    runtime["SettingsUpdated"][key] = float(V1_TIME + 60)


def empty_diagnostics() -> dict[str, Any]:
    return {
        "page_visits": {"home": 0, "admin": 0, "robots": 0},
        "visitor_counts": {"Human": 0, "Crawler": 0},
        "exploit_attempts": [],
        "exploit_summary": {},
        "login_attempts": [],
        "request_counts": {m: {"Successful": 0, "Failed": 0} for m in ("GET", "POST", "PATCH", "PUT", "DELETE")},
        "status_code_counts": {"2xx": 0, "4xx": 0},
        "status_codes_detailed": {},
        "status_sources": {"Roblox": {}, "Roxy": {}, "Relay": {}, "Internal": {}, "Cache": {}},
        "refusals": {},
        "endpoints": {},
        "cache_endpoints": {},
        "request_failures": {},
        "internal_requests": {},
        "cache_stats": {
            "Hits": 0,
            "Stale": 0,
            "Misses": 0,
            "Stores": 0,
            "Coalesced": 0,
            "Skipped": 0,
            "Evictions": 0,
            "Bypassed": 0,
            "BytesServed": 0,
            "LastHit": 0,
            "LastMiss": 0,
        },
        "errors": {},
        "header_names": {},
        "user_agents": {},
        "blocked_header_names": {},
        "blocked_user_agents": {},
        "live_requests": [],
        "traffic_minutes": {},
        "pause_drops": {"Count": 0},
        "throttle_drops": {"Count": 0},
        "ClearEpochs": {},
        "KeyClearEpochs": {},
    }


@dataclass
class V1TreeBuilder:
    """A fake v1 tree under `root`. Change the dicts, then call `write()`."""

    root: Path
    secrets: FakeV1Secrets = field(default_factory=make_secrets)
    runtime: dict[str, Any] = field(default_factory=default_runtime)
    diagnostics: dict[str, Any] = field(default_factory=empty_diagnostics)
    write_state: bool = True
    legacy_runtime: dict[str, Any] | None = None  # a Runtime blob inside roxy_data.json (pre-split v1)
    corrupt_data: bool = False
    data_backup: bool = False
    token_text: str | None = None  # raw token file text (overrides `secrets.tokens`)
    write_rotator: bool = True
    files_listing: list[str] | None = None

    def write(self) -> Path:
        root = self.root
        root.mkdir(parents=True, exist_ok=True)
        listing = self.files_listing or ["admin_credentials.txt", "app_password.txt", "auth_tokens.txt", "emails.txt"]
        (root / "files.txt").write_text("\n".join(listing) + "\n", encoding="utf-8")
        s = self.secrets
        (root / "admin_credentials.txt").write_text(
            f"{s.username}\n{s.password}\n{s.hmac_key}\n{s.session_secret}\n", encoding="utf-8"
        )
        (root / "app_password.txt").write_text(s.app_password + "\n", encoding="utf-8")
        token_text = self.token_text if self.token_text is not None else "\n".join(s.tokens) + "\n"
        (root / "auth_tokens.txt").write_text(token_text, encoding="utf-8")
        (root / "emails.txt").write_text(f"{s.email_to}\n{s.email_from}\n", encoding="utf-8")
        if self.write_rotator:
            (root / "rotate_proxy.txt").write_text(s.rotator_url + "\n", encoding="utf-8")
        if self.write_state:
            (root / "roxy_state.json").write_text(json.dumps({"Runtime": self.runtime}, separators=(",", ":")))
        data: dict[str, Any] = {"Diagnostics": self.diagnostics}
        if self.legacy_runtime is not None:
            data["Runtime"] = self.legacy_runtime
        text = json.dumps(data, separators=(",", ":"))
        if self.corrupt_data:
            (root / "roxy_data.json").write_text(text[: len(text) // 2] + "\x00{{not json", encoding="utf-8")
        else:
            (root / "roxy_data.json").write_text(text, encoding="utf-8")
        if self.data_backup:
            (root / "roxy_data.json.bak").write_text(text, encoding="utf-8")
        # v1's per-worker coordination files, lock files and cache shards: present, never migrated, never touched.
        for name in ("roxy_throttle.json", "roxy_tarpit.json", "roxy_workers.json", "roxy_routing.json"):
            (root / name).write_text('{"Ips":{}}', encoding="utf-8")
            (root / f"{name}.lock").write_text("", encoding="utf-8")
        (root / "roxy_state.json.lock").write_text("", encoding="utf-8")
        cache = root / "cache"
        cache.mkdir(exist_ok=True)
        (cache / "meta.json").write_text("{}", encoding="utf-8")
        (cache / "shard_0.json").write_text("{}", encoding="utf-8")
        return root


# --- ready-made trees ----------------------------------------------------------------------------------------------


def small_tree(root: Path, *, token_count: int = 1) -> V1TreeBuilder:
    """A typical small install: a few changed settings, one rule of each kind, dashes in admin text, stats."""
    builder = V1TreeBuilder(root, secrets=make_secrets(token_count))
    rt = builder.runtime
    set_setting(rt, "allowed_requests_per_minute", 25)  # imported
    set_setting(rt, "cache_ttl_seconds", 300)  # imported (v1 default 60)
    set_setting(rt, "rotate_cooldown", 120)  # renamed to rotator_cooldown_s
    set_setting(rt, "token_weight", 50)  # meaning changed: never imported
    set_setting(rt, "max_endpoint_records", 300)  # not larger than the v2 default: reported, not imported
    set_setting(rt, "max_live_requests", 600)  # renamed to live_tail_buffer
    set_setting(rt, "cache_post_requests", 1)  # mapped to "all" with a high-risk warning
    rt["Settings"]["throttle_reset_duration"] = 50  # saved at its default: not imported
    rt["SettingsUpdated"]["throttle_reset_duration"] = float(V1_TIME)
    rt["PauseReason"] = f"Back soon {EM} maintenance window"
    rt["EndpointBlocks"] = {
        "games.roblox.com/v1/games/*/servers": {
            "Added": float(V1_TIME),
            "Note": f"server list scrapers {EM} see ticket",
            "Message": f"Blocked {EM} use the official API instead.",
            "Type": "glob",
        },
        r"^users\.roblox\.com/v1/users/\d+/status$": {
            "Added": float(V1_TIME + 5),
            "Note": "",
            "Message": "",
            "Type": "regex",
        },
    }
    rt["EndpointRules"] = {
        "thumbnails.roblox.com/v1/batch": {
            "Limit": 30,
            "Period": 60,
            "Added": float(V1_TIME),
            "Type": "glob",
            "Note": "batch lookups",
            "Message": f"Slow down {EN} batch lookups are limited.",
        }
    }
    rt["CacheRules"] = {
        "games.roblox.com/v1/games/*/votes": {"TTL": 900, "Type": "glob", "Note": "votes move slowly", "Added": 1.0},
        r"^games\.roblox\.com/v1/games$": {"TTL": 120, "Type": "regex", "Note": "v1 rule on a default pattern"},
    }
    rt["UserAgentRules"] = {
        "a1b2c3d4": {
            "Needle": "python-requests",
            "Mode": "contains",
            "Scope": "ip",
            "Kind": "burst",
            "Limit": 20,
            "Period": 60,
            "Cooldown": 2.0,
            "Message": f"Scripted clients {EM} please cache your results.",
            "Note": "",
            "Enabled": True,
            "Added": float(V1_TIME),
            "Updated": float(V1_TIME),
        },
        "0f0f0f0f": {
            "Needle": "^Roblox/WinInet$",
            "Mode": "regex",
            "Scope": "global",
            "Kind": "cooldown",
            "Limit": 10,
            "Period": 60,
            "Cooldown": 1.5,
            "Message": "",
            "Note": f"game servers {EM} like the others {EM} share one budget",
            "Enabled": False,
            "Added": float(V1_TIME + 1),
        },
    }
    rt["HeaderRules"] = {
        "|either|contains|xeno": {
            "Header": "",
            "Scope": "either",
            "Mode": "contains",
            "Needle": "Xeno",
            "Note": "exploit executor",
            "Message": "",
            "Added": float(V1_TIME),
        },
        "user-agent|value|regex|^\\d+$": {
            "Header": "User-Agent",
            "Scope": "value",
            "Mode": "regex",
            "Needle": "^\\D+$",
            "Note": "",
            "Message": f"Filtered {EM} contact the owner",
            "Added": float(V1_TIME),
        },
    }
    rt["CacheIgnoredParams"] = {"t": {"Added": 1.0, "Note": ""}, "_cb2": {"Added": 1.0, "Note": "cache buster"}}
    rt["IgnoredValueHeaders"]["x-amz-cf-id"] = {"Added": float(V1_TIME), "Auto": True, "Note": "auto: 600 distinct"}
    rt["ThrottleBypassIps"] = {
        "198.51.100.7": {"Added": float(V1_TIME), "Expires": 0.0, "Note": f"load test {EM} remove later"},
        "192.0.2.1": {"Added": float(V1_TIME), "Expires": float(V1_TIME + 10), "Note": "expired long ago"},
        "not-an-ip": {"Added": float(V1_TIME), "Expires": 0.0, "Note": ""},
    }
    rt["ThrottleTiers"] = copy.deepcopy(V1_DEFAULT_TIERS)
    rt["TwoFACodes"] = {secrets.token_hex(32): float(V1_TIME + 60)}
    rt["Challenges"] = {secrets.token_hex(32): float(V1_TIME + 60)}
    rt["TrustedDevices"] = {
        secrets.token_hex(32): {"Expires": float(V1_TIME + 999), "IP": "192.0.2.50", "UserAgent": "x", "Added": 1.0}
    }
    rt["InvalidationTokens"] = {secrets.token_urlsafe(32): float(V1_TIME + 86400)}
    add_statistics(builder.diagnostics)
    return builder


def add_statistics(diag: dict[str, Any]) -> None:
    """Statistics in the shape v1 writes them: the 579 Roblox 429s over just under 50,000 requests (plan 2.5)."""
    diag["request_counts"]["GET"] = {"Successful": 40000, "Failed": 6000}
    diag["request_counts"]["POST"] = {"Successful": 3500, "Failed": 300}
    diag["status_sources"]["Roblox"] = {"200": 42000, "429": 579, "404": 120}
    diag["status_sources"]["Roxy"] = {"429": 900, "403": 15}
    diag["status_codes_detailed"] = {"200": 42000, "429": 579, "404": 120}
    diag["status_code_counts"] = {"2xx": 42000, "4xx": 699}
    diag["cache_stats"].update(Hits=21000, Stale=500, Coalesced=389, Misses=28000, Stores=20000)
    diag["page_visits"] = {"home": 1234, "admin": 12, "robots": 40}
    diag["pause_drops"] = {"Count": 7}
    diag["ClearEpochs"] = {"request_counts": float(V1_TIME - 86400 * 30), "status_sources": float(V1_TIME - 86400 * 30)}
    diag["endpoints"] = {
        "games.roblox.com/v1/games/{gameId}/votes": {
            "Count": 5000,
            "LastRequestTime": float(V1_TIME),
            "LastOutcome": "served",
            "LastStatus": 200,
            "Methods": {"GET": 5000},
        },
        "realtime.roblox.com/v1/notifications": {"Count": 300, "LastOutcome": "served", "LastStatus": 200},
        "chat.roblox.com/v2/get-user-conversations": {
            "Count": 2,
            "LastOutcome": "upstream_failed",
            "LastStatus": 500,
        },
    }
    diag["cache_endpoints"] = {"games.roblox.com/v1/games/{gameId}/votes": {"Hits": 400, "Count": 900}}
    diag["request_failures"] = {
        "Token: Rate limited (429)": {
            "Method": "Token",
            "Count": 579,
            "LastEndpoint": "games.roblox.com/v1/games/123/votes",
            "LastStatus": "429",
        },
        "Rotate: timeout": {"Method": "Rotate", "Count": 3, "LastEndpoint": "badges.roblox.com/v1/badges/9"},
    }
    diag["internal_requests"] = {
        "token_validate": {
            "Count": 10,
            "Failed": 1,
            "LastEndpoint": "https://accountinformation.roblox.com/v1/birthdate",
        },
        "rotate_probe": {"Count": 4, "Failed": 0, "LastEndpoint": "https://api.ipify.org"},
    }
    diag["header_names"] = {
        "user-agent": {
            "Count": 900,
            "FirstSeen": float(V1_TIME - 1000),
            "LastSeen": float(V1_TIME),
            "Values": {
                "Roblox/WinInet": {"Count": 800, "FirstSeen": float(V1_TIME - 1000), "LastSeen": float(V1_TIME)}
            },
        },
        "x-forwarded-for": {
            "Count": 900,
            "FirstSeen": float(V1_TIME - 1000),
            "LastSeen": float(V1_TIME),
            "Values": {"192.0.2.33": {"Count": 3, "FirstSeen": 1.0, "LastSeen": 2.0}},
        },
        "cookie": {
            "Count": 2,
            "FirstSeen": float(V1_TIME - 500),
            "LastSeen": float(V1_TIME - 400),
            "Values": {"fp:0123456789ab": {"Count": 2, "FirstSeen": 1.0, "LastSeen": 2.0}},
        },
    }
    diag["user_agents"] = {
        "Roblox/WinInet": {"Count": 800, "FirstSeen": float(V1_TIME - 1000), "LastSeen": float(V1_TIME)},
        "python-requests/2.31": {"Count": 50, "FirstSeen": float(V1_TIME - 900), "LastSeen": float(V1_TIME - 10)},
    }
    diag["blocked_user_agents"] = {
        "python-requests/2.31": {"Count": 5, "FirstSeen": float(V1_TIME - 2000), "LastSeen": float(V1_TIME - 5)}
    }
    diag["errors"] = {
        "ValueError: bad thing": {
            "Count": 4,
            "FirstSeen": float(V1_TIME - 3000),
            "LastSeen": float(V1_TIME - 100),
            "LastDetail": "GET /games.roblox.com/v1/x\nIP: 192.0.2.10\n\nTraceback (most recent call last): ...",
            "Source": "Roxy",
        }
    }
    diag["exploit_summary"] = {
        'Non-Roblox URL: "evil.example/admin"': {"Count": 12, "LastSeen": float(V1_TIME - 50)},
        "Invalid 2FA code": {"Count": 3, "LastSeen": float(V1_TIME - 70)},
    }
    diag["exploit_attempts"] = [
        {
            "Id": "e1",
            "IP": "192.0.2.77",
            "Date": float(V1_TIME - 400),
            "Reason": 'Non-Roblox URL: "evil.example/admin"',
            "UserAgent": "scanner",
        }
    ]


def large_tree(root: Path) -> V1TreeBuilder:
    """Every v1 rule store at its v1 cap, plus large statistics (plan 19.6 "large")."""
    builder = small_tree(root)
    rt = builder.runtime
    rt["EndpointBlocks"] = {
        f"games.roblox.com/v1/blocked{i}": {"Added": float(V1_TIME + i), "Note": f"n{i}", "Message": "", "Type": "glob"}
        for i in range(200)
    }
    rt["EndpointRules"] = {
        f"users.roblox.com/v1/limited{i}": {
            "Limit": 5 + i,
            "Period": 60,
            "Added": float(V1_TIME),
            "Type": "glob",
            "Note": "",
            "Message": f"Rule {i} {EM} slow down",
        }
        for i in range(200)
    }
    rt["CacheRules"] = {
        f"catalog.roblox.com/v1/cached{i}": {"TTL": 60 + i, "Type": "glob", "Note": ""} for i in range(200)
    }
    rt["UserAgentRules"] = {
        f"{i:08x}": {
            "Needle": f"bot-{i}",
            "Mode": "contains",
            "Scope": "ip",
            "Kind": "burst",
            "Limit": 10,
            "Period": 60,
            "Cooldown": 2.0,
            "Message": "",
            "Note": "",
            "Enabled": True,
            "Added": float(V1_TIME + i),
        }
        for i in range(100)
    }
    rt["HeaderRules"] = {
        f"|either|contains|marker-{i}": {
            "Header": "",
            "Scope": "either",
            "Mode": "contains",
            "Needle": f"marker-{i}",
            "Note": "",
            "Message": "",
            "Added": float(V1_TIME),
        }
        for i in range(100)
    }
    rt["ThrottleBypassIps"] = {
        f"198.51.100.{i}": {"Added": float(V1_TIME), "Expires": 0.0, "Note": f"office {i}"} for i in range(100)
    }
    rt["CacheIgnoredParams"] = {f"p{i}": {"Added": 1.0, "Note": ""} for i in range(50)}
    rt["ThrottleTiers"] = [
        {"Multiplier": float(i + 1), "Message": f"Rung {i + 1} {EM} wait longer", "Note": ""} for i in range(12)
    ]
    diag = builder.diagnostics
    diag["errors"] = {
        f"RuntimeError: case {i}": {
            "Count": i + 1,
            "FirstSeen": float(V1_TIME - 1000),
            "LastSeen": float(V1_TIME),
            "LastDetail": f"detail {i}",
            "Source": "Roxy",
        }
        for i in range(1000)
    }
    diag["header_names"] = {
        f"x-header-{i}": {
            "Count": 100,
            "FirstSeen": float(V1_TIME - 1000),
            "LastSeen": float(V1_TIME),
            "Values": {
                f"value-{j}": {"Count": 1, "FirstSeen": float(V1_TIME - 10), "LastSeen": float(V1_TIME)}
                for j in range(20)
            },
        }
        for i in range(300)
    }
    diag["user_agents"] = {
        f"agent/{i}": {"Count": 1, "FirstSeen": float(V1_TIME - 1), "LastSeen": float(V1_TIME)} for i in range(1000)
    }
    diag["exploit_summary"] = {
        f"HTTP 404 via GET /probe{i}": {"Count": 1, "LastSeen": float(V1_TIME)} for i in range(100)
    }
    diag["endpoints"].update(
        {
            f"extra{i}.roblox.com/v1/thing": {"Count": 10 + i, "LastOutcome": "served", "LastStatus": 200}
            for i in range(250)
        }
    )
    return builder


__all__ = [
    "EM",
    "EN",
    "TOKEN_PREFIX",
    "V1_DEFAULT_IGNORED_VALUE_HEADERS",
    "V1_DEFAULT_TIERS",
    "V1_SETTING_DEFAULTS",
    "V1_TIME",
    "FakeV1Secrets",
    "V1TreeBuilder",
    "add_statistics",
    "default_runtime",
    "empty_diagnostics",
    "fake_token",
    "large_tree",
    "make_secrets",
    "set_setting",
    "small_tree",
]
