"""Review round 4 (lens secfix): client addresses that the apisec-2 masking leaves raw in admin API exports.

What this is
    Adversarial tests of the apisec-2 fix (`common.mask_ip_text`, applied by `common.ExportBuilder` to every cell
    while `export_include_ips` is off). The IPv6 candidate pattern refuses to start right after a colon
    (`(?<![0-9A-Za-z:])`), so an IPv6 address or network written as `<word>:<address>` is never masked. That is
    exactly how Roxy writes an IPv6 client: the spam detectors' subject is `ip:<limit key>` (`abuse/spam.py`), and
    the limit key of an IPv6 client is its /64 network (`core/client_ip.py limit_key`, `ipv6_limit_prefix` 64), so
    the subject reads `ip:2001:db8:1:2::/64`; the abuse insight rules use the same `ip:<client>` subjects. The IPv4
    pattern also skips an address right after `<letter>/` (meant for `Chrome/120.0.0.0`).

Why it exists
    Plan 9.15 and 12.3, and the `export_include_ips` help text: "every address is replaced by a keyed hash" in files
    designed to leave the server. A /64 is one subscriber's network: as identifying as an IPv4 address.

How it works
    One IPv6 client is seeded the way production writes it: a spam detector dry-run decision whose subject is the
    client's limit key, and a recommendation about that client. Every download that carries those rows is fetched
    as CSV and JSON and searched for the raw network. A control seeds the IPv4 form. A unit check shows the masking
    function itself on the subject shapes Roxy writes. The IPv6 tests were strict xfails (finding secfix-2); the
    admin downloads and the LLM export now share one masker (`core/ipmask.py`) that finds an address after a word
    and a colon and keeps a product version only in User-Agent columns.

What to read next
    `roxy/core/ipmask.py` (`mask_ip_text`), `roxy/admin/api/common.py` (`ExportBuilder`), `roxy/abuse/spam.py`
    (`ip:{limit_key}`), `roxy/core/client_ip.py` (`limit_key`),
    `tests/integration/admin_api/test_r3_apisec_export_ips.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.admin.api.common import mask_ip_text
from roxy.config.insight_params import INSIGHT_RULES
from roxy.core.client_ip import limit_key
from roxy.core.ids import new_id
from roxy.insights.engine import write_recommendation
from roxy.insights.models import Evidence, Recommendation, make_fingerprint

CLIENT_V6 = "2001:db8:1:2::77"
"""A documentation address (RFC 3849) standing in for an IPv6 caller."""
NETWORK_V6 = limit_key(CLIENT_V6, 64)  # "2001:db8:1:2::/64": what Roxy limits, bans and names in subjects
RAW_V6 = NETWORK_V6.split("/", 1)[0]  # "2001:db8:1:2::"
CLIENT_V4 = "198.51.100.78"


def _hash(ip: str) -> str:
    return f"H<{len(ip)}>"


def test_control_the_masker_hides_an_ipv4_subject() -> None:
    """Control (passes today): `ip:<IPv4>` is masked to `ip:<keyed hash>`."""
    assert mask_ip_text(f"ip:{CLIENT_V4}", _hash) == "ip:H<13>"
    assert mask_ip_text(f"[{CLIENT_V6}]:443", _hash) == "[ip:H<16>]:443"  # an IPv6 not after a colon is masked


def test_the_masker_hides_the_ipv6_subjects_roxy_writes() -> None:
    """The masking function on the subject shapes Roxy stores for an IPv6 client (`ip:` plus its limit key, a
    bypass network, a ban target)."""
    leaks = [
        text
        for text in (f"ip:{NETWORK_V6}", f"ip:{CLIENT_V6}", f"bypass:{NETWORK_V6}", f"ban:{CLIENT_V6}")
        if RAW_V6 in mask_ip_text(text, _hash)
    ]
    assert leaks == [], f"left raw by mask_ip_text: {leaks}"


async def _seed(api_app: Any, metrics_seed: Any, subject: str) -> None:
    assert int(api_app.ctx.settings.int("export_include_ips")) == 0  # the default: exports must hash addresses
    metrics_seed.event(
        "spam_would_ban",
        "warning",
        "",
        {
            "detector": "SPAM-RATE",
            "subject": subject,
            "value": 9.0,
            "threshold": 5.0,
            "window_s": 600,
            "action": "ban",
            "configured_action": "ban",
            "game_server": False,
            "evidence": "9 requests a second over 600 s",
        },
    )
    await metrics_seed.flush()
    now = int(api_app.clock.now())
    spec = INSIGHT_RULES["ABUSE-BOT"]
    rec = Recommendation(
        rule_id="ABUSE-BOT",
        family=spec.family,
        subject=subject,
        title=f"ABUSE-BOT on {subject}",
        severity="warn",
        confidence="high",
        explanation=f"The client {subject} looks automated.",
        evidence=Evidence(window_from=now - 3600, window_to=now, sample_size=50).add("bot_score", 90, "score"),
        changes=[],
        expected_impact="",
        risk="low",
    )
    rec.id = new_id("rec", api_app.clock)
    rec.fingerprint = make_fingerprint("ABUSE-BOT", subject)
    rec.state = "dismissed"  # closed: the leader's own evaluation never resolves or rewrites it
    rec.created_at = rec.updated_at = now
    rec.expires_at = now + 86_400
    await api_app.ctx.dbs.metrics.write(lambda conn: write_recommendation(conn, rec))


DOWNLOADS = {
    "spam detector decisions": ("protection/spam/events", {"range": "24h"}),
    "overview events": ("overview/events", {"range": "24h"}),
    "recommendations": ("recommendations", {"state": "dismissed"}),
}


async def _leaks(api: Any, raw: str) -> list[str]:
    found: list[str] = []
    for label, (path, params) in DOWNLOADS.items():
        for fmt in ("csv", "json"):
            response = await api.get(path, params={**params, "format": fmt})
            if response.status_code != 200:  # a filter value this build does not take: try without it
                response = await api.get(path, params={"format": fmt})
            assert response.status_code == 200, (label, fmt, response.text[:200])
            assert response.headers.get("content-disposition", "").startswith("attachment"), (label, fmt)
            if raw in response.text:
                found.append(f"{label} ({fmt})")
    return found


async def test_control_an_ipv4_client_is_masked_in_every_download(api: Any, api_app: Any, metrics_seed: Any) -> None:
    """Control (passes today): the same rows with an IPv4 client leave no raw address."""
    await _seed(api_app, metrics_seed, f"ip:{CLIENT_V4}")
    assert await _leaks(api, CLIENT_V4) == []


async def test_no_download_carries_a_raw_ipv6_client_network(api: Any, api_app: Any, metrics_seed: Any) -> None:
    await _seed(api_app, metrics_seed, f"ip:{NETWORK_V6}")
    leaks = await _leaks(api, RAW_V6)
    assert leaks == [], f"raw IPv6 client network {NETWORK_V6} in: {', '.join(leaks)}"
