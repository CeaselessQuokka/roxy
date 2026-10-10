"""Review round 4 (lens secfix): an IPv6 client network the LLM export leaves raw in its `untrusted` texts.

What this is
    Adversarial tests of the LLM export's address hashing (`insights/llm_export.py mask_ips`, run on every outside
    text in `UntrustedPool.materialize`), next to the insights-1 and insights-2 trust rule fixes. `mask_ips` finds an
    IPv6 candidate as a run of hex digits and colons and, when the run does not parse, retries it with every colon
    stripped from both ends (`candidate.strip(":")`). A network written the way Roxy writes an IPv6 client,
    `ip:2001:db8:1:2::/64` (the spam and abuse subjects: `ip:` plus the client's /64 limit key), gives the run
    `:2001:db8:1:2::`; stripping removes the leading colon AND the trailing `::`, `2001:db8:1:2` does not parse, and
    the network stays in the export as it was.

Why it exists
    Plan 12.3 and DESIGN 14.5: "IPs are `ip:<hash>` from `common.export_ip_policy`; raw IPs only in full detail with
    `export_include_ips`". The summary export is the one meant to be pasted into an AI assistant.

How it works
    A recommendation about an IPv6 client is seeded as production stores it (subject `ip:<limit key>`), dismissed
    as "not accurate" so both detail levels list it under `potential_issues`. The summary export is fetched through
    the API with `export_include_ips` at its default (0) and searched for the raw network. Controls: the IPv4 form,
    and the same network written without the `ip:` prefix. The IPv6 tests were strict xfails (finding secfix-3);
    `mask_ips` now uses the admin downloads' masker (`core/ipmask.py`), which keeps the trailing `::`.

What to read next
    `roxy/core/ipmask.py`, `roxy/insights/llm_export.py` (`mask_ips`, `UntrustedPool._clean`), `roxy/abuse/spam.py`,
    `roxy/core/client_ip.py` (`limit_key`).
"""

from __future__ import annotations

from typing import Any

from roxy.config.insight_params import INSIGHT_RULES
from roxy.core.client_ip import limit_key
from roxy.core.ids import new_id
from roxy.insights import llm_export
from roxy.insights.engine import write_recommendation
from roxy.insights.models import Evidence, Recommendation, make_fingerprint

CLIENT_V6 = "2001:db8:1:2::77"
NETWORK_V6 = limit_key(CLIENT_V6, 64)  # "2001:db8:1:2::/64"
RAW_V6 = NETWORK_V6.split("/", 1)[0]  # "2001:db8:1:2::"
CLIENT_V4 = "198.51.100.79"


def _hash(ip: str) -> str:
    return "0123456789abcdef"


def test_control_mask_ips_hashes_an_ipv4_subject_and_a_bare_network() -> None:
    assert CLIENT_V4 not in llm_export.mask_ips(f"ip:{CLIENT_V4}", _hash)
    assert RAW_V6 not in llm_export.mask_ips(f"the network {NETWORK_V6} is busy", _hash)


def test_mask_ips_hashes_the_ipv6_subjects_roxy_writes() -> None:
    leaks = [
        text
        for text in (f"ip:{NETWORK_V6}", f"bypass:{NETWORK_V6}", f"client ip:{NETWORK_V6} flagged")
        if RAW_V6 in llm_export.mask_ips(text, _hash)
    ]
    assert leaks == [], f"left raw by mask_ips: {leaks}"


async def _seed(api_app: Any, subject: str) -> None:
    now = int(api_app.clock.now())
    spec = INSIGHT_RULES["ABUSE-BOT"]
    rec = Recommendation(
        rule_id="ABUSE-BOT",
        family=spec.family,
        subject=subject,
        title="ABUSE-BOT on one client",
        severity="warn",
        confidence="high",
        explanation="This client looks automated.",
        evidence=Evidence(window_from=now - 3600, window_to=now, sample_size=50).add("bot_score", 90, "score"),
        risk="low",
    )
    rec.id = new_id("rec", api_app.clock)
    rec.fingerprint = make_fingerprint("ABUSE-BOT", subject)
    rec.state = "dismissed"
    rec.dismissed_reason = "not_accurate"  # listed under potential_issues in summary and full exports
    rec.created_at = rec.updated_at = now
    rec.expires_at = now + 86_400
    await api_app.ctx.dbs.metrics.write(lambda conn: write_recommendation(conn, rec))


async def _summary(api: Any) -> str:
    response = await api.get("export/llm", params={"window": "24h", "detail": "summary", "format": "json"})
    assert response.status_code == 200, response.text[:300]
    return str(response.text)


async def test_control_an_ipv4_client_is_hashed_in_the_summary_export(api: Any, api_app: Any) -> None:
    assert int(api_app.ctx.settings.int("export_include_ips")) == 0
    await _seed(api_app, f"ip:{CLIENT_V4}")
    text = await _summary(api)
    assert "recommendation_subject" in text  # the seeded card is in the export
    assert CLIENT_V4 not in text


async def test_the_summary_export_never_carries_a_raw_ipv6_client_network(api: Any, api_app: Any) -> None:
    assert int(api_app.ctx.settings.int("export_include_ips")) == 0
    await _seed(api_app, f"ip:{NETWORK_V6}")
    text = await _summary(api)
    assert "recommendation_subject" in text
    assert RAW_V6 not in text, f"the raw network {NETWORK_V6} is in the summary LLM export"
