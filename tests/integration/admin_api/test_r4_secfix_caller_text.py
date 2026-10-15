"""Review round 4 (lens secfix): answers that carry caller-chosen text from this round's producers must say so.

What this is
    Contract tests of DESIGN.md 13.1 `caller_text` (added in review round 3): "an answer whose rows hold text a
    caller chose (a path, a template, a header name, a User-Agent, an error quoting them) lists those fields; pages
    render them as plain text, never markup". Round 3 made two producers feed tables with attacker-chosen text:
      * parity-2 (ptable-2): every proxy probe (a non-Roblox URL, an unsafe URL, auth smuggling) now reaches the
        Security probe log, `GET /security/probes`, whose rows carry the probed URL (`target`), the `path` and the
        caller's `user_agent`;
      * the producers lane and storage_abuse: refusal events name their rules, and the Protection attempts tabs
        (`GET /protection/endpoint-blocks/attempts` and its two siblings) list the refused `path` per row.
    The upstream failures, challenges, refusals, clients, endpoints and blocked fingerprints answers of the same
    round declare their `caller_text`; these two do not, so the P11 pages (which read `caller_text` to decide what
    to escape) get no warning for the one table any scanner on the internet can write into.

Why it exists
    Plan 9.16 (no caller string is ever rendered as markup) and the 13.1 contract; the probe log is fed by
    unauthenticated traffic, so it is the first place a stored injection would be tried.

How it works
    The real app: one probe through the proxy route (a path with markup), one endpoint block refusal seeded through
    the recorder with a markup path; each answer must carry `caller_text` naming the fields that hold that text.
    Both were strict xfails (finding secfix-5); the columns now carry `Column(caller_text=True)`, which
    `common.table_answer` lists, and `tests/unit/admin_api/test_api_caller_text_columns.py` checks every table.

What to read next
    `roxy/admin/api/security.py` (`probes`, `PROBE_SPEC`), `roxy/admin/api/protection.py` (`_attempts`,
    `ATTEMPT_SPEC`), `roxy/admin/api/upstream.py` (`FAILURES_CALLER_TEXT`, a route that does declare it).
"""

from __future__ import annotations

from typing import Any

from roxy.core.reasons import CacheState, Outcome, ReasonCode, Source

MARKUP = "<img src=x onerror=alert(1)>"


async def test_the_probe_log_declares_its_caller_text(api: Any, api_app: Any) -> None:
    headers = {"User-Agent": f"scanner {MARKUP}", "X-Forwarded-For": "203.0.113.61"}
    probed = await api_app.harness.http.get(f"/this-is-not-roblox/{MARKUP}", headers=headers)
    assert probed.status_code == 404, probed.text[:200]
    await api_app.ctx.recorder.flush()
    answer = await api.get("security/probes", params={"ip": "203.0.113.61"})
    assert answer.status_code == 200, answer.text[:200]
    body = answer.json()
    assert body["items"], body  # the probe is listed
    assert {"target", "user_agent"} <= set(body.get("caller_text") or ()), sorted(body)


async def test_the_attempts_tabs_declare_their_caller_text(api: Any, api_app: Any, metrics_seed: Any) -> None:
    metrics_seed.record(
        1,
        outcome=Outcome.REFUSED,
        reason=ReasonCode.ENDPOINT_BLOCKED,
        status=403,
        source=Source.ROXY,
        cache_state=CacheState.NA,
        upstream_calls=0,
        upstream_bytes_in=0,
        upstream_bytes_out=0,
        check=ReasonCode.ENDPOINT_BLOCKED.value,
        client_ip="203.0.113.62",
        path=f"games.roblox.com/v1/{MARKUP}",
    )
    await metrics_seed.flush()
    answer = await api.get("protection/endpoint-blocks/attempts")
    assert answer.status_code == 200, answer.text[:200]
    body = answer.json()
    assert any(MARKUP in str(item.get("path")) for item in body["items"]), body["items"]
    assert "path" in set(body.get("caller_text") or ()), sorted(body)
