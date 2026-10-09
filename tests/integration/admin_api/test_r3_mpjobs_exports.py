"""Review round 3, lens mpjobs: big exports against the 1 GB box (memory) and the event loop.

What this is
    Two adversarial tests (strict xfails) against the running app:
      * a table download (`GET /admin/api/v1/audit?format=csv`) of the audit log at the export row cap, measured
        with `tracemalloc` on the server side only (the ASGI app is driven directly and the body bytes are counted
        and dropped, so no client copy is measured);
      * the LLM export (`build_export`, 7 days, full detail, the hourly file job's build) at its documented bounds
        (200 recommendations, explanations of at most 4000 characters), with an event loop lag sampler.

Why it exists
    The production box has 909 MB of RAM and no swap, and systemd caps each color (a master and 2 workers) at
    `MemoryHigh=320M`, `MemoryMax=420M` (DESIGN.md section 0). Plan P9 bounds every table and file; the export cap
    is 50,000 rows (`common.MAX_EXPORT_ROWS`), but nothing bounds a row's width (audit previews are up to 2,000
    characters each side plus a 1,000 character reason) or the number of downloads a worker builds at once (the LLM
    export has `MAX_CONCURRENT_BUILDS`, table exports have nothing). The agent brief and the lens: never block the
    event loop; CPU-heavy work goes to a thread (`UntrustedPool` itself says thousands of entries must never hold
    the event loop). H-LOOP-LAG passes below 50 ms.

How it works
    The audit log gets 50,000 rule-change rows of about 0.9 KB each (a pattern, a note before and after, a reason),
    well inside the column bounds. The recommendations get 4,000-character explanations, next to a busy week of
    settings and rule edits and recurring errors. The thresholds: one download must stay under 96 MiB of Python
    allocations (a third of the color's `MemoryHigh` would already be more than a worker's share), and no single
    event loop stall may reach 50 ms (the H-LOOP-LAG pass band; every other section of the export stays far below
    it, measured with a stack sampler: only the recommendation texts, scrubbed in one synchronous pass, exceed it).

What to read next
    `roxy/admin/api/common.py` (`collect_pages`, `render_export`, `export_table`), `roxy/admin/api/audit.py`,
    `roxy/insights/llm_export.py` (`_Build.recommendations`, `UntrustedPool.refs`, `finalize`).
"""

from __future__ import annotations

import asyncio
import gc
import json
import time
import tracemalloc
from typing import Any

import pytest

from roxy.admin.api.common import export_ip_policy
from roxy.config.insight_params import INSIGHT_RULES
from roxy.core.ids import new_id
from roxy.insights import llm_export, simulate
from roxy.insights.engine import write_recommendation
from roxy.insights.models import Evidence, ProposedChange, Recommendation, make_fingerprint

MIB = 1024 * 1024
EXPORT_BUDGET_BYTES = 96 * MIB
LOOP_STALL_LIMIT_S = 0.05  # H-LOOP-LAG's pass band; plan 6.7 wants proxy overhead p99 under 15 ms
WORDS = [
    "the",
    "cache",
    "keeps",
    "answering",
    "while",
    "roblox",
    "limits",
    "this",
    "endpoint",
    "so",
    "callers",
    "wait",
    "longer",
    "than",
    "they",
    "should",
]


def _text(n: int, salt: int) -> str:
    out: list[str] = []
    i = salt
    while sum(len(w) + 1 for w in out) < n:
        out.append(WORDS[i % len(WORDS)] + str(i % 7))
        i += 3
    return " ".join(out)[:n]


async def _drive(app: Any, headers: dict[str, str], path: str, query: bytes) -> tuple[int, int]:
    """One request straight through the ASGI app; the body is counted and dropped (no client copy)."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query,
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 443),
    }
    state: dict[str, Any] = {"status": 0, "bytes": 0, "sent": False}

    async def receive() -> dict[str, Any]:
        if not state["sent"]:
            state["sent"] = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            state["status"] = int(message["status"])
        else:
            state["bytes"] += len(message.get("body", b""))

    await app(scope, receive, send)
    return int(state["status"]), int(state["bytes"])


@pytest.mark.timeout(240)
@pytest.mark.xfail(
    strict=True,
    reason="finding mpjobs-5: a table download holds every row, the whole CSV and its bytes in memory at once "
    "(about 260 MB for one 50,000-row audit export), with no byte bound and no per-worker limit on concurrent builds",
)
async def test_r3_mpjobs_one_table_download_fits_a_workers_memory_share(api: Any, api_app: Any) -> None:
    now = int(api_app.clock.now())

    def rows(conn: Any) -> None:
        conn.executemany(
            "INSERT INTO audit_log (at, actor, actor_ip, action, target, before_json, after_json, reason, request_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    now - i,
                    "admin:owner",
                    "203.0.113.9",
                    "rule.update",
                    f"rules_cache:{i}",
                    json.dumps({"pattern": f"games.roblox.com/v1/x{i}/*", "note": _text(300, i)}),
                    json.dumps({"pattern": f"games.roblox.com/v1/x{i}/*", "note": _text(300, i + 1)}),
                    _text(200, i + 2),
                    None,
                )
                for i in range(50_000)
            ],
        )

    await api_app.ctx.dbs.control.write(rows)
    headers = dict(api.headers())
    token = api.http.cookies.get("__Host-roxy_session")
    headers.update({"Host": "testserver", "Cookie": f"__Host-roxy_session={token}"})
    gc.collect()
    tracemalloc.start()
    try:
        status, size = await _drive(api_app.app, headers, "/admin/api/v1/audit", b"format=csv")
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert status == 200
    assert size > 30 * MIB  # the file itself (about 46 MB at this row width)
    # Two or three of these at once (a double click, two tabs, two tables) take a worker past its color's MemoryMax.
    assert peak < EXPORT_BUDGET_BYTES, f"one download peaked at {peak / MIB:.0f} MiB of Python allocations"


@pytest.mark.timeout(240)
@pytest.mark.xfail(
    strict=True,
    reason="finding mpjobs-6: the LLM export scrubs every recommendation text on the event loop in one pass, "
    "a 0.1 to 0.3 s stall at its bounds (the hourly leader job and every API export)",
)
async def test_r3_mpjobs_llm_export_never_stalls_the_event_loop(api_app: Any) -> None:
    now = int(api_app.clock.now())
    spec = INSIGHT_RULES["UP-429-ENDPOINT"]
    for i in range(200):  # llm_export.LIMITS["full"].recommendations
        rec = Recommendation(
            rule_id="UP-429-ENDPOINT",
            family=spec.family,
            subject=f"games.roblox.com/v1/e{i}",
            title=f"UP-429-ENDPOINT on games.roblox.com/v1/e{i}",
            severity="warn",
            confidence="high",
            explanation=_text(4000, i),  # "a recommendation's explanation, at most 4000 characters"
            evidence=Evidence(window_from=now - 3600, window_to=now, sample_size=50).add("roblox_429", 50, "responses"),
            changes=[ProposedChange("manual", text=_text(1000, i))],
            expected_impact=_text(500, i),
            risk="low",
        )
        rec.id = new_id("rec", api_app.clock)
        rec.fingerprint = make_fingerprint("UP-429-ENDPOINT", rec.subject)
        rec.state = "open"
        rec.created_at = rec.updated_at = now
        rec.expires_at = now + 86_400
        rec.dry_run_available = simulate.can_simulate(rec)
        await api_app.ctx.dbs.metrics.write(lambda conn, r=rec: write_recommendation(conn, r))

    def changes(conn: Any) -> None:  # a busy week of settings and rule edits (the export keeps the newest 500)
        conn.executemany(
            "INSERT INTO settings_history (key, old_json, new_json, changed_at, changed_by, reason, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                ("cache_ttl_seconds", json.dumps(100 + i), json.dumps(101 + i), now - 3600 - i, "admin:owner",
                 _text(480, i), "admin")
                for i in range(5000)
            ],
        )  # fmt: skip
        conn.executemany(
            "INSERT INTO audit_log (at, actor, actor_ip, action, target, before_json, after_json, reason, request_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (now - 3600 - i, "admin:owner", None, "rule.update", f"rules_cache:{i}",
                 json.dumps({"pattern": f"games.roblox.com/v1/x{i}/*", "note": _text(400, i)}),
                 json.dumps({"pattern": f"games.roblox.com/v1/x{i}/*", "note": _text(400, i + 1)}),
                 _text(480, i + 2), None)
                for i in range(5000)
            ],
        )  # fmt: skip

    def errors(conn: Any) -> None:  # recurring errors with their redacted tracebacks
        frames = "\n".join(f'  File "/opt/roxy/src/roxy/m{j}.py", line {j}, in f{j}\n    call()' for j in range(60))
        conn.executemany(
            "INSERT INTO errors (signature, count, first_seen, last_seen, source, last_detail, module_line, "
            "traceback_redacted) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (f"sig{i}", 5, now - 7200, now - 60, "worker", _text(2000, i), f"roxy/x.py:{i}", frames)
                for i in range(300)
            ],
        )

    await api_app.ctx.dbs.control.write(changes)
    await api_app.ctx.dbs.metrics.write(errors)
    sources = llm_export.ExportSources.from_context(api_app.ctx)
    hasher, mode = export_ip_policy(api_app.ctx, "r3-mpjobs")
    worst = 0.0
    done = False

    async def sampler() -> None:
        nonlocal worst
        last = time.perf_counter()
        while not done:
            await asyncio.sleep(0.005)
            now_s = time.perf_counter()
            worst = max(worst, now_s - last - 0.005)
            last = now_s

    task = asyncio.create_task(sampler())
    try:
        result = await llm_export.build_export(
            sources, window="7d", detail="full", ip_hasher=hasher, ip_mode=mode, generated_by="test"
        )
    finally:
        done = True
        await task
    assert result.content
    # Every proxied request this worker holds waits out the stall (plan 6.7: proxy overhead p99 under 15 ms).
    assert worst < LOOP_STALL_LIMIT_S, f"the event loop stalled for {worst * 1000:.0f} ms during one export build"
