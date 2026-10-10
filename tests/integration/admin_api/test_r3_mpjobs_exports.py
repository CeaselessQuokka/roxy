"""Review round 3, lens mpjobs: big exports against the 1 GB box (memory) and the event loop.

What this is
    Two adversarial tests (strict xfails until their findings were fixed) against the running app:
      * a table download (`GET /admin/api/v1/audit?format=csv`) of the audit log at the export row cap, measured
        with `tracemalloc` on the server side only (the ASGI app is driven directly and the body bytes are counted
        and dropped, so no client copy is measured). Finding mpjobs-5, fixed: it held every row, the whole CSV and
        its bytes (about 270 MiB); now `common.export_pages` reads one page at a time into a file of at most
        `common.MAX_EXPORT_BYTES` (16 MiB, then `Roxy-Export-Truncated: true`), and a worker builds at most
        `common.MAX_CONCURRENT_EXPORTS` (2) at once;
      * the LLM export (`build_export`, 7 days, full detail, the hourly file job's build) at its documented bounds
        (200 recommendations, explanations of at most 4000 characters), with an event loop sampler. Finding
        mpjobs-6, fixed: it scrubbed every recommendation text on the event loop in one pass (0.1 to 0.3 s); now
        `UntrustedPool.refs` defers the cleaning and splitting to `materialize` on a worker thread and the
        recommendations are shaped in batches with a yield between them.

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
    allocations (a third of the color's `MemoryHigh` would already be more than a worker's share). The export may
    redact or hash no text on the event loop thread at all, and the loop thread's CPU between two ticks of the
    sampler stays under `LOOP_CPU_LIMIT_S` (twice the H-LOOP-LAG pass band of 50 ms; CPU time, so a busy machine
    cannot make it pass or fail by preempting the process, as a wall clock stall threshold did).

What to read next
    `roxy/admin/api/common.py` (`export_pages`, `ExportBuilder`, `export_format`), `roxy/admin/api/audit.py`,
    `roxy/insights/llm_export.py` (`_Build.recommendations`, `UntrustedPool.refs`, `finalize`).
"""

from __future__ import annotations

import asyncio
import gc
import json
import threading
import time
import tracemalloc
from typing import Any

import pytest

from roxy.admin.api import common
from roxy.admin.api.common import export_ip_policy
from roxy.config.insight_params import INSIGHT_RULES
from roxy.core.ids import new_id
from roxy.core.redact import redact_text
from roxy.insights import llm_export, simulate
from roxy.insights.engine import write_recommendation
from roxy.insights.models import Evidence, ProposedChange, Recommendation, make_fingerprint

MIB = 1024 * 1024
EXPORT_BUDGET_BYTES = 96 * MIB
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


async def _drive(app: Any, headers: dict[str, str], path: str, query: bytes) -> tuple[int, int, dict[str, str]]:
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
    state: dict[str, Any] = {"status": 0, "bytes": 0, "sent": False, "headers": {}}

    async def receive() -> dict[str, Any]:
        if not state["sent"]:
            state["sent"] = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            state["status"] = int(message["status"])
            state["headers"] = {bytes(k).decode().lower(): bytes(v).decode() for k, v in message.get("headers", [])}
        else:
            state["bytes"] += len(message.get("body", b""))

    await app(scope, receive, send)
    return int(state["status"]), int(state["bytes"]), dict(state["headers"])


@pytest.mark.timeout(240)
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
        status, size, sent = await _drive(api_app.app, headers, "/admin/api/v1/audit", b"format=csv")
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert status == 200
    # The whole log would be about 46 MB of CSV: the file is filled up to the byte cap and says it was cut
    # (mpjobs-5 fix: `common.MAX_EXPORT_BYTES`, pages read one at a time by `common.export_pages`).
    assert common.MAX_EXPORT_BYTES - MIB < size <= common.MAX_EXPORT_BYTES, size
    assert sent["content-length"] == str(size)
    assert sent["roxy-export-truncated"] == "true"
    assert 0 < int(sent["roxy-export-rows"]) < 50_000
    # At most `MAX_CONCURRENT_EXPORTS` (2) of these run in a worker at once (apisec-6), so two stay inside a
    # worker's share of the color's MemoryHigh.
    assert peak < EXPORT_BUDGET_BYTES, f"one download peaked at {peak / MIB:.0f} MiB of Python allocations"
    assert peak < common.MAX_EXPORT_BYTES + 8 * MIB, f"{peak / MIB:.0f} MiB: more than the file and a page"


LOOP_CPU_LIMIT_S = 0.1
"""Most CPU the event loop thread may spend in one stretch between two ticks of the sampler during an export build:
twice the H-LOOP-LAG pass band (50 ms). It is CPU time of the loop thread (`time.thread_time`), not wall time, so a
busy machine that preempts the process does not inflate it; the fixed build stays near a tenth of it."""


@pytest.mark.timeout(240)
async def test_r3_mpjobs_llm_export_never_stalls_the_event_loop(api_app: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Finding mpjobs-6 (fixed): the export's text scrubbing runs off the event loop, and the loop is never held long.

    Two properties, neither a wall clock threshold (a stall measured in wall time also counts every moment a busy
    machine preempts the process, which is how this test once passed by luck and could fail by bad luck):
    - structural: every call of the export's redaction and IP hashing (`llm_export.redact_text`, `mask_ips`)
      happens on a worker thread, never on the event loop thread (`UntrustedPool.refs` defers, `finalize` cleans);
    - bounded: the CPU the loop thread spends between two ticks of a 5 ms sampler stays under `LOOP_CPU_LIMIT_S`.
    The test app's heap is frozen for the garbage collector (`gc.freeze`) during the build: a full collection of
    the whole test process takes about 100 ms on whichever thread triggers it, and that is the process's heap, not
    the export's work (a collection during the build then scans only the objects the build made).
    """
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
        # Applied, not open: the test app's leader evaluates UP-429-ENDPOINT at start and resolves its open cards
        # that the data does not support, racing this seed; the export shapes an applied card the same way.
        rec.state = "applied"
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
    loop_thread = threading.get_ident()
    calls = {"loop": 0, "worker": 0}

    def watched(function: Any) -> Any:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            calls["loop" if threading.get_ident() == loop_thread else "worker"] += 1
            return function(*args, **kwargs)

        return wrapper

    monkeypatch.setattr(llm_export, "redact_text", watched(redact_text))  # the name `llm_export` calls
    monkeypatch.setattr(llm_export, "mask_ips", watched(llm_export.mask_ips))
    worst_cpu = worst_wall = 0.0
    done = False

    async def sampler() -> None:
        nonlocal worst_cpu, worst_wall
        last_cpu, last_wall = time.thread_time(), time.perf_counter()
        while not done:
            await asyncio.sleep(0.005)
            cpu, wall = time.thread_time(), time.perf_counter()
            # The loop thread's CPU between two ticks is what the other callbacks (the build) ran in one piece.
            worst_cpu = max(worst_cpu, cpu - last_cpu)
            worst_wall = max(worst_wall, wall - last_wall - 0.005)
            last_cpu, last_wall = cpu, wall

    gc.collect()
    gc.freeze()
    task = asyncio.create_task(sampler())
    try:
        result = await llm_export.build_export(
            sources, window="7d", detail="full", ip_hasher=hasher, ip_mode=mode, generated_by="test"
        )
    finally:
        done = True
        await task
        gc.unfreeze()
    assert result.content
    assert len(result.document["recommendations"]) == 200
    assert all(len(rec["explanation"]) == 20 for rec in result.document["recommendations"])  # 4000 / 200
    assert calls["worker"] > 0, calls  # the texts were cleaned (on a worker thread)
    assert calls["loop"] == 0, f"the export redacted or hashed {calls['loop']} texts on the event loop thread"
    # Every proxied request this worker holds waits while the loop is busy (plan 6.7: proxy overhead p99 under 15 ms).
    assert worst_cpu < LOOP_CPU_LIMIT_S, (
        f"the event loop thread ran {worst_cpu * 1000:.0f} ms of CPU in one piece during one export build "
        f"(worst wall clock stall {worst_wall * 1000:.0f} ms)"
    )
