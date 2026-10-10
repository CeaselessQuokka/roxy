"""Review round 4, lens logicfix: the dry run's sampling scale when `request_sample_pct` changed inside the window.

What this is
    An adversarial test of the insights-9 fix (`simulate.dry_run`: counts multiplied by `DryRunReport.scale`, 100 /
    `request_sample_pct`). The scale is read from the LIVE setting at preview time and applied to every sample of
    the replay window (an hour by default), but each sample was taken at the rate in force when its request
    arrived. After an admin lowers the sampling rate (to save disk, the setting's own advice), every sample taken
    before the change was counted twice. This was a strict xfail for finding LOGICFIX-6; each sample now counts for
    100 / the rate it was taken at: its own `sample_pct` (metrics.db schema 7), else the rate in force at its time
    from the settings history. The first test's setup was corrected with the fix: the admin's change is recorded
    half an hour ago (as its comment always said), not at the moment of the dry run, which no running Roxy can
    produce for samples taken before it.

Why it exists
    Plan 19.10 row 11: "dry-run estimates within 10% of a replayed ground truth"; the fix's note promises "counts are
    scaled to all requests". The impact texts of the rules (`impact_from_dry_run`, UP-429-ENDPOINT) quote these
    numbers to the admin.

How it works
    The same shape as `test_r3_insights_simulate.py::test_r3_insights_sampled_dry_run_counts_are_scaled`: ten keys,
    each asked twenty times within the TTL over the hour (10 calls, 190 avoided). The first half hour is sampled at
    100%, then the admin sets `request_sample_pct` to 50 and every other request of the second half is sampled.

What to read next
    `roxy/insights/simulate.py` (`dry_run`, `_sample_scale`), `roxy/metrics/samples.py` (`should_sample`).
"""

from __future__ import annotations

from typing import Any

from roxy.config.audit import Actor
from roxy.config.runtime import load_runtime_settings
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.insights.engine import InsightsEngine
from roxy.insights.models import Recommendation
from roxy.insights.rules.cache import new_rule
from roxy.rules.store import RulesStore

ADMIN = Actor("admin", "r4-logicfix")
NOW = 1_791_385_200.0  # 2026-10-07T15:00:00Z
TEMPLATE = "games.roblox.com/v1/games/votes"


async def test_r4_logicfix_a_sampling_change_inside_the_window_keeps_the_estimate(dbs: Any) -> None:
    clock = FakeClock(NOW)
    runtime = await load_runtime_settings(dbs, clock)
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    engine = InsightsEngine(dbs=dbs, settings=runtime, rules=store, clock=clock, rule_set={})
    # The real traffic: 10 keys asked 20 times each, spread over the hour (one key every 6 minutes, a request every
    # 18 s), all inside the 600 s TTL of the proposed rule: 10 calls, 190 avoided.
    rows = []
    for key in range(10):
        for step in range(20):
            at_s = NOW - 3600 + key * 360 + step * 18
            second_half = at_s >= NOW - 1800
            if second_half and step % 2 == 1:
                continue  # sampled at 50% once the admin lowered the rate half an hour ago
            rows.append((int(at_s * 1000), f"k{key}", TEMPLATE, "GET", "200", "direct", f"{key:016x}"))

    def write(conn: Any) -> None:
        conn.executemany(
            "INSERT INTO request_samples (at_ms, key_id, endpoint_template, method, upstream_status, egress, "
            "body_hash, auth_class) VALUES (?, ?, ?, ?, ?, ?, ?, 'anon')",
            rows,
        )

    dbs.metrics.write_sync(write)
    # The admin lowered the rate half an hour ago: the settings history says when (rows written before metrics.db
    # schema 7 carry no rate of their own, so the dry run reads the rate in force at each row's time from it).
    await SettingsService(dbs.control, runtime=runtime, clock=FakeClock(NOW - 1800)).update(
        {"request_sample_pct": 50}, ADMIN, "half of the requests are sampled from now on (saves disk)"
    )
    await runtime.reload()
    assert float(runtime.get("request_sample_pct")) == 50
    rec = Recommendation(
        rule_id="CACHE-LOW-HIT",
        family="cache",
        subject=TEMPLATE,
        title="t",
        changes=[new_rule(TEMPLATE, {"ttl": 600, "stale_ttl": 0, "methods": "GET"})],
    )
    report = await engine.dry_run(rec)
    truth_requests, truth_avoided = 200, 200 - 10
    assert report.avoided_calls is not None
    assert report.baseline_requests is not None
    assert abs(report.baseline_requests - truth_requests) <= 0.10 * truth_requests, (
        f"{report.baseline_requests} requests estimated for a true {truth_requests} ({len(rows)} samples, scale "
        f"{report.scale}): {report.note}"
    )
    assert abs(report.avoided_calls - truth_avoided) <= 0.10 * truth_avoided, (
        f"{report.avoided_calls} avoided calls estimated for a true {truth_avoided}"
    )


async def test_r4_logicfix_each_sample_counts_for_the_rate_it_carries(dbs: Any) -> None:
    """Since metrics.db schema 7 every sample carries the rate it was taken at (`request_samples.sample_pct`), which
    wins over the settings history: here the history was pruned, the live rate is 50 and half the rows were taken
    at 100%."""
    clock = FakeClock(NOW)
    runtime = await load_runtime_settings(dbs, clock)
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    engine = InsightsEngine(dbs=dbs, settings=runtime, rules=store, clock=clock, rule_set={})
    rows = []
    for key in range(10):
        for step in range(20):
            at_s = NOW - 3600 + key * 360 + step * 18
            second_half = at_s >= NOW - 1800
            if second_half and step % 2 == 1:
                continue
            pct = 50.0 if second_half else 100.0
            rows.append((int(at_s * 1000), f"k{key}", TEMPLATE, "GET", "200", "direct", f"{key:016x}", pct))

    def write(conn: Any) -> None:
        conn.executemany(
            "INSERT INTO request_samples (at_ms, key_id, endpoint_template, method, upstream_status, egress, "
            "body_hash, auth_class, sample_pct) VALUES (?, ?, ?, ?, ?, ?, ?, 'anon', ?)",
            rows,
        )

    dbs.metrics.write_sync(write)
    await SettingsService(dbs.control, runtime=runtime, clock=clock).update({"request_sample_pct": 50}, ADMIN, "now")
    dbs.control.write_sync(lambda conn: conn.execute("DELETE FROM settings_history"))  # history pruned
    await runtime.reload()
    rec = Recommendation(
        rule_id="CACHE-LOW-HIT",
        family="cache",
        subject=TEMPLATE,
        title="t",
        changes=[new_rule(TEMPLATE, {"ttl": 600, "stale_ttl": 0, "methods": "GET"})],
    )
    report = await engine.dry_run(rec)
    assert report.baseline_requests == 200, report  # 100 rows at 100% and 50 at 50%: exactly the requests sent
    assert report.avoided_calls is not None
    assert abs(report.avoided_calls - 190) <= 0.10 * 190, report  # a sampled miss stands for 2 requests: 185
    assert "different rates" in report.note
