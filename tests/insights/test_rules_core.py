"""The core rules against their committed fixtures (plan 19.10 row 11), the 11.6 card, and the no-literal scan.

What this is
    Every case of every `up_429_endpoint__*`, `cache_ttl_tune__*` and `sys_errors__*` fixture (the file's own case
    and each variant) run through the harness, which evaluates the rule through the engine's per-rule entry point.
    Plus the explicit plan 11.6 "before and after" card, unit tests of the rules' helpers, and the plan 11.1 AST
    test: no rule module compares against a numeric literal threshold.

Why it exists
    The fixtures were written from the 11.5 table before the rules existed; passing them, unchanged, is the
    acceptance criterion. The AST scan keeps every future rule honest about its thresholds.

What to read next
    `tests/insights/harness.py`, `roxy/insights/rules/core.py`.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from insights.harness import fixture_ids, loaded, run_case
from roxy.insights import rules as rules_package
from roxy.insights.rules import load_rules
from roxy.insights.rules.core import highest_sustained_rate, traceback_excerpt

CORE_PREFIXES = ("up_429_endpoint__", "cache_ttl_tune__", "sys_errors__")
CASES = fixture_ids(CORE_PREFIXES)
RULES_DIR = Path(rules_package.__file__).resolve().parent
ALLOWED_LITERALS = (0, 1)
"""Comparisons against 0 and 1 are identity and emptiness checks, not thresholds."""


@pytest.mark.parametrize(
    ("stem", "case"), CASES, ids=[stem if case is None else f"{stem}[{case}]" for stem, case in CASES]
)
async def test_core_rule_fixture(stem: str, case: str | None) -> None:
    await run_case(stem, case)


def test_every_core_rule_has_fixtures_for_fires_quiet_switch_and_thresholds() -> None:
    by_rule: dict[str, list[str]] = {}
    for stem, case in CASES:
        by_rule.setdefault(stem.split("__", 1)[0], []).append(case or stem.split("__", 1)[1])
    assert set(by_rule) == {"up_429_endpoint", "cache_ttl_tune", "sys_errors"}
    for cases in by_rule.values():
        assert "disabled" in cases  # the per-rule switch (19.10)
        assert len(cases) >= 5


async def test_before_after_11_6_card() -> None:
    """Plan 11.6: the v1 banner's situation produces the v2 card, number for number."""
    recs = await run_case("up_429_endpoint__before_after_11_6")
    card = next(r for r in recs if r.subject == "users.roblox.com/v1/users")
    assert card.severity == "critical"
    assert card.confidence == "high"
    assert card.family == "upstream"
    assert "users.roblox.com/v1/users" in card.title
    assert "(POST)" in card.title
    assert "direct" in card.title
    assert card.evidence.metric("roblox_429") == 412
    assert card.evidence.metric("share_of_all_roblox_429") == pytest.approx(0.71, abs=0.005)
    assert card.evidence.metric("cache_hit_ratio") == 0
    assert card.evidence.metric("upstream_calls") == 2940
    assert card.evidence.metric("median_body_unchanged_on_refetch") == pytest.approx(0.96, abs=0.005)
    assert card.evidence.metric("retried_share_of_429") == pytest.approx(0.23, abs=0.005)
    assert card.evidence.metric("bucket_fill_peak_pct") == 100
    assert card.evidence.metric("retry_after_avg_s") == 30
    changes = {c.kind if c.kind != "setting" else f"setting:{c.key}": c for c in card.changes}
    rule = changes["rule_upsert"]
    assert rule.current is None
    assert rule.proposed["ttl"] == 600
    assert rule.proposed["stale_ttl"] == 120
    assert rule.proposed["methods"] == "GET,POST"
    assert (changes["setting:fallback_on_429"].current, changes["setting:fallback_on_429"].proposed) == (1, 0)
    assert changes["setting:cache_post_requests"].proposed == "allowlist"
    assert changes["bucket_override"].current == {"per_min": 120.0, "burst": 10}
    assert changes["bucket_override"].proposed == {"per_min": 89, "burst": 10}  # 80% of 112, the 429-free rate
    assert card.safe_auto is False  # a global setting is part of it (11.2)
    assert "2,485 fewer upstream calls per hour" in card.expected_impact
    state = await loaded("up_429_endpoint__before_after_11_6")
    report = await state.engine.dry_run(card)
    assert report.available
    assert report.avoided_calls == 2485
    assert report.sample_size == 2845
    payload = card.to_payload()
    keys_11_2 = {"id", "rule_id", "family", "severity", "confidence", "title", "explanation", "evidence", "changes"}
    keys_11_2 |= {"expected_impact", "risk", "safe_auto", "dry_run", "created_at", "updated_at", "expires_at", "state"}
    assert keys_11_2 <= set(payload)  # the 11.2 object
    assert payload["evidence"]["window"] == {"from": "2026-10-07T14:00:00Z", "to": "2026-10-07T15:00:00Z"}


def test_highest_sustained_rate_needs_a_whole_429_free_run() -> None:
    start = 0
    calls = {m * 60: 100 for m in range(10)}
    assert highest_sustained_rate(calls, set(), start, 600) == 100
    calls[240] = 40  # one slow minute caps every run that contains it
    assert highest_sustained_rate(calls, set(), start, 600) == 100  # minutes 5 to 9 are a clean run at 100
    assert highest_sustained_rate(calls, {300}, start, 600) == 40  # a 429 at minute 5 leaves runs through minute 4
    assert highest_sustained_rate(calls, {120, 300}, start, 600) is None  # no 5 clean minutes in a row


def test_traceback_excerpt_keeps_the_last_five_frames() -> None:
    frames = "".join(f'File "roxy/m{i}.py", line {i}, in f{i}\n    call_{i}()\n' for i in range(8))
    excerpt = traceback_excerpt(frames + "KeyError: 'x'\n")
    assert excerpt.startswith('File "roxy/m3.py"')
    assert excerpt.count("File ") == 5
    assert excerpt.endswith("KeyError: 'x'")


def test_registry_loads_the_core_rules_with_help_and_settings() -> None:
    loaded_rules = load_rules()
    for rule_id in ("UP-429-ENDPOINT", "CACHE-TTL-TUNE", "SYS-ERRORS"):
        rule = loaded_rules[rule_id]
        assert rule.help_text
        assert not rule.help_text.startswith(" ")
        card = rule.describe()
        assert card["settings"]["enabled"] == f"insight_{rule.slug}_enabled"
        for name, key in card["settings"]["params"].items():
            assert rule.setting_key(name) == key
    with pytest.raises(KeyError):
        loaded_rules["SYS-ERRORS"].setting_key("not_a_param")


def _literal(node: ast.AST) -> float | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int | float) and not isinstance(node.value, bool):
        return float(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _literal(node.operand)
        return None if inner is None else -inner
    return None


def test_no_rule_module_compares_against_a_numeric_literal() -> None:
    """Plan 11.1: every threshold is a named parameter; a comparison with a number literal is a hidden one."""
    problems = []
    modules = [p for p in RULES_DIR.glob("*.py") if p.name not in ("__init__.py", "base.py")]
    assert any(p.name == "core.py" for p in modules)
    for path in modules:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            for operand in (node.left, *node.comparators):
                value = _literal(operand)
                if value is not None and value not in ALLOWED_LITERALS:
                    problems.append(f"{path.name}:{node.lineno}: comparison with literal {value:g}")
    assert problems == []


def test_the_literal_scan_catches_a_hidden_threshold() -> None:
    tree = ast.parse("def f(n):\n    return n > 20 or 0 < n or n == -3\n")
    found = [
        _literal(op)
        for node in ast.walk(tree)
        if isinstance(node, ast.Compare)
        for op in (node.left, *node.comparators)
        if _literal(op) is not None
    ]
    assert [v for v in found if v not in ALLOWED_LITERALS] == [20, -3]
