"""Every Check Proxy Health fixture (`tests/fixtures/health`, roxy.health_fixture/1) must pass (plan 13.2, 19.10).

What this is
    One parametrized test per fixture file and per variant (ids `<file stem>` and `<file stem>[<case>-<name>]`),
    plus checks on the fixture set itself: every 13.2 check has its pass, warn and fail scenarios, and the loader
    refuses unknown keys, unknown faults and unknown checks.

Why it exists
    The fixtures were written independently from the 13.2 table before the checks existed; this test is how the
    checks prove they implement the table (acceptance criteria 19.10).

How it works
    `harness.run_case` builds the state, runs the check through `HealthRunner.run_checks` and reads the stored
    row; `harness.compare` lists every difference from `expect`. On failure the stored row and the calls are
    printed next to the differences.

What to read next
    `tests/health/harness.py`, `tests/fixtures/health/README.md`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from health.harness import FixtureError, compare, describe, load_cases, run_case
from roxy.health import checks

CASES = load_cases()


@pytest.mark.parametrize("case", CASES, ids=[case.test_id for case in CASES])
async def test_health_fixture(case: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    outcome = await run_case(case, tmp_path, monkeypatch)
    problems = compare(case, outcome)
    assert not problems, "\n".join(problems) + "\n" + describe(outcome)


# 13.2 lists no warn state for these checks (README: "only n/a where 13.2 lists none").
NO_WARN = {"H-CRED-PRESENT", "H-CRED-GUARD", "H-DB-INTEGRITY"}
NO_FAIL = {"H-CACHE-HIT"}  # "lower (only warn)"


def test_every_check_has_its_scenarios() -> None:
    seen: dict[str, set[str]] = {}
    for case in CASES:
        seen.setdefault(case.check, set()).add(case.case)
    for spec in checks.SPECS:
        cases = seen.get(spec.id, set())
        assert "pass" in cases, f"{spec.id} has no pass fixture"
        if spec.id not in NO_WARN:
            assert "warn" in cases, f"{spec.id} has no warn fixture"
        if spec.id not in NO_FAIL:
            assert "fail" in cases, f"{spec.id} has no fail fixture"


def test_fixture_count_and_ids_are_unique() -> None:
    ids = [case.test_id for case in CASES]
    assert len(ids) == len(set(ids))
    files = {case.path for case in CASES}
    assert len(files) == len(list(Path(__file__).resolve().parents[1].joinpath("fixtures", "health").glob("*.yaml")))


BAD_BASE = """
format: roxy.health_fixture/1
check: H-DISK
case: pass
name: example
description: x
now: "2026-10-07T15:00:00Z"
inputs: {}
expect: {status: pass}
"""


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ("typo_key: 1\n", "unknown keys"),
        ("", None),
    ],
)
def test_loader_rejects_unknown_top_level_keys(tmp_path: Path, extra: str, message: str | None) -> None:
    (tmp_path / "h_disk__pass__example.yaml").write_text(BAD_BASE + extra, encoding="utf-8")
    if message is None:
        assert len(load_cases(tmp_path)) == 1
        return
    with pytest.raises(FixtureError, match=message):
        load_cases(tmp_path)


def test_loader_rejects_unknown_faults_inputs_and_checks(tmp_path: Path) -> None:
    path = tmp_path / "h_disk__pass__example.yaml"
    path.write_text(BAD_BASE.replace("inputs: {}", "inputs: {faults: {disk_on_fire: true}}"), encoding="utf-8")
    with pytest.raises(FixtureError, match="faults"):
        load_cases(tmp_path)
    path.write_text(BAD_BASE.replace("inputs: {}", "inputs: {weather: sunny}"), encoding="utf-8")
    with pytest.raises(FixtureError, match="inputs"):
        load_cases(tmp_path)
    path.write_text(BAD_BASE.replace("check: H-DISK", "check: H-NOPE"), encoding="utf-8")
    with pytest.raises(FixtureError, match="unknown check"):
        load_cases(tmp_path)
