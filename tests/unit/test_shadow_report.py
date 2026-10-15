"""scripts/shadow_report.py: the plan 18.4 shadow comparison report (decision D1).

What this is
    Tests of the report with no records (it must say plainly that no shadow week ran and why), with a saved v1
    hotfix report (per-template counters, the coordination file shape too), with Roxy v2 `credential_comparison`
    events in a migrated metrics.db, and with both at once; the plan 18.4 classes per template, the cutover gate at
    and around its 50% boundary, `--strict`, Markdown escaping, bounds and unreadable inputs.

Why it exists
    The owner decided D1 = never before any measurement, so the report's most likely output is the "no shadow week"
    text, and it must be accurate. If a comparison is ever run, the per-template table and the gate decide what the
    owner reviews, so the arithmetic has to be right.

How it works
    The script is loaded by path and `main(argv, out=...)` writes to a StringIO. v2 events are inserted with plain
    sqlite3 into a database migrated by the shared `dbs` fixture.

What to read next
    scripts/shadow_report.py, REMAKE_PLAN.md section 18.4.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sqlite3
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def shadow() -> ModuleType:
    spec = importlib.util.spec_from_file_location("roxy_shadow_report_script", REPO / "scripts" / "shadow_report.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["roxy_shadow_report_script"] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


def run(shadow: ModuleType, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return shadow.main(list(argv), out=out), out.getvalue()


def hotfix_document(templates: dict[str, dict[str, int]]) -> dict[str, Any]:
    """What the hotfix's GET /admin/shadow answers (only the parts the report reads, plus some it ignores)."""
    return {
        "Since": 1_790_000_000,
        "Templates": {
            name: {**counters, "LastSeen": 1.0, "LastAnonStatus": 200} for name, counters in templates.items()
        },
        "Totals": {},
        "MaxTemplates": 200,
        "Settings": {"Enabled": True, "SamplePct": 1, "BudgetPerMin": 5},
    }


def test_no_records_says_no_shadow_week_ran_and_why(shadow: ModuleType) -> None:
    status, text = run(shadow)
    assert status == 0
    assert "No shadow week ran." in text
    assert "D1 = never" in text
    assert "per 1,000 upstream calls" in text, "it says what the report would contain"
    assert chr(0x2014) not in text, "no em dash"
    assert chr(0x2013) not in text, "no en dash"
    status, text = run(shadow, "--json")
    document = json.loads(text)
    assert document["ran"] is False
    assert document["gate"]["verdict"] == "no data"
    assert document["templates"] == []
    assert document["schema"] == "roxy.shadow_report/1"


def test_hotfix_report_classes_and_decisions(shadow: ModuleType, tmp_path: Path) -> None:
    report = hotfix_document(
        {
            "games.roblox.com/v1/games": {"Sampled": 40, "AnonOk": 40, "Replayed": 40, "Identical": 40},
            "users.roblox.com/v1/users/{userId}": {
                "Sampled": 30,
                "AnonOk": 30,
                "Replayed": 30,
                "Identical": 28,
                "Differs": 2,
            },
            "inventory.roblox.com/v2/assets/{assetId}/owners": {"Sampled": 10, "AnonFailed": 10},
            "thumbnails.roblox.com/v1/assets": {
                "Sampled": 20,
                "AnonOk": 18,
                "Anon429": 2,
                "Replayed": 18,
                "Identical": 18,
            },
            "badges.roblox.com/v1/badges/{badgeId}": {"Sampled": 2, "AnonOk": 2, "Replayed": 2, "Identical": 2},
        }
    )
    path = tmp_path / "shadow.json"
    path.write_text(json.dumps(report))
    status, text = run(shadow, "--json", "--hotfix-report", str(path))
    assert status == 0
    document = json.loads(text)
    classes = {row["template"]: row["class"] for row in document["templates"]}
    assert classes == {
        "games.roblox.com/v1/games": "identical",
        "users.roblox.com/v1/users/{userId}": "differs",
        "inventory.roblox.com/v2/assets/{assetId}/owners": "anonymous fails",
        "thumbnails.roblox.com/v1/assets": "anonymous rate-limited",
        "badges.roblox.com/v1/badges/{badgeId}": "not enough data",
    }
    decisions = {row["template"]: row["decision"] for row in document["templates"]}
    assert "allowlist decision" in decisions["users.roblox.com/v1/users/{userId}"]
    assert "cache_private" in decisions["inventory.roblox.com/v2/assets/{assetId}/owners"]
    assert document["ran"] is True
    assert document["sources"][0].startswith("v1 hotfix shadow report")
    status, markdown = run(shadow, "--hotfix-report", str(path))
    assert "| `inventory.roblox.com/v2/assets/{assetId}/owners` | 10 |" in markdown
    assert "## Cutover gate" in markdown


@pytest.mark.parametrize(
    ("anon_429", "verdict"),
    [(0, "pass"), (3, "pass"), (4, "review")],
    ids=["none", "exactly_50_percent_more", "above_50_percent_more"],
)
def test_cutover_gate(shadow: ModuleType, tmp_path: Path, anon_429: int, verdict: str) -> None:
    """Credential: 2 429s per 1,000 replays. The anonymous rate may be up to 3 per 1,000 (50% more)."""
    report = hotfix_document(
        {
            "games.roblox.com/v1/games": {
                "Sampled": 1000,
                "AnonOk": 1000 - anon_429,
                "Anon429": anon_429,
                "Replayed": 1000,
                "Identical": 998,
                "Cred429": 2,
            }
        }
    )
    path = tmp_path / "shadow.json"
    path.write_text(json.dumps(report))
    status, text = run(shadow, "--json", "--strict", "--hotfix-report", str(path))
    gate = json.loads(text)["gate"]
    assert gate["verdict"] == verdict
    assert gate["cred_per_1000"] == pytest.approx(2.0)
    assert gate["anon_per_1000"] == pytest.approx(float(anon_429))
    assert status == (1 if verdict == "review" else 0)
    status, _ = run(shadow, "--json", "--hotfix-report", str(path))
    assert status == 0, "without --strict the gate is for the owner to read"


def test_gate_without_credential_replays_cannot_be_judged(shadow: ModuleType, tmp_path: Path) -> None:
    path = tmp_path / "shadow.json"
    path.write_text(json.dumps(hotfix_document({"a.roblox.com/x": {"Sampled": 5, "Anon429": 5}})))
    status, text = run(shadow, "--json", "--strict", "--hotfix-report", str(path))
    assert status == 0
    assert json.loads(text)["gate"]["verdict"] == "no data"


def test_the_coordination_file_shape_works_too(shadow: ModuleType, tmp_path: Path) -> None:
    path = tmp_path / "coord.json"
    path.write_text(json.dumps({"Workers": {}, "Shadow": hotfix_document({"a.roblox.com/x": {"Sampled": 1}})}))
    status, text = run(shadow, "--json", "--hotfix-report", str(path))
    assert status == 0
    assert json.loads(text)["templates"][0]["template"] == "a.roblox.com/x"


@pytest.mark.parametrize("content", ["not json", json.dumps({"Workers": {}}), json.dumps([1, 2])])
def test_unreadable_inputs_are_exit_1(shadow: ModuleType, tmp_path: Path, content: str) -> None:
    path = tmp_path / "bad.json"
    path.write_text(content)
    status, text = run(shadow, "--hotfix-report", str(path))
    assert status == 1
    assert text.startswith("shadow_report: ")
    status, text = run(shadow, "--hotfix-report", str(tmp_path / "missing.json"))
    assert status == 1


def insert_event(conn: sqlite3.Connection, at_ms: int, detail: dict[str, Any]) -> None:
    conn.execute(
        "INSERT INTO events (at_ms, type, severity, endpoint_template, detail_json) VALUES (?, ?, 'info', ?, ?)",
        (at_ms, "credential_comparison", detail.get("endpoint_template"), json.dumps(detail)),
    )


def test_v2_comparison_events(shadow: ModuleType, dbs: Any, state_dir: Path) -> None:
    now_ms = int(time.time() * 1000)
    conn = sqlite3.connect(state_dir / "metrics.db")
    template = "economy.roblox.com/v1/assets/{assetId}/resale-data"
    for _ in range(6):
        insert_event(
            conn,
            now_ms - 1000,
            {"endpoint_template": template, "anon_status": 200, "cred_status": 200, "identical": True},
        )
    insert_event(
        conn,
        now_ms - 1000,
        {"endpoint_template": template, "anon_status": 200, "cred_status": 200, "identical": False, "count": 3},
    )
    insert_event(conn, now_ms - 1000, {"endpoint_template": template, "anon_status": 429, "cred_status": None})
    insert_event(conn, now_ms - 1000, {"endpoint_template": template, "anon_status": 200, "cred_status": 429})
    old = now_ms - 30 * 86_400_000
    insert_event(conn, old, {"endpoint_template": template, "anon_status": 403, "cred_status": None})
    conn.commit()
    conn.close()
    status, text = run(shadow, "--json", "--state-dir", str(state_dir))
    assert status == 0, text
    document = json.loads(text)
    (row,) = document["templates"]
    assert row["sampled"] == 11, "6 identical, 3 differing (one aggregated event), one 429, one cred 429"
    assert row["identical"] == 6
    assert row["differs"] == 3
    assert row["anon_429"] == 1
    assert row["cred_429"] == 1
    assert row["anon_failed"] == 0, "the 30 day old event is outside the 7 day window"
    assert row["class"] == "differs"
    assert "metrics.db" in document["sources"][0]


def test_both_producers_add_up(shadow: ModuleType, dbs: Any, state_dir: Path, tmp_path: Path) -> None:
    conn = sqlite3.connect(state_dir / "metrics.db")
    insert_event(
        conn,
        int(time.time() * 1000),
        {"endpoint_template": "a.roblox.com/x", "anon_status": 200, "cred_status": 200, "identical": True},
    )
    conn.commit()
    conn.close()
    path = tmp_path / "shadow.json"
    path.write_text(
        json.dumps(hotfix_document({"a.roblox.com/x": {"Sampled": 4, "AnonOk": 4, "Replayed": 4, "Identical": 4}}))
    )
    status, text = run(shadow, "--json", "--hotfix-report", str(path), "--state-dir", str(state_dir))
    assert status == 0
    (row,) = json.loads(text)["templates"]
    assert (row["sampled"], row["identical"], row["class"]) == (5, 5, "identical")


def test_markdown_cells_are_escaped_and_templates_bounded(
    shadow: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shadow, "MAX_TEMPLATES", 2)
    path = tmp_path / "shadow.json"
    templates = {f"a.roblox.com/{i}|x": {"Sampled": 10 - i} for i in range(3)}
    path.write_text(json.dumps(hotfix_document(templates)))
    status, text = run(shadow, "--hotfix-report", str(path))
    assert status == 0
    assert "a.roblox.com/0\\|x" in text
    assert "a.roblox.com/2" not in text
    assert "more than 2 templates" in text.lower()


def test_missing_state_dir_is_exit_1(shadow: ModuleType, tmp_path: Path) -> None:
    status, text = run(shadow, "--state-dir", str(tmp_path))
    assert status == 1
    assert "metrics.db" in text
