"""Visitor classification (rows 19, 130) and the metric catalog's honest definitions (P2, P6)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from roxy.metrics import catalog, queries, visitors

REPO = Path(__file__).resolve().parents[3]


def test_crawler_markers_equal_v1() -> None:
    tree = ast.parse((REPO / "app" / "config.py").read_text(encoding="utf-8"))
    v1 = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "CRAWLER_USER_AGENT_MARKERS" for t in node.targets
        ):
            v1 = ast.literal_eval(node.value)
    assert v1 is not None
    assert list(visitors.CRAWLER_USER_AGENT_MARKERS) == list(v1)


@pytest.mark.parametrize(
    ("ua", "expected"),
    [
        ("Mozilla/5.0 (Windows NT 10.0) Firefox/130.0", "human"),
        ("Googlebot/2.1", "crawler"),
        ("curl/8.5.0", "crawler"),
        ("Python-urllib/3.12", "crawler"),
        ("Mozilla/5.0 HeadlessChrome", "crawler"),
        ("", "unknown"),
        ("   ", "unknown"),
        (None, "unknown"),
    ],
)
def test_classify(ua: str | None, expected: str) -> None:
    assert visitors.classify(ua) == expected


def test_only_the_home_page_classifies() -> None:
    assert visitors.visit_detail("home", "curl/8") == {"page": "home", "visitor": "crawler"}
    assert visitors.visit_detail("robots", "curl/8") == {"page": "robots", "visitor": ""}
    assert visitors.visit_detail("nope", None)["page"] == "other"
    assert visitors.admin_visit_discount() == {"page": "admin", "visitor": ""}


def test_catalog_self_check_passes_and_keys_are_unique() -> None:
    catalog.catalog_self_check()
    assert len(catalog.METRICS) > 30


def test_every_kpi_and_measure_has_a_spec() -> None:
    names = set(queries.KPI_KEYS) | set(queries.MEASURE_NAMES) - {
        "cache_hit",
        "cache_stale",
        "cache_revalidating",
        "cache_coalesced",
        "cache_miss",
    }
    names |= {"p50_ms", "p95_ms", "p99_ms", "hit_ratio", "avoided_pct", "roblox_429_per_10k"}
    names |= set(queries.LAST_HOUR_KPIS)
    missing = sorted(n for n in names if n not in catalog.METRICS)
    assert missing == []


def test_honest_definitions_are_written_down() -> None:
    avoided = catalog.METRICS["avoided"].definition
    for phrase in ("demand minus the upstream calls", "background", "retries", "probes", "internal calls"):
        assert phrase in avoided
    assert "cache_stale_error" in catalog.METRICS["errors_hidden"].definition
    assert "excluding refusals" in catalog.METRICS["demand"].definition


def test_no_dash_characters_in_catalog_text() -> None:
    dashes = (chr(0x2014), chr(0x2013))
    for spec in catalog.METRICS.values():
        text = " ".join(str(getattr(spec, f)) for f in spec.__dataclass_fields__)
        assert not any(d in text for d in dashes), spec.key
