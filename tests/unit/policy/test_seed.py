"""The shipped endpoint policy seed: valid, complete, identical to the reviewed copy, and safe by default."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from roxy.policy.matcher import TemplateIndex
from roxy.policy.seed import CATEGORIES, SeedError, Verdict, load_seed, parse_seed

ROOT = Path(__file__).resolve().parents[3]
DOCS_SEED = ROOT / "docs" / "endpoint_policy" / "endpoint_policy_seed.json"
PACKAGE_SEED = ROOT / "src" / "roxy" / "policy" / "endpoint_policy_seed.json"


def test_packaged_seed_equals_the_reviewed_copy() -> None:
    assert PACKAGE_SEED.read_bytes() == DOCS_SEED.read_bytes()


def test_seed_loads_every_operation_once() -> None:
    seed = load_seed()
    assert len(seed.rows) == 992
    assert len(seed.by_id) == len(seed.rows)
    assert {row.verdict for row in seed.rows} == set(Verdict)
    assert all(row.category in CATEGORIES for row in seed.rows)
    assert all(row.path.startswith("/") and "#" not in row.path for row in seed.rows)


def test_no_two_identical_templates_disagree() -> None:
    assert TemplateIndex(load_seed().rows).ties() == []


def test_every_row_links_to_roblox_docs() -> None:
    for row in load_seed().rows:
        assert row.domain_doc.startswith("https://create.roblox.com/docs/cloud/reference/domains/"), row.id
        if row.feature_doc is not None:
            assert row.feature_doc.startswith("https://create.roblox.com/docs/cloud/reference/features/"), row.id


@pytest.mark.parametrize(
    "category", ["login-session-security", "account-identity", "economy-spend", "open-cloud-key-only"]
)
def test_dangerous_categories_ship_blocked(category: str) -> None:
    rows = [row for row in load_seed().rows if row.category == category]
    assert rows
    assert all(row.verdict is Verdict.BLOCK for row in rows)


def test_only_reads_carry_the_account_by_default() -> None:
    for row in load_seed().rows:
        if row.verdict is Verdict.ALLOW_TOKEN:
            assert row.method in ("GET", "POST"), row.id
            assert row.category == "public-read", row.id


def test_undocumented_risky_hosts_are_blocked() -> None:
    defaults = load_seed().host_defaults
    for host in ("gamejoin.roblox.com", "billing.roblox.com", "engagementpayouts.roblox.com", "voice.roblox.com"):
        assert defaults[host].verdict is Verdict.BLOCK


def test_a_broken_seed_is_refused() -> None:
    data = json.loads(DOCS_SEED.read_text(encoding="utf-8"))
    data["endpoints"][0]["verdict"] = "MAYBE"
    with pytest.raises(SeedError):
        parse_seed(data)
    data = json.loads(DOCS_SEED.read_text(encoding="utf-8"))
    data["endpoints"].append(dict(data["endpoints"][0]))
    with pytest.raises(SeedError):
        parse_seed(data)
    with pytest.raises(SeedError):
        parse_seed({"endpoints": []})
