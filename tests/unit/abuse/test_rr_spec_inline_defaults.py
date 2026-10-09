"""Reviewer finding spec-8: the abuse package keeps no inline copies of catalog defaults (spec F10 as a class).

What this is
    A static scan of `src/roxy/abuse` for calls that pass a catalog setting key together with a literal fallback
    value (`facts.int("throttle_reset_duration", 50)`, `values.get("throttle_escalation_enabled", 1)`), plus checks
    that the typed `Facts` readers take no default at all and read the catalog default for a missing key.

Why it exists
    Spec review finding F10 asked to drop inline fallbacks or read `catalog_default`, so a tunable's real default
    lives in one place (plan principle P3, 15.1). Fix pass 1 changed the three call sites the review named, and the
    module docstring of `abuse/checks/base.py` states that settings missing from the snapshot fall back to the
    catalog default, "never to a second, inline copy of the default". The `Facts.int`, `Facts.float`, `Facts.bool`
    and `Facts.str` helpers still took an inline default and 27 call sites passed one (all equal to the catalog,
    so nothing was wrong on the wire, but the next catalog change would have drifted silently). The helpers now read
    `Facts.required` (the live value, else the catalog default, else KeyError), and `pipeline.py` and `spam.py` read
    `live_setting` and `_live` the same way.

How it works
    Walks the AST of every module in `src/roxy/abuse`. The control proves the scanner finds an inline copy when one
    exists (so an empty result means something); the main test requires none in the package.

What to read next
    `roxy/abuse/checks/base.py` (`Facts`, `live_setting`), `roxy/abuse/pipeline.py` (`_facts`),
    `roxy/abuse/spam.py` (`_live`), `roxy/core/scope.py` (`catalog_default`).
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any

import pytest

from roxy.abuse.checks.base import Facts
from roxy.config.catalog import CATALOG
from roxy.rules.store import RulesSnapshot

ABUSE = Path(__file__).resolve().parents[3] / "src" / "roxy" / "abuse"


def inline_fallbacks_in(source: str, name: str) -> list[tuple[str, int, str, Any]]:
    """(file, line, key, literal) for every call whose first argument is a catalog key and second a literal."""
    found: list[tuple[str, int, str, Any]] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or len(node.args) < 2:
            continue
        key = node.args[0]
        if not (isinstance(key, ast.Constant) and isinstance(key.value, str) and key.value in CATALOG):
            continue
        try:
            literal = ast.literal_eval(node.args[1])
        except ValueError:
            continue
        found.append((name, node.lineno, key.value, literal))
    return found


def inline_fallbacks() -> list[tuple[str, int, str, Any]]:
    found: list[tuple[str, int, str, Any]] = []
    for path in sorted(ABUSE.rglob("*.py")):
        found.extend(inline_fallbacks_in(path.read_text(encoding="utf-8"), path.name))
    return found


def test_spec_8_control_the_scanner_finds_an_inline_copy() -> None:
    """Control: the scan recognizes the shapes the finding counted, so an empty result below means something."""
    sample = (
        'facts.int("throttle_reset_duration", 50)\n'
        'values.get("throttle_escalation_enabled", 1)\n'
        'facts.int("throttle_reset_duration")\n'
    )
    assert [(key, literal) for _, _, key, literal in inline_fallbacks_in(sample, "sample.py")] == [
        ("throttle_reset_duration", 50),
        ("throttle_escalation_enabled", 1),
    ]


def test_spec_8_abuse_settings_have_no_inline_default_copies() -> None:
    assert inline_fallbacks() == []


@pytest.mark.parametrize("reader", ["int", "float", "bool", "str"])
def test_spec_8_typed_readers_take_no_default(reader: str) -> None:
    """The typed readers cannot be handed a second default: their only parameter is the key."""
    assert list(inspect.signature(getattr(Facts, reader)).parameters) == ["self", "key"]


def _facts(values: dict[str, Any]) -> Facts:
    return Facts(
        now=0.0,
        now_ms=0,
        values=values,
        rules=RulesSnapshot.empty(),
        services=None,
        target="",
        path="",
        ip="",
        limit_key="",
        per_ip=None,
        ladder=(),
    )


def test_spec_8_missing_settings_read_the_catalog_default() -> None:
    facts = _facts({"flood_limit_per_minute": 7})
    assert facts.int("flood_limit_per_minute") == 7  # the live value wins
    assert facts.int("throttle_reset_duration") == CATALOG["throttle_reset_duration"].default
    assert facts.bool("ban_disguise_as_throttle") is bool(CATALOG["ban_disguise_as_throttle"].default)
    assert facts.str("place_limit_key") == CATALOG["place_limit_key"].default
    assert facts.float("bot_weight_probes") == float(CATALOG["bot_weight_probes"].default)
    with pytest.raises(KeyError, match="not a catalog setting"):
        facts.int("no_such_setting_anywhere")
