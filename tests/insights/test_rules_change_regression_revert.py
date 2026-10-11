"""SYS-CHANGE-REGRESSION reverts a first override and a reset to default (found by the gaps_insights lane).

What this is
    Unit tests of `roxy/insights/rules/system.py` `history_value` and `SysChangeRegression._revert`.

Why it exists
    `settings_history` stores NULL for "no override": the before of a key's first override and the after of a reset
    to its default. The rule passed that None to `catalog.validate_value`, which refused it, so every evaluation
    after such a change logged `insight_rule_failed` for SYS-CHANGE-REGRESSION (seen in the e2e dashboard's log while
    the lane ran the browser tests) and the change was never judged.

How it works
    A context over the catalog defaults; history rows as `config/read_changes.py recent_changes` returns them.

What to read next
    `roxy/insights/rules/system.py`, `roxy/config/settings_service.py` (where the NULLs come from).
"""

from __future__ import annotations

from typing import Any

from roxy.config import catalog
from roxy.insights.context import InsightContext
from roxy.insights.rules.system import SysChangeRegression, history_value

KEY = "cache_error_ttl_seconds"


def _ctx(**overrides: Any) -> InsightContext:
    values = {key: catalog.DEFAULTS.get(key, spec.default) for key, spec in catalog.CATALOG.items()}
    values.update(overrides)
    return InsightContext(now=1_000_000.0, dbs=None, settings=values, rules=None)


def _change(before: Any, after: Any) -> dict[str, Any]:
    return {"kind": "setting", "key": KEY, "target": f"setting:{KEY}", "before": before, "after": after, "at": 1}


def test_none_in_the_history_is_the_default() -> None:
    default = catalog.DEFAULTS.get(KEY, catalog.CATALOG[KEY].default)
    assert history_value(KEY, None) == default
    assert history_value(KEY, 300) == 300


def test_a_first_override_reverts_to_the_default() -> None:
    default = catalog.DEFAULTS.get(KEY, catalog.CATALOG[KEY].default)
    change = SysChangeRegression()._revert(_ctx(**{KEY: 300}), _change(None, 300))
    assert change is not None
    assert (change.key, change.current, change.proposed) == (KEY, 300, default)


def test_a_reset_to_the_default_reverts_to_the_value_before_it() -> None:
    change = SysChangeRegression()._revert(_ctx(), _change(300, None))
    assert change is not None
    assert change.proposed == 300


def test_a_value_the_catalog_refuses_is_not_proposed() -> None:
    assert SysChangeRegression()._revert(_ctx(), _change("not a duration", None)) is None
    assert SysChangeRegression()._revert(_ctx(**{KEY: 300}), _change(None, 301)) is None  # changed again since
