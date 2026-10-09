"""The recommendation rules of plan 11.5, one class per rule, discovered from the modules of this package.

What this is
    `load_rules()` imports every module of `roxy.insights.rules` (so a new rule module needs no registration
    anywhere else) and returns one instance per registered rule, keyed by rule id, in plan 11.5 order.
    `rule_ids()` lists them.

Why it exists
    Several authors add rule families in parallel (`core.py`, and later `upstream.py`, `cache.py`, `abuse.py`, ...);
    discovery keeps them from editing one shared list.

How it works
    `pkgutil.iter_modules` over this package; each module's `@register` decorators fill the registry in
    `rules/base.py`. A module that fails to import is a bug, so the error propagates (the engine would otherwise
    silently lose a rule family).

What to read next
    `roxy/insights/rules/base.py` (the authoring guide), `roxy/insights/rules/core.py` (example rules).
"""

from __future__ import annotations

import importlib
import pkgutil

from roxy.config.insight_params import INSIGHT_RULES
from roxy.insights.rules.base import Rule, register, registered

_SKIP = frozenset({"base"})


def _import_all() -> None:
    for module in pkgutil.iter_modules(__path__):
        if module.name.startswith("_") or module.name in _SKIP:
            continue
        importlib.import_module(f"{__name__}.{module.name}")


def load_rules() -> dict[str, Rule]:
    """One instance of every registered rule, in plan 11.5 (catalog) order."""
    _import_all()
    classes = registered()
    order = {rule_id: index for index, rule_id in enumerate(INSIGHT_RULES)}
    return {rule_id: classes[rule_id]() for rule_id in sorted(classes, key=lambda rid: order.get(rid, len(order)))}


def rule_ids() -> list[str]:
    """Ids of every registered rule."""
    return list(load_rules())


__all__ = ["Rule", "load_rules", "register", "registered", "rule_ids"]
