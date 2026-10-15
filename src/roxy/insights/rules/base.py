"""The base class every recommendation rule extends, and a short guide for rule authors.

What this is
    `Rule`: one plan 11.5 row as code. A subclass sets `id` (a key of `config/insight_params.INSIGHT_RULES`),
    optionally `safe_auto` and `triggers`, writes its help text as the class docstring, and implements
    `async evaluate(ctx) -> list[Recommendation]`. `register` adds a rule class to the registry the engine loads.

Why it exists
    Plan 11.1: rules are small classes over a read-only context, every threshold is a named, tunable parameter,
    and the engine (not the rule) applies the per-rule switch, the severity override, the evidence minimum, the
    fingerprint and the lifecycle. Keeping those out of rules means 50 rules by several authors behave the same.

How it works (the guide for rule authors)
    1. Create (or extend) a module in `roxy/insights/rules/`, for example `upstream.py`. Every module of the package
       is imported by the registry, so nothing else needs editing.
    2. Declare the rule:

           @register
           class Up5xx(Rule):
               '''Roblox server errors (5xx) are spiking. <help text shown in the dashboard>'''

               id = "UP-5XX"
               safe_auto = False                     # True only if every change is scoped to one endpoint
               triggers = frozenset({"breaker_open"})

               async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
                   window = ctx.window(minutes=self.param(ctx, "window_min"))
                   rows = await ctx.by_template(window)
                   ...
                   return [self.recommendation(ctx, subject=template, title=..., severity="warn", ...)]

    3. Thresholds: read them ONLY with `self.param(ctx, "<name>")` (the `insight_<slug>_<name>` setting declared
       in `config/insight_params.py`). A test scans every rule module and fails on a comparison against a numeric
       literal other than 0 or 1 (plan 11.1). Fixed algorithm constants that are not 11.5 thresholds (a headroom
       factor named by the plan, for example) are module constants with a docstring that cites the plan.
    4. Data: use the `InsightContext` (`roxy/insights/context.py`) only: rollups, 429 rows, samples, change
       observations, rule tables, settings, cooldowns, breakers, buckets, egress usage, events, errors, health,
       recent config changes, anomalies, and the provider seams for data without a table. Never open a database
       yourself and never write anything: evaluation is read-only; apply and undo live in `insights/actions.py`.
    5. Build each result with `self.recommendation(ctx, ...)`: one per subject (an endpoint template, a client, a
       rule row, a setting key, an error signature, a check id). The subject is the dedupe key with the rule id, so
       keep it stable between runs and make it contain the object's natural key (fixtures test that).
    6. Set `evidence.sample_size` to the number of observations the decision rests on; override
       `minimum_evidence(ctx)` when a parameter defines the minimum (the engine drops anything below it).
    7. Changes are `ProposedChange` objects (11.2 kinds) with the CURRENT value read from the context, so the
       admin sees a diff. A global setting is never `safe_auto`; the engine enforces that from the change kinds.
    8. Test it with the committed fixtures: `tests/insights/harness.py run_fixture("<file stem>")` runs any fixture
       file by name through the engine's per-rule entry point, exactly like the leader does.

What to read next
    `roxy/insights/context.py` (what a rule can read), `roxy/insights/models.py` (what it returns),
    `roxy/insights/rules/core.py` (three complete rules), `roxy/insights/engine.py` (what happens next).
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any, ClassVar, TypeVar

from roxy.config.insight_params import INSIGHT_RULES
from roxy.config.spec import InsightRuleSpec, ParamSpec
from roxy.insights.models import Evidence, ProposedChange, Recommendation

if TYPE_CHECKING:
    from roxy.insights.context import InsightContext

R = TypeVar("R", bound="type[Rule]")

_REGISTRY: dict[str, type[Rule]] = {}


class Rule:
    """Base class of every recommendation rule (see the module docstring for the authoring guide)."""

    id: ClassVar[str] = ""
    safe_auto: ClassVar[bool] = False
    """True when this rule's recommendations may be auto-applied (D7) once every change is scoped and risk is low."""
    triggers: ClassVar[frozenset[str]] = frozenset()
    """Trigger kinds (`engine.TRIGGER_KINDS`) that should evaluate this rule before the next scheduled run."""

    # ---- metadata from the catalog ----

    @property
    def spec(self) -> InsightRuleSpec:
        """The catalog entry of this rule (`config/insight_params.py`)."""
        return INSIGHT_RULES[self.id]

    @property
    def family(self) -> str:
        return self.spec.family

    @property
    def slug(self) -> str:
        return self.spec.slug

    @property
    def params(self) -> tuple[ParamSpec, ...]:
        return self.spec.params

    @property
    def help_text(self) -> str:
        """The class docstring: the rule's help text on the Recommendations page (plan 11.1)."""
        return inspect.cleandoc(type(self).__doc__ or self.spec.title)

    def setting_key(self, name: str) -> str:
        """`insight_<slug>_<name>`: the catalog setting of one of this rule's parameters."""
        if name not in {param.name for param in self.params}:
            raise KeyError(f"{self.id} has no parameter {name!r}; declare it in config/insight_params.py")
        return f"insight_{self.slug}_{name}"

    def param(self, ctx: InsightContext, name: str) -> float:
        """The live value of one declared threshold (never a literal in the rule body)."""
        return float(ctx.setting(self.setting_key(name)))

    def int_param(self, ctx: InsightContext, name: str) -> int:
        """`param` for whole-number thresholds (counts, minutes)."""
        return round(self.param(ctx, name))

    # ---- the contract ----

    def minimum_evidence(self, ctx: InsightContext) -> int:
        """The smallest `evidence.sample_size` a recommendation of this rule may have (plan 11.1). Default 1."""
        del ctx
        return 1

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        """Look at the context and return zero or more recommendations. Read-only; never raise for missing data
        (return nothing instead). The engine catches exceptions, logs them and keeps the other rules running."""
        raise NotImplementedError

    # ---- helpers ----

    def recommendation(
        self,
        ctx: InsightContext,
        *,
        subject: str,
        title: str,
        severity: str = "warn",
        confidence: str = "medium",
        explanation: str = "",
        evidence: Evidence | None = None,
        changes: list[ProposedChange] | None = None,
        expected_impact: str = "",
        risk: str = "low",
        safe_auto: bool | None = None,
    ) -> Recommendation:
        """A recommendation of this rule with the family, rule id and evaluation window filled in."""
        del ctx
        return Recommendation(
            rule_id=self.id,
            family=self.family,
            subject=subject,
            title=title,
            severity=severity,
            confidence=confidence,
            explanation=explanation,
            evidence=evidence or Evidence(),
            changes=list(changes or []),
            expected_impact=expected_impact,
            risk=risk,
            safe_auto=self.safe_auto if safe_auto is None else safe_auto,
        )

    def describe(self) -> dict[str, Any]:
        """The rule's catalog card (Recommendations page "Tune this rule" drawer)."""
        return {
            "id": self.id,
            "family": self.family,
            "title": self.spec.title,
            "help": self.help_text,
            "safe_auto": self.safe_auto,
            "settings": {
                "enabled": f"insight_{self.slug}_enabled",
                "severity": f"insight_{self.slug}_severity",
                "params": {param.name: f"insight_{self.slug}_{param.name}" for param in self.params},
            },
        }


def register[R: "type[Rule]"](cls: R) -> R:
    """Class decorator: add a rule to the registry. The id must be a catalog rule id and unique."""
    rule_id = getattr(cls, "id", "")
    if rule_id not in INSIGHT_RULES:
        raise ValueError(f"rule id {rule_id!r} is not in config/insight_params.py INSIGHT_RULES")
    existing = _REGISTRY.get(rule_id)
    if existing is not None and existing is not cls:
        raise ValueError(f"rule {rule_id} is registered twice ({existing.__qualname__} and {cls.__qualname__})")
    _REGISTRY[rule_id] = cls
    return cls


def registered() -> dict[str, type[Rule]]:
    """The registry (rule id -> class), in registration order."""
    return dict(_REGISTRY)


__all__ = ["Rule", "register", "registered"]
