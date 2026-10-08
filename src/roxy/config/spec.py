"""Setting metadata types: the vocabulary every runtime setting is described with.

What this is
    The dataclasses that describe one runtime setting (`SettingSpec`), one option of an enum setting
    (`OptionSpec`), one tunable threshold of a recommendation rule (`ParamSpec`), and the small enums they use.

Why it exists
    Plan principle P3 ("single source of truth"): every setting is declared once, with its type, range, help
    text, risk, and where it appears in the dashboard. The settings API, validation, the settings editor, the
    generated docs (docs/SETTINGS.md) and the LLM export are all generated from these declarations, so the UI
    can never again write a key the server does not know (the v1 `tarpit_on_user_agent_rule` bug).

How it works
    Group modules in `roxy/config/settings/` each export `SETTINGS: list[SettingSpec]`. `roxy/config/catalog.py`
    collects them, adds the per-rule insight settings generated from `roxy/config/insight_params.py`, checks the
    whole catalog for mistakes at import time, and exposes `CATALOG` (key -> spec) plus `validate_value()`.
    The dataclasses are frozen: a spec is data, never state.

What to read next
    `roxy/config/catalog.py` (assembly and validation), then `roxy/config/runtime.py` (the live store that
    holds the current values and hot-reloads them across worker processes).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class SettingType(StrEnum):
    """The value types a setting can have. The editor picks its input control from this."""

    INT = "int"
    FLOAT = "float"
    BOOL = "bool"  # stored as 0 or 1, like v1, so imports and the API stay simple
    ENUM = "enum"  # one of `options`
    DURATION = "duration"  # integer seconds, or milliseconds when unit == "ms"; the UI accepts "90s", "15m"
    BYTES = "bytes"  # integer bytes; the UI accepts "64 MiB"
    PERCENT = "percent"  # number between min and max, shown with a % sign
    STRING = "string"
    LIST_STR = "list[str]"
    LIST_INT = "list[int]"
    LIST_CIDR = "list[cidr]"


class Risk(StrEnum):
    """How dangerous a setting (or one of its values) is. High-risk values need a reason and a confirmation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Apply(StrEnum):
    """When a change takes effect. `live` settings hot-reload fleet-wide within about a second (config_version)."""

    LIVE = "live"
    RESTART = "restart"


class Group(StrEnum):
    """Sections of the Settings page (plan 15.1). The value is the stable id; `GROUP_LABELS` has the title."""

    ROUTING = "routing"
    CREDENTIAL = "credential"
    UPSTREAM = "upstream"
    CACHE = "cache"
    THROTTLING = "throttling"
    ABUSE = "abuse"
    TARPIT = "tarpit"
    ADMIN_SECURITY = "admin_security"
    ALERTS = "alerts"
    METRICS = "metrics"
    INSIGHTS = "insights"
    INSIGHT_RULES = "insight_rules"
    PUBLIC_SITE = "public_site"
    DASHBOARD = "dashboard"


GROUP_LABELS: dict[Group, str] = {
    Group.ROUTING: "Routing and egress",
    Group.CREDENTIAL: "Credential",
    Group.UPSTREAM: "Upstream pacing and resilience",
    Group.CACHE: "Cache",
    Group.THROTTLING: "Throttling",
    Group.ABUSE: "Abuse detection",
    Group.TARPIT: "Tarpit",
    Group.ADMIN_SECURITY: "Admin security and sessions",
    Group.ALERTS: "Alerts and email",
    Group.METRICS: "Metrics, retention and capture",
    Group.INSIGHTS: "Insights",
    Group.INSIGHT_RULES: "Recommendation rule tuning",
    Group.PUBLIC_SITE: "Public site and compatibility",
    Group.DASHBOARD: "Dashboard",
}


class RiskOp(StrEnum):
    EQ = "eq"
    NE = "ne"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"


@dataclass(frozen=True, slots=True)
class RiskCondition:
    """A value condition that makes a setting high risk (used by the SEC-DEFAULTS rule and the editor badge).

    Example: `RiskCondition(RiskOp.EQ, 1, "Browsers on any site can use Roxy as a free API.")` on
    `public_cors_allow_any_origin`.
    """

    op: RiskOp
    value: Any
    why: str

    def matches(self, current: Any) -> bool:
        """Return True when `current` satisfies this condition."""
        try:
            match self.op:
                case RiskOp.EQ:
                    return bool(current == self.value)
                case RiskOp.NE:
                    return bool(current != self.value)
                case RiskOp.GT:
                    return bool(current > self.value)
                case RiskOp.GTE:
                    return bool(current >= self.value)
                case RiskOp.LT:
                    return bool(current < self.value)
                case RiskOp.LTE:
                    return bool(current <= self.value)
                case RiskOp.IN:
                    return current in self.value
        except TypeError:
            return False
        return False


@dataclass(frozen=True, slots=True)
class OptionSpec:
    """One choice of an enum setting, with the text that explains what choosing it does."""

    value: str
    label: str
    description: str


@dataclass(frozen=True, slots=True)
class SettingSpec:
    """Everything Roxy knows about one runtime setting (plan 15.1).

    Required text fields are never empty: `description` says what it does, and either `if_raised` plus
    `if_lowered` (numbers) or per-option `description` (enums) or `if_enabled` plus `if_disabled` (booleans)
    say what changing it does. `pages` lists at least one dashboard anchor `<page>#<card>` (plan 15.6)
    where the setting is editable inline, besides the Settings page itself.
    """

    key: str
    group: Group
    label: str
    type: SettingType
    default: Any
    description: str
    pages: tuple[str, ...]
    unit: str = ""
    min: float | None = None
    max: float | None = None
    step: float | None = None
    options: tuple[OptionSpec, ...] = ()
    if_raised: str = ""
    if_lowered: str = ""
    if_enabled: str = ""
    if_disabled: str = ""
    risk: Risk = Risk.LOW
    high_risk_if: tuple[RiskCondition, ...] = ()
    apply: Apply = Apply.LIVE
    related_settings: tuple[str, ...] = ()
    related_rules: tuple[str, ...] = ()
    related_recommendations: tuple[str, ...] = ()
    auto_apply_bounds: tuple[float, float] | None = None
    sensitive: bool = False
    since: str = "2.0"
    renamed_from: str | None = None
    v1_default: Any = None
    max_length: int | None = None  # strings: characters; lists: items
    item_max_length: int | None = None  # list[str]: characters per item
    item_min: float | None = None  # list[int]: per-item bounds
    item_max: float | None = None
    pending_owner_verification: bool = False
    notes: str = ""  # anything else an admin should know (shown under "More")

    def option_values(self) -> tuple[str, ...]:
        """The allowed values of an enum setting."""
        return tuple(option.value for option in self.options)

    def is_high_risk_value(self, value: Any) -> str | None:
        """Return the reason text if `value` is a high-risk value for this setting, else None."""
        for condition in self.high_risk_if:
            if condition.matches(value):
                return condition.why
        return None


@dataclass(frozen=True, slots=True)
class ParamSpec:
    """One named threshold of a recommendation rule (plan 11.1).

    The catalog turns each into a setting `insight_<rule_id>_<name>` in the `insight_rules` group, so every
    threshold is tunable, validated, audited and exported, and no rule hides a magic number in code.
    """

    name: str
    default: float
    min: float
    max: float
    unit: str
    label: str
    if_raised: str = "Fires less often, only on stronger evidence."
    if_lowered: str = "Fires sooner, with more false positives."
    is_int: bool = True


@dataclass(frozen=True, slots=True)
class InsightRuleSpec:
    """Catalog-level description of one recommendation rule, used to generate its settings (plan 15.3 J2)."""

    rule_id: str  # for example "UP-429-ENDPOINT"
    family: str  # upstream, cache, abuse, egress, credential, filter, system, security, host
    title: str  # one line, plain English
    params: tuple[ParamSpec, ...] = field(default_factory=tuple)

    @property
    def slug(self) -> str:
        """`UP-429-ENDPOINT` -> `up_429_endpoint`, the form used in setting keys."""
        return self.rule_id.lower().replace("-", "_")
