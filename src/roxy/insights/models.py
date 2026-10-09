"""The recommendation object of plan 11.2: Recommendation, Evidence and ProposedChange.

What this is
    Plain dataclasses for what a rule returns and what the engine stores (`recommendations.payload_json`), plus the
    closed vocabularies they use: severities, confidences, risks, lifecycle states (11.1), change kinds (11.2) and
    dismiss reasons (11.3). `Recommendation.to_payload()` is the JSON shape of plan 11.2 (the dashboard, the API, the
    SSE stream and the LLM export all read it); `Recommendation.from_payload()` reads it back.

Why it exists
    One shape for every rule (about 50 of them, written by several authors) keeps the engine, the actions (apply,
    undo, preview) and the fixtures independent of each rule's internals. The change object says exactly what would
    be written, with its current value, so an admin sees a diff before anything happens (plan P2, P4).

How it works
    - A `ProposedChange` names its `kind` (11.2) and the fields that kind uses (README of tests/fixtures/insights):
      `setting` uses `key`, `current`, `proposed`; `bucket_override` uses `bucket_key`; `rule_upsert` and the other
      table kinds use `table`, `match`, `current` (the row, or None for a new one) and `proposed` (columns);
      `tarpit_category` uses `category`; `manual` carries only its `text`. `scoped` says whether the change touches
      one endpoint, rule row or client only: a global setting is never scoped, so it is never `safe_auto` (11.2).
    - `Evidence` holds the window, named metrics (11.2 `metrics: [{name, value, unit}]`), links, `sample_size` (how
      many observations the decision rests on; the engine enforces each rule's minimum) and free `details` (tables,
      timelines) for the card.
    - The engine fills `id`, `fingerprint`, `state` and the timestamps; a rule fills everything else.

What to read next
    `roxy/insights/rules/base.py` (how a rule builds these), `roxy/insights/engine.py` (dedupe and lifecycle),
    `roxy/insights/actions.py` (how a change is applied and undone).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

SEVERITIES: Final[tuple[str, ...]] = ("info", "warn", "critical")
SEVERITY_RANK: Final[dict[str, int]] = {name: rank for rank, name in enumerate(SEVERITIES)}
CONFIDENCES: Final[tuple[str, ...]] = ("low", "medium", "high")
RISKS: Final[tuple[str, ...]] = ("low", "medium", "high")

STATES: Final[tuple[str, ...]] = (
    "open",
    "applied",
    "auto_applied",
    "rolled_back",
    "snoozed",
    "dismissed",
    "resolved",
    "expired",
)
"""Lifecycle states (plan 11.1)."""
ACTIVE_STATES: Final[frozenset[str]] = frozenset({"open", "snoozed"})
"""States the engine keeps updating while the condition holds; the others are closed."""
QUIET_STATES: Final[frozenset[str]] = frozenset({"dismissed", "rolled_back"})
"""Closed states that keep the same fingerprint quiet for `dismiss_cooldown_days` unless severity rises (11.3)."""
APPLIED_STATES: Final[frozenset[str]] = frozenset({"applied", "auto_applied"})

CHANGE_KINDS: Final[tuple[str, ...]] = (
    "setting",
    "bucket_override",
    "rule_upsert",
    "rule_delete",
    "filter_add",
    "filter_remove",
    "ban_add",
    "ban_remove",
    "bypass_add",
    "bypass_remove",
    "ignored_param_add",
    "tarpit_category",
    "routing_rule",
    "credential_allowlist_remove",
    "host_add",
    "manual",
)
"""Change kinds of plan 11.2."""

SCOPED_KINDS: Final[frozenset[str]] = frozenset(
    {
        "bucket_override",
        "rule_upsert",
        "rule_delete",
        "filter_add",
        "filter_remove",
        "ban_add",
        "ban_remove",
        "bypass_add",
        "bypass_remove",
        "ignored_param_add",
        "routing_rule",
        "credential_allowlist_remove",
    }
)
"""Kinds that touch one row (an endpoint's rule or bucket, one client, one parameter). `setting`, `host_add` and
`tarpit_category` change behavior for every caller; `manual` cannot be applied at all (11.2)."""

DISMISS_REASONS: Final[dict[str, str]] = {
    "not_accurate": "Not accurate",
    "intended_behavior": "Intended behavior",
    "will_handle_manually": "Will handle manually",
    "other": "Other",
}
"""The dismiss dropdown of plan 11.3; `other` needs a text."""

SNOOZE_DURATIONS_S: Final[dict[str, int]] = {"1h": 3600, "1d": 86_400, "1w": 7 * 86_400}
"""Snooze choices of plan 11.3."""

MAX_SUBJECT_CHARS: Final = 300
MAX_TITLE_CHARS: Final = 300
MAX_TEXT_CHARS: Final = 4000
MAX_METRICS: Final = 40
MAX_CHANGES: Final = 20
MAX_LINKS: Final = 10


def iso(ts: float | None) -> str | None:
    """Unix seconds as ISO 8601 UTC with `Z` (11.2 window form), or None."""
    if ts is None:
        return None
    return datetime.fromtimestamp(float(ts), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_fingerprint(rule_id: str, subject: str) -> str:
    """The dedupe key of plan 11.1 (`rule_id` + subject), bounded: `<rule id>:<sha256(subject)[:16]>`."""
    digest = hashlib.sha256(subject.encode("utf-8", "replace")).hexdigest()[:16]
    return f"{rule_id}:{digest}"


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, 0)


@dataclass(frozen=True, slots=True)
class Metric:
    """One named evidence number (11.2 `evidence.metrics[]`)."""

    name: str
    value: Any
    unit: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "value": self.value}
        if self.unit:
            out["unit"] = self.unit
        return out


@dataclass(slots=True)
class Evidence:
    """What a recommendation rests on (11.2 `evidence`)."""

    window_from: float | None = None
    window_to: float | None = None
    metrics: list[Metric] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    sample_size: int = 0
    details: dict[str, Any] = field(default_factory=dict)

    def add(self, name: str, value: Any, unit: str = "") -> Evidence:
        """Append a metric and return self (chainable)."""
        if len(self.metrics) < MAX_METRICS:
            self.metrics.append(Metric(name, value, unit))
        return self

    def metric(self, name: str, default: Any = None) -> Any:
        """The value of the named metric, or `default`."""
        for item in self.metrics:
            if item.name == name:
                return item.value
        return default

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "window": {"from": iso(self.window_from), "to": iso(self.window_to)},
            "metrics": [m.to_dict() for m in self.metrics],
            "links": list(self.links[:MAX_LINKS]),
            "sample_size": int(self.sample_size),
        }
        if self.details:
            out["details"] = self.details
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Evidence:
        window = data.get("window") or {}
        return cls(
            window_from=_parse_iso(window.get("from")),
            window_to=_parse_iso(window.get("to")),
            metrics=[
                Metric(str(m.get("name")), m.get("value"), str(m.get("unit") or "")) for m in data.get("metrics", [])
            ],
            links=[str(link) for link in data.get("links", [])],
            sample_size=int(data.get("sample_size") or 0),
            details=dict(data.get("details") or {}),
        )


def _parse_iso(text: Any) -> float | None:
    if not text:
        return None
    try:
        return datetime.strptime(str(text), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return None


@dataclass(slots=True)
class ProposedChange:
    """One change of a recommendation (11.2 `changes[]`); see the module docstring for which fields a kind uses."""

    kind: str
    key: str | None = None
    table: str | None = None
    match: dict[str, Any] | None = None
    bucket_key: str | None = None
    category: str | None = None
    current: Any = None
    proposed: Any = None
    text: str = ""

    def __post_init__(self) -> None:
        if self.kind not in CHANGE_KINDS:
            raise ValueError(f"unknown change kind {self.kind!r}")

    @property
    def scoped(self) -> bool:
        """True when the change touches one row only (never a global setting, 11.2)."""
        return self.kind in SCOPED_KINDS

    @property
    def target(self) -> str:
        """A short label of what the change touches (`setting:<key>`, `rules_cache:<pattern>`, ...)."""
        if self.kind == "setting" or self.kind == "host_add":
            return f"setting:{self.key}"
        if self.kind == "bucket_override":
            return f"upstream_limits:{self.bucket_key}"
        if self.kind == "tarpit_category":
            return f"tarpit:{self.category}"
        if self.kind == "manual":
            return "manual"
        match = self.match or {}
        label = match.get("pattern") or match.get("cidr") or match.get("subject") or match.get("id") or ""
        if not label and isinstance(self.proposed, Mapping):
            label = self.proposed.get("pattern") or self.proposed.get("name") or self.proposed.get("subject") or ""
        return f"{self.table}:{label}"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind}
        if self.kind == "manual":
            out["text"] = self.text
            return out
        for name in ("key", "table", "match", "bucket_key", "category"):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        out["current"] = self.current
        out["proposed"] = self.proposed
        if self.text:
            out["text"] = self.text
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProposedChange:
        return cls(
            kind=str(data["kind"]),
            key=data.get("key"),
            table=data.get("table"),
            match=dict(data["match"]) if isinstance(data.get("match"), Mapping) else None,
            bucket_key=data.get("bucket_key"),
            category=data.get("category"),
            current=data.get("current"),
            proposed=data.get("proposed"),
            text=str(data.get("text") or ""),
        )


@dataclass(slots=True)
class Recommendation:
    """One recommendation (plan 11.2). Rules fill the content; the engine fills identity, state and times."""

    rule_id: str
    family: str
    subject: str
    title: str
    severity: str = "warn"
    confidence: str = "medium"
    explanation: str = ""
    evidence: Evidence = field(default_factory=Evidence)
    changes: list[ProposedChange] = field(default_factory=list)
    expected_impact: str = ""
    risk: str = "low"
    safe_auto: bool = False
    dry_run_available: bool = False
    id: str = ""
    fingerprint: str = ""
    state: str = "open"
    created_at: float | None = None
    updated_at: float | None = None
    expires_at: float | None = None
    snoozed_until: float | None = None
    dismissed_reason: str | None = None
    computed_severity: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"unknown confidence {self.confidence!r}")
        if self.risk not in RISKS:
            raise ValueError(f"unknown risk {self.risk!r}")
        self.subject = str(self.subject)[:MAX_SUBJECT_CHARS]
        self.title = str(self.title)[:MAX_TITLE_CHARS]
        self.explanation = str(self.explanation)[:MAX_TEXT_CHARS]
        self.expected_impact = str(self.expected_impact)[:MAX_TEXT_CHARS]
        self.changes = list(self.changes)[:MAX_CHANGES]

    @property
    def change_kinds(self) -> tuple[str, ...]:
        return tuple(change.kind for change in self.changes)

    @property
    def all_scoped(self) -> bool:
        """Every change touches one row only (and there is at least one): the 11.2 condition for `safe_auto`."""
        return bool(self.changes) and all(change.scoped for change in self.changes)

    def to_payload(self) -> dict[str, Any]:
        """The 11.2 JSON object (plus `subject`, `fingerprint` and `computed_severity`)."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "family": self.family,
            "subject": self.subject,
            "fingerprint": self.fingerprint,
            "severity": self.severity,
            "computed_severity": self.computed_severity or self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "explanation": self.explanation,
            "evidence": self.evidence.to_dict(),
            "changes": [change.to_dict() for change in self.changes],
            "expected_impact": self.expected_impact,
            "risk": self.risk,
            "safe_auto": self.safe_auto,
            "dry_run": {"available": self.dry_run_available},
            "created_at": iso(self.created_at),
            "updated_at": iso(self.updated_at),
            "expires_at": iso(self.expires_at),
            "snoozed_until": iso(self.snoozed_until),
            "dismissed_reason": self.dismissed_reason,
            "state": self.state,
        }

    @classmethod
    def from_payload(cls, data: Mapping[str, Any]) -> Recommendation:
        return cls(
            rule_id=str(data["rule_id"]),
            family=str(data.get("family") or ""),
            subject=str(data.get("subject") or ""),
            title=str(data.get("title") or ""),
            severity=str(data.get("severity") or "warn"),
            confidence=str(data.get("confidence") or "medium"),
            explanation=str(data.get("explanation") or ""),
            evidence=Evidence.from_dict(data.get("evidence") or {}),
            changes=[ProposedChange.from_dict(c) for c in data.get("changes") or []],
            expected_impact=str(data.get("expected_impact") or ""),
            risk=str(data.get("risk") or "low"),
            safe_auto=bool(data.get("safe_auto")),
            dry_run_available=bool((data.get("dry_run") or {}).get("available")),
            id=str(data.get("id") or ""),
            fingerprint=str(data.get("fingerprint") or ""),
            state=str(data.get("state") or "open"),
            created_at=_parse_iso(data.get("created_at")),
            updated_at=_parse_iso(data.get("updated_at")),
            expires_at=_parse_iso(data.get("expires_at")),
            snoozed_until=_parse_iso(data.get("snoozed_until")),
            dismissed_reason=data.get("dismissed_reason"),
            computed_severity=str(data.get("computed_severity") or ""),
        )


def changes_digest(changes: Sequence[ProposedChange]) -> str:
    """A short stable digest of a change list (the engine publishes an update only when the proposal changed)."""
    import json

    text = json.dumps([c.to_dict() for c in changes], sort_keys=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


__all__ = [
    "ACTIVE_STATES",
    "APPLIED_STATES",
    "CHANGE_KINDS",
    "CONFIDENCES",
    "DISMISS_REASONS",
    "QUIET_STATES",
    "RISKS",
    "SCOPED_KINDS",
    "SEVERITIES",
    "SNOOZE_DURATIONS_S",
    "STATES",
    "Evidence",
    "Metric",
    "ProposedChange",
    "Recommendation",
    "changes_digest",
    "iso",
    "make_fingerprint",
    "severity_rank",
]
