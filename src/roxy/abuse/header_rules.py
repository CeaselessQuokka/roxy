"""Header filter rules ("request filters"): refuse requests whose header names or values match a needle.

What this is
    `header_pairs` (a request's headers in arrival order), `rule_hit` and `match_header_rule` (v1 `rule_hit` and
    `match_header_rule`: first rule that hits wins), `header_rule_message`, and the tester helpers
    `parse_header_text` and `explain_header_rules` behind Protection > Request filters (plan 4.3 row 45, row 112).

Why it exists
    Some abusive tools give themselves away in a header (an executor fingerprint header, an odd `Accept` value).
    A filter refuses them, by default disguised as an ordinary throttle so the tool's author does not learn which
    header gave it away (v1 smoke test: the body equals the rung 1 throttle text and names no header).

How it works
    - A rule has a scope (`key`: the header name, `value`: the value, `either`), a mode (contains, exact, regex) and
      a needle; naming a target `header` forces scope `value` and looks only at that header. Rules are tried in
      insertion order (id) and the first hit wins; within a rule, headers are tried in arrival order.
    - A regex that times out counts as a hit (fail closed).
    - Names are compared case-insensitively; the tarpit reason and tester show them Title-Cased like v1 did.
    - v1 decision kept (B31): rules see every header nginx forwards, including the ones nginx adds.

What to read next
    `roxy/rules/match.py` (`text_matches`, `header_rule_canonical_key`), then `roxy/abuse/checks/header_rules.py`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from pydantic import ValidationError

from roxy.abuse.messages import clean_admin_message
from roxy.abuse.verdict import title_case_header
from roxy.rules.match import text_matches
from roxy.rules.models import HeaderRuleIn
from roxy.rules.store import RulesSnapshot

MAX_TEST_HEADERS: Final = 200
"""v1 tester limit (index.py:1267)."""
MAX_TEST_NAME: Final = 200
MAX_TEST_VALUE: Final = 2000


@dataclass(frozen=True, slots=True)
class HeaderHit:
    """Which rule hit, on which header, and whether the name or the value matched."""

    rule_id: str
    rule: Any
    header: str
    field: str  # "key" or "value"
    text: str


def header_pairs(req: Any) -> list[tuple[str, str]]:
    """`(name, value)` pairs in arrival order (names as received; values from the request's header map)."""
    headers: Mapping[str, str] = getattr(req, "headers", {}) or {}
    names: Sequence[str] = getattr(req, "header_names_in_order", None) or list(headers)
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name in names:
        lower = name.lower()
        if lower in seen:
            continue  # the map already joined repeated headers into one value
        seen.add(lower)
        pairs.append((name, str(headers.get(lower, headers.get(name, "")))))
    return pairs


def rule_hit(rule: Any, pairs: Iterable[tuple[str, str]], rule_id: str | None = None) -> HeaderHit | None:
    """v1 `rule_hit`: the first header this rule matches, or None."""
    scope = str(rule.scope or "either")
    mode = str(rule.mode or "contains")
    needle = str(rule.needle or "")
    target = str(getattr(rule, "header", "") or "").lower()
    ident = rule_id if rule_id is not None else str(getattr(rule, "canonical_key", "") or getattr(rule, "id", ""))
    if not needle:
        return None
    for name, value in pairs:
        if target:
            if name.lower() != target:
                continue
            if text_matches(mode, needle, value, on_timeout=True):
                return HeaderHit(ident, rule, name, "value", value)
            continue
        key_hit = scope in ("key", "either") and text_matches(mode, needle, name, on_timeout=True)
        value_hit = scope in ("value", "either") and text_matches(mode, needle, value, on_timeout=True)
        if key_hit or value_hit:
            return HeaderHit(ident, rule, name, "key" if key_hit else "value", name if key_hit else value)
    return None


def match_header_rule(snapshot: RulesSnapshot, pairs: Sequence[tuple[str, str]]) -> HeaderHit | None:
    """The first enabled rule (insertion order) that hits any header, or None (v1 `match_header_rule`)."""
    for rule in snapshot.enabled_header_rules:
        hit = rule_hit(rule, pairs)
        if hit is not None:
            return hit
    return None


def header_rule_message(rule: Any) -> str:
    """The rule's public message (empty: the refusal is disguised as a throttle)."""
    return clean_admin_message(getattr(rule, "message", ""))


def parse_header_text(text: str) -> list[tuple[str, str]]:
    """v1 `_parse_header_text`: `Name: value` per line; lines without a colon (a request line) are skipped."""
    pairs: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            continue
        name, _, value = stripped.partition(":")
        name = name.strip()
        if name:
            pairs.append((name[:MAX_TEST_NAME], value.strip()[:MAX_TEST_VALUE]))
    return pairs


def explain_header_rules(
    snapshot: RulesSnapshot, pairs: Sequence[tuple[str, str]], draft: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """The tester: every rule's hit for these headers, which one would refuse, and how a draft would behave."""
    pairs = [(str(n)[:MAX_TEST_NAME], str(v)[:MAX_TEST_VALUE]) for n, v in list(pairs)[:MAX_TEST_HEADERS]]
    rules = []
    first: str | None = None
    for rule in snapshot.header_rules:
        hit = rule_hit(rule, pairs)
        is_first = bool(rule.enabled and hit is not None and first is None)
        if is_first:
            first = rule.canonical_key
        rules.append(
            {
                "id": rule.id,
                "canonical_key": rule.canonical_key,
                "header": rule.header,
                "scope": rule.scope,
                "mode": rule.mode,
                "needle": rule.needle,
                "enabled": rule.enabled,
                "matched": hit is not None,
                "matched_header": title_case_header(hit.header) if hit else "",
                "matched_field": hit.field if hit else "",
                "matched_text": hit.text if hit else "",
                "is_first_match": is_first,
            }
        )
    result: dict[str, Any] = {
        "header_count": len(pairs),
        "blocked": first is not None,
        "blocked_by": first,
        "rules": rules,
        "draft": None,
        "headers": [{"name": n, "value": v} for n, v in pairs],
    }
    if draft is not None:
        try:
            model = HeaderRuleIn.model_validate(dict(draft))
        except ValidationError as exc:
            message = exc.errors()[0].get("msg", "Invalid rule") if exc.errors() else "Invalid rule"
            result["draft"] = {"valid": False, "error": str(message)}
        else:
            hit = rule_hit(model, pairs, rule_id="(draft)")
            result["draft"] = {
                "valid": True,
                "error": "",
                "header": model.header,
                "scope": model.scope,
                "mode": model.mode,
                "needle": model.needle,
                "matched": hit is not None,
                "matched_header": title_case_header(hit.header) if hit else "",
                "matched_field": hit.field if hit else "",
                "matched_text": hit.text if hit else "",
                "already_blocked": first is not None,
            }
    return result


__all__ = [
    "MAX_TEST_HEADERS",
    "HeaderHit",
    "explain_header_rules",
    "header_pairs",
    "header_rule_message",
    "match_header_rule",
    "parse_header_text",
    "rule_hit",
]
