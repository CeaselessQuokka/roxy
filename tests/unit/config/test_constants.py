"""Tests for `roxy.config.constants`: every plan 15.4 "Kept as a constant" row, pinned to its v2 value."""

from __future__ import annotations

import inspect
import re
import typing
from pathlib import Path

from roxy.config import catalog, constants
from roxy.core import redact
from roxy.core.reasons import Source
from roxy.rules import models

# Plan 15.4 "Kept as a constant": name -> v2 value.
PLAN_15_4 = {
    "CACHEABLE_ERROR_STATUSES": frozenset({400, 403, 404, 410}),
    "MAX_THROTTLE_TIERS": 12,
    "MAX_THROTTLE_MULTIPLIER": 1000,
    "MAX_TRACKED_STRIKE_TIERS": 32,
    "MAX_ENDPOINT_RULES": 200,
    "MAX_ENDPOINT_BLOCKS": 200,
    "MAX_CACHE_RULES": 500,
    "MAX_USER_AGENT_RULES": 100,
    "MAX_HEADER_RULES": 100,
    "MAX_THROTTLE_BYPASS_IPS": 500,
    "MAX_CACHE_IGNORED_PARAMS": 100,
    "MAX_IGNORED_VALUE_HEADERS": 200,
    "MAX_RULE_MESSAGE": 400,
    "MAX_USER_AGENT_NEEDLE": 200,
    "MAX_USER_AGENT_RULE_COOLDOWN": 3600,
    "DEFAULT_USER_AGENT_RULE_LIMIT": 10,
    "DEFAULT_USER_AGENT_RULE_PERIOD": 60,
    "DEFAULT_USER_AGENT_RULE_COOLDOWN": 2.0,
    "DEFAULT_ENDPOINT_RULE_PERIOD": 60,
    "DEFAULT_CACHE_RULE_TTL": 300,
    "CACHE_PAGE_MAX": 200,
    "MAX_SPREAD_VALUES": 500,
    "MIN_SPREAD_ENTRIES": 5,
    "MAX_LIVE_BODY_LENGTH": 2000,
    "MAX_ENDPOINT_RECENT_BODY": 600,
    "MAX_ENDPOINT_RECENT_REQUESTS": 50,
    "MAX_CONCRETE_PER_TEMPLATE": 100,
    "MAX_IPS_PER_ENDPOINT_RECORD": 25,
    "MAX_IPS_PER_ATTEMPT_RECORD": 50,
    "ACTIVITY_ENDPOINTS_PER_RECORD": 12,
    "MAX_REFUSAL_RECORDS": 100,
    "MAX_INTERNAL_REQUEST_RECORDS": 50,
    "MAX_REQUEST_FAILURE_RECORDS": 500,
    "MAX_STATUS_CODES": 200,
    "MAX_RETRY_REASONS": 100,
    "MAX_EXPLOIT_SUMMARY": 100,
    "MAX_TRACKED_THROTTLE_IPS": 200_000,
    "MAX_TRACKED_LOGIN_IPS": 100_000,
    "MAX_TARPIT_ARRIVALS": 20_000,
    "MAX_TARPIT_IP_RECORDS": 200,
    "MAX_TARPIT_REASON_RECORDS": 200,
    "MAX_EXPIRABLES_PER_STORE": 500,
    "WORKER_STALE_AFTER": 20,
    "MAX_TRACKED_WORKERS": 64,
    "TOKEN_COOKIE_DOMAIN": ".roblox.com",
    "MAX_TOKEN_CHECK_WORKERS": 1,
    "TOKEN_CHECK_GRACE": 5,
    "MAX_TOKEN_USAGE_RECORDS": 1,
    "SMTP_TIMEOUT_S": 15,
    "ALERT_LOG_LINES": 60,
    "ADMIN_SEEN_COOKIE_MAX_AGE_S": 180 * 86400,
    "AUTO_IGNORE_MIN_REQUESTS": 500,
    "AUTO_IGNORE_UNIQUE_RATIO": 0.9,
}


def test_every_plan_15_4_constant_has_its_value() -> None:
    for name, expected in PLAN_15_4.items():
        assert getattr(constants, name) == expected, name


def test_every_kept_constant_has_a_reason_comment() -> None:
    source = inspect.getsource(constants).splitlines()
    for name in PLAN_15_4:
        line = next(i for i, text in enumerate(source) if re.match(rf"{name}\b", text))
        window = "\n".join(source[max(0, line - 6) : line + 1])
        assert "Reason" in window or "# " in source[line], f"{name} has no reason comment"


def test_token_prefix_is_the_single_copy_from_redact() -> None:
    assert constants.TOKEN_PREFIX is redact.TOKEN_PREFIX
    assert constants.TOKEN_PREFIX.startswith("_|WARNING:-DO-NOT-SHARE-THIS.")


def test_latency_histogram_has_21_mergeable_buckets() -> None:
    bounds = constants.LATENCY_BUCKET_BOUNDS_MS
    assert constants.LATENCY_BUCKET_COUNT == 21
    assert list(bounds) == sorted(set(bounds))
    assert bounds[0] == 5
    assert bounds[-1] == 20000


def test_suggested_params_and_status_sources() -> None:
    assert constants.SUGGESTED_CACHE_IGNORED_PARAMS[-1] == "v"
    assert len(constants.SUGGESTED_CACHE_IGNORED_PARAMS) == 10
    assert tuple(source.value for source in Source) == constants.STATUS_SOURCES


def test_closed_enums_match_the_rule_models() -> None:
    def literal(model: type, field: str) -> tuple[str, ...]:
        annotation = model.model_fields[field].annotation  # type: ignore[attr-defined]
        return tuple(typing.get_args(annotation))

    assert literal(models.UserAgentRuleIn, "mode") == constants.USER_AGENT_RULE_MODES
    assert literal(models.UserAgentRuleIn, "kind") == constants.USER_AGENT_RULE_KINDS
    assert literal(models.UserAgentRuleIn, "scope") == constants.USER_AGENT_RULE_SCOPES
    assert literal(models.HeaderRuleIn, "scope") == constants.HEADER_RULE_SCOPES
    assert literal(models.HeaderRuleIn, "mode") == constants.HEADER_RULE_MODES
    assert literal(models.EndpointLimitIn, "scope") == constants.ENDPOINT_RULE_SCOPES
    assert literal(models.RoutingRuleIn, "mode") == constants.ROUTING_RULE_MODES
    assert literal(models.AccessListIn, "kind") == constants.ACCESS_LIST_KINDS
    assert literal(models.BanIn, "subject_type") == constants.BAN_SUBJECT_TYPES
    assert literal(models.ThrottleTierIn, "action") == constants.THROTTLE_TIER_ACTIONS


def test_tarpit_categories_match_the_catalog_switches() -> None:
    switches = {key.removeprefix("tarpit_on_") for key in catalog.CATALOG if key.startswith("tarpit_on_")}
    assert set(constants.TARPIT_CATEGORIES) == switches
    assert {"ban", "spam", "upstream_cooldown_retry", "user_agent_rule"} <= set(constants.TARPIT_CATEGORIES)


def test_table_caps_replace_the_removed_list_settings() -> None:
    # The ignored paths and the credential allowlist are tables only (spec review 3 and 4): their caps live
    # here, and no list setting with its own limit exists next to them any more.
    assert "ignored_paths" not in catalog.CATALOG
    assert "credential_endpoint_allowlist" not in catalog.CATALOG
    assert constants.MAX_IGNORED_PATHS == 100
    assert constants.MAX_CREDENTIAL_ALLOWLIST_RULES == 50


def test_no_dash_characters_in_the_new_modules() -> None:
    root = Path(constants.__file__).resolve().parents[1]
    for relative in (
        "config/constants.py",
        "config/defaults.py",
        "config/runtime.py",
        "config/settings_service.py",
        "config/audit.py",
        "rules/models.py",
        "rules/store.py",
        "rules/service.py",
    ):
        text = (root / relative).read_text(encoding="utf-8")
        assert chr(0x2014) not in text, relative
        assert chr(0x2013) not in text, relative
