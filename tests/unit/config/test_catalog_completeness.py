"""Catalog completeness: every key of plan 15.3 (tables A to K, E2, J2) exists in the assembled catalog, and every
environment variable of table L exists in `EnvSettings`.

What this is
    The plan's key tables copied here as explicit lists, one list per table, checked against `CATALOG` (the
    merged catalog built from all twelve group modules plus the generated per-rule settings).

Why it exists
    Each group module has its own test, but each of those only sees its own module. This test is the one place
    that proves the whole contract of plan 15.3 landed: no key was forgotten between modules, none was put in two
    modules, nothing outside the plan slipped in, and the catalog loads in full (no `ROXY_CATALOG_PARTIAL`).

How it works
    Keys are written out by hand from the plan tables (rows that join keys with "/" are split). For J2 the plan
    says "for every rule id in 11.5 the catalog generates `insight_<rule_id>_enabled` and `_severity`", so the
    rule ids are listed explicitly and those two keys are formed from them; every threshold key is listed in full.
    Table L lists environment variables, which are restart-only deployment facts rather than catalog settings
    (plan 15.3 L), so they are checked against `EnvSettings` by setting each variable and reading it back.

What to read next
    `roxy/config/catalog.py` (how the catalog is assembled), `roxy/config/env.py`, and REMAKE_PLAN.md 15.3.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from roxy.config import catalog
from roxy.config.env import REMOVED_ENV_VARS, EnvSettings
from roxy.config.spec import Group

# --- plan 15.3 A. Routing and egress -----------------------------------------------------------------------------
PLAN_A = [
    "direct_enabled",
    "direct_weight",
    "rotator_weight",
    "direct_shift_threshold_pct",
    "rotator_enabled",
    "rotator_cooldown_s",
    "rotator_max_failures",
    "rotator_session_mode",
    "rotator_sticky_seconds",
    "rotator_country",
    "rotator_session_username_template",
    "rotator_max_sessions",
    "rotator_cooldown_distinct_exits",
    "rotator_cooldown_window_s",
    "rotator_quota_gb_per_month",
    "rotator_price_per_gb_usd",
    "rotator_billing_day",
    "rotator_budget_alert_pcts",
    "rotator_hard_stop_pct",
    "rotator_daily_cap_mb",
    "rotator_tls_overhead_bytes",
    "rotator_probe_timeout_s",
    "rotator_recent_ips",
    "strict_host_allowlist",
    "allowed_roblox_hosts",
    "upstream_max_attempts",
    "fallback_on_429",
    "request_timeout",
    "upstream_connect_timeout_s",
    "direct_user_agent",
    "ua_experiment_enabled",
    "ua_experiment_days",
    "ua_experiment_alt_user_agent",
]

# --- plan 15.3 B. Credential -------------------------------------------------------------------------------------
PLAN_B = [
    "credential_enabled",
    "credential_endpoint_allowlist",
    "credential_bucket_per_min",
    "credential_bucket_burst",
    "credential_probe_interval_min",
    "credential_probe_url",
    "credential_probe_reserved_per_min",
    "credential_cooldown_default_s",
]

# --- plan 15.3 C. Upstream pacing and resilience -----------------------------------------------------------------
PLAN_C = [
    "global_bucket_per_min",
    "global_bucket_burst",
    "direct_bucket_per_min",
    "direct_bucket_burst",
    "rotator_bucket_per_min",
    "rotator_bucket_burst",
    "host_bucket_default_per_min",
    "host_bucket_default_burst",
    "endpoint_bucket_default_per_min",
    "endpoint_bucket_default_burst",
    "adaptive_rate_enabled",
    "adaptive_decrease_pct",
    "adaptive_increase_pct",
    "adaptive_probe_after_h",
    "adaptive_min_per_min",
    "adaptive_max_per_min",
    "aimd_enabled",
    "aimd_initial",
    "aimd_min",
    "aimd_max",
    "aimd_increase_after",
    "aimd_decrease_factor",
    "cooldown_default_s",
    "cooldown_min_s",
    "cooldown_max_s",
    "cooldown_host_escalation_endpoints",
    "cooldown_host_escalation_window_s",
    "breaker_failure_threshold",
    "breaker_window_s",
    "breaker_failure_ratio",
    "breaker_open_s",
    "backoff_base_ms",
    "backoff_cap_ms",
    "queue_wait_interactive_ms",
    "queue_wait_stale_ms",
    "queue_wait_background_ms",
    "queue_wait_admin_ms",
    "queue_wait_internal_ms",
    "queue_max_length",
    "request_deadline_s",
    "csrf_token_cache_s",
]

# --- plan 15.3 D. Cache ------------------------------------------------------------------------------------------
PLAN_D = [
    "cache_enabled",
    "cache_ttl_seconds",
    "cache_error_ttl_seconds",
    "cache_swr_seconds",
    "cache_stale_seconds",
    "cache_disk_enabled",
    "cache_max_entries",
    "cache_max_bytes",
    "cache_max_body",
    "cache_memory_entries",
    "cache_memory_bytes",
    "cache_eviction_policy",
    "cache_compress",
    "cache_coalesce",
    "cache_coalesce_wait_ms",
    "cache_post_requests",
    "cache_respect_no_cache",
    "cache_serve_throttled",
    "cache_negative_429",
    "cache_default_rules_enabled",
    "ttl_tuner_enabled",
    "ttl_tuner_max_s",
    "swr_max_inflight",
    "request_sample_pct",
    "request_sample_hours",
    "request_sample_max_rows",
]

# --- plan 15.3 E. Throttling and abuse detection (the `spam_<id>_*` row is table E2) --------------------------------
PLAN_E = [
    "allowed_requests_per_minute",
    "throttle_reset_duration",
    "throttle_window_mode",
    "throttle_count_cache_hits",
    "stale_ip_duration",
    "throttle_escalation_enabled",
    "throttle_strike_decay_seconds",
    "throttle_strike_on_retry",
    "global_throttle_limit",
    "global_throttle_period",
    "user_agent_rules_enabled",
    "flood_limit_per_minute",
    "place_limit_enabled",
    "place_limit_per_minute",
    "place_limit_key",
    "roblox_egress_cidrs",
    "ipv6_limit_prefix",
    "spam_enabled",
    "spam_dry_run",
    "ban_disguise_as_throttle",
    "bot_score_block_threshold",
    "bot_score_legit_max",
    "bot_score_abuse_min",
    "bot_weight_library_ua",
    "bot_weight_no_roblox_signature",
    "bot_weight_probes",
    "bot_weight_refusals",
    "bot_weight_timing",
    "bot_weight_header_order",
    "bot_weight_cache_busting",
    "challenge_enabled",
    "challenge_difficulty_bits",
    "challenge_trigger_score",
    "challenge_cookie_minutes",
    "bypass_default_expiry_h",
    "ignored_paths",
    "max_body_bytes",
    "max_header_count",
    "max_header_bytes",
    "max_url_length",
]

# --- plan 15.3 E2. Spam detectors --------------------------------------------------------------------------------
PLAN_E2 = [
    "spam_rate_enabled",
    "spam_rate_threshold",
    "spam_rate_window_s",
    "spam_rate_action",
    "spam_rate_ban_minutes",
    "spam_rate_ban_max_minutes",
    "spam_refused_enabled",
    "spam_refused_threshold",
    "spam_refused_window_s",
    "spam_refused_action",
    "spam_refused_ban_minutes",
    "spam_refused_ban_max_minutes",
    "spam_probe_enabled",
    "spam_probe_threshold",
    "spam_probe_window_s",
    "spam_probe_action",
    "spam_probe_ban_minutes",
    "spam_probe_ban_max_minutes",
    "spam_auth_enabled",
    "spam_auth_threshold",
    "spam_auth_window_s",
    "spam_auth_action",
    "spam_auth_ban_minutes",
    "spam_auth_ban_max_minutes",
    "spam_enum_enabled",
    "spam_enum_threshold",
    "spam_enum_window_s",
    "spam_enum_action",
    "spam_enum_ban_minutes",
    "spam_enum_ban_max_minutes",
    "spam_bust_enabled",
    "spam_bust_threshold",
    "spam_bust_window_s",
    "spam_bust_action",
    "spam_bust_ban_minutes",
    "spam_bust_ban_max_minutes",
    "spam_dist_enabled",
    "spam_dist_threshold",
    "spam_dist_window_s",
    "spam_dist_action",
    "spam_dist_ban_minutes",
    "spam_dist_ban_max_minutes",
]

# --- plan 15.3 F. Tarpit -----------------------------------------------------------------------------------------
PLAN_F = [
    "tarpit_enabled",
    "tarpit_min_seconds",
    "tarpit_max_seconds",
    "tarpit_max_concurrent",
    "tarpit_max_capacity_fraction",
    "tarpit_connection_budget",
    "tarpit_slot_grace_s",
    "tarpit_default_type",
    "tarpit_drip_interval_ms",
    "tarpit_jitter_min_ms",
    "tarpit_jitter_max_ms",
    "tarpit_on_header_rule",
    "tarpit_on_probe",
    "tarpit_on_throttle",
    "tarpit_on_throttle_all",
    "tarpit_on_endpoint_rule",
    "tarpit_on_blocked_endpoint",
    "tarpit_on_auth_attempt",
    "tarpit_on_user_agent_rule",
    "tarpit_on_ban",
    "tarpit_on_spam",
    "tarpit_on_upstream_cooldown_retry",
]

# --- plan 15.3 G. Admin security and sessions --------------------------------------------------------------------
PLAN_G = [
    "admin_session_idle_timeout_s",
    "admin_heartbeat_interval_s",
    "admin_activity_window_s",
    "admin_session_max_age_s",
    "admin_reauth_window_s",
    "admin_login_max_failures",
    "admin_login_window_s",
    "admin_login_global_max_per_min",
    "admin_login_global_delay_s",
    "admin_email_code_enabled",
    "two_fa_expiration",
    "email_code_digits",
    "challenge_expiration",
    "admin_trusted_devices_enabled",
    "trusted_device_days",
    "invalidation_link_ttl_s",
    "admin_allowlist_enabled",
]

# --- plan 15.3 H. Alerts and email -------------------------------------------------------------------------------
PLAN_H = [
    "error_email_cooldown",
    "email_cooldown",
    "alert_webhook_enabled",
    "alert_min_severity",
    "alert_digest_hour",
    "alert_rate_limit_per_hour",
    "health_auto_interval_h",
    "health_auto_include_credential",
]

# --- plan 15.3 I. Metrics, records, retention, capture -----------------------------------------------------------
PLAN_I = [
    "metrics_flush_interval_ms",
    "metrics_queue_max",
    "retention_minute_days",
    "retention_hour_days",
    "retention_day_days",
    "retention_client_minute_days",
    "retention_client_hour_days",
    "retention_client_day_days",
    "retention_events_days",
    "retention_upstream_429_days",
    "retention_recommendations_days",
    "retention_health_days",
    "retention_fingerprints_days",
    "retention_errors_days",
    "retention_anomalies_days",
    "retention_audit_days",
    "retention_settings_history_days",
    "retention_expired_bans_days",
    "retention_exports_days",
    "retention_snapshots_days",
    "events_max_rows",
    "upstream_429_max_rows",
    "health_runs_max",
    "snapshots_max_bytes",
    "storage_total_budget_gb",
    "maintenance_hour",
    "live_tail_buffer",
    "max_exploit_records",
    "max_login_records",
    "max_crawl_records",
    "max_throttle_records",
    "max_endpoint_records",
    "max_header_name_records",
    "max_header_value_records",
    "max_user_agent_records",
    "max_error_records",
    "endpoint_recent_requests",
    "activity_tracking",
    "max_ip_activity_records",
    "max_caller_records",
    "auto_ignore_high_cardinality",
    "capture_enabled",
    "capture_max_records",
    "capture_max_bytes",
    "capture_max_body",
    "capture_ttl_seconds",
    "capture_sample_served_pct",
    "log_hash_client_ips",
    "export_include_ips",
    "export_stable_ip_hash",
]

# --- plan 15.3 J. Insights ---------------------------------------------------------------------------------------
PLAN_J = [
    "insights_enabled",
    "insights_interval_s",
    "insights_auto_apply",
    "auto_apply_max_per_hour",
    "auto_apply_max_step_pct",
    "auto_apply_watch_minutes",
    "auto_apply_rollback_threshold_pct",
    "recommendation_expiry_days",
    "dismiss_cooldown_days",
    "insight_cred_probe_cost_max_per_hour",
]

# --- plan 15.3 J2. Per-rule settings -----------------------------------------------------------------------------
# Every rule id of plan 11.5 (50 rules). Each one gets `insight_<id>_enabled` and `insight_<id>_severity`.
PLAN_RULE_IDS = [
    "UP-429-ENDPOINT",
    "UP-429-HOST",
    "UP-429-CREDENTIAL",
    "UP-429-AMPLIFY",
    "UP-RETRYAFTER-IGNORED",
    "UP-4XX-SPIKE",
    "UP-CSRF-LOOP",
    "UP-CHALLENGE",
    "UP-UA-EXPERIMENT",
    "UP-5XX",
    "UP-TIMEOUT",
    "UP-LATENCY",
    "UP-QUEUE-SAT",
    "UP-BUCKET-TUNE",
    "UP-BREAKER-FLAP",
    "CACHE-LOW-HIT",
    "CACHE-TTL-TUNE",
    "CACHE-KEYSPLIT",
    "CACHE-PRESSURE",
    "CACHE-OFF",
    "CACHE-NEG",
    "HOT-ENDPOINT",
    "HOST-ADD",
    "EGR-BURN",
    "EGR-UNDERUSE",
    "EGR-POOL-BURNED",
    "EGR-CALIBRATE",
    "CRED-EXPIRING",
    "CRED-UNUSED",
    "CRED-ROTATOR-GUARD",
    "CRED-PROBE-COST",
    "ABUSE-SPAM",
    "ABUSE-BOT",
    "ABUSE-DIST",
    "FILTER-ADD",
    "FILTER-REMOVE",
    "FILTER-COLLATERAL",
    "TARPIT-TUNE",
    "THROTTLE-TUNE",
    "PLACE-HEAVY",
    "SYS-DISK",
    "SYS-WORKER-SAT",
    "SYS-LOOP-LAG",
    "SYS-ERRORS",
    "SYS-METRICS-DROP",
    "SYS-CHANGE-REGRESSION",
    "SYS-HEALTH-FAIL",
    "SEC-ADMIN-ALLOWLIST",
    "SEC-BYPASS-FOREVER",
    "SEC-DEFAULTS",
]

# Every generated threshold setting in the J2 table, written out in full.
PLAN_J2_THRESHOLDS = [
    "insight_up_429_endpoint_min_429s",
    "insight_up_429_endpoint_share_pct",
    "insight_up_429_endpoint_window_min",
    "insight_up_429_endpoint_high_confidence_n",
    "insight_up_429_host_min_templates",
    "insight_up_429_host_window_min",
    "insight_up_429_credential_min_429s",
    "insight_up_429_amplify_calls_per_request",
    "insight_up_retryafter_ignored_min_retries",
    "insight_up_retryafter_ignored_window_min",
    "insight_up_4xx_spike_baseline_multiple",
    "insight_up_4xx_spike_min_responses",
    "insight_up_4xx_spike_min_calls",
    "insight_up_4xx_spike_window_min",
    "insight_up_csrf_loop_retry_pct",
    "insight_up_csrf_loop_window_min",
    "insight_up_challenge_min_pages",
    "insight_up_challenge_window_min",
    "insight_up_ua_experiment_min_calls_per_arm",
    "insight_up_5xx_rate_pct",
    "insight_up_5xx_window_min",
    "insight_up_5xx_min_calls",
    "insight_up_timeout_rate_pct",
    "insight_up_timeout_window_min",
    "insight_up_latency_p95_ms",
    "insight_up_latency_p99_ms",
    "insight_up_latency_window_min",
    "insight_up_latency_min_calls",
    "insight_up_queue_sat_drop_pct",
    "insight_up_queue_sat_p95_wait_ms",
    "insight_up_bucket_tune_clean_hours",
    "insight_up_bucket_tune_rejection_pct",
    "insight_up_bucket_tune_raise_pct",
    "insight_up_bucket_tune_lower_pct",
    "insight_up_breaker_flap_openings_per_hour",
    "insight_cache_low_hit_top_n",
    "insight_cache_low_hit_max_hit_ratio_pct",
    "insight_cache_low_hit_window_min",
    "insight_cache_ttl_tune_identical_raise_pct",
    "insight_cache_ttl_tune_identical_lower_pct",
    "insight_cache_ttl_tune_min_refetches",
    "insight_cache_ttl_tune_window_h",
    "insight_cache_keysplit_min_entries",
    "insight_cache_keysplit_distinct_pct",
    "insight_cache_keysplit_max_hit_pct",
    "insight_cache_pressure_young_eviction_pct",
    "insight_cache_pressure_window_min",
    "insight_cache_neg_min_404_per_hour",
    "insight_hot_endpoint_top_n",
    "insight_host_add_min_places",
    "insight_host_add_min_ips",
    "insight_host_add_window_h",
    "insight_egr_burn_projected_pct",
    "insight_egr_underuse_direct_429_pct",
    "insight_egr_underuse_rotator_429_max_pct",
    "insight_egr_underuse_quota_used_max_pct",
    "insight_egr_pool_burned_rotator_429_pct",
    "insight_egr_pool_burned_window_min",
    "insight_egr_calibrate_diff_pct",
    "insight_cred_unused_min_comparisons",
    "insight_cred_unused_identical_pct",
    "insight_abuse_bot_min_requests_per_hour",
    "insight_filter_add_refusals_per_hour",
    "insight_filter_add_hours",
    "insight_filter_remove_idle_rule_days",
    "insight_filter_remove_idle_bypass_days",
    "insight_filter_collateral_served_pct",
    "insight_tarpit_tune_skipped_pct",
    "insight_throttle_tune_legit_throttled_pct",
    "insight_place_heavy_share_pct",
    "insight_place_heavy_window_min",
    "insight_sys_disk_budget_pct",
    "insight_sys_disk_free_disk_pct",
    "insight_sys_disk_dims_per_minute",
    "insight_sys_worker_sat_cpu_pct",
    "insight_sys_worker_sat_window_min",
    "insight_sys_loop_lag_p99_ms",
    "insight_sys_loop_lag_window_min",
    "insight_sys_errors_baseline_multiple",
    "insight_sys_errors_caller_500_pct",
    "insight_sys_errors_window_min",
    "insight_sys_change_regression_worse_pct",
    "insight_sys_change_regression_watch_min",
    "insight_sys_change_regression_baseline_h",
    "insight_sec_admin_allowlist_max_networks",
    "insight_sec_admin_allowlist_days",
]


def _rule_slug(rule_id: str) -> str:
    return rule_id.lower().replace("-", "_")


PLAN_J2 = [
    *(f"insight_{_rule_slug(rule)}_{suffix}" for rule in PLAN_RULE_IDS for suffix in ("enabled", "severity")),
    *PLAN_J2_THRESHOLDS,
]

# --- plan 15.3 K. Public site and compatibility (plus the `ui_*` dashboard keys) ---------------------------------
PLAN_K = [
    "pause_message_default",
    "compat_collapse_upstream_errors",
    "public_cors_allow_any_origin",
    "public_status_page_enabled",
    "site_contact_name",
    "site_bug_bounty_text",
    "site_hosting_note",
    "site_support_links",
    "site_white_hats_text",
    "site_footer_text",
    "ui_timezone",
    "ui_default_theme",
]

# Table -> (keys, the Settings page groups those keys may live in).
PLAN_TABLES: dict[str, tuple[list[str], frozenset[Group]]] = {
    "A": (PLAN_A, frozenset({Group.ROUTING})),
    "B": (PLAN_B, frozenset({Group.CREDENTIAL})),
    "C": (PLAN_C, frozenset({Group.UPSTREAM})),
    "D": (PLAN_D, frozenset({Group.CACHE})),
    "E": (PLAN_E, frozenset({Group.THROTTLING, Group.ABUSE})),
    "E2": (PLAN_E2, frozenset({Group.ABUSE})),
    "F": (PLAN_F, frozenset({Group.TARPIT})),
    "G": (PLAN_G, frozenset({Group.ADMIN_SECURITY})),
    "H": (PLAN_H, frozenset({Group.ALERTS})),
    "I": (PLAN_I, frozenset({Group.METRICS})),
    "J": (PLAN_J, frozenset({Group.INSIGHTS})),
    "J2": (PLAN_J2, frozenset({Group.INSIGHT_RULES})),
    "K": (PLAN_K, frozenset({Group.PUBLIC_SITE, Group.DASHBOARD})),
}

ALL_PLAN_KEYS = [key for keys, _groups in PLAN_TABLES.values() for key in keys]

# --- plan 15.3 L. Environment and deployment (restart required) --------------------------------------------------
# Env var -> (EnvSettings field, a valid sample value, the value the field must then hold, as text).
PLAN_L: dict[str, tuple[str, str, str]] = {
    "ROXY_ENV": ("env", "development", "development"),
    "ROXY_WORKERS": ("workers", "3", "3"),
    "ROXY_BIND": ("bind", "127.0.0.1:8002", "127.0.0.1:8002"),
    "ROXY_INTERNAL_SOCKET": ("internal_socket", "/run/roxy-green/internal.sock", "/run/roxy-green/internal.sock"),
    "ROXY_MAX_REQUESTS": ("max_requests", "1000", "1000"),
    "ROXY_TRUSTED_PROXY_HOPS": ("trusted_proxy_hops", "2", "2"),
    "ROXY_TRUSTED_PROXY_CIDRS": ("trusted_proxy_cidrs", "10.0.0.0/8", "10.0.0.0/8"),
    "ROXY_NGINX_WORKER_PROCESSES": ("nginx_worker_processes", "2", "2"),
    "ROXY_NGINX_WORKER_CONNECTIONS": ("nginx_worker_connections", "768", "768"),
    "ROXY_SEND_HSTS": ("send_hsts", "1", "True"),
    "ROXY_LOG_LEVEL": ("log_level", "warning", "warning"),
    "ROXY_STATE_DIR": ("state_dir", "/srv/roxy-test-state", "/srv/roxy-test-state"),
    "ROXY_CONTROL_DB": ("control_db", "/srv/roxy-test-state/c.db", "/srv/roxy-test-state/c.db"),
    "ROXY_HOT_DB": ("hot_db", "/srv/roxy-test-state/h.db", "/srv/roxy-test-state/h.db"),
    "ROXY_METRICS_DB": ("metrics_db", "/srv/roxy-test-state/m.db", "/srv/roxy-test-state/m.db"),
    "ROXY_CACHE_DB": ("cache_db", "/srv/roxy-test-state/k.db", "/srv/roxy-test-state/k.db"),
    "ROXY_ROTATOR_IP_ECHO_URL": ("rotator_ip_echo_url", "https://echo.example.test/ip", "https://echo.example.test/ip"),
    "ROXY_BACKUP_REMOTE": ("backup_remote", "offsite", "offsite"),
    "ROXY_SITE_ORIGIN": ("site_origin", "https://proxy.example.test", "https://proxy.example.test"),
}

# Variables v2 removed (plan 15.3 L): read only by the v1 migrator, ignored and reported by the lifespan.
PLAN_L_REMOVED = [
    "ROXY_THREADS",
    "ROXY_ROTATE_PROXY",
    "ROXY_ROTATE_PROXY_FILE",
    "ROXY_FILE_ROOT",
    "ROXY_DATA_FILE",
    "ROXY_STATE_FILE",
    "ROXY_ROUTING_FILE",
    "ROXY_THROTTLE_FILE",
    "ROXY_COORD_FILE",
    "ROXY_TARPIT_FILE",
    "ROXY_WORKERS_FILE",
    "ROXY_CAPTURE_FILE",
    "ROXY_CACHE_DIR",
    "ROXY_ACCESS_LOG",
]


# Plan 15.3 keys that are deliberately NOT settings, because plan 6.2 keeps the same data in a control.db table
# that the rules store reads (spec review 3 and 4; recorded in CHANGES.md). A setting next to the table would be a
# second, disconnected source: editing it would change nothing.
REPLACED_BY_TABLES = {
    "credential_endpoint_allowlist": "credential_allowlist",
    "ignored_paths": "ignored_paths",
}


# --- catalog tests -----------------------------------------------------------------------------------------------


def test_keys_replaced_by_tables_are_tables_not_settings() -> None:
    from roxy.rules.models import RULE_TABLES

    for key, table in REPLACED_BY_TABLES.items():
        assert key not in catalog.CATALOG, key
        assert table in RULE_TABLES, table


def test_catalog_loaded_in_full() -> None:
    """No partial mode, no missing module, no self check problem, every Settings page group populated."""
    assert catalog.PARTIAL is False, "run without ROXY_CATALOG_PARTIAL"
    assert catalog.MISSING_MODULES == ()
    assert catalog.SELF_CHECK_PROBLEMS == ()
    assert [group for group in Group if not catalog.GROUPED.get(group)] == []


def test_plan_tables_list_each_key_once() -> None:
    """A key listed in two plan tables here would hide a missing one."""
    assert len(ALL_PLAN_KEYS) == len(set(ALL_PLAN_KEYS))
    assert len(PLAN_RULE_IDS) == len(set(PLAN_RULE_IDS)) == 50


@pytest.mark.parametrize("table", sorted(PLAN_TABLES))
def test_every_plan_key_is_in_the_catalog(table: str) -> None:
    keys, _groups = PLAN_TABLES[table]
    missing = [key for key in keys if key not in catalog.CATALOG and key not in REPLACED_BY_TABLES]
    assert missing == [], f"plan 15.3 {table} keys missing from the catalog"


@pytest.mark.parametrize("table", sorted(PLAN_TABLES))
def test_plan_keys_sit_in_their_settings_group(table: str) -> None:
    keys, groups = PLAN_TABLES[table]
    keys = [key for key in keys if key not in REPLACED_BY_TABLES]
    wrong = {key: catalog.CATALOG[key].group.value for key in keys if catalog.CATALOG[key].group not in groups}
    assert wrong == {}, f"plan 15.3 {table} keys outside {sorted(g.value for g in groups)}"


def test_catalog_has_no_key_outside_the_plan() -> None:
    """Plan 15.3 is the contract for keys: a new setting is added to the plan table first, then here."""
    extra = sorted(set(catalog.CATALOG) - set(ALL_PLAN_KEYS))
    assert extra == []


def test_every_plan_rule_has_insight_params() -> None:
    assert sorted(catalog.INSIGHT_RULES) == sorted(PLAN_RULE_IDS)


# --- environment (table L) tests ---------------------------------------------------------------------------------


@pytest.fixture
def clean_environ(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """No ROXY_* or systemd credential variables from the shell leak into these checks."""
    for name in list(os.environ):
        if name.startswith("ROXY_") or name == "CREDENTIALS_DIRECTORY":
            monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.mark.parametrize("variable", sorted(PLAN_L))
def test_every_plan_env_var_is_read(variable: str, clean_environ: pytest.MonkeyPatch) -> None:
    field, sample, expected = PLAN_L[variable]
    assert field in EnvSettings.model_fields, f"{variable} has no EnvSettings field"
    clean_environ.setenv(variable, sample)
    value = getattr(EnvSettings(), field)
    if isinstance(value, tuple):
        text = ",".join(str(item) for item in value)
    elif isinstance(value, Path):
        text = value.as_posix()
    else:
        text = str(value)
    assert text == expected


def test_removed_env_vars_are_known() -> None:
    assert sorted(PLAN_L_REMOVED) == sorted(REMOVED_ENV_VARS)
    for variable in PLAN_L_REMOVED:
        assert variable.removeprefix("ROXY_").lower() not in EnvSettings.model_fields
