"""The alert catalog (plan 17.7): subjects kept exactly, cooldown keys, severities and channels."""

from __future__ import annotations

import pytest

from roxy.notify.alerts import ALERT_SPECS, make_alert

EXPECTED_SUBJECTS = {
    ("error", (("signature", "KeyError at cache.py:88"),)): "Roxy Error: KeyError at cache.py:88",
    ("all_unavailable", ()): "Roxy: all upstream methods unavailable",
    ("credential_rejected", ()): "Token Expired",
    ("credential_cooldown", ()): "Roxy: credential cooling down",
    ("credential_rotated", ()): "Roxy: Roblox sent a new credential cookie",
    ("admin_login", ()): "Roxy Admin Login",
    ("service_down", (("unit", "roxy@blue"), ("host", "box"))): "Roxy DOWN: roxy@blue failed on box",
    ("deploy_failed", (("short_sha", "abc1234"), ("step", 4))): "Roxy: deploy abc1234 failed at step 4",
    ("leak_guard", ()): "Roxy SECURITY: credential leak blocked",
    ("roblox_429", (("rate", "3.1"),)): "Roxy: Roblox is rate-limiting us (3.1%)",
    ("caller_5xx", (("rate", "2.5"),)): "Roxy: caller errors at 2.5%",
    ("rotator_quota", (("pct", 80),)): "Roxy: rotator at 80% of monthly quota",
    ("disk", (("pct", 91),)): "Roxy: storage at 91% of budget",
    ("db_integrity", ()): "Roxy: database integrity check failed",
    ("backup_failed", ()): "Roxy: backup failed",
    ("backup_stale", (("hours", 30),)): "Roxy: no backup for 30 h",
    ("health_failures", (("n", 3), ("fingerprint", "f1"))): "Roxy: health check found 3 new failures",
    ("auto_apply_rollback", (("rec_id", "r1"),)): "Roxy: auto-applied change rolled back",
    ("login_global", ()): "Roxy: login attempts throttled globally",
    ("digest", (("n", 4), ("day", "2026-10-07"))): "Roxy daily digest: 4 open recommendations",
}


@pytest.mark.parametrize(("key", "subject"), list(EXPECTED_SUBJECTS.items()), ids=lambda v: str(v)[:40])
def test_subjects_match_plan_17_7(key: tuple[str, tuple[tuple[str, object], ...]], subject: str) -> None:
    alert_type, params = key
    alert = make_alert(alert_type, summary="s", **dict(params))
    assert alert.subject == subject


def test_every_spec_is_covered() -> None:
    assert {key[0] for key in EXPECTED_SUBJECTS} == set(ALERT_SPECS)


def test_cooldown_keys_severity_and_channels() -> None:
    error = make_alert("error", summary="s", signature="X")
    assert error.cooldown_key == "error:X"
    assert error.severity == "warn"
    assert error.cooldown_s == 300
    assert make_alert("credential_rejected", summary="s").cooldown_key == "credential:rejected"
    login = make_alert("admin_login", summary="s")
    assert login.always_send
    assert login.channels == ("email",)
    assert login.cooldown_key is None
    leak = make_alert("leak_guard", summary="s")
    assert leak.always_send
    assert leak.severity == "critical"
    assert make_alert("rotator_quota", summary="s", pct=95, severity="critical").severity == "critical"
    assert make_alert("digest", summary="s", n=1, day="d").channels == ("email",)


def test_parameters_cannot_inject_headers_and_bad_input_fails_loudly() -> None:
    alert = make_alert("error", summary="s", signature="a\r\nBcc: someone@example.invalid")
    assert "\n" not in alert.subject
    assert "\r" not in alert.subject
    with pytest.raises(KeyError):
        make_alert("nope", summary="s")
    with pytest.raises(ValueError):
        make_alert("error", summary="s")  # missing {signature}
    with pytest.raises(ValueError):
        make_alert("error", summary="s", signature="x", severity="loud")
