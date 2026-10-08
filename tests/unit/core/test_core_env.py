"""EnvSettings tests (plan 15.3 L): defaults, parsing, the credentials directory, and no credential accessor."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest
from pydantic import ValidationError

from roxy.config.env import REMOVED_ENV_VARS, EnvSettings, removed_env_vars_present


@pytest.fixture
def clean_environ(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    import os

    for name in list(os.environ):
        if name.startswith("ROXY_") or name == "CREDENTIALS_DIRECTORY":
            monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_defaults_match_plan(clean_environ: pytest.MonkeyPatch) -> None:
    env = EnvSettings()
    assert env.env == "production"
    assert env.workers == 2
    assert env.bind == "127.0.0.1:8001"
    assert env.max_requests == 20000
    assert env.trusted_proxy_hops == 1
    assert env.trusted_proxy_cidrs == (ipaddress.ip_network("127.0.0.1/32"), ipaddress.ip_network("::1/128"))
    assert env.send_hsts is False
    assert env.log_level == "info"
    assert env.state_dir == Path("/var/lib/roxy")
    assert env.control_db == Path("/var/lib/roxy/control.db")
    assert env.cache_db == Path("/var/lib/roxy/cache.db")
    assert env.rotator_ip_echo_url == "https://api.ipify.org?format=json"
    assert env.site_origin == "https://roxytheproxy.com"
    assert env.color == "dev"
    assert env.internal_socket == Path("/run/roxy-dev/internal.sock")
    assert env.auto_migrate is False
    assert env.credentials_dir is None
    assert env.backup_remote is None


def test_values_from_environment(clean_environ: pytest.MonkeyPatch, tmp_path: Path) -> None:
    clean_environ.setenv("ROXY_ENV", "Development")
    clean_environ.setenv("ROXY_COLOR", "green")
    clean_environ.setenv("ROXY_STATE_DIR", str(tmp_path))
    clean_environ.setenv("ROXY_HOT_DB", str(tmp_path / "elsewhere" / "hot.db"))
    clean_environ.setenv("ROXY_TRUSTED_PROXY_CIDRS", "127.0.0.1/32, 198.51.100.0/24 ,::1/128")
    clean_environ.setenv("ROXY_TRUSTED_PROXY_HOPS", "2")
    clean_environ.setenv("ROXY_AUTO_MIGRATE", "1")
    clean_environ.setenv("ROXY_LOG_LEVEL", "DEBUG")
    clean_environ.setenv("ROXY_BACKUP_REMOTE", "")
    clean_environ.setenv("CREDENTIALS_DIRECTORY", str(tmp_path / "creds"))
    env = EnvSettings()
    assert env.is_development
    assert env.migrate_on_start
    assert env.color == "green"
    assert env.internal_socket == Path("/run/roxy-green/internal.sock")
    assert env.control_db == tmp_path / "control.db"
    assert env.hot_db == tmp_path / "elsewhere" / "hot.db"
    assert ipaddress.ip_network("198.51.100.0/24") in env.trusted_proxy_cidrs
    assert env.trusted_proxy_hops == 2
    assert env.log_level == "debug"
    assert env.backup_remote is None  # empty means unset
    assert env.credentials_dir == tmp_path / "creds"
    assert env.db_paths()["metrics"] == tmp_path / "metrics.db"


def test_systemd_credentials_directory_wins(clean_environ: pytest.MonkeyPatch, tmp_path: Path) -> None:
    clean_environ.setenv("ROXY_CREDENTIALS_DIR", str(tmp_path / "dev"))
    assert EnvSettings().credentials_dir == tmp_path / "dev"
    clean_environ.setenv("CREDENTIALS_DIRECTORY", str(tmp_path / "systemd"))
    assert EnvSettings().credentials_dir == tmp_path / "systemd"


def test_auto_migrate_ignored_in_production(clean_environ: pytest.MonkeyPatch) -> None:
    clean_environ.setenv("ROXY_AUTO_MIGRATE", "1")
    env = EnvSettings()
    assert env.auto_migrate is True
    assert env.migrate_on_start is False  # production workers never migrate (plan 5.5)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ROXY_ENV", "staging"),
        ("ROXY_TRUSTED_PROXY_CIDRS", "127.0.0.1/32,nonsense"),
        ("ROXY_COLOR", "Blue Team"),
        ("ROXY_SITE_ORIGIN", "https://roxytheproxy.com/admin"),
        ("ROXY_WORKERS", "0"),
        ("ROXY_LOG_LEVEL", "loud"),
    ],
)
def test_bad_values_fail_startup(clean_environ: pytest.MonkeyPatch, name: str, value: str) -> None:
    clean_environ.setenv(name, value)
    with pytest.raises(ValidationError):
        EnvSettings()


def test_settings_are_frozen(clean_environ: pytest.MonkeyPatch) -> None:
    env = EnvSettings()
    with pytest.raises(ValidationError):
        env.workers = 8  # type: ignore[misc]


def test_no_accessor_for_the_roblox_credential() -> None:
    """Only egress/credential.py may read the credential (plan C2, 19.5 item 7): env exposes the directory only."""
    names = set(EnvSettings.model_fields) | {n for n in dir(EnvSettings) if not n.startswith("_")}
    suspicious = {n for n in names if "roblox" in n.lower() or ("credential" in n.lower() and n != "credentials_dir")}
    assert suspicious == set()


def test_removed_vars_reported_by_name_only() -> None:
    assert removed_env_vars_present({"ROXY_ROTATE_PROXY": "http://u:p@h:1", "ROXY_BIND": "x"}) == ["ROXY_ROTATE_PROXY"]
    assert "ROXY_THREADS" in REMOVED_ENV_VARS
