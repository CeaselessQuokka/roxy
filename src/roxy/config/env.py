"""Environment settings: the deployment facts read once at startup from `ROXY_*` variables (plan 15.3 L).

What this is
    `EnvSettings`, a pydantic-settings model with every environment variable of plan 15.3 L plus `ROXY_COLOR`,
    `ROXY_AUTO_MIGRATE` and the systemd credentials directory. Changing any of these needs a restart.

Why it exists
    Some configuration is a fact about the machine, not a tunable: which port this color binds, where the
    databases live, which proxies may set `X-Forwarded-For`. Those belong in `/etc/roxy/roxy.env` and the per
    color env file, validated once, so a typo fails the start with a clear message instead of misbehaving later.
    Everything an admin may tune at runtime lives in the settings catalog instead (`config/catalog.py`).
    Secrets are NEVER environment variables (plan 9.8): they are systemd credentials, files in the private
    directory `$CREDENTIALS_DIRECTORY`. This model exposes only that directory. In particular it has no accessor
    for the Roblox credential: only `egress/credential.py` may read that file (plan C2, test 19.5 item 7).

How it works
    pydantic-settings reads `ROXY_<FIELD>` for each field (case-insensitive), converts and validates it, and fills
    defaults. Database paths default to files under `ROXY_STATE_DIR`, and the internal socket defaults to
    `/run/roxy-<color>/internal.sock`, both computed from fields declared before them. The comma separated
    `ROXY_TRUSTED_PROXY_CIDRS` is parsed by our own validator (`NoDecode` stops pydantic-settings from expecting
    JSON). The model is frozen: nothing changes these values while the process runs.
    Tests build one directly: `EnvSettings(state_dir=tmp_path, env="development")`.

What to read next
    `roxy/lifespan.py` (what is done with these values at startup), then `roxy/config/catalog.py`.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from roxy.core.client_ip import IPNetwork, parse_cidrs

DATABASE_NAMES = ("control", "hot", "metrics", "cache")

DEFAULT_TRUSTED_PROXY_CIDRS = "127.0.0.1/32,::1/128"

REMOVED_ENV_VARS = (
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
)
"""v1 variables that v2 ignores (plan 15.3 L). Only `scripts/migrate_from_v1.py` reads them."""

_COLOR_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,15}")
_ORIGIN_RE = re.compile(r"https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?")


def _default_path(data: dict[str, Any], name: str) -> Path:
    return Path(data["state_dir"]) / f"{name}.db"


class EnvSettings(BaseSettings):
    """Deployment configuration from the environment (plan 15.3 L). Restart required for any change."""

    model_config = SettingsConfigDict(
        env_prefix="ROXY_",
        case_sensitive=False,
        extra="ignore",  # unknown and removed ROXY_* variables are ignored (and reported by the lifespan)
        env_ignore_empty=True,  # `ROXY_BACKUP_REMOTE=` means "not set", not the empty string
        populate_by_name=True,
        frozen=True,
    )

    env: Literal["production", "development"] = "production"
    """ROXY_ENV. `development` relaxes Secure cookies on localhost and allows ROXY_AUTO_MIGRATE."""

    color: str = "dev"
    """ROXY_COLOR: which blue/green slot this process is (`blue`, `green`), or `dev`."""

    workers: int = Field(default=2, ge=1, le=32)
    """ROXY_WORKERS: gunicorn worker processes (v1 default was 4; D2 and DESIGN section 0 use 2)."""

    bind: str = "127.0.0.1:8001"
    """ROXY_BIND: the loopback address nginx connects to (blue 8001, green 8002, set per color)."""

    internal_socket: Path = Field(default_factory=lambda data: Path(f"/run/roxy-{data['color']}/internal.sock"))
    """ROXY_INTERNAL_SOCKET: the Unix socket serving `internal_app` (plan 5.8)."""

    max_requests: int = Field(default=20000, ge=0)
    """ROXY_MAX_REQUESTS: recycle a worker after this many requests (0 disables; v1 ignored the variable)."""

    trusted_proxy_hops: int = Field(default=1, ge=0, le=5)
    """ROXY_TRUSTED_PROXY_HOPS: how many proxies in front of the app append to X-Forwarded-For (plan 9.11)."""

    trusted_proxy_cidrs: Annotated[tuple[IPNetwork, ...], NoDecode] = Field(
        default_factory=lambda: parse_cidrs(DEFAULT_TRUSTED_PROXY_CIDRS)
    )
    """ROXY_TRUSTED_PROXY_CIDRS: socket peers whose X-Forwarded-For is believed (comma separated)."""

    nginx_worker_processes: int | None = Field(default=None, ge=1)
    """ROXY_NGINX_WORKER_PROCESSES: hint written by the deploy for the tarpit connection budget (10.6)."""

    nginx_worker_connections: int | None = Field(default=None, ge=1)
    """ROXY_NGINX_WORKER_CONNECTIONS: hint written by the deploy for the tarpit connection budget (10.6)."""

    send_hsts: bool = False
    """ROXY_SEND_HSTS: also send HSTS from the app. Off: nginx owns HSTS (plan 9.1)."""

    log_level: Literal["debug", "info", "warning", "error", "critical"] = "info"
    """ROXY_LOG_LEVEL."""

    state_dir: Path = Path("/var/lib/roxy")
    """ROXY_STATE_DIR: databases, exports and snapshots."""

    control_db: Path = Field(default_factory=lambda data: _default_path(data, "control"))
    """ROXY_CONTROL_DB (default `<state_dir>/control.db`)."""

    hot_db: Path = Field(default_factory=lambda data: _default_path(data, "hot"))
    """ROXY_HOT_DB (default `<state_dir>/hot.db`)."""

    metrics_db: Path = Field(default_factory=lambda data: _default_path(data, "metrics"))
    """ROXY_METRICS_DB (default `<state_dir>/metrics.db`)."""

    cache_db: Path = Field(default_factory=lambda data: _default_path(data, "cache"))
    """ROXY_CACHE_DB (default `<state_dir>/cache.db`)."""

    rotator_ip_echo_url: str = "https://api.ipify.org?format=json"
    """ROXY_ROTATOR_IP_ECHO_URL: the exit IP probe target (plan 8.2)."""

    backup_remote: str | None = None
    """ROXY_BACKUP_REMOTE: rclone remote NAME only; its keys live in the `rclone_config` credential (D15)."""

    site_origin: str = "https://roxytheproxy.com"
    """ROXY_SITE_ORIGIN: public origin used in emails and CSRF origin checks."""

    auto_migrate: bool = False
    """ROXY_AUTO_MIGRATE: run migrations at startup. Honored ONLY when ROXY_ENV=development (plan 5.5)."""

    release_sha: str | None = None
    """ROXY_RELEASE_SHA: the commit this release was built from, reported by /internal/version (optional; the
    release directory name is used when unset)."""

    credentials_dir: Path | None = Field(
        default=None,
        # systemd's variable wins over the development one. `populate_by_name` still allows
        # `EnvSettings(credentials_dir=...)` in tests.
        validation_alias=AliasChoices("CREDENTIALS_DIRECTORY", "ROXY_CREDENTIALS_DIR"),
    )
    """Where the systemd credentials are: `$CREDENTIALS_DIRECTORY` (set by systemd's LoadCredential=), or
    ROXY_CREDENTIALS_DIR in development. Only the DIRECTORY is exposed here; each module that owns a secret reads
    its own file (the Roblox credential only in egress/credential.py)."""

    # --- validators -------------------------------------------------------------------------------------------

    @field_validator("trusted_proxy_cidrs", mode="before")
    @classmethod
    def _parse_cidrs(cls, value: Any) -> Any:
        if isinstance(value, str):
            return parse_cidrs(value)
        if isinstance(value, list | tuple) and all(isinstance(item, str) for item in value):
            return parse_cidrs(value)
        return value

    @field_validator("log_level", "env", mode="before")
    @classmethod
    def _lowercase(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("color")
    @classmethod
    def _check_color(cls, value: str) -> str:
        value = value.strip().lower()
        if not _COLOR_RE.fullmatch(value):
            raise ValueError("ROXY_COLOR must be 1 to 16 lowercase letters, digits, '-' or '_' (blue, green, dev)")
        return value

    @field_validator("site_origin")
    @classmethod
    def _check_origin(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not _ORIGIN_RE.fullmatch(value):
            raise ValueError("ROXY_SITE_ORIGIN must be an origin like https://example.com (no path)")
        return value

    @field_validator("release_sha")
    @classmethod
    def _check_sha(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not re.fullmatch(r"[0-9a-fA-F]{7,64}|[A-Za-z0-9._-]{1,64}", value):
            raise ValueError("ROXY_RELEASE_SHA must be a commit id or a short version label")
        return value

    # --- derived values ---------------------------------------------------------------------------------------

    @property
    def is_development(self) -> bool:
        return self.env == "development"

    @property
    def migrate_on_start(self) -> bool:
        """True only in development with ROXY_AUTO_MIGRATE=1. Production workers never migrate (plan 5.5)."""
        return self.auto_migrate and self.is_development

    def db_paths(self) -> dict[str, Path]:
        """The four database files by name: control, hot, metrics, cache."""
        return {"control": self.control_db, "hot": self.hot_db, "metrics": self.metrics_db, "cache": self.cache_db}


def removed_env_vars_present(environ: Mapping[str, str] | None = None) -> list[str]:
    """Names (never values: ROXY_ROTATE_PROXY holds a password) of v1 variables still set in the environment."""
    source = os.environ if environ is None else environ
    return [name for name in REMOVED_ENV_VARS if name in source]
