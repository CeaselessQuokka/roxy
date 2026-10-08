"""The admin account (plan 18.3, DESIGN.md D5): only with --import-admin-password, argon2id, bootstrap flag."""

from __future__ import annotations

import json
from typing import Any

import pytest
from argon2 import PasswordHasher, Type, extract_parameters
from argon2.exceptions import VerifyMismatchError
from v1_migration_helpers import rows

from roxy.migration.admin_import import (
    PLAN_MEMORY_COST_KIB,
    PLAN_PARALLELISM,
    PLAN_TIME_COST,
    choose_hasher,
    plan_hasher,
)
from roxy.migration.report import ALREADY, IMPORTED, KEPT, NOT_IMPORTED


async def test_migration_admin_not_imported_without_the_flag(v1: Any, ws: Any, migrate: Any) -> None:
    v1.V1TreeBuilder(ws.v1).write()
    report = await migrate()
    assert report.admin["status"] == NOT_IMPORTED
    assert rows(ws.state / "control.db", "SELECT count(*) FROM admin_users")[0][0] == 0


async def test_migration_admin_password_import(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.V1TreeBuilder(ws.v1)
    builder.write()
    report = await migrate(admin=True)
    secrets = builder.secrets
    control = ws.state / "control.db"
    (user,) = rows(control, "SELECT * FROM admin_users")
    assert user["username"] == secrets.username
    assert user["email"] == secrets.email_to
    assert user["mfa_bootstrap_pending"] == 1
    assert user["totp_secret_enc"] is None
    encoded = user["password_hash"]
    assert encoded.startswith("$argon2id$")
    assert secrets.password not in encoded
    assert PasswordHasher().verify(encoded, secrets.password)
    parameters = extract_parameters(encoded)
    assert (parameters.time_cost, parameters.memory_cost, parameters.parallelism) == (
        PLAN_TIME_COST,
        PLAN_MEMORY_COST_KIB,
        PLAN_PARALLELISM,
    )
    assert report.admin["status"] == IMPORTED
    assert report.admin["mfa_bootstrap_pending"] is True
    assert report.admin["email"] == "o***@example.invalid"

    (audit,) = rows(control, "SELECT * FROM audit_log WHERE action = 'admin_user.import'")
    assert audit["actor"] == "import:v1"
    assert encoded not in (audit["after_json"] or "")
    assert json.loads(audit["after_json"])["mfa_bootstrap_pending"] == 1


async def test_migration_admin_existing_account_is_kept(v1: Any, ws: Any, migrate: Any) -> None:
    """A rerun finds the account (already imported); a changed v1 password never overwrites the v2 hash."""
    builder = v1.V1TreeBuilder(ws.v1)
    builder.write()
    original = builder.secrets.password
    await migrate(admin=True)
    again = await migrate(admin=True)
    assert again.admin["status"] == ALREADY

    changed_password = original + "-changed"
    builder.secrets.password = changed_password
    builder.write()
    changed = await migrate(admin=True)
    assert changed.admin["status"] == KEPT
    (user,) = rows(ws.state / "control.db", "SELECT password_hash FROM admin_users")
    assert PasswordHasher().verify(user[0], original)
    with pytest.raises(VerifyMismatchError):
        PasswordHasher().verify(user[0], changed_password)


@pytest.mark.parametrize("make", [choose_hasher, plan_hasher])
def test_hashers_are_argon2id_with_plan_parameters(make: Any) -> None:
    """The admin auth module's hasher (when importable) and the fallback agree on plan 9.5."""
    hasher = make()
    assert (hasher.time_cost, hasher.memory_kib, hasher.parallelism) == (3, 65536, 2)
    encoded = hasher.hash("fake-test-password-1234")
    assert extract_parameters(encoded).type is Type.ID
    assert hasher.verify(encoded, "fake-test-password-1234")
    assert not hasher.verify(encoded, "something-else-entirely")
    assert hasher.parameters == "argon2id t=3 m=65536KiB p=2"


def test_choose_hasher_uses_the_admin_auth_module() -> None:
    pytest.importorskip("roxy.admin.auth.passwords")
    assert "roxy.admin.auth.passwords" in choose_hasher().source


async def test_migration_admin_weak_password_is_reported(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.V1TreeBuilder(ws.v1)
    builder.secrets.password = "short"
    builder.write()
    report = await migrate(admin=True)
    assert report.admin["status"] == IMPORTED
    assert any("v2 password policy" in warning for warning in report.warnings)
    assert "short" not in " ".join(report.warnings)


async def test_migration_admin_invalid_username_is_refused(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.V1TreeBuilder(ws.v1)
    builder.secrets.username = "owner name with spaces"
    builder.write()
    report = await migrate(admin=True)
    assert report.admin["status"] == "skipped"
    assert rows(ws.state / "control.db", "SELECT count(*) FROM admin_users")[0][0] == 0
