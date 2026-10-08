"""`scripts/create_admin.py` (plan 9.5): console creation, TOTP confirmation, --reset-mfa, --reset-password."""

from __future__ import annotations

import importlib.util
import io
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from roxy.admin.auth import recovery_codes, totp, users
from roxy.admin.auth.testing import fast_hasher

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "create_admin.py"
GOOD_PASSWORD = "violet tractor ladder 7731"


@pytest.fixture
def script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("create_admin_under_test", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _answers(values: list[str]) -> Callable[[str], str]:
    queue: Iterator[str] = iter(values)
    return lambda _prompt: next(queue)


class _CodeReader:
    """Answers the "enter the code" prompt with the right code for the secret the script printed."""

    def __init__(self, out: io.StringIO) -> None:
        self.out = out

    def __call__(self, _prompt: str) -> str:
        key = self.out.getvalue().split("enter this key by hand: ")[-1].splitlines()[0].replace(" ", "")
        return totp.code_at(key, time.time())


def _run(script: ModuleType, args: list[str], passwords: list[str], *, verify: bool = True) -> tuple[int, str]:
    out = io.StringIO()
    status = script.main(
        args if verify else [*args, "--no-verify"],
        out=out,
        read=_CodeReader(out),
        ask_secret=_answers(passwords),
        hasher=fast_hasher(),
    )
    return status, out.getvalue()


def test_create_then_refuse_duplicate(script: ModuleType, dbs: Any, state_dir: Path, credentials_dir: Path) -> None:
    args = ["--username", "owner", "--state-dir", str(state_dir), "--credentials-dir", str(credentials_dir)]
    status, output = _run(script, args, [GOOD_PASSWORD, GOOD_PASSWORD])
    assert status == 0, output
    assert "Authenticator confirmed." in output
    assert "Recovery codes" in output
    codes = [line.strip() for line in output.splitlines() if recovery_codes.normalize(line.strip() or "x")]
    assert len(codes) == 10
    user = dbs.control.read_sync(lambda c: users.get_by_username(c, "owner"))
    assert user is not None
    assert user.has_totp
    assert not user.mfa_bootstrap_pending
    assert fast_hasher().verify_sync(user.password_hash, GOOD_PASSWORD)
    assert GOOD_PASSWORD not in output
    audit = dbs.control.read_sync(lambda c: c.execute("SELECT actor, action FROM audit_log").fetchall())
    assert ("cli:create_admin", "auth.user_created") in [tuple(row) for row in audit]

    again, text = _run(script, args, [GOOD_PASSWORD, GOOD_PASSWORD])
    assert again == 1
    assert "already exists" in text


def test_policy_and_mismatch_are_explained(
    script: ModuleType, state_dir: Path, credentials_dir: Path, dbs: Any
) -> None:
    args = ["--username", "owner", "--state-dir", str(state_dir), "--credentials-dir", str(credentials_dir)]
    status, output = _run(script, args, ["short", "passwordpassword", GOOD_PASSWORD, "different one here"])
    assert status == 1
    assert "at least 14" in output
    assert "common passwords" in output
    assert "differ" in output
    assert dbs.control.read_sync(lambda c: users.count_users(c)) == 0


def test_reset_mfa_and_password(script: ModuleType, dbs: Any, state_dir: Path, credentials_dir: Path) -> None:
    base = ["--username", "owner", "--state-dir", str(state_dir), "--credentials-dir", str(credentials_dir)]
    assert _run(script, base, [GOOD_PASSWORD, GOOD_PASSWORD])[0] == 0
    before = dbs.control.read_sync(lambda c: users.get_by_username(c, "owner"))
    dbs.control.write_sync(
        lambda c: c.execute(
            "INSERT INTO admin_sessions (id_hash, user_id, created_at, last_seen_at, expires_at, epoch, "
            "csrf_secret_hash, mfa_level) VALUES ('h', ?, 0, 0, 9999999999, 0, 'x', 'totp')",
            (before.id,),
        )
    )
    status, output = _run(script, [*base, "--reset-mfa"], [], verify=False)
    assert status == 0, output
    after = dbs.control.read_sync(lambda c: users.get_by_username(c, "owner"))
    assert after.totp_secret_enc != before.totp_secret_enc
    assert after.recovery_codes_hash_json != before.recovery_codes_hash_json
    assert dbs.control.read_sync(lambda c: c.execute("SELECT count(*) FROM admin_sessions").fetchone()[0]) == 0

    new_password = "copper meadow lantern 4410"
    status, _ = _run(script, [*base, "--reset-password"], [new_password, new_password])
    assert status == 0
    final = dbs.control.read_sync(lambda c: users.get_by_username(c, "owner"))
    assert fast_hasher().verify_sync(final.password_hash, new_password)
    assert final.totp_secret_enc == after.totp_secret_enc  # password reset alone keeps the authenticator

    missing, text = _run(script, ["--username", "ghost", *base[2:], "--reset-mfa"], [])
    assert missing == 1
    assert "no admin named" in text


def test_missing_totp_key_is_a_clear_error(script: ModuleType, dbs: Any, state_dir: Path, tmp_path: Path) -> None:
    empty = tmp_path / "empty-credentials"
    empty.mkdir()
    status, output = _run(
        script, ["--username", "owner", "--state-dir", str(state_dir), "--credentials-dir", str(empty)], []
    )
    assert status == 1
    assert "totp_encryption_key" in output
