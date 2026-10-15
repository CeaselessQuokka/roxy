"""Credential files (plans C1 and 9.8): one credential from a multi-line token file, modes, keys, no overwrite."""

from __future__ import annotations

import json
import secrets as secrets_module
import stat
from pathlib import Path
from typing import Any

import pytest
from v1_migration_helpers import assert_no_secret, tree_snapshot

from roxy.core.iphash import decode_key_material
from roxy.migration.secrets_out import KEY_NAMES


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


async def test_migration_multi_line_token_file(v1: Any, ws: Any, migrate: Any) -> None:
    """Only the first non-empty line survives; the others are counted and shown masked (plan C1)."""
    secrets = v1.make_secrets(token_count=3)
    builder = v1.V1TreeBuilder(ws.v1, secrets=secrets)
    first, second, third = secrets.tokens
    builder.token_text = f"\n   \n  {first}  \n\n{second}\n{third}\n"
    builder.write()
    report = await migrate()
    stored = (ws.credentials / "roblox_credential").read_text(encoding="utf-8")
    assert stored == first  # stripped, exactly one value, never a list
    assert second not in stored
    assert third not in stored
    item = next(c for c in report.credentials if c["name"] == "roblox_credential")
    assert item["status"] == "written"
    assert item["discarded_lines"] == 2
    assert item["discarded_masked"] == [f"…{second[-6:]}", f"…{third[-6:]}"]
    assert item["masked"] == f"…{first[-6:]}"
    assert any("only the first was kept (plan C1)" in warning for warning in report.warnings)


async def test_migration_credential_files_and_modes(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.V1TreeBuilder(ws.v1)
    builder.write()
    report = await migrate()
    secrets = builder.secrets
    assert _mode(ws.credentials) == 0o700
    expected = {
        "roblox_credential": secrets.tokens[0],
        "rotator_url": secrets.rotator_url,
        "smtp_password": secrets.app_password,
        "alert_emails": f"to: {secrets.email_to}\nfrom: {secrets.email_from}\n",
    }
    for name, content in expected.items():
        path = ws.credentials / name
        assert path.read_text(encoding="utf-8") == content, name
        assert _mode(path) == 0o600, name
    for name in KEY_NAMES:
        path = ws.credentials / name
        assert _mode(path) == 0o600
        assert len(decode_key_material(path.read_bytes())) == 32
    keys = {name: (ws.credentials / name).read_text() for name in KEY_NAMES}
    assert len(set(keys.values())) == 3  # three independent random keys
    statuses = {c["name"]: c["status"] for c in report.credentials}
    assert statuses == {
        "roblox_credential": "written",
        "rotator_url": "written",
        "smtp_password": "written",
        "alert_emails": "written",
        "credential_encryption_key": "generated",
        "totp_encryption_key": "generated",
        "ip_hash_key": "generated",
    }
    assert [p.name for p in ws.credentials.iterdir() if p.name.startswith(".")] == []  # no temporary files left


async def test_migration_never_overwrites_credential_files(v1: Any, ws: Any, migrate: Any) -> None:
    """An existing credential or key is kept (C1: replacing the credential is deliberate; a new key would lock
    the owner out of everything encrypted with the old one)."""
    builder = v1.V1TreeBuilder(ws.v1)
    builder.write()
    ws.credentials.mkdir(mode=0o755)
    other = v1.fake_token()
    (ws.credentials / "roblox_credential").write_text(other, encoding="utf-8")
    existing_key = "ab" * 32
    (ws.credentials / "ip_hash_key").write_text(existing_key, encoding="utf-8")
    report = await migrate()
    assert (ws.credentials / "roblox_credential").read_text(encoding="utf-8") == other
    assert (ws.credentials / "ip_hash_key").read_text(encoding="utf-8") == existing_key
    assert _mode(ws.credentials) == 0o700  # tightened
    statuses = {c["name"]: c["status"] for c in report.credentials}
    assert statuses["roblox_credential"] == "kept_existing_different"
    assert statuses["ip_hash_key"] == "already_present"
    assert statuses["totp_encryption_key"] == "generated"
    assert any("roblox_credential already exists" in warning for warning in report.warnings)


async def test_migration_without_credentials_dir_writes_none(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.V1TreeBuilder(ws.v1)
    builder.write()
    report = await migrate(credentials=False)
    assert not ws.credentials.exists()
    assert report.credentials[0]["status"] == "skipped"


async def test_migration_missing_secret_files_are_reported(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.V1TreeBuilder(ws.v1, write_rotator=False)
    builder.token_text = "\n\n"
    builder.write()
    before = tree_snapshot(ws.v1)
    report = await migrate()
    statuses = {c["name"]: c["status"] for c in report.credentials}
    assert statuses["roblox_credential"] == "no_source"
    assert statuses["rotator_url"] == "no_source"
    assert not (ws.credentials / "roblox_credential").exists()
    assert any("no Roblox credential" in warning for warning in report.warnings)
    assert tree_snapshot(ws.v1) == before


async def test_migration_removes_temporary_files_left_by_a_crash(v1: Any, ws: Any, migrate: Any) -> None:
    """A SIGKILL between writing a temporary file and linking it into place leaves `.<name>.<hex>.tmp` holding a
    secret; the next run deletes such files (only names the migrator itself uses) and says so (review finding 8)."""
    builder = v1.V1TreeBuilder(ws.v1)
    builder.write()
    ws.credentials.mkdir(mode=0o700)
    stale = [ws.credentials / ".rotator_url.0a1b2c3d.tmp", ws.credentials / ".ip_hash_key.ffffffff.tmp"]
    for path in stale:
        path.write_text(builder.secrets.rotator_url, encoding="utf-8")
    unrelated = [ws.credentials / ".notes.0a1b2c3d.tmp", ws.credentials / ".rotator_url.tmp"]
    for path in unrelated:
        path.write_text("owner file", encoding="utf-8")
    report = await migrate()
    assert [path for path in stale if path.exists()] == []
    assert all(path.exists() for path in unrelated)
    warning = next(w for w in report.warnings if "interrupted run" in w)
    assert ".rotator_url.0a1b2c3d.tmp" in warning
    assert {c["name"]: c["status"] for c in report.credentials}["rotator_url"] == "written"


async def test_migration_tightens_loose_existing_credential_files(v1: Any, ws: Any, migrate: Any) -> None:
    """An existing credential or key file readable by others is set to 0600 with a warning (review finding 10)."""
    builder = v1.V1TreeBuilder(ws.v1)
    builder.write()
    ws.credentials.mkdir(mode=0o755)
    loose = ws.credentials / "smtp_password"
    loose.write_text(builder.secrets.app_password, encoding="utf-8")
    loose.chmod(0o644)
    key = ws.credentials / "ip_hash_key"
    key.write_text("cd" * 32, encoding="utf-8")
    key.chmod(0o640)
    report = await migrate()
    assert (_mode(loose), _mode(key)) == (0o600, 0o600)
    statuses = {c["name"]: c["status"] for c in report.credentials}
    assert (statuses["smtp_password"], statuses["ip_hash_key"]) == ("already_present", "already_present")
    assert any("smtp_password was mode 644; it is now 600" in w for w in report.warnings)
    assert any("ip_hash_key was mode 640; it is now 600" in w for w in report.warnings)


async def test_migration_rotator_url_from_the_v1_environment_variable(
    v1: Any, ws: Any, migrate: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v1 read ROXY_ROTATE_PROXY first (auth.py read_rotate_proxy); plan 15.3 L: the migrator moves that value into
    the rotator_url credential (review finding 13). It is a secret: never in the report."""
    builder = v1.V1TreeBuilder(ws.v1, write_rotator=False)
    builder.write()
    url = f"http://fakeuser:fakepw{secrets_module.token_hex(6)}@127.0.0.1:9"
    monkeypatch.setenv("ROXY_ROTATE_PROXY", f"  {url}\n")
    report = await migrate()
    assert (ws.credentials / "rotator_url").read_text(encoding="utf-8") == url
    item = next(c for c in report.credentials if c["name"] == "rotator_url")
    assert item["status"] == "written"
    assert "ROXY_ROTATE_PROXY" in item["detail"]
    assert_no_secret(json.dumps(report.as_dict()), [url, url.split("@")[0].split(":")[-1]], [], "", "the report")


async def test_migration_rotator_environment_variable_wins_over_the_file(
    v1: Any, ws: Any, migrate: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = v1.V1TreeBuilder(ws.v1)
    builder.write()
    url = f"http://fakeuser:fakepw{secrets_module.token_hex(6)}@127.0.0.1:9"
    monkeypatch.setenv("ROXY_ROTATE_PROXY", url)
    report = await migrate()
    assert (ws.credentials / "rotator_url").read_text(encoding="utf-8") == url
    assert any("rotate_proxy.txt holds a different URL" in w for w in report.warnings)
    text = json.dumps(report.as_dict())
    assert_no_secret(text, [url, builder.secrets.rotator_url], [], "", "the report")


async def test_migration_rotator_file_variable_is_read_inside_the_root(
    v1: Any, ws: Any, migrate: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ROXY_ROTATE_PROXY_FILE named the v1 rotator file; an absolute path outside --v1-root is read by its file
    name inside the root, like a files.txt line, so a copied tree never makes the migrator read the live one."""
    builder = v1.V1TreeBuilder(ws.v1, write_rotator=False)
    builder.write()
    (ws.v1 / "proxy-url.txt").write_text(builder.secrets.rotator_url + "\n", encoding="utf-8")
    outside = tmp_path / "live-etc-roxy"
    outside.mkdir()
    (outside / "proxy-url.txt").write_text("http://u:other-fake@127.0.0.1:1\n", encoding="utf-8")
    monkeypatch.setenv("ROXY_ROTATE_PROXY_FILE", str(outside / "proxy-url.txt"))
    report = await migrate()
    assert (ws.credentials / "rotator_url").read_text(encoding="utf-8") == builder.secrets.rotator_url
    assert any("ROXY_ROTATE_PROXY_FILE" in w and "outside the v1 root" in w for w in report.warnings)
