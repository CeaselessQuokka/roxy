"""No secret in the report or in any log line (plans 18.3, 9.15, C4): only masked forms ever leave the v1 files."""

from __future__ import annotations

import json
import logging
import secrets as secrets_module
from typing import Any

import pytest
from v1_migration_helpers import all_text, assert_no_secret, rows, run_cli

from roxy.config.constants import MAX_RULE_NOTE
from roxy.core.redact import MASK
from roxy.migration.report import SecretScrubber

pytestmark = pytest.mark.usefixtures("restore_logging")


def test_migration_report_and_logs_hold_no_secret(
    v1: Any, ws: Any, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    builder = v1.small_tree(ws.v1, token_count=4)
    # A secret pasted into admin text and v1 statistics must still not reach the report.
    builder.runtime["EndpointBlocks"]["games.roblox.com/v1/leak"] = {
        "Note": f"oops {builder.secrets.app_password}",
        "Message": "",
        "Type": "glob",
    }
    builder.diagnostics["errors"]["TokenError: " + builder.secrets.tokens[1][-40:]] = {
        "Count": 1,
        "FirstSeen": 1.0,
        "LastSeen": 2.0,
        "LastDetail": "cookie " + builder.secrets.tokens[0],
        "Source": "Roxy",
    }
    builder.write()
    caplog.set_level(logging.DEBUG)
    secrets = builder.secrets
    values = [secrets.password, secrets.hmac_key, secrets.session_secret, secrets.app_password, secrets.rotator_url]
    values.append(secrets.rotator_url.split("@", 1)[0].split(":")[-1])  # the proxy password alone

    for extra in (("--dry-run", "--import-admin-password"), ("--import-admin-password",)):
        status, stdout, logs = run_cli(ws, *extra)
        assert status == 0, stdout
        json_text = ws.report.with_name(ws.report.name + ".json").read_text(encoding="utf-8")
        markdown = ws.report.with_name(ws.report.name + ".md").read_text(encoding="utf-8")
        captured = capsys.readouterr()
        for where, text in (
            ("the JSON report", json_text),
            ("the Markdown report", markdown),
            ("stdout", stdout + captured.out),
            ("stderr", captured.err),
            ("the JSON log", logs),
            ("captured log records", caplog.text),
        ):
            assert_no_secret(text, values, secrets.tokens, v1.TOKEN_PREFIX, where)
        credential = next(c for c in json.loads(json_text)["credentials"] if c["name"] == "roblox_credential")
        assert "…" + secrets.tokens[1][-6:] in credential["discarded_masked"]  # an ellipsis and the last 6
        assert "v1_migration_finished" in logs

    # The databases hold no secret either (the admin password only as an argon2id hash).
    for name in ("control", "metrics", "hot", "cache"):
        assert_no_secret(all_text(ws.state / f"{name}.db"), values, secrets.tokens, v1.TOKEN_PREFIX, f"{name}.db")


def test_cli_exit_codes(v1: Any, ws: Any, tmp_path: Any) -> None:
    status, stdout, _logs = run_cli(ws)
    assert status == 2
    assert "is not a directory" in stdout
    v1.small_tree(ws.v1).write()
    (ws.v1 / "roxy_data.json").write_text("{", encoding="utf-8")
    status, stdout, _logs = run_cli(ws)
    assert status == 1  # a step reported an error (the data file), but the rest was imported
    assert "completed_with_errors" in stdout


async def test_migration_ladder_text_never_holds_a_v1_secret(v1: Any, ws: Any, migrate: Any) -> None:
    """Rung messages and notes are scrubbed like rule notes: the app password and pieces of the credential pasted
    into them never reach throttle_tiers or the audit copy of the ladder (review finding 3)."""
    builder = v1.V1TreeBuilder(ws.v1)
    app_password = builder.secrets.app_password
    token = builder.secrets.tokens[0]
    builder.runtime["ThrottleTiers"][0]["Message"] = f"Slow down. Mail password {app_password}"
    builder.runtime["ThrottleTiers"][1]["Note"] = "debug cookie " + token[-40:]
    builder.write()
    report = await migrate()
    control = ws.state / "control.db"
    assert_no_secret(all_text(control), [app_password], [token], v1.TOKEN_PREFIX, "control.db")
    assert token[-40:-10] not in all_text(control)
    tiers = rows(control, "SELECT * FROM throttle_tiers ORDER BY position")
    assert len(tiers) == 4  # the rungs stay (dropping one would shift every later multiplier)
    assert tiers[0]["message"] == f"Slow down. Mail password {MASK}"
    assert MASK in tiers[1]["note"]
    assert sum("throttle_tiers" in w and "secret value was removed" in w for w in report.warnings) == 2


async def test_migration_text_is_scrubbed_before_it_is_cut(v1: Any, ws: Any, migrate: Any) -> None:
    """A secret straddling the v2 length limit must not leave its first characters behind (review finding 9)."""
    builder = v1.V1TreeBuilder(ws.v1)
    builder.secrets.app_password = secrets_module.token_hex(12)  # 24 characters, like a Gmail app password
    password = builder.secrets.app_password
    keep = 18  # characters of the password that a cut-then-scrub order would leave in place
    builder.runtime["EndpointBlocks"] = {
        "games.roblox.com/v1/x": {"Note": "n" * (MAX_RULE_NOTE - keep) + password, "Type": "glob"},
        # v1 itself cut notes at 200 characters, so a stored note can already end in part of a secret.
        "games.roblox.com/v1/y": {"Note": "already cut by v1: " + password[:13], "Type": "glob"},
    }
    builder.write()
    await migrate()
    notes = [row["note"] for row in rows(ws.state / "control.db", "SELECT note FROM rules_endpoint_block")]
    assert len(notes) == 2
    for note in notes:
        assert password[:12] not in note, note[-30:]
    assert any(note.endswith(MASK) for note in notes)


def test_scrubber_masks_pieces_of_every_secret() -> None:
    """Every secret long enough to tell apart from ordinary text is matched by pieces as well as whole; the
    rotator URL is matched whole only, so its scheme and host stay readable in the report."""
    app_password = "fakeapppw" + secrets_module.token_hex(8)  # 25 characters: pieces of 12
    proxy_password = "fakepw" + secrets_module.token_hex(6)
    url = f"http://fakeuser:{proxy_password}@gw.proxy.invalid:823"
    scrubber = SecretScrubber([app_password, url, proxy_password], pieces=[app_password, proxy_password])
    assert scrubber.clean_known(f"x {app_password[3:15]} y") == f"x {MASK} y"
    assert scrubber.clean_known(f"x {app_password[3:15].upper()} y") == f"x {MASK} y"  # pieces ignore case
    assert scrubber.clean_known(f"x {app_password[3:14]} y") == f"x {app_password[3:14]} y"  # under one piece
    assert scrubber.clean_known(f"pw {proxy_password[:9]}!") == f"pw {MASK}!"
    assert scrubber.clean_known("http://gw.proxy.invalid:823") == "http://gw.proxy.invalid:823"
    assert scrubber.clean_known(url) == MASK


async def test_migration_warns_about_a_v1_password_too_short_to_mask(v1: Any, ws: Any, migrate: Any) -> None:
    """Values under 6 characters are not masked (that would hide ordinary words and refuse unrelated rule
    patterns); the report says so without naming the value."""
    builder = v1.V1TreeBuilder(ws.v1)
    builder.secrets.password = "q7x"
    builder.write()
    report = await migrate()
    assert any("fewer than 6 characters" in warning for warning in report.warnings)
    assert "q7x" not in json.dumps(report.as_dict())


async def test_migration_logs_discarded_credentials_masked(
    v1: Any, ws: Any, migrate: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """Plan C1: the migrator logs (masked) that extra credential lines were discarded (review finding 12)."""
    secrets = v1.make_secrets(token_count=3)
    v1.V1TreeBuilder(ws.v1, secrets=secrets).write()
    caplog.set_level(logging.DEBUG)
    await migrate()
    records = [r for r in caplog.records if r.getMessage() == "v1_credentials_discarded"]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    fields = records[0].fields  # type: ignore[attr-defined]
    assert fields == {"count": 2, "masked": [f"…{token[-6:]}" for token in secrets.tokens[1:]]}
    assert_no_secret(caplog.text + repr(fields), [], secrets.tokens, v1.TOKEN_PREFIX, "the log")
