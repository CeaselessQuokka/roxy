"""Review round 4 (lens secfix): the "Back up now" request file the dashboard writes for the root backup.

What this is
    Adversarial tests of the new backup request path (`admin/api/data.py back_up_now`, `write_backup_request`) next
    to the apisec-5 fix (`backup_plan`, `snapshot_feasibility`). `POST /data/backups` first plans the on-server
    `VACUUM INTO` copies against `snapshots_max_bytes` and the free disk; when they do not fit it answers 409
    `not_feasible` before anything else, so the request for the ROOT backup (`<state dir>/backup-request`, watched by
    `roxy-backup-request.path`, which compresses, checks, encrypts and copies the set off the server) is never
    written. With local snapshots switched off (`snapshots_max_bytes` 0, a value the catalog allows), with a
    snapshots folder full of reset and pre-migration snapshots, or with a nearly full disk, the button never
    reaches the real backup, while `scripts/ctl.py backup-now` writes the same request unconditionally.
    The file's own safety (a planted link at its path is replaced, never followed; mode 0640; no temporary file
    left; only the three known fields) is checked too.

Why it exists
    CHANGES.md: "Back up now reaches the root backup". A full disk is exactly when an owner presses it before
    cleaning up; the local copy is a convenience, the off-server backup is the backup.

How it works
    The real app (`api_app`) and a signed-in admin. One test turns local snapshots off and expects the request file
    anyway (a strict xfail for finding secfix-4 until the request was written right after the audited intent,
    whatever the local plan says). The others plant a link at the request path and read the file.

What to read next
    `roxy/admin/api/data.py` (`back_up_now`, `backup_plan`, `write_backup_request`), `scripts/ctl.py`
    (`cmd_backup_now`), `deploy/tools/backup.sh` (`consume_request`).
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from roxy.admin.api import data


async def test_back_up_now_asks_the_root_backup_even_when_no_local_snapshot_fits(api: Any, api_app: Any) -> None:
    await api_app.settings(snapshots_max_bytes=0)  # the owner keeps no on-server copies (a valid catalog value)
    request = Path(api_app.ctx.env.state_dir) / data.BACKUP_REQUEST_NAME
    answer = await api.post("data/backups", json={"reason": "before cleaning up"})
    assert request.exists(), f"Back up now answered {answer.status_code} {answer.text[:200]} and asked no root backup"
    assert answer.status_code < 400, answer.text[:200]


async def test_a_planted_link_at_the_request_path_is_replaced_not_followed(api: Any, api_app: Any) -> None:
    state_dir = Path(api_app.ctx.env.state_dir)
    victim = state_dir / "victim.txt"
    victim.write_text("keep me", encoding="utf-8")
    request = state_dir / data.BACKUP_REQUEST_NAME
    request.symlink_to(victim)
    answer = await api.post("data/backups", json={"reason": "now"})
    assert answer.status_code == 200, answer.text[:200]
    assert victim.read_text(encoding="utf-8") == "keep me"
    assert not request.is_symlink()
    assert request.is_file()
    assert stat.S_IMODE(request.lstat().st_mode) == 0o640
    document = json.loads(request.read_text(encoding="utf-8"))
    assert set(document) == {"requested_at", "by", "audit_id"}
    assert [name for name in os.listdir(state_dir) if name.startswith(f".{data.BACKUP_REQUEST_NAME}.")] == []


async def test_a_pending_request_that_is_a_link_or_huge_is_never_read_through(api: Any, api_app: Any) -> None:
    state_dir = Path(api_app.ctx.env.state_dir)
    secret = state_dir / "elsewhere.json"
    secret.write_text(json.dumps({"by": "should-not-be-read", "requested_at": "x"}), encoding="utf-8")
    (state_dir / data.BACKUP_REQUEST_NAME).symlink_to(secret)
    listed = await api.get("data/backups")
    assert listed.status_code == 200, listed.text[:200]
    assert "should-not-be-read" not in listed.text
