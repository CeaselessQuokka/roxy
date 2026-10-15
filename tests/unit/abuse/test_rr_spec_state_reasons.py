"""Reviewer finding spec-2: pause and throttle-all reasons are caller-facing admin text, so plan C5 applies to them.

What this is
    Checks that the audited writers of the two admin switches (`set_pause`, `schedule_pause`, `set_throttle_all`)
    refuse a reason with an em or en dash (callers would otherwise receive it as their 503 or 429 body), write
    nothing when they refuse, and still store an ordinary reason cut to v1's 300 characters.

Why it exists
    Plan C5 bans the two dash characters in every piece of UI and caller copy, and plan 15.3 K marks the pause text
    "C5 checked". Every other piece of admin text callers can see (block, rule, User-Agent and header filter
    messages, ladder rungs, ban reasons) goes through `rules/models.py check_admin_text`, which refuses a dash; the
    migrator rewrites dashes in imported pause and throttle-all reasons (plan C5, 18.3). The switch writers used to
    only trim and cut the text, so a reason typed into the top bar reached every caller with its dash. They now
    check it with the same function (`abuse/messages.py checked_state_reason`).

How it works
    Each writer is called with a reason containing an em dash (built with `chr`, so this file has none). It must
    raise the C5 ValueError before its transaction: the stored state, `config_version` and the audit log stay as
    they were. A clean reason longer than 300 characters is still accepted and cut, as v1 did.

What to read next
    `roxy/abuse/pause.py`, `roxy/abuse/throttle_all.py`, `roxy/abuse/messages.py` (`checked_state_reason`), and
    `roxy/rules/models.py` (`check_admin_text`).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from roxy.abuse import pause, throttle_all
from roxy.abuse.messages import MAX_STATE_REASON
from roxy.abuse.state import read_state_value
from roxy.config.audit import Actor
from roxy.config.catalog import DASH_MESSAGE
from roxy.config.runtime import read_config_version
from roxy.core.clock import FakeClock

ADMIN = Actor("admin", "rr-spec")
EM_DASH = chr(0x2014)
EN_DASH = chr(0x2013)
REASON = f"Back in ten minutes {EM_DASH} sorry {EN_DASH} thanks"
WRITERS = ["set_pause", "schedule_pause", "set_throttle_all"]


def _writers(dbs: Any, clock: FakeClock, reason: str) -> dict[str, Callable[[], Awaitable[Any]]]:
    now = int(clock.now())
    return {
        "set_pause": lambda: pause.set_pause(dbs.control, clock, ADMIN, paused=True, reason=reason),
        "schedule_pause": lambda: pause.schedule_pause(
            dbs.control, clock, ADMIN, start=now + 60, end=now + 600, reason=reason
        ),
        "set_throttle_all": lambda: throttle_all.set_throttle_all(
            dbs.control, clock, ADMIN, enabled=True, reason=reason
        ),
    }


def _stored(dbs: Any) -> tuple[Any, Any, int, int]:
    def read(conn: Any) -> tuple[Any, Any, int, int]:
        audits = int(conn.execute("SELECT count(*) FROM audit_log").fetchone()[0])
        return (
            read_state_value(conn, pause.STATE_KEY),
            read_state_value(conn, throttle_all.STATE_KEY),
            read_config_version(conn),
            audits,
        )

    return dbs.control.read_sync(read)


@pytest.mark.parametrize("writer", WRITERS)
async def test_spec_2_switch_reasons_never_store_a_dash(dbs: Any, fake_clock: FakeClock, writer: str) -> None:
    before = _stored(dbs)
    with pytest.raises(ValueError, match="em dash or en dash") as caught:
        await _writers(dbs, fake_clock, REASON)[writer]()
    assert str(caught.value) == DASH_MESSAGE  # the same text the rules service answers for a dashed message
    assert _stored(dbs) == before, "a refused reason writes nothing: no state, no config_version bump, no audit row"


@pytest.mark.parametrize("writer", WRITERS)
async def test_spec_2_clean_reasons_are_stored_and_cut_like_v1(dbs: Any, fake_clock: FakeClock, writer: str) -> None:
    """Control: an ordinary reason (plain hyphens are fine) is stored trimmed and cut to 300 characters (v1)."""
    reason = "  Upgrading the database - back soon " + "x" * 400
    state = await _writers(dbs, fake_clock, reason)[writer]()
    stored = state.scheduled_reason if writer == "schedule_pause" else state.reason
    assert stored == reason.strip()[:MAX_STATE_REASON].strip()
    assert len(stored) == MAX_STATE_REASON


async def test_spec_2_control_rules_refuse_a_dashed_message() -> None:
    """Control: the rules side refuses the same text in a refusal message."""
    from roxy.rules.models import check_admin_text

    with pytest.raises(ValueError):
        check_admin_text(REASON, 300, "The message")
