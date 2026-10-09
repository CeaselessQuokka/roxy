"""Review round, lens mp: the alert gate's hourly cap across a hot.db outage and its end.

What this is
    The reproduction (now a regular test) of finding mp-10. Two `Notifier` objects play the two workers of one color
    (ROXY_WORKERS=2), sharing one migrated hot.db and one owner mailbox (`RecordingTransport`). A "lock holder"
    process keeps hot.db write-locked for a while, the way a stalled worker, a long prune batch or a backup would;
    the test clock stays inside one hour.

Why it exists
    Plan 17.7: at most `alert_rate_limit_per_hour` messages per channel per hour for the fleet (leak guard trips
    excepted), and plan C6: no per-worker memory may multiply a limit. The fix pass closed ALERT-CAP: while hot.db
    cannot be written each worker falls back to `MemoryGate` with its share of the cap (`cap // ROXY_WORKERS`), so
    the fleet stays within the cap DURING the outage. What the memory gates sent is never written into hot.db's
    `email_gate` rows, so when hot.db comes back the shared gate counts the hour from where it was before the
    outage: the fleet may send the whole cap again inside the same hour (and alerts deduped in memory go out again
    inside their cooldown). It is the alert twin of finding mp-1 (leaving the abuse pipeline's degraded mode).

How it works
    The cap is set to 4 (each worker's share 2). Phase 1, hot.db locked: each worker sends 4 distinct alerts: the
    fleet sends 4, as it should. Phase 2, lock released, same hour: each worker sends 4 more distinct alerts. The
    fleet total for the hour must stay at 4 (measured before the fix: 8; with the default cap of 20 and 25 alerts
    per worker, 40). Fixed: each memory gate keeps a `GateJournal` that `gate.merge` folds into hot.db in the same
    transaction as the worker's next shared decision (or from the notifier's background retry); the first worker
    back reserves the other workers' shares for the window, and each of them releases its share when it reports.

What to read next
    `roxy/notify/notifier.py` (`Notifier._decide`, `sync_gate`), `roxy/notify/gate.py` (`decide`, `merge`,
    `MemoryGate`, `GateJournal`, `worker_share`), tests/integration/test_review_c7_failure_modes.py
    (`test_review_readonly_hot_alert_cap_still_holds`).
"""

from __future__ import annotations

import multiprocessing as mp
import sqlite3
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from roxy.config.catalog import CATALOG
from roxy.core.clock import FakeClock
from roxy.storage.db import DB_NAMES, Database
from roxy.storage.migrate import migrate_paths

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX processes"),
]

CTX = mp.get_context("spawn")
WORKERS = 2


def _hold_lock(path: str, ready: Any, release: Any) -> None:
    conn = sqlite3.connect(path, isolation_level=None, timeout=30)
    conn.execute("BEGIN IMMEDIATE")
    ready.set()
    release.wait(60)
    conn.execute("ROLLBACK")
    conn.close()


@pytest.fixture
def hot_path(tmp_path: Path) -> str:
    files = {name: tmp_path / f"{name}.db" for name in DB_NAMES}
    migrate_paths(files)
    return str(files["hot"])


@pytest.fixture
def procs() -> Iterator[list[Any]]:
    started: list[Any] = []
    yield started
    for proc in started:
        if proc.is_alive():
            proc.kill()
        proc.join(5)


CAP = 4
"""`alert_rate_limit_per_hour` for the test (catalog default 20): every send during the outage waits for the gate's
1 s write budget, so a small cap keeps the test short. Each worker's share is 2."""


class _Settings:
    """The read side of RuntimeSettings the notifier uses: catalog defaults, with the cap set to `CAP`."""

    def get(self, key: str) -> Any:
        return CAP if key == "alert_rate_limit_per_hour" else CATALOG[key].default


async def test_rr_mp_alert_cap_holds_for_the_hour_across_a_hot_db_outage(hot_path: str, procs: list[Any]) -> None:
    from pydantic import SecretStr

    from roxy.admin.auth.testing import RecordingTransport
    from roxy.notify import gate
    from roxy.notify.alerts import Alert
    from roxy.notify.mail import MailConfig, MailSender
    from roxy.notify.notifier import Notifier

    hot = Database("hot", hot_path)
    clock = FakeClock()
    transport = RecordingTransport()  # the owner's one mailbox
    config = MailConfig(to_addr="owner@example.invalid", from_addr="alerts@example.invalid", password=SecretStr("x"))
    fleet = [
        Notifier(
            hot_db=hot,
            settings=_Settings(),
            site_origin="http://localhost",
            mail=MailSender(config, transport=transport),
            webhook=None,
            clock=clock,
            workers=WORKERS,
        )
        for _ in range(WORKERS)
    ]
    cap = CAP

    async def burst(tag: str) -> None:
        for index, notifier in enumerate(fleet):
            for n in range(cap):
                await notifier.send(
                    Alert(
                        type="error",
                        severity="critical",
                        subject=f"Roxy: {tag} {index}.{n}",
                        summary="x",
                        cooldown_key=f"{tag}:{index}:{n}",
                    )
                )

    ready, release = CTX.Event(), CTX.Event()
    holder = CTX.Process(target=_hold_lock, args=(hot_path, ready, release), daemon=True)
    holder.start()
    procs.append(holder)
    try:
        assert ready.wait(20), "the lock holder never took hot.db's write lock"
        await burst("outage")
        during = len(transport.messages)
        release.set()
        holder.join(10)
        clock.advance(60)  # one minute later: the same hourly window
        await burst("after")
        total = len(transport.messages)
        assert all([await notifier.sync_gate() for notifier in fleet])  # both journals reached hot.db
        clock.advance(gate.CAP_WINDOW_S)  # the next hour: a new window, the reservation is gone
        await fleet[0].send(Alert(type="error", severity="critical", subject="Roxy: next", summary="x"))
        next_hour = len(transport.messages) - total
    finally:
        release.set()
        for notifier in fleet:
            await notifier.aclose()
        await hot.close()
    print(f"\ncap {cap} per hour; sent during the outage {during}, in the same hour after it {total - during}")
    assert during == cap, "the in-memory gates keep the fleet within the cap during the outage (ALERT-CAP)"
    assert total <= cap, f"the fleet sent {total} alerts in one hour with a cap of {cap}"
    assert next_hour == 1, "a new hour starts a new window with nothing reserved"
