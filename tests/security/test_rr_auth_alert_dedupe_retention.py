"""Adversarial review (lens auth, alerts 11.6 and 17.7): the alert dedupe window versus email_gate retention.

What this is
    A reviewer probe. Plan 17.7 gives some alert types a cooldown far longer than a day: the rotator quota alert
    has a per cycle cooldown (`AlertSpec.cooldown_s` is 31 days for `rotator_quota`), and the notifier expects
    `gate.decide` to dedupe by that gap fleet wide. But the leader pruned `email_gate` on a FIXED idle of
    `RetentionPolicy.email_gate_idle_s` (one day). So the `alert:<cooldown key>` row was deleted long before the
    cooldown ended, and the same alert was sent again inside its own cooldown window.

Why it exists
    The contract (17.7) is "every alert is deduped fleet wide by its cooldown key". A one day prune broke it for
    every alert whose cooldown is longer than a day (rotator quota most clearly), so the owner got repeat mail
    inside a single billing cycle. Fixed in `storage/retention.py`: `alert:` rows are kept
    `email_gate_alert_idle_s` (45 days, longer than any alert cooldown), the cap rows keep the one day idle.

How it works
    Write the dedupe row with `gate.decide` at time T using the rotator quota cooldown, advance the clock by two
    days (well inside the 31 day cooldown, past the one day prune idle), run `prune_email_gate`, then decide the
    same cooldown key again. It must still be deduped.

What to read next
    `roxy/notify/gate.py` (`decide`), `roxy/notify/alerts.py` (`ALERT_SPECS["rotator_quota"]`),
    `roxy/storage/retention.py` (`prune_email_gate`, `RetentionPolicy.email_gate_idle_s`).
"""

from __future__ import annotations

from typing import Any

from roxy.notify import gate
from roxy.notify.alerts import ALERT_SPECS
from roxy.storage.retention import RetentionPolicy, prune_email_gate

DAY_S = 86_400


async def test_long_cooldown_alert_stays_deduped_through_retention(dbs: Any) -> None:
    cooldown_s = int(ALERT_SPECS["rotator_quota"].cooldown_s or 0)
    assert cooldown_s > DAY_S, "the rotator quota alert cooldown is longer than the email_gate prune idle"
    key = "quota:95:1760000000"
    now = 1_760_000_000

    first = await dbs.hot.write(
        lambda conn: gate.decide(
            conn, cooldown_key=key, cooldown_s=cooldown_s, channels=["email"], cap=1000, uncapped=False, now=now
        )
    )
    assert first.allowed == ("email",), "the first alert of this cooldown key goes out"

    # The leader prunes email_gate while the owner is still inside the same billing cycle (and the cooldown).
    later = now + 2 * DAY_S
    await dbs.hot.write(lambda conn: prune_email_gate(conn, later, RetentionPolicy(), 10_000))

    second = await dbs.hot.write(
        lambda conn: gate.decide(
            conn, cooldown_key=key, cooldown_s=cooldown_s, channels=["email"], cap=1000, uncapped=False, now=later
        )
    )
    assert second.deduped, (
        "the same cooldown key must stay deduped for its whole cooldown; retention must not drop the gate row early"
    )
    assert not second.allowed
