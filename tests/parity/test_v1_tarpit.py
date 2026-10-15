"""v1 parity: a tarpit hold is invisible to the caller.

What this is
    A port of v1 smoke lines 1982 and 1984 (S067: "a probe still gets its normal 404, and no response header names
    the hold").

Why it exists
    A tarpit only works while the caller cannot tell it is being held: a header that said "held" would let a bot
    drop the connection at once and move on. v2 adds `drip` and `jitter` to v1's `hold`, and every refusal now
    carries `Roxy-*` headers, so the promise needs its own check.

How it works
    The `parity` fixture runs the real app. The same kind of probe is sent once with the tarpit off and once with
    it on (holds of 0 to 1 s, the e2e test's setting, so the test stays fast); the tarpit's own statistics prove
    the second one was planned as a hold. The two answers must have the same status, body and header names (the
    request id aside), and no header name may mention the hold.

What to read next
    `roxy/abuse/tarpit.py` (plans and statistics) and `roxy/proxy/router.py` (where a plan is waited out).
"""

from __future__ import annotations

from typing import Any


def header_names(response: Any) -> set[str]:
    return {name.lower() for name in response.headers if name.lower() != "roxy-request-id"}


async def test_v1_a_held_probe_gets_the_same_answer_as_an_unheld_one(parity: Any) -> None:
    """v1 smoke lines 1982 and 1984."""
    unheld = await parity.get("/evil.example.com/wp-login.php")
    await parity.settings(tarpit_enabled=1, tarpit_min_seconds=0, tarpit_max_seconds=1)
    before = len(parity.ctx.abuse.tarpit.stats.snapshot()["reasons"])
    held = await parity.get("/evil.example.com/wp-login.php")
    assert len(parity.ctx.abuse.tarpit.stats.snapshot()["reasons"]) > before  # this one went through the tarpit
    assert (held.status_code, held.content) == (unheld.status_code, unheld.content) == (404, b'"Not a Roblox URL"\n')
    assert header_names(held) == header_names(unheld)
    assert not [name for name in header_names(held) if "held" in name or "tarpit" in name or "hold" in name]
