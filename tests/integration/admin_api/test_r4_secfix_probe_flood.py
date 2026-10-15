"""Review round 4 (lens secfix): a scanner can still mint one probe log signature, and one event budget, per request.

What this is
    A variant of the probe log fix (ptable-2) and of v1 bug B19. The ptable-2 fixer made every proxy probe reach the
    Security probe log with "Roxy's own words" as its signature, so that "a scanner cannot create a new signature,
    summary row or event budget per request" and "the recorder folds a flood over its per-signature event budget"
    (`abuse/pipeline.py probe_log_reason`, `metrics/recorder.py _event`: `EVENT_BURST` events per type and
    signature, the rest folded into one row a minute). The other producer of the same log, the client error hook
    (`metrics/security_events.py install_error_hooks`), writes `HTTP <status> via <METHOD> <path>`, and
    `probe_signature` keeps `HTTP <status> via <METHOD>` as the signature. The method is the caller's choice (any
    token; review round 3 also sent every method on `/` but GET, HEAD and OPTIONS through this hook, parity-1). A
    method of more than 12 letters, or with a lowercase letter or a digit, does not even match `_HTTP_REASON`, and
    the whole line, path included, becomes the signature. Each distinct method is a new signature with a fresh
    budget, so a flood with a new method per request is never folded.

Why it exists
    B19 (v1 keyed its exploit summary by the caller's own text) and plan P9: a log anyone on the internet can write
    into must stay bounded per unit of attacker effort, and its summary must not be rewritten by the attacker.

How it works
    One client sends 80 requests to `/` from one address; as a control with one method (`POST`, folded), then
    each with its own method token. The recorder is flushed and the probe events of that address are counted, with
    their distinct signatures. The second test was a strict xfail (finding secfix-7); the hook now names one of ten
    method classes (`security_events.client_error_reason`: the standard methods or `OTHER`), and an unknown token
    goes to the redacted target column.

What to read next
    `roxy/metrics/security_events.py` (`probe_signature`, `_HTTP_REASON`, `install_error_hooks`),
    `roxy/metrics/recorder.py` (`_event`, `MAX_EVENT_BUDGETS`, `EVENT_BURST`), `roxy/public/pages.py`
    (`HomeMethodRoute`).
"""

from __future__ import annotations

import string
from typing import Any

from roxy.metrics.recorder import EVENT_BURST

FLOOD = 80


def _method(i: int) -> str:
    letters = string.ascii_uppercase
    return "X" + letters[i // 26] + letters[i % 26]  # XAA, XAB, ...: plain uppercase tokens, 3 letters


async def _flood(api_app: Any, ip: str, methods: list[str]) -> tuple[int, int]:
    http = api_app.harness.new_client()
    for method in methods:
        answer = await http.request(method, "/", headers={"X-Forwarded-For": ip, "User-Agent": "scanner"})
        assert answer.status_code == 405, (method, answer.status_code)
    await api_app.ctx.recorder.flush()

    def count(conn: Any) -> tuple[int, int]:
        row = conn.execute(
            "SELECT count(*), count(DISTINCT reason_code) FROM events WHERE type = 'probe' AND detail_json LIKE ?",
            (f'%"ip": "{ip}"%',),
        ).fetchone()
        if row[0] == 0:  # the detail may be stored compact
            row = conn.execute(
                "SELECT count(*), count(DISTINCT reason_code) FROM events WHERE type = 'probe' AND detail_json LIKE ?",
                (f'%"ip":"{ip}"%',),
            ).fetchone()
        return int(row[0]), int(row[1])

    result: tuple[int, int] = await api_app.ctx.dbs.metrics.read(count)
    return result


async def test_control_one_method_flood_is_folded_over_its_budget(api_app: Any) -> None:
    rows, signatures = await _flood(api_app, "203.0.113.71", ["POST"] * FLOOD)
    assert signatures == 1
    assert rows <= EVENT_BURST + 2, rows  # the budget, then one folded row


async def test_a_flood_with_a_new_method_per_request_is_folded_too(api_app: Any) -> None:
    rows, signatures = await _flood(api_app, "203.0.113.72", [_method(i) for i in range(FLOOD)])
    assert (rows <= EVENT_BURST + 2, signatures <= 2) == (True, True), (
        f"{rows} probe events with {signatures} distinct signatures from one address's {FLOOD} requests"
    )
