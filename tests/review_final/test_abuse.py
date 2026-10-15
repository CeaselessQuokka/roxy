"""Final review, lens abuse protection: the reproductions of .remake/final_review/find_abuse.md, now regression tests.

What this is
    One test (or a small group) per finding of the abuse protection lens (plan 10, DESIGN 11.5 and 11.9): the spam
    detectors and their game server protection, the User-Agent hash ban, the request size limit counts, the bypass
    coverage texts, the bot score under two workers, the spam flush's write lock under a flood from many addresses,
    and the texts of the Protection, Clients and System pages that describe these checks. Each test was a strict
    xfail naming its finding until the final review fixed it; each is a regression test now, so a later change that
    brings the defect back fails it.

Why it exists
    The final review before the owner signs off asks for reproductions, not opinions: a finding without a failing test
    is not a finding.

How it works
    Unit level tests drive `abuse/spam.py SpamDetectors`, `abuse/bot.py ClientTracker` and the rules store over the
    root conftest's temporary databases (`dbs`, `fake_clock`) with the abuse suite's `FakeSettings`
    (`tests/unit/abuse/abuse_support.py`, catalog defaults plus overrides). Page level tests use the dashboard
    integration fixtures of `tests/integration/pages/conftest.py` (`pages_app`, `page`): the real app, a signed-in
    admin, proxy traffic through the real pipeline, and the real read models.

What to read next
    .remake/final_review/find_abuse.md, roxy/abuse/spam.py, roxy/abuse/bans.py, roxy/core/middleware.py.
"""

from __future__ import annotations

import sqlite3
import sys
import tracemalloc
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

_ABUSE_TESTS = Path(__file__).resolve().parents[1] / "unit" / "abuse"
if str(_ABUSE_TESTS) not in sys.path:
    sys.path.insert(0, str(_ABUSE_TESTS))  # the abuse suite imports its helpers as a top-level module

from abuse_support import FakeReq, FakeSettings  # noqa: E402

from integration.pages.conftest import page, page_admin, pages_app  # noqa: E402,F401  (the page fixtures)
from pages_harness import parse_html  # noqa: E402
from roxy.abuse.bans import previous_offenses  # noqa: E402
from roxy.abuse.checks import default_checks  # noqa: E402
from roxy.abuse.limiter import DegradedEntry, LimiterRow, MemoryRowStore  # noqa: E402
from roxy.abuse.pipeline import AbusePipeline, Allow  # noqa: E402
from roxy.abuse.spam import SpamDetectors  # noqa: E402
from roxy.abuse.throttle import StrikeRow, load_strike_rows  # noqa: E402
from roxy.admin.pages._protection_views import BOT_SIGNAL_NOTES  # noqa: E402
from roxy.config.audit import Actor  # noqa: E402
from roxy.config.catalog import CATALOG  # noqa: E402
from roxy.core.clock import FakeClock  # noqa: E402
from roxy.insights.rules.abuse import FilterRemove  # noqa: E402
from roxy.insights.rules.security import SecBypassForever  # noqa: E402
from roxy.rules.service import RulesService  # noqa: E402
from roxy.rules.store import build_rules_snapshot  # noqa: E402

CLIENT = "203.0.113.7"  # TEST-NET-3 documentation range, never a real system
TEMPLATE = "games.roblox.com/v1/games"
PROXY_PATH = "/games.roblox.com/v1/games?universeIds=1"


def detectors(dbs: Any, clock: FakeClock, events: list[Any], **overrides: Any) -> SpamDetectors:
    """One worker's spam detectors over the test's databases, armed or not as `overrides` say."""
    return SpamDetectors(
        FakeSettings(overrides),
        dbs.hot,
        clock,
        control_db=dbs.control,
        rules_service=RulesService(dbs.control, clock=clock),
        events=lambda kind, severity, detail: events.append((kind, dict(detail))),
    )


def observe(spam: SpamDetectors, n: int, *, ip: str = CLIENT, **kwargs: Any) -> None:
    """`n` finished requests of one client, as `pipeline._record` reports them."""
    base: dict[str, Any] = {
        "limit_key": ip,
        "place_id": None,
        "template": TEMPLATE,
        "path": "/v1/games",
        "query": [],
        "user_agent": "Roblox/Linux",
        "refused": False,
        "probe": False,
        "auth": False,
        "game_server": False,
        "bypass": False,
    }
    base.update(kwargs)
    for _ in range(n):
        spam.observe(**base)


def ban_rows(dbs: Any) -> list[tuple[Any, ...]]:
    return dbs.control.read_sync(
        lambda conn: [tuple(r) for r in conn.execute("SELECT subject_type, subject, created_by FROM bans")]
    )


# ============================================================================================ abuse-1


# Fixed (fixer abuse): the mark is kept on every row of the client and read per client when any detector fires
# (`spam.observe`, `SpamDetectors._mark_game_servers`).
@pytest.mark.parametrize(("signal", "count"), [("refused", 201), ("probe", 5), ("auth", 3)])
async def test_a_trusted_game_server_is_never_auto_banned_by_any_detector(
    dbs: Any, fake_clock: FakeClock, signal: str, count: int
) -> None:
    """Plan 10.3 collateral protection and the catalog text of `roblox_egress_cidrs`: a caller inside the Roblox
    game server ranges with the game server signature is "never auto-banned by the spam detectors"; the detector
    refuses the offending requests and adds a strike instead. Every request below carries that signature
    (`game_server=True`, what `bot.has_game_server_signature` gives the pipeline), and the detectors are armed."""
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, spam_dry_run=0)
    observe(spam, count, game_server=True, **{signal: True})
    acted = await spam.flush()
    assert [d.detector for d in acted] == [signal]  # the detector fired
    assert ban_rows(dbs) == [], events  # ... and banned a trusted game server (Roblox's shared egress address)


# ============================================================================================ abuse-2


# Fixed (fixer abuse): dry run applies to the configured action before the game server conversion
# (`SpamDetectors._effective_action`).
async def test_dry_run_takes_no_action_on_a_trusted_game_server(dbs: Any, fake_clock: FakeClock) -> None:
    """`spam_dry_run` (default 1): "a detector whose action is ban only records 'would have banned' ... nobody is
    actually banned". SPAM-RATE's action is ban, so in dry run nothing may be done to anyone; today only the
    trusted game server, the one client the protection exists for, is refused and struck while everyone else is
    merely logged."""
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, spam_rate_threshold=1.0)  # dry run on (the catalog default)
    observe(spam, 121, game_server=True)  # more than 1 x (10 / 50) x 600: SPAM-RATE fires
    stranger: list[Any] = []
    other = detectors(dbs, fake_clock, stranger, spam_rate_threshold=1.0)
    observe(other, 121, ip="203.0.113.8")  # the same flood without the signature, for comparison
    await spam.flush()
    await other.flush()
    assert [e[0] for e in stranger] == ["spam_would_ban"]  # an ordinary client: only logged, as documented
    strikes = await dbs.hot.read(lambda conn: load_strike_rows(conn, [CLIENT]))
    assert not strikes[CLIENT].exists, events  # a strike written during a dry run
    assert spam.flagged(CLIENT, fake_clock.now()) is None  # and its requests refused during a dry run


# ============================================================================================ abuse-3


# Fixed (fixer abuse): a ban accepts the Security page's 32-character key (or a full SHA-256) and stores the 16
# characters the lookup computes; any other length is refused (`rules/models.py normalize_ua_hash`).
async def test_a_user_agent_ban_from_the_dashboards_hash_refuses_that_user_agent(
    pages_app: Any,  # noqa: F811
    page: Any,  # noqa: F811
) -> None:
    """The only User-Agent hash the dashboard exposes is the Security fingerprint table's `ua_hash` (the drawer URL,
    `GET /security/fingerprints/user-agents`): `metrics.fingerprints.row_hash`, 32 hex characters of SHA-256. The ban
    matcher looks up `abuse.bans.ua_hash`, 16 hex characters. `BanIn` accepts 16 to 64 hex characters, so the ban is
    created, listed "in force", and refuses nothing. Fixed means: the ban refuses that User-Agent, or the dashboard
    refuses a hash that can never match (422)."""
    await pages_app.settings(ban_disguise_as_throttle=0)  # a plain 403 "banned" answer, easy to see
    agent = "python-requests/2.31.0"
    client = pages_app.harness.new_client()
    first = await client.get(PROXY_PATH, headers={"User-Agent": agent, "X-Forwarded-For": "198.51.100.40"})
    assert first.status_code == 200
    await pages_app.flush()
    listed = await page.api("GET", "security/fingerprints/user-agents", params={"page_size": 100})
    assert listed.status_code == 200, listed.text
    shown = next(item["ua_hash"] for item in listed.json()["items"] if item["user_agent"] == agent)
    made = await page.api(
        "POST",
        "protection/bans",
        json={"subject_type": "ua_hash", "subject": shown, "permanent": True, "reason": "abuse-3 reproduction"},
    )
    if made.status_code == 422:
        return  # the dashboard refuses a hash the matcher can never find: fixed
    assert made.status_code == 200, made.text
    assert made.json()["ban"]["active"] is True  # listed as in force
    second = await client.get(PROXY_PATH, headers={"User-Agent": agent, "X-Forwarded-For": "198.51.100.41"})
    assert second.status_code == 403, (second.status_code, second.headers.get("Roxy-Refusal"))
    assert second.headers.get("Roxy-Refusal") == "banned"


# ============================================================================================ abuse-4


# Fixed (fixer data): the client error hook records the refused outcome of a size or method limit refusal
# (`security_events.counts_as_refusal`, `MetricsRecorder.record_limit_refusal`).
async def test_the_request_limits_card_counts_size_and_method_refusals(
    pages_app: Any,  # noqa: F811
    page: Any,  # noqa: F811
) -> None:
    """Protection > Request limits (`limits_card`, `LIMIT_REASONS`) counts `body_too_large`, `headers_too_large`,
    `url_too_long` and `method_not_allowed` from the outcome rollups (`queries.reason_counts`). The middleware
    (`core/middleware.py SizeLimitMiddleware._refuse`) and the 405 handler only call `emit_client_error`, which
    records a probe; nothing records an outcome, so every count stays 0 however often the limits refuse."""
    client = pages_app.harness.new_client()
    caller = {"User-Agent": "Roblox/Linux", "X-Forwarded-For": "198.51.100.50"}
    max_url = int(pages_app.ctx.settings.int("max_url_length"))
    max_body = int(pages_app.ctx.settings.int("max_body_bytes"))
    max_headers = int(pages_app.ctx.settings.int("max_header_count"))
    long_url = await client.get("/games.roblox.com/v1/games?q=" + "a" * (max_url + 10), headers=caller)
    many = {**caller, **{f"X-Extra-{i}": "1" for i in range(max_headers + 1)}}
    headers = await client.get(PROXY_PATH, headers=many)
    body = await client.post("/games.roblox.com/v1/games", headers=caller, content=b"x" * (max_body + 1))
    method = await client.post("/", headers=caller)
    assert (long_url.status_code, headers.status_code, body.status_code, method.status_code) == (414, 431, 413, 405)
    await pages_app.flush()
    card = parse_html((await page.fragment("protection", "limits")).text)
    counts = {
        item.select_one(".prot-counts__label").text().strip(): item.select_one(".prot-counts__n").text().strip()
        for item in card.select("ul.prot-counts li")
    }
    assert counts["URL too long"] == "1", counts
    assert counts["Headers too large"] == "1", counts
    assert counts["Body too large"] == "1", counts
    assert counts["Method not allowed"] == "1", counts


# ============================================================================================ abuse-5


def _recommend_only(detector: str) -> bool:
    """Whether the catalog offers `recommend` as the detector's only action."""
    return {option.value for option in CATALOG[f"spam_{detector}_action"].options} == {"recommend"}


def _fire(spam: SpamDetectors, detector: str) -> None:
    """Observations that make `detector` fire with the catalog thresholds."""
    if detector == "bust":
        for i in range(200):  # 200 requests, each with a never-seen query value: unique ratio 1.0 > 0.9
            observe(spam, 1, query=[("t", str(i))])
    elif detector == "enum":
        for i in range(501):  # 501 distinct ids on one template: more than 500
            observe(spam, 1, path=f"/v1/users/{1000 + i}", template="users.roblox.com/v1/users/{id}")
    else:  # dist: 60 addresses, one User-Agent, one template, 1,020 requests in all
        for i in range(60):
            observe(spam, 17, ip=f"198.51.100.{i + 1}", user_agent="DistBot/1.0")


# Fixed (fixer abuse) for enum and bust: their subject is one client, so the chosen action applies to it
# (`spam.RECOMMEND_ONLY` is SPAM-DIST only). SPAM-DIST's subject is a swarm of addresses, so it keeps recommending and
# the catalog offers it `recommend` only (`config/settings/spam.py _Detector.actions`, applied by the integrator).
@pytest.mark.parametrize("detector", ["enum", "bust", "dist"])
async def test_a_spam_action_the_catalog_offers_takes_effect(dbs: Any, fake_clock: FakeClock, detector: str) -> None:
    """The catalog offers `ban`, `strike`, `tarpit` and `recommend` for every detector (and warns that `ban` is high
    risk for these three), but `spam.RECOMMEND_ONLY` turns every enum, bust and dist detection into `recommend` and
    `read_spam.detector_states` shows them as recommend. Fixed means: the catalog offers only what the detector does,
    or the chosen action happens (the per-address SPAM-BUST subject can be struck)."""
    if _recommend_only(detector):
        return
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, spam_dry_run=0, **{f"spam_{detector}_action": "strike"})
    _fire(spam, detector)
    acted = await spam.flush()
    assert [d.detector for d in acted] == [detector]  # it fired
    assert [kind for kind, _detail in events] == ["spam_strike"], events  # ... and only recommended


# ============================================================================================ abuse-6


def _skipped_words() -> dict[str, str]:
    """A keyword per check the bypass skips (`skipped_by_bypass`) that every bypass text must name."""
    skipped = {check.name for check in default_checks() if check.skipped_by_bypass}
    assert {"flood", "spam", "place_limit"} <= skipped  # the code: a bypass skips these too
    return {"flood": "flood", "spam": "spam", "place_limit": "place"}


def _missing(text: str) -> list[str]:
    lowered = text.lower()
    return [word for word in _skipped_words().values() if word not in lowered]


async def test_every_bypass_text_names_what_a_bypass_skips() -> None:
    """`texts.bypass_scope()` fixed the Bypass card and the client dialog (finding v1parity-9); the other texts still
    list the v1 set only. The owner reads them to judge how dangerous a forgotten entry is."""
    problems: dict[str, list[str]] = {}
    catalog = CATALOG["bypass_default_expiry_h"].description
    problems["catalog bypass_default_expiry_h"] = _missing(catalog)
    row = {"id": 1, "kind": "bypass", "cidr": "192.0.2.10/32", "note": "load test", "created_at": 1_760_000_000}
    ctx = SimpleNamespace(now=1_760_000_100.0)
    forever = SecBypassForever()
    captured: dict[str, Any] = {}
    forever.recommendation = lambda _ctx, **kwargs: captured.update(kwargs) or kwargs  # type: ignore[method-assign]
    forever._recommend(ctx, row, None)
    problems["SEC-BYPASS-FOREVER explanation"] = _missing(captured["explanation"])
    # Skeptic: the rendered explanation, not the method's source text, so a fix that builds the sentence from
    # `texts.bypass_scope()` (no literal "flood" in the source) passes.
    remove = FilterRemove()
    said: dict[str, Any] = {}
    remove.recommendation = lambda _ctx, **kwargs: said.update(kwargs) or kwargs  # type: ignore[method-assign]

    async def no_hits(_table: str) -> dict[Any, Any]:
        return {}

    async def access_rows(_table: str) -> list[dict[str, Any]]:
        return [row]

    remove_ctx = SimpleNamespace(now=1_760_000_100.0, setting=lambda _key: 30, rule_hits=no_hits, rule_rows=access_rows)
    await remove._bypass(remove_ctx)  # type: ignore[arg-type]
    problems["FILTER-REMOVE bypass explanation"] = _missing(said["explanation"])
    assert {where: words for where, words in problems.items() if words} == {}


async def test_the_bypass_remove_dialog_names_what_a_bypass_skips(
    pages_app: Any,  # noqa: F811
    page: Any,  # noqa: F811
) -> None:
    """Protection > Bypass, an entry's drawer: the Remove dialog says what the network goes back to
    (`_access_drawer.html`, a hard-coded list), not `texts.bypass_scope()`."""
    made = await page.api("POST", "protection/access/bypass", json={"cidr": "192.0.2.201", "expires_in_h": 2})
    assert made.status_code == 200, made.text
    entry = made.json()["item"]["id"]
    drawer = parse_html((await page.fragment("protection", "bypass", detail=entry)).text)
    dialog = drawer.select_one(f"#dlg-prot-access-del-{entry}")
    assert dialog is not None
    assert _missing(dialog.text()) == [], dialog.text()


# ============================================================================================ abuse-8


def test_the_no_roblox_signature_note_says_what_an_empty_list_does() -> None:
    """`bot.has_game_server_signature` is True only with Roblox-Id, a Roblox User-Agent AND an address inside a
    non-empty `roblox_egress_cidrs`. The note reads "1 when the Roblox-Id header and a Roblox User-Agent are missing
    (and, when the Roblox egress list is set, ...)", so with the default empty list it promises 0 to a game server
    that scores 1 (15 points of every real game server's score)."""
    note = BOT_SIGNAL_NOTES["no_roblox_signature"][1]
    # Skeptic: the wrong part is the conditional (the address check only "when the list is set"); a note may still
    # say "are missing" as long as it also says what an empty list does.
    assert "when the roblox egress list is set" not in note.lower(), note
    assert "empty" in note.lower(), note


# ============================================================================================ abuse-9


async def test_threshold_texts_say_at_or_above_where_the_check_does(
    pages_app: Any,  # noqa: F811
    page: Any,  # noqa: F811
) -> None:
    """`spam.evaluate_row`: probe and auth fire at `total >= threshold`; `checks/challenge.py BotScoreCheck` refuses at
    `value >= threshold`. The detector card (`spam_detector.html`) says "When it sees more than 5 probe requests",
    the setting label says "Block clients above bot score" and its description "is above this value"."""
    wrong: dict[str, str] = {}
    for detector in ("probe", "auth"):
        card = parse_html((await page.fragment("protection", f"spam-{detector}")).text)
        lead = next(p.text() for p in card.select("p") if "When it sees" in p.text())
        if "more than" in lead:
            wrong[f"spam-{detector}"] = " ".join(lead.split())
    spec = CATALOG["bot_score_block_threshold"]
    # "at or above" is the right wording; a bare "above" is the defect (the integrator refined this check).
    if "above" in spec.label.replace("at or above", "") or "is above" in spec.description:
        wrong["bot_score_block_threshold"] = spec.label
    assert wrong == {}


# ============================================================================================ abuse-10


async def test_the_client_ban_dialog_does_not_promise_the_caller_a_message(
    pages_app: Any,  # noqa: F811
    page: Any,  # noqa: F811
) -> None:
    """`POST /clients/{ip}/ban` stores `message` as the ban's `reason_text` (evidence on the Bans card); a banned
    caller gets "Access denied." or a disguised throttle text (`checks/bans.py`), never that message. The Protection
    page's own ban dialog says so ("Message kept with the ban, shown here as evidence")."""
    doc = await page.doc("/admin/clients/ip/198.51.100.7")
    label = doc.select_one('label[for="dlg-client-ban-message"]')
    assert label is not None
    assert "caller gets" not in label.text(), label.text()


# ============================================================================================ abuse-11


async def test_deleting_expired_bans_keeps_escalation_or_says_it_does_not(
    pages_app: Any,  # noqa: F811
    page: Any,  # noqa: F811
) -> None:
    """`bans.previous_offenses` doubles a detector's next ban for every automatic ban of the subject created in the
    last 30 days, expired ones included (they are kept 30 days for that). Protection > Bans > Delete bans > Expired
    bans deletes them, and its dialog says "Nothing changes for any caller". Fixed means: the escalation survives the
    deletion, or the dialog says that repeat offenders start again from the first ban length."""
    now = int(pages_app.clock.now())
    subject = "198.51.100.77"

    def insert(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO bans (subject_type, subject, reason_code, reason_text, created_at, created_by, expires_at) "
            "VALUES ('ip', ?, 'spam_probe', 'abuse-11', ?, 'auto:spam_probe', ?)",
            (subject, now - 2 * 86_400, now - 86_400),
        )

    pages_app.ctx.dbs.control.write_sync(insert)
    assert await previous_offenses(pages_app.ctx.dbs.control, "ip", subject, now) == 1
    card = parse_html((await page.fragment("protection", "bans")).text)
    dialog = card.select_one("#dlg-prot-bans-expired")
    assert dialog is not None
    text = dialog.text()
    reset = await page.api("POST", "protection/bans/reset", json={"scope": "expired", "reason": "abuse-11"})
    assert reset.status_code == 200, reset.text
    kept = await previous_offenses(pages_app.ctx.dbs.control, "ip", subject, now)
    if kept == 1:
        return  # the escalation history survived: "nothing changes" is true
    assert "Nothing changes for any caller" not in text
    assert any(word in text.lower() for word in ("repeat", "escalat", "doubl")), text


# ============================================================================================ abuse-12


async def test_the_fleet_tarpit_tile_counts_against_the_hold_cap(
    pages_app: Any,  # noqa: F811
    page: Any,  # noqa: F811
) -> None:
    """`tarpit.capacity` caps holds at `min(tarpit_max_concurrent, floor(budget x fraction))` = 50 by default; over
    it a refusal is answered at once. The fleet tile reads "N of 4,000" (`connection_budget`) with the help "the most
    it may hold before refusing at once", and warns at `capacity_used_pct >= 80`, which at most reaches 1.25 percent
    by default and 50 percent at the catalog maximum fraction (0.5): a saturated tarpit looks idle."""
    doc = await page.doc("/admin/system")
    tile = doc.select_one('[data-kpi="tarpit_connections"]')
    if tile is None:  # the fleet card may be lazy
        doc = parse_html((await page.fragment("system", "fleet")).text)
        tile = doc.select_one('[data-kpi="tarpit_connections"]')
    assert tile is not None
    number = tile.select_one(".kpi__number").text().strip()
    cap = (await pages_app.ctx.abuse.tarpit.state())["max_concurrent"]
    assert number.endswith(f"of {cap:,}"), number


# ============================================================================================ abuse-14


WORKER_HEADROOM_MIB = 8
"""DESIGN 15.7: a color settles at about 405 MiB of PSS at 200 requests a second against `MemoryHigh=420M`, so about
15 MiB of headroom per color, under 8 MiB per worker with ROXY_WORKERS=2."""


# Fixed (fixer abuse): `limiter.MEMORY_ROWS_MAX` is 6,000 (both stores full: about 4.4 MiB per worker).
def test_the_degraded_mode_row_stores_fit_the_memory_plan() -> None:
    """Plan P9 bounds every map; DESIGN 0 and 15.7 size every bound for the 909 MB box. While hot.db cannot be
    written (C7, also when a flood keeps its write lock busy past the 500 ms budget), each worker keeps what it
    decides in `pipeline._memory_rows` and `_memory_strikes`, `limiter.MemoryRowStore` with `MEMORY_ROWS_MAX`
    (50,000) entries each, every entry a `DegradedEntry` with its row and its seed (`pipeline._degraded_walk`). A
    flood from 25,000 addresses fills the limiter store (flood and per-IP rows). Filled as the walk fills them, the
    two stores take about 38 MiB per worker, 77 MiB for a color, while the memory plan leaves about 15 MiB."""
    tracemalloc.start()
    try:
        rows: MemoryRowStore[DegradedEntry[LimiterRow]] = MemoryRowStore()
        strikes: MemoryRowStore[DegradedEntry[StrikeRow]] = MemoryRowStore()
        for i in range(rows.max_rows // 2):
            ip = f"10.{i // 65_536}.{(i // 256) % 256}.{i % 256}"
            for key in (f"flood:{ip}", ip):  # the flood row and the per-IP row of one client
                rows.put(
                    key, DegradedEntry(LimiterRow(key, 1_760_000_000_000 + i, 0, 0, True), LimiterRow(key), "gcra")
                )
        for i in range(strikes.max_rows):
            ip = f"10.{i // 65_536}.{(i // 256) % 256}.{i % 256}"
            strikes.put(
                ip, DegradedEntry(StrikeRow(ip, 1, 1_760_000_000, 1, 1_760_000_050, True), StrikeRow(ip), "strikes")
            )
        used_mib = tracemalloc.get_traced_memory()[0] / 2**20
    finally:
        tracemalloc.stop()
    assert len(rows) == rows.max_rows
    assert len(strikes) == strikes.max_rows
    assert used_mib <= WORKER_HEADROOM_MIB, f"{used_mib:.1f} MiB per worker"


# ============================================================================================ abuse-15


async def _quiet_sleep(_seconds: float) -> None:
    return None


# Fixed (fixer abuse): a per-experience endpoint budget follows `place_limit_key` like the place limit (per place and
# caller network by default; `checks/endpoint_rules.py`, `endpoint_rules.endpoint_limit`).
async def test_a_forged_place_id_cannot_use_up_a_games_per_place_endpoint_budget(
    dbs: Any, fake_clock: FakeClock
) -> None:
    """Plan 10.2: a place key is "a claim, keyed with the caller prefix by default, see threat 6" (threat 6: a forger
    claims a place id "to exhaust its place limit"). The place limit does that (`place_limit_key` `place_prefix`,
    `checks/place_limit.py caller_network`), but an endpoint rate rule with scope `place` keys on
    `ep:<rule>|place:<id>` (`abuse/endpoint_rules.py endpoint_limit`): anyone sending the game's Roblox-Id from
    another network spends the game's budget, and the game's real servers are refused with 429."""
    service = RulesService(dbs.control, clock=fake_clock)
    await service.create(
        "rules_endpoint_limit",
        {"pattern": TEMPLATE, "limit": 2, "period": 60, "scope": "place"},
        Actor("admin", "owner"),
        "abuse-15 reproduction",
    )
    snapshot = dbs.control.read_sync(lambda conn: build_rules_snapshot(conn, fake_clock.now()))
    pipeline = AbusePipeline(
        settings=FakeSettings(),
        rules=snapshot,
        hot_db=dbs.hot,
        control_db=dbs.control,
        clock=fake_clock,
        worker_id="review-worker",
        tarpit_sleep=_quiet_sleep,
        monotonic=fake_clock.monotonic,
    )
    forger = FakeReq(client_ip="198.51.100.9", limit_key="198.51.100.9", place_id="1818")
    for _ in range(2):
        assert isinstance(await pipeline.evaluate(forger), Allow)
    game_server = FakeReq(client_ip="203.0.113.50", limit_key="203.0.113.50", place_id="1818")
    verdict = await pipeline.evaluate(game_server)
    assert isinstance(verdict, Allow), (verdict.reason, verdict.detail)


# ============================================================================================ abuse-16


# Fixed (fixer abuse): folded subjects every client feeds are counted but never evaluated
# (`spam.SHARED_OVERFLOW_SUBJECTS`).
async def test_the_folded_overflow_place_is_never_a_detection_subject(dbs: Any, fake_clock: FakeClock) -> None:
    """`spam._chosen` folds a client's ninth and later distinct places in an hour into `OVERFLOW` (`(other)`) to bound
    the rows a caller can create (DESIGN 11.9). The flush evaluates `place:(other)` like any place, so SPAM-RATE fires
    on the sum of every client's overflow and `insights/rules/abuse.py AbuseSpam._place` recommends "Review place
    (other) on Clients", a place no caller sent and the Clients page cannot show."""
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events)
    for place in range(1, 709):  # 8 places kept, then 700 more distinct ones folded into `(other)`
        observe(spam, 1, place_id=str(place))
    acted = await spam.flush()
    flagged = [d.subject for d in acted if "(other)" in d.subject]
    assert flagged == [], [(kind, detail.get("subject")) for kind, detail in events]
