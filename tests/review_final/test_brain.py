"""Final review, lens brain: the recommendations engine, Check Proxy Health and the alerts (regression tests).

What this is
    One test per finding of `.remake/final_review/find_brain.md`, each a strict xfail naming its finding until the final
    review fixed it and a regression test now. The tests drive the
    real code: the engine and the D7 auto-applier over a committed insights fixture (`tests/insights/harness.py`),
    the real app in process for the dashboard and the admin API (`tests/integration/pages/conftest.py`), the real
    notifier with a recording mail transport for the alerts, and the catalog and docs texts the owner reads.

Why it exists
    The final review rule: a finding without a reproduction is not a finding. For a wrong text the test asserts the
    right text, and where a fix could land on either side (the code or the text) the test accepts both.

How it works
    Every database lives in a temporary directory (the root conftest's `dbs` and `env`, or a freshly loaded insights
    fixture that the test closes itself, never the harness's shared cache); the clock is a `FakeClock`; Roblox is
    `respx` or nothing at all. No test opens a network connection.

What to read next
    `roxy/insights/rules/upstream.py` (UP-BUCKET-TUNE), `roxy/insights/autoapply.py`, `roxy/insights/actions.py`,
    `roxy/notify/`, `roxy/egress/events.py`, `roxy/health/checks.py`, `docs/RUNBOOKS.md`.
"""

# ruff: noqa: F811  (the imported pytest fixtures are the tests' parameters)

from __future__ import annotations

import json
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from integration.pages.conftest import anon, page, page_admin, pages_app  # noqa: F401  (the page fixtures)
from roxy.config import catalog
from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.core.reasons import Egress
from roxy.egress.credential import CredentialManager
from roxy.egress.crypto import load_encryption_key
from roxy.egress.events import EventSink
from roxy.egress.models import EgressResponse
from roxy.insights.actions import RecommendationActions
from roxy.insights.autoapply import AutoApplier
from roxy.insights.engine import InsightsEngine
from roxy.insights.models import ProposedChange
from roxy.insights.rules import load_rules
from roxy.notify.mail import MailConfig, MailSender
from roxy.notify.notifier import Notifier
from roxy.rules.service import RulesService
from roxy.rules.store import RulesStore

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src" / "roxy"
ADMIN = Actor("admin", "final-review", "203.0.113.5")
ORIGIN = "https://roxy.example"
MAIL = MailConfig("owner@example.invalid", "alerts@example.invalid", SecretStr("not-a-real-password"))


class RecordingTransport:
    """A mail transport that keeps the messages (no SMTP)."""

    def __init__(self) -> None:
        self.messages: list[EmailMessage] = []

    async def __call__(self, message: EmailMessage, config: Any) -> None:
        self.messages.append(message)

    def subjects(self) -> list[str]:
        return [str(m["Subject"]) for m in self.messages]

    def body(self, subject: str) -> str:
        found = [str(m.get_content()) for m in self.messages if str(m["Subject"]) == subject]
        assert found, f"no mail with subject {subject!r}; got {self.subjects()}"
        return found[-1]


class CatalogSettings:
    """Catalog defaults with the `RuntimeSettings` read API, plus test overrides."""

    def __init__(self, **overrides: Any) -> None:
        self.values: dict[str, Any] = catalog.defaults()
        self.values.update(overrides)

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def int(self, key: str) -> int:
        return int(self.values[key])

    def float(self, key: str) -> float:
        return float(self.values[key])

    def bool(self, key: str) -> bool:
        return bool(self.values[key])

    def str(self, key: str) -> str:
        return str(self.values[key])


def _response(status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> EgressResponse:
    return EgressResponse(
        status=status,
        headers=httpx.Headers(headers or {}),
        body=body,
        elapsed_ms=1.0,
        bytes_out=0,
        bytes_in=0,
        egress=Egress.CREDENTIAL,
        session_id=None,
        http_version="HTTP/1.1",
    )


def _fetch(*answers: EgressResponse) -> Any:
    queue = list(answers)

    async def fetch(url: str) -> EgressResponse:
        return queue.pop(0)

    return fetch


def _section(markdown: str, heading: str) -> str:
    """The text of one `## heading` section of a Markdown document."""
    start = markdown.index(f"## {heading}\n")
    end = markdown.find("\n## ", start + 4)
    return markdown[start : end if end >= 0 else len(markdown)]


async def _d7_world(state: Any, rule_id: str) -> tuple[InsightsEngine, RulesService, AutoApplier]:
    """The leader's engine (one rule), actions and D7 auto-applier over a loaded insights fixture, auto-apply on."""
    store = RulesStore(state.dbs.control, clock=state.clock)
    await store.reload()
    engine = InsightsEngine(
        dbs=state.dbs,
        settings=state.runtime,
        rules=store,
        clock=state.clock,
        providers=state.providers,
        rule_set={rule_id: load_rules()[rule_id]},
    )
    settings = SettingsService(state.dbs.control, runtime=state.runtime, clock=state.clock)
    rules = RulesService(state.dbs.control, clock=state.clock, store=store)
    actions = RecommendationActions(engine=engine, settings_service=settings, rules_service=rules, clock=state.clock)
    await settings.update({"insights_auto_apply": 1}, ADMIN, "D7 on for the review")
    return engine, rules, AutoApplier(engine=engine, actions=actions, notifier=None, clock=state.clock)


# ===================================================================================================== brain-1


async def test_up_bucket_tune_never_raises_again_on_rejections_from_before_its_last_raise() -> None:
    """Plan 7.3 "bounded upward probing": a raise needs `clean_hours` (24) with zero 429s AND rejections over 1% of
    the attempts. After a raise the 24 hours of rejections the rule read were all turned away at the OLD rate, so
    they say nothing about the new one; the next raise must wait for evidence gathered at the new rate. Today the
    engine re-opens the card as soon as the watch window (`auto_apply_watch_minutes`, 30) ends, and the D7
    auto-applier (safe_auto, risk low, a 10% step inside `auto_apply_max_step_pct`, 2 changes an hour inside
    `auto_apply_max_per_hour`) raises the same bucket again on the same day of rejections: +10% every 30 minutes
    toward Roblox until a 429 arrives."""
    from insights import harness as insight_harness

    state = await insight_harness.load("up_bucket_tune__too_tight")  # not the shared cache: this test writes to it
    try:
        engine, rules, auto = await _d7_world(state, "UP-BUCKET-TUNE")
        key = "endpoint:thumbnails.roblox.com/v1/batch"

        now = state.now
        await engine.run_once(now=now)
        first = await auto.run(now=now)
        assert len(first["applied"]) == 1, first
        assert (await rules.get_row("upstream_limits", key))["per_min"] == 66  # the fixture's 60 raised by 10%

        later = now + float(state.runtime.get("auto_apply_watch_minutes")) * 60 + 60
        state.clock.set(later)
        await engine.run_once(now=later)
        await auto.run(now=later)
        reopened = [rec for rec in await engine.list(states=("open", "auto_applied")) if rec.subject == key]
        per_min = (await rules.get_row("upstream_limits", key))["per_min"]
        # The only rejections the rule can see were turned away at 60 per minute, before the raise to 66.
        assert per_min == 66, f"raised again to {per_min} per minute within the hour, on the same day of rejections"
        assert len(reopened) == 1, [(rec.state, rec.title) for rec in reopened]
    finally:
        state.close()


# ===================================================================================================== brain-2


async def test_an_undo_cannot_arm_the_spam_detectors_past_the_arm_route(page: Any, pages_app: Any) -> None:
    """Plan 10.3 and `admin/api/settings.py ARM_ONLY_SETTINGS`: `spam_dry_run` 0 arms automatic bans and is allowed
    only through `POST /protection/spam/arm` after the collateral preview; PATCH, PUT, revert and import refuse it,
    and `audit.revert_info` offers no revert that arms (P11 functional-9). SEC-DEFAULTS fires on `spam_dry_run` 0
    (a high-risk value) and proposes 1; once applied, `POST /recommendations/{id}/undo` writes 0 back through
    `RecommendationActions._revert_one` -> `SettingsService.revert` with no `WriteRules` guard and no high-risk
    confirmation: the detectors are armed again, days later, with no collateral review, by one undo click."""
    from integration.pages.test_page_recommendations import seed

    await pages_app.settings(spam_dry_run=0)  # armed earlier through the arm route (its own collateral review)
    rec_id = await seed(
        pages_app,
        rule_id="SEC-DEFAULTS",
        subject="spam_dry_run",
        changes=[ProposedChange("setting", key="spam_dry_run", current=0, proposed=1)],
    )
    digest = (await page.api("GET", f"recommendations/{rec_id}/preview")).json()["changes_digest"]
    applied = await page.api(
        "POST",
        f"recommendations/{rec_id}/apply",
        json={"changes_digest": digest, "confirm_high_risk": True, "reason": "Back to dry run for now"},
    )
    assert applied.status_code == 200, applied.text
    await pages_app.ctx.settings.reload()
    assert pages_app.ctx.settings.int("spam_dry_run") == 1  # back in dry run
    refused = await page.api(
        "PATCH",
        "settings",
        json={"changes": {"spam_dry_run": 0}, "reason": "Arm again", "confirm_high_risk": True},
    )
    assert refused.status_code == 422, refused.text  # the settings editor refuses this very write (arm-only)
    undone = await page.api("POST", f"recommendations/{rec_id}/undo", json={"reason": "Changed my mind"})
    await pages_app.ctx.settings.reload()
    armed = pages_app.ctx.settings.int("spam_dry_run") == 0
    assert not armed, f"the undo armed the spam detectors (answer {undone.status_code}: {undone.text[:200]})"


# ===================================================================================================== brain-3


async def test_auto_apply_measures_a_new_cache_rules_ttl_from_the_lifetime_in_force() -> None:
    """Plan 11.4: a value "may move at most `auto_apply_max_step_pct` (50%) per change"; `autoapply.py` says
    "Numeric rule values (a bucket's rate, a cache rule's TTL) obey the same step limit against their current
    value". `guardrail_problem` measures the step only from `change.current`, which is None for a new rule, so a
    CACHE-TTL-TUNE (or UP-429-ENDPOINT, HOT-ENDPOINT) card that creates the endpoint's first own rule passes with
    any TTL. In the committed fixture `cache_ttl_tune__fires_raise`, badges (no rule of its own, cached at
    `cache_ttl_seconds` 120 s, as the card's own evidence says) goes to 3,600 s unattended, while groups, whose own
    row moves 120 s -> about 1,800 s, is refused for the step. Callers then get bodies up to an hour old."""
    from insights import harness as insight_harness

    state = await insight_harness.load("cache_ttl_tune__fires_raise")  # not the shared cache: this test writes to it
    try:
        engine, _rules, auto = await _d7_world(state, "CACHE-TTL-TUNE")
        await engine.run_once(now=state.now)
        cards = {rec.subject: rec for rec in await engine.list(states=("open",))}
        badges = next(rec for subject, rec in cards.items() if subject.startswith("badges.roblox.com"))
        groups = next(rec for subject, rec in cards.items() if subject.startswith("groups.roblox.com"))
        assert badges.evidence.metric("current_ttl_s") == 120  # what the badges endpoint is cached for today
        result = await auto.run(now=state.now)
        assert groups.id not in result["applied"]  # an existing row's 120 s -> 1,800 s is over the 50% step
        assert badges.id not in result["applied"], (
            f"badges' cache lifetime moved from 120 s to {badges.changes[0].proposed['ttl']} s unattended"
        )
    finally:
        state.close()


# ===================================================================================================== brain-4


def _event(at_ms: int, *, error: bool) -> Any:
    """One served caller request for the guard metrics (a failed one when `error`)."""
    from roxy.core.reasons import AuthClass, CacheState, Outcome, ReasonCode, Source
    from roxy.metrics.recorder import OutcomeEvent

    return OutcomeEvent(
        at_ms=at_ms,
        request_id="final-review",
        endpoint_template="games.roblox.com/v1/games",
        host="games.roblox.com",
        method="GET",
        egress=Egress.NONE,
        outcome=Outcome.SERVED_CACHE,
        reason=ReasonCode.CACHE_HIT,
        status=200,
        source=Source.CACHE,
        cache_state=CacheState.HIT,
        auth_class=AuthClass.ANON,
        caller_bytes_in=0,
        caller_bytes_out=100,
        upstream_calls=0,
        upstream_bytes_in=0,
        upstream_bytes_out=0,
        latency_ms=5.0,
        queue_wait_ms=0.0,
        upstream_ms=0.0,
        client_ip="203.0.113.9",
        place_id=None,
        user_agent="Roblox/Linux",
        bypass=False,
        error=error,
    )


async def _record(ctx: Any, clock: Any, start: float, minutes: int, *, error_every: int = 0) -> None:
    """20 requests a minute for `minutes` from `start` through the real recorder (every `error_every`th failing)."""
    from roxy.metrics.recorder import MetricsRecorder

    recorder = MetricsRecorder(ctx.dbs, ctx.settings, clock)
    for minute in range(minutes):
        for n in range(20):
            at = int((start + minute * 60) * 1000) + n * 1000
            recorder.record_outcome(_event(at, error=bool(error_every) and n % error_every == 0))
    await recorder.aclose()


async def test_a_watch_whose_guard_numbers_got_worse_never_says_they_stayed_within_bounds(
    page: Any, pages_app: Any
) -> None:
    """Plan 11.4: the watch window compares the guard metrics after a change with the baseline before it. Every
    apply opens one (`actions._apply`), but `AutoApplier.watch` rolls back only `auto_applied` changes and closes
    every other window as `kept`, with the regressions in its result. The drawer then prints
    `WATCH_WORDS["kept"]`, "Kept: the guard numbers stayed within bounds", for a change that made the error rate
    go from 0 to 50%: the owner reads that the change is safe when it measurably was not. (A rollback refused for
    good is closed as `kept` too, under the same words, beside "Rollback refused".)"""
    from integration.pages.test_page_recommendations import seed

    ctx, clock = pages_app.ctx, pages_app.clock
    now = clock.now()
    await _record(ctx, clock, now - 1800, 30)  # the baseline: no errors
    rec_id = await seed(pages_app)
    digest = (await page.api("GET", f"recommendations/{rec_id}/preview")).json()["changes_digest"]
    applied = await page.api("POST", f"recommendations/{rec_id}/apply", json={"changes_digest": digest})
    assert applied.status_code == 200, applied.text
    await _record(ctx, clock, now, 30, error_every=2)  # half of the requests fail after the change
    clock.advance(float(ctx.settings.int("auto_apply_watch_minutes")) * 60 + 1)
    await ctx.auto_apply.watch()
    watch = await ctx.dbs.metrics.read(
        lambda conn: conn.execute(
            "SELECT state, result_json FROM recommendation_watches WHERE recommendation_id = ?", (rec_id,)
        ).fetchone()
    )
    assert watch is not None
    assert watch[0] == "kept"
    assert "error_rate" in json.loads(watch[1])["worse"]  # the guard numbers got worse, measurably
    assert (await pages_app.harness.login(page.admin)).status_code == 200  # the clock jump ended the old session
    drawer = await page.doc("/admin/recommendations/detail", params={"rec": rec_id})
    text = drawer.text()
    assert "Watch window" in text
    assert "stayed within bounds" not in text, "the drawer says the guard numbers stayed within bounds"


# ===================================================================================================== brain-5


async def test_a_deliberate_pause_does_not_fail_the_caller_error_check(page: Any, pages_app: Any) -> None:
    """Plan 17.7 and `notify/producers.py caller_5xx_facts`: "a deliberate pause (`paused`, 503) left out of both
    sides"; the guard metrics leave it out too (`refused` and `errors` skip `paused`). H-ERR-RATE
    (`health/checks.py check_err_rate`) divides every 5xx status of the caller sources by the requests, a pause
    included: while the owner pauses Roxy (by hand, in a scheduled maintenance window, or on the first start of a
    v2 that inherited v1's pause, lead decision 1) the check fails with "Callers are getting server errors; the
    Errors view shows which" (the Errors view shows nothing), a scheduled run sends "Roxy: health check found 1
    new failures", and SYS-HEALTH-FAIL opens a card."""
    from pages_harness import PlannedRequest
    from roxy.health import checks
    from roxy.health.model import RunOptions, Status

    paused = await page.api("POST", "protection/pause", json={"paused": True})
    assert paused.status_code == 200, paused.text
    await pages_app.ctx.settings.reload()
    plan = [PlannedRequest(path="/games.roblox.com/v1/games?universeIds=1", ip="203.0.113.7")] * 10
    statuses = await pages_app.seed_traffic(plan)
    assert set(statuses) == {503}, statuses  # every caller got the pause answer, and nothing else happened
    result = await pages_app.ctx.health.run_check(
        checks.CATALOG["H-ERR-RATE"], {}, trigger="manual", options=RunOptions(include_credential=False)
    )
    words = f"{result.value} {result.explanation}"
    assert result.status is not Status.FAIL or "paus" in words.lower(), (result.status, words)


# ===================================================================================================== brain-6


@pytest.fixture
def _clean_secrets() -> Any:
    from roxy.core.redact import SecretRegistry

    SecretRegistry.clear()
    yield
    SecretRegistry.clear()


@pytest.mark.usefixtures("_clean_secrets")
async def test_the_credential_alerts_link_their_runbook_and_page(env: Any, dbs: Any) -> None:
    """Plan 17.7: every alert body has `Where` (page link) and `What to do` (runbook link); the Token Expired row
    names the "link to Credential page". `notify/alerts.py ALERT_SPECS` gives these types a runbook
    (`credential-rejected`, `credential-cooldown`, `credential-rotated`, `rotator-quota`, `leak-guard`), but
    `egress/events.py EventSink.alert` builds the `Alert` itself (`build_alert`) with neither `runbook` nor `link`,
    so the most urgent mails Roxy sends tell the owner to "see the admin guide"."""
    transport = RecordingTransport()
    settings = CatalogSettings()
    notifier = Notifier(
        hot_db=dbs.hot,
        settings=settings,
        site_origin=ORIGIN,
        mail=MailSender(MAIL, transport=transport),
        webhook=None,
        clock=FakeClock(),
    )
    events = EventSink(lambda: notifier, lambda: None)
    manager = CredentialManager(
        credentials_dir=env.credentials_dir,
        dbs=dbs,
        settings=settings,
        clock=FakeClock(),
        worker_id="w1",
        encryption_key=load_encryption_key(env.credentials_dir),
        events=events,
        allow_loopback_target=False,
    )
    await manager.start()
    await manager.probe("liveness", fetch=_fetch(_response(401)))  # Roblox rejects the credential
    await manager.set_cooldown(900, "retry_after")  # a 15 minute Retry-After on the account
    await manager.observe_set_cookie(
        [".ROBLOSECURITY=" + "ROTATEDVALUE" + "9F" * 120 + "; domain=.roblox.com; path=/; secure"],
        endpoint="users.roblox.com/v1/users/authenticated",
    )
    await events.drain()
    for subject, runbook in (
        ("Token Expired", "credential-rejected"),
        ("Roxy: credential cooling down", "credential-cooldown"),
        ("Roxy: Roblox sent a new credential cookie", "credential-rotated"),
    ):
        body = transport.body(subject)
        assert f"What to do: {ORIGIN}/admin/help#runbook-{runbook}" in body, (subject, body)
        assert "Where: n/a" not in body, (subject, body)


# ===================================================================================================== brain-7


def test_the_user_agent_experiment_length_is_read_by_the_experiment() -> None:
    """`ua_experiment_days` (default 7): "How many days the User-Agent experiment runs before UP-UA-EXPERIMENT
    reports its result", and `ua_experiment_enabled` splits direct calls "for ua_experiment_days". No module
    outside the catalog reads it: `egress/headers.py` splits every direct call for as long as
    `ua_experiment_enabled` is 1, and UP-UA-EXPERIMENT counts only the last `request_sample_hours` of samples. An
    owner who switches the experiment on gets a split of the anonymous direct traffic (half of it under the
    alternative identity, whatever 429s it draws) that runs until someone switches it off. Either the experiment
    honors its length or the setting goes."""
    if "ua_experiment_days" not in catalog.CATALOG:
        return
    readers = [
        str(path.relative_to(SRC))
        for path in SRC.rglob("*.py")
        if "config" not in path.relative_to(SRC).parts and "ua_experiment_days" in path.read_text(encoding="utf-8")
    ]
    assert readers, "no module outside roxy/config reads ua_experiment_days"


# ===================================================================================================== brain-8


async def test_the_rollback_runbook_step_works_on_a_rolled_back_recommendation(page: Any, pages_app: Any) -> None:
    """docs/RUNBOOKS.md, "Auto-applied change rolled back", **Roll back.**: "Apply it again by hand after review
    (`POST /admin/api/v1/recommendations/{rec_id}/apply`)". A rolled back recommendation cannot be applied
    (`allowed_actions` and `RecommendationActions._apply` accept open or snoozed only), and the engine keeps its
    fingerprint quiet for `dismiss_cooldown_days` (QUIET_STATES), so no new card offers the change for a week. The
    owner following the runbook gets 409 `wrong_state`. Either the step works or the runbook says what does."""
    from integration.pages.test_page_recommendations import seed

    runbook = _section((REPO / "docs" / "RUNBOOKS.md").read_text(encoding="utf-8"), "Auto-applied change rolled back")
    rec_id = await seed(pages_app)
    digest = (await page.api("GET", f"recommendations/{rec_id}/preview")).json()["changes_digest"]
    applied = await page.api("POST", f"recommendations/{rec_id}/apply", json={"changes_digest": digest})
    assert applied.status_code == 200, applied.text
    undone = await page.api("POST", f"recommendations/{rec_id}/undo", json={"reason": "Guard numbers got worse"})
    assert undone.status_code == 200, undone.text
    detail = (await page.api("GET", f"recommendations/{rec_id}")).json()
    assert detail["recommendation"]["state"] == "rolled_back"  # the state an automatic rollback leaves too
    step = next((line for line in runbook.splitlines() if line.startswith("**Roll back.**")), "")
    if "/apply" in step or "apply it again" in step.lower():
        digest = (await page.api("GET", f"recommendations/{rec_id}/preview")).json()["changes_digest"]
        again = await page.api(
            "POST", f"recommendations/{rec_id}/apply", json={"changes_digest": digest, "reason": "After review"}
        )
        assert again.status_code == 200, f"the runbook's step answers {again.status_code}: {again.text}"


# ==================================================================================================== brain-13


def test_the_auto_apply_rollback_alerts_link_a_page_the_mail_can_open() -> None:
    """Plan 17.7: "Links use `ROXY_SITE_ORIGIN` (for example `<ROXY_SITE_ORIGIN>/admin/recommendations/<id>`)".
    `AutoApplier._notify` and `_notify_refused` (the critical "could not be rolled back" alert, which tells the owner
    to "undo it by hand") pass `link="/admin/recommendations"`: the mail's "Where:" is a bare path a mail client
    cannot open, and it names the list, not the recommendation. (`upstream/service.py _alert_all_unavailable` passes
    no link at all: "Where: n/a".)"""
    from roxy.insights.models import Evidence, Recommendation
    from roxy.notify.notifier import render_email

    class Captured:
        """The notifier's `notify` and `site_origin` (a fix may read the origin from the notifier)."""

        site_origin = ORIGIN

        def __init__(self) -> None:
            self.alerts: list[Any] = []

        def notify(self, alert: Any) -> None:
            self.alerts.append(alert)

    captured = Captured()
    applier = AutoApplier.__new__(AutoApplier)
    applier.notifier = captured
    applier.site_origin = ORIGIN  # a fix may give the applier the origin itself (skeptic: robust to either fix)
    rec = Recommendation(
        rule_id="UP-BUCKET-TUNE",
        family="upstream",
        subject="endpoint:games.roblox.com/v1/games",
        title="Bucket endpoint:games.roblox.com/v1/games is too tight",
        severity="info",
        evidence=Evidence(sample_size=1),
    )
    rec.id = "rec_01FINALREVIEW0000000000000"
    applier._notify(rec, {"error_rate": {"before": 0.0, "after": 0.5}})
    applier._notify_refused(rec, {"error_rate": {"before": 0.0, "after": 0.5}}, "an admin changed the row")
    assert len(captured.alerts) == 2
    for alert in captured.alerts:
        _subject, body = render_email(alert, suppressed=0, now=1_791_385_200.0, tz_name="UTC", site_origin=ORIGIN)
        where = next(line for line in body.splitlines() if line.startswith("Where: "))
        assert where.startswith(f"Where: {ORIGIN}/admin/recommendations"), (alert.type, where)


# ==================================================================================================== brain-14


async def test_apply_fix_links_the_card_of_the_failing_check_only(dbs: Any) -> None:
    """Plan 13.1: "Apply fix (shown when a recommendation is linked to the check)". `health/store.py
    linked_recommendations` links a SYS-HEALTH-FAIL card when `check_id in text` (subject, title and fingerprint
    joined), so a failing H-TLS (the Roblox hosts' TLS) row offers the card of H-TLS-PUBLIC (the public
    certificate), and its Apply fix opens the wrong check's fix."""
    from roxy.core.ids import new_id
    from roxy.health import checks, store
    from roxy.insights.engine import write_recommendation
    from roxy.insights.models import Evidence, Recommendation, make_fingerprint

    clock = FakeClock()
    rec = Recommendation(
        rule_id="SYS-HEALTH-FAIL",
        family="system",
        subject="H-TLS-PUBLIC",
        title="Health check H-TLS-PUBLIC is failing: 3 days left",
        severity="critical",
        evidence=Evidence(sample_size=1),
        changes=[ProposedChange("manual", text="Follow the fix for H-TLS-PUBLIC")],
    )
    rec.id = new_id("rec", clock)
    rec.fingerprint = make_fingerprint(rec.rule_id, rec.subject)
    rec.state = "open"
    rec.created_at = rec.updated_at = clock.now()
    await dbs.metrics.write(lambda conn: write_recommendation(conn, rec))
    linked = await dbs.metrics.read(
        lambda conn: store.linked_recommendations(conn, ["H-TLS", "H-TLS-PUBLIC"], checks.RECOMMENDATION_RULES)
    )
    assert linked.get("H-TLS-PUBLIC", {}).get("id") == rec.id
    assert "H-TLS" not in linked, f"H-TLS offers the H-TLS-PUBLIC card: {linked.get('H-TLS')}"
