"""The dashboard page registry: the 18 pages of plan 14.1, their cards, and the v1 section map they must cover.

What this is
    Pure data plus a few lookups, read by the sidebar, the phone menu, the command palette, the shortcut overlay,
    the page routes (`roxy.admin.pages`) and the acceptance tests:
      * `PAGES`: one `PageSpec` per page (id, title, nav group, icon, `g` shortcut, the one-sentence "What this page
        is for", the "How to read this page" text, and its `CardSpec` cards in display order). Card ids are the
        anchors of DESIGN.md section 9 (`upstream#buckets` is card `buckets` of page `upstream`) plus the cards the
        plan 14.1 v1 section map names; every anchor a catalog setting names is added automatically.
      * `NAV_GROUPS` and `nav_model()`: the sidebar groups in order (templates read them through the Jinja global
        `admin_nav()`, `roxy/core/templating.py`).
      * `V1_SECTIONS`: the 37 rows of the plan 14.1 v1 section to v2 page map (with the corrections of
        `.remake/v1notes/dashboard.md` section 1.1), each with the page, card and key elements that prove the v1
        section survived. `tests/e2e/test_v1_sections.py` turns each row into one test.
      * `is_built(page_id)`: whether the page's module `roxy.admin.pages.<id>` exists. A page that is registered but
        not built renders a plain "coming soon" body, so the shell and the navigation work from the start.

Why it exists
    Plan 14.1 lists the pages; DESIGN.md section 9 pins the card anchors the settings catalog points at; plan 14.7
    asks every page for its purpose sentence and a "How to read this page" panel. Keeping all of it in one module
    means the sidebar, the palette, the tests and the page routes can never disagree about which pages exist or
    what they must show, and seven page builders work in parallel without editing a shared list.

How it works
    Frozen dataclasses built at import. `cards_for(page_id)` merges the declared cards with the anchors the
    catalog's `pages` field names for that page (so a setting can never point at a card the registry lacks);
    `settings_for(anchor)` lists the catalog settings placed on a card. Nothing here touches a database.

What to read next
    `roxy/admin/pages/kit.py` (how a page module renders these cards), `roxy/admin/pages/shell.py` (the shell
    context), `.remake/P11_CONTRACT.md` (the builders' contract), `tests/e2e/test_v1_sections.py`.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import cache
from typing import Any, Final

from roxy.config.catalog import CATALOG, NON_PAGE_HOMES
from roxy.config.spec import SettingSpec

PAGE_PACKAGE: Final = "roxy.admin.pages"
PAGE_PREFIX: Final = "/admin"
SHELL_PAGE: Final = "*"
"""`V1Check.page` for checks on the shell (top bar, dialogs), which every page renders."""


@dataclass(frozen=True, slots=True)
class CardSpec:
    """One card of a page: its anchor id (unique on the page), its title and one sentence of help.

    `fragment_only`: the card is not part of the first paint (a drawer such as one rule's tuning panel) and lives
    only at its fragment URL. `settings_open`: the card exists to hold settings, so its settings list starts open.
    """

    id: str
    title: str
    help: str = ""
    fragment_only: bool = False
    settings_open: bool = False


@dataclass(frozen=True, slots=True)
class PageSpec:
    """One dashboard page (plan 14.1). `cards` are the declared ones; use `cards_for(id)` for the full list."""

    id: str
    title: str
    group: str
    icon: str
    about: str
    purpose: str
    how_to_read: tuple[str, ...]
    cards: tuple[CardSpec, ...]
    keys: str = ""
    label: str = ""

    @property
    def nav_label(self) -> str:
        return self.label or self.title

    @property
    def href(self) -> str:
        return f"{PAGE_PREFIX}/{self.id}"

    @property
    def module(self) -> str:
        return f"{PAGE_PACKAGE}.{self.id}"


NAV_GROUPS: Final[tuple[tuple[str, str], ...]] = (
    ("monitor", "Monitor"),
    ("upstream-group", "Upstream"),
    ("defense", "Defense"),
    ("operate", "Operate"),
)
"""Sidebar groups in order (id, label). The Help page sits apart, at the bottom of the sidebar."""

HELP_GROUP: Final = "help"


def _c(card_id: str, title: str, help_text: str = "", **options: Any) -> CardSpec:
    return CardSpec(card_id, title, help_text, **options)


_PAGES: Final[tuple[PageSpec, ...]] = (
    PageSpec(
        id="overview",
        title="Overview",
        group="monitor",
        icon="overview",
        keys="g o",
        about="Status, key numbers and what needs attention",
        purpose="See at a glance whether Roxy is healthy, whether Roblox is still happy with it, and what needs "
        "your attention first.",
        how_to_read=(
            "Start at the top: the status strip says whether the proxy is running, paused or limited, and whether "
            "the Roblox credential and the rotator are usable. Below it, the most important recommendations are "
            "the things Roxy suggests you change, most severe first.",
            "Each number tile shows a total for the time range chosen in the top bar. The small arrow compares it "
            "with the period before (or the comparison you picked); green means better, red means worse, and the "
            "words say so too. When part of the data was reset, a tile shows a notice instead of an arrow.",
            "The chart compares requests callers sent with the calls Roxy had to make to Roblox: the gap between "
            "the two lines is what the cache and coalescing saved.",
        ),
        cards=(
            _c("status", "Status", "Whether the proxy, the credential, the rotator and the leader are working."),
            _c("recommendations", "Top recommendations", "The three most severe open recommendations."),
            _c("kpis", "Key numbers", "Totals for the selected range, with the change against the comparison."),
            _c("visitors", "Visitors", "Visits to the public site and the admin login page, and crawler fetches."),
            _c("traffic", "Requests in and calls out", "Caller requests against the calls Roxy made to Roblox."),
            _c("outcomes", "Outcomes", "How requests ended: from the cache, from Roblox, refused, or failed."),
            _c("top-endpoints", "Top endpoints", "The endpoint templates callers ask for most in this range."),
            _c("top-places", "Top places", "The experiences (Roblox-Id) sending the most requests in this range."),
            _c("events", "Recent notable events", "Bans, cooldowns, breakers, alerts and configuration changes."),
        ),
    ),
    PageSpec(
        id="recommendations",
        title="Recommendations",
        group="monitor",
        icon="bulb",
        keys="g r",
        about="Evidence-backed changes you can preview, apply and undo",
        purpose="Review what Roxy found in its own numbers and decide which suggested changes to preview, apply, "
        "snooze or dismiss.",
        how_to_read=(
            "Each recommendation says what Roxy noticed, the evidence behind it, and exactly what it would change. "
            "Nothing changes until you press Apply, and every applied change can be undone from its history.",
            "Preview runs the change against recent sampled traffic first, so you can see what it would have done. "
            "Severity says how urgent it is; confidence says how sure the rule is.",
            "The Rules list lets you tune or switch off any rule, and the engine settings decide how often Roxy "
            "looks and whether it may apply safe changes by itself.",
        ),
        cards=(
            _c("list", "Recommendations", "Every recommendation with filters by severity, family and state."),
            _c("history", "History", "Every apply, undo, snooze and dismiss, newest first."),
            _c("rules", "Rules", "Every rule with its switch, severity and thresholds; open one to tune it."),
            _c(
                "engine",
                "Engine settings",
                "How often Roxy looks for problems and what it may do alone.",
                settings_open=True,
            ),
            _c(
                "preview-settings",
                "Dry-run samples",
                "How many requests are kept as samples for previews.",
                settings_open=True,
            ),
        ),
    ),
    PageSpec(
        id="traffic",
        title="Traffic",
        group="monitor",
        icon="activity",
        about="Requests, bytes, status codes and trends over time",
        purpose="Follow how much traffic Roxy handles, how it ends, how fast it is answered and how it changes "
        "from week to week.",
        how_to_read=(
            "Every chart covers the time range in the top bar. Drag across a chart (or use its zoom buttons) to "
            "look closer, and press a legend entry to hide a line. With a comparison chosen, the dashed lines are "
            "the earlier period.",
            "Status codes are split by who returned them: Roblox, Roxy's cache, or Roxy itself, so you can tell a "
            "Roblox outage from a Roxy refusal.",
            "Vertical markers are configuration changes and data resets; open one to see the audit entry.",
        ),
        cards=(
            _c("requests", "Requests over time", "Requests stacked by how they ended."),
            _c("bytes", "Bytes in and out", "Bytes between callers and Roxy, and between Roxy and Roblox."),
            _c("verbs", "By verb", "Requests per HTTP method."),
            _c("status", "Status codes", "Answers by status class and by who returned them."),
            _c("latency", "Latency", "How long requests took, Roxy's own time and Roblox's separately."),
            _c("heatmap", "Busiest hours", "Requests by hour of day and weekday."),
            _c("trends", "Trends", "Week over week, month over month and year over year."),
        ),
    ),
    PageSpec(
        id="live",
        title="Live",
        group="monitor",
        icon="live",
        keys="g l",
        about="Every request as it happens",
        purpose="Watch requests as Roxy handles them, filter them, and open one to see its full trace.",
        how_to_read=(
            "New requests appear at the top within a second. The list pauses while your pointer is over it, or "
            "with the Pause button or the P key, so you can read; new rows wait and are counted.",
            "Use the filters to narrow the list to one outcome, status, egress, cache state, client or endpoint. "
            "Open a row for its timing, its route through Roxy and, when capture is on, a redacted copy.",
        ),
        cards=(
            _c("tail", "Live requests", "Requests from every worker as they finish."),
            _c(
                "capture",
                "Capture",
                "Keep redacted copies of requests for a short time to inspect them.",
                settings_open=True,
            ),
        ),
    ),
    PageSpec(
        id="upstream",
        title="Upstream",
        group="upstream-group",
        icon="upstream",
        keys="g u",
        about="Roblox health, 429s, buckets, breakers and cooldowns",
        purpose="See how Roblox is answering Roxy and tune the pacing that keeps Roxy under Roblox's rate limits.",
        how_to_read=(
            "The health cards show each egress path (direct, credential, rotator) and each Roblox host: how many "
            "calls worked, how many failed, and when each last worked. A 429 means Roblox asked Roxy to slow down.",
            "Buckets are Roxy's own speed limits per host and endpoint, kept below Roblox's. Cooldowns and breakers "
            "pause calls after Roblox complains or keeps failing; while they are on, callers get cached answers "
            "where possible.",
            "Paste a request id into the trace lookup to see why one request waited or failed.",
        ),
        cards=(
            _c("health", "Egress and host health", "Calls, failures and the last success per egress and host."),
            _c("routing", "Routing", "Which egress path each request takes and the routing rules."),
            _c("hosts", "Hosts", "The Roblox hosts Roxy may call."),
            _c("429-timeline", "Roblox 429s", "When and where Roblox asked Roxy to slow down."),
            _c("latency", "Latency percentiles", "How long Roblox took to answer."),
            _c("buckets", "Buckets", "Roxy's own speed limits per egress, host and endpoint, and how full they are."),
            _c("concurrency", "Concurrency", "Adaptive concurrency (AIMD), off by default."),
            _c("cooldowns", "Cooldowns", "Pauses after Roblox said too many requests, and the reset."),
            _c("breakers", "Breakers", "Endpoints Roxy stopped calling after repeated failures."),
            _c("queue", "Queue", "How long requests may wait for a free slot."),
            _c("retries", "Retries", "Retries by status and reason, CSRF token refreshes included."),
            _c("failures", "Request failures", "Calls to Roblox that failed, newest first."),
            _c("challenges", "Challenges and HTML answers", "Answers that looked like a bot check or a web page."),
            _c("internal-calls", "Internal calls", "Calls Roxy made for itself: probes and lookups."),
            _c("trace", "Request trace", "Why one request waited or failed, by its request id."),
        ),
    ),
    PageSpec(
        id="egress",
        title="Egress",
        group="upstream-group",
        icon="globe",
        about="Direct, credential and rotator usage and quota",
        purpose="See how many bytes leave through each path, how much of the rotator quota is used, and whether "
        "the rotator is healthy.",
        how_to_read=(
            "Direct traffic leaves from the server's own address; credential traffic carries the one Roblox "
            "account and always goes direct; rotator traffic goes through DataImpulse and costs money per byte.",
            "The budget card projects the month's rotator use from the days so far. Exit IPs and sessions show "
            "which addresses Roblox saw.",
        ),
        cards=(
            _c("usage", "Usage", "Bytes and requests per egress path in this range."),
            _c("rotator", "Rotator", "The DataImpulse rotator: its URL, switch and health."),
            _c("budget", "Budget", "Rotator quota, price and the month's projection."),
            _c("exit-ips", "Exit IPs", "Addresses the rotator sent requests from."),
            _c("sessions", "Sessions", "Open rotator sessions and their health."),
            _c("top-endpoints", "Top endpoints by bytes", "Which endpoints use the most egress bytes."),
            _c("trips", "Leak guard", "Times the leak guard stopped a request, and the egress switches."),
        ),
    ),
    PageSpec(
        id="cache",
        title="Cache",
        group="upstream-group",
        icon="database",
        keys="g c",
        about="Hit ratio, rules, the cache browser and purges",
        purpose="See how many requests the cache answers without asking Roblox, tune how long answers are kept, "
        "and inspect or purge stored answers.",
        how_to_read=(
            "The hit ratio is the share of requests answered from the cache; avoided calls are the calls Roblox "
            "never had to answer. Both are better when higher.",
            "Rules decide how long answers for an endpoint are kept. Ignored parameters are query parameters that "
            "do not change the answer, so requests that differ only there share one stored answer.",
            "The key spread finds parameters that split one answer into many copies. The browser lists stored "
            "answers; a purge removes them at once on every worker.",
        ),
        cards=(
            _c("stats", "Cache statistics", "Hit ratio, avoided calls, stored answers and the memory tier."),
            _c("ratios", "Hit ratio over time", "Hit and avoided ratios for the selected range."),
            _c("settings", "Cache settings", "Lifetimes, sizes and what may be cached.", settings_open=True),
            _c(
                "coalescing",
                "Coalescing",
                "Identical requests at the same moment share one upstream call.",
                settings_open=True,
            ),
            _c("endpoints", "Per endpoint", "Hit ratio, lifetime, rule and stale serves per endpoint."),
            _c("rules", "Cache rules", "How long answers for each endpoint are kept."),
            _c("ignored-params", "Ignored parameters", "Query parameters left out of the cache key."),
            _c("spread", "Key spread", "Parameters that split one answer into many stored copies."),
            _c("browser", "Cache browser", "Search, inspect and refresh stored answers."),
            _c("purge", "Purge", "Remove stored answers by host, rule, pattern, search or all at once."),
        ),
    ),
    PageSpec(
        id="endpoints",
        title="Endpoints",
        group="upstream-group",
        icon="endpoints",
        about="Every endpoint template with volume, 429s and latency",
        purpose="Find the endpoints callers use most and see, for each one, its volume, cache hit ratio, Roblox "
        "429s, latency and the rules that apply to it.",
        how_to_read=(
            "An endpoint template is a Roblox path with its ids replaced by placeholders, so every request of one "
            "kind is counted together. Sort by any column; open a row for its trend, top callers and recent "
            "requests.",
        ),
        cards=(
            _c("table", "Endpoints", "Every endpoint template seen in this range."),
            _c("recent", "Recent requests", "The latest requests per endpoint."),
            _c("detail", "Endpoint detail", "One template: trend, callers, paths and rules.", fragment_only=True),
        ),
    ),
    PageSpec(
        id="clients",
        title="Clients",
        group="defense",
        icon="users",
        about="Places and IPs, their rates, refusals and bot scores",
        purpose="See who calls Roxy, by experience (place) and by address, how fast, how often they are refused, "
        "and act on one of them.",
        how_to_read=(
            "A place is a Roblox experience, identified by the Roblox-Id header its servers send. Rates are "
            "requests per minute over the last minute, five minutes and hour. Refused counts include every reason "
            "Roxy turned a request away.",
            "The bot score adds up signals that a caller is a script rather than a game server. Open a client for "
            "its timeline and for actions: ban, bypass or a rule just for it.",
        ),
        cards=(
            _c("places", "Places", "Experiences calling Roxy and the per-place limits."),
            _c("ips", "IP addresses", "Addresses calling Roxy, with rates, refusals and bot scores."),
            _c("lookup", "Identify an experience", "Look up a place id: its name, creator and links."),
            _c("client-score", "Bot score", "The signals and weights of the bot score.", settings_open=True),
            _c("activity", "Activity", "Per-client activity records and their reset."),
        ),
    ),
    PageSpec(
        id="protection",
        title="Protection",
        group="defense",
        icon="shield",
        keys="g p",
        about="Throttles, bans, filters, spam detectors and the tarpit",
        purpose="Decide which callers Roxy turns away and how: limits, bans, filters, spam detectors and the tarpit.",
        how_to_read=(
            "The pipeline shows the order of checks every request passes, with how many each one refused in this "
            "range. The first check that refuses decides the answer.",
            "The throttle limits each caller per minute; repeat offenders climb the ladder to longer penalties. "
            "Rules and filters refuse specific endpoints, User-Agents or headers. Spam detectors find abuse "
            "patterns and can ban automatically once armed.",
            "The tarpit holds refused abusers for a while before answering, which slows down scripts without "
            "costing Roblox anything.",
        ),
        cards=(
            _c("pipeline", "Pipeline", "Every check in order with how many requests it refused."),
            _c("throttle", "Throttle", "The per-IP limit, who is throttled now and the history.", settings_open=True),
            _c("ladder", "Ladder", "Escalating penalties for repeat offenders."),
            _c("strikes", "Strike board", "Callers with strikes against them, and forgiving them."),
            _c("throttle-all", "Emergency limit", "The throttle-all switch and who it refuses right now."),
            _c("limits", "Request limits", "Flood limit and size limits on requests.", settings_open=True),
            _c("places", "Place limits", "Limits per experience (Roblox-Id).", settings_open=True),
            _c("bans", "Bans", "Bans in force, made by hand or by a detector."),
            _c("lists", "Deny and allow lists", "Addresses always refused, and the admin allowlist."),
            _c("bypass", "Bypass", "Addresses that skip limits, for testing; add your own address."),
            _c("ua-rules", "User-Agent rules", "Rules matched on the User-Agent, with a tester."),
            _c("request-filters", "Request filters", "Header rules that refuse requests, with a tester and presets."),
            _c("endpoint-blocks", "Endpoint blocks", "Endpoints refused for everyone, and attempts to reach them."),
            _c("endpoint-rules", "Endpoint rules", "Per-endpoint rate limits, and the attempts they refused."),
            _c("ignored-paths", "Ignored paths", "Paths refused at once without counting as probes."),
            _c("spam", "Spam detectors", "Detectors for abuse patterns, in dry run until armed.", settings_open=True),
            _c("tarpit", "Tarpit", "Holds refused abusers before answering.", settings_open=True),
            _c("bot", "Bot heuristics", "Signals that a caller is a script.", settings_open=True),
            _c(
                "challenge",
                "Challenge",
                "An optional challenge for suspected bots, off by default.",
                settings_open=True,
            ),
            _c("refusals", "Refusal reasons", "Every refusal reason with counts and the message callers got."),
        ),
    ),
    PageSpec(
        id="security",
        title="Security",
        group="defense",
        icon="lock",
        about="Logins, probes, fingerprints and sessions",
        purpose="See who signs in, who probes Roxy for weaknesses, what clients send, and manage your sessions, "
        "devices and second factors.",
        how_to_read=(
            "Logins list every admin sign-in attempt. Probes are requests that looked for something that is not "
            "there (an admin page elsewhere, a file, a script), which is how attacks usually start.",
            "Fingerprints count the header names, values and User-Agents callers send, so unusual clients stand "
            "out. Sessions, trusted devices, passkeys and recovery codes are yours to review and revoke.",
        ),
        cards=(
            _c(
                "admin-access",
                "Admin access",
                "Login limits, session lifetimes and the admin allowlist.",
                settings_open=True,
            ),
            _c("logins", "Admin logins", "Every sign-in attempt, successful or not."),
            _c("probes", "Probes", "Requests that looked for weaknesses."),
            _c("probe-summary", "Probe summary", "Probes grouped by signature."),
            _c("crawls", "Crawler activity", "Search engines and other crawlers."),
            _c("fingerprints", "Fingerprints", "Header names, values and User-Agents, blocked variants included."),
            _c("csp-reports", "CSP reports", "Browser reports of blocked content on Roxy's own pages."),
            _c("sessions", "Sessions", "Signed-in sessions; revoke any of them."),
            _c("trusted-devices", "Trusted devices", "Browsers that skip the second factor."),
            _c("passkeys", "Passkeys", "Your passkeys."),
            _c("recovery-codes", "Recovery codes", "How many recovery codes are left; make new ones."),
        ),
    ),
    PageSpec(
        id="health",
        title="Health",
        group="operate",
        icon="heart",
        about="Run the health check and compare runs",
        purpose="Run Check Proxy Health, watch each check finish, and compare the result with earlier runs.",
        how_to_read=(
            "A health run checks every part of Roxy in about a minute: databases, workers, the cache, each Roblox "
            "host, the credential and the rotator. Each check passes, warns or fails, and says how to fix it.",
            "Runs are kept so you can compare today with last week. The schedule can run checks on its own.",
        ),
        cards=(
            _c("run", "Run a health check", "Start a run and watch the checks finish."),
            _c("checks", "Checks", "Every check, what it measures and how it is judged."),
            _c("history", "Run history", "Earlier runs, with their results and comparisons."),
            _c("schedule", "Schedule", "Automatic runs.", settings_open=True),
        ),
    ),
    PageSpec(
        id="settings",
        title="Settings",
        group="operate",
        icon="sliders",
        keys="g s",
        about="Every runtime setting with history and import or export",
        purpose="Find and change any runtime setting, see what changed and why, and export or import your changes.",
        how_to_read=(
            "Every setting has a description, its default, its range and what happens when you raise or lower "
            "it. A badge marks high-risk settings: those need a reason and a confirmation before they are saved.",
            "Changes apply to every worker within a second and are written to the audit log. History shows every "
            "change with who made it and why, and lets you put an old value back.",
        ),
        cards=(
            _c("editor", "All settings", "Every setting, grouped, with search and filters."),
            _c("history", "Change history", "Every settings change, newest first, with revert."),
            _c("import-export", "Import and export", "Your changes as a file, and loading them back."),
            _c("alerts", "Alerts", "Where alerts go and how often.", settings_open=True),
            _c("public-site", "Public site", "Texts and switches of the public pages.", settings_open=True),
        ),
    ),
    PageSpec(
        id="credential",
        title="Credential",
        group="operate",
        icon="key",
        about="The one Roblox credential: status, budget and allowlist",
        purpose="Check the one Roblox account Roxy may use, what it is used for, and replace it safely when needed.",
        how_to_read=(
            "Roxy holds exactly one Roblox credential and never rotates or switches accounts on its own, because "
            "many accounts from one address look like account farming to Roblox.",
            "The status shows whether the credential works and when it was last checked; the value itself is "
            "never shown, only its last characters. The allowlist names the only endpoints it may be used for.",
        ),
        cards=(
            _c("status", "Status", "Whether the credential works, its masked value and its cooldowns."),
            _c("budget", "Budget", "Calls the credential may make per minute and the probes' share."),
            _c("probes", "Probes", "The latest checks of the credential."),
            _c("allowlist", "Allowlist", "Endpoints the credential may be used for."),
            _c("replace", "Replace", "Replace the credential, or go back to the bootstrap value."),
        ),
    ),
    PageSpec(
        id="data",
        title="Data",
        group="operate",
        icon="disk",
        about="Storage, retention, resets, backups and exports",
        purpose="See what Roxy stores and for how long, reset statistics you no longer want, and take backups and "
        "exports.",
        how_to_read=(
            "Storage lists every database and table with its size. Retention decides how long each kind of record "
            "is kept; record caps bound the busiest tables.",
            "A reset deletes one family of statistics (optionally only between two dates). It shows a preview "
            "first, takes a snapshot where it can, and leaves a marker on every chart. Settings and rules are "
            "never touched by a statistics reset.",
        ),
        cards=(
            _c("storage", "Storage", "What is being stored: databases and tables with their sizes."),
            _c("retention", "Retention", "How long each kind of record is kept.", settings_open=True),
            _c("record-caps", "Record caps", "The most rows the busiest tables may hold.", settings_open=True),
            _c("resets", "Resets", "Delete one family of statistics, with a preview first."),
            _c("backups", "Backups", "Backups and Back up now."),
            _c("vacuum", "Vacuum", "Give space back to the disk."),
            _c("exports", "Exports", "Download any dataset as CSV or JSON, and the LLM export."),
        ),
    ),
    PageSpec(
        id="audit",
        title="Audit",
        group="operate",
        icon="clipboard",
        about="Who changed what, when and why",
        purpose="Look up who changed what, when and why, see exactly what each change did, and put a setting back "
        "the way it was.",
        how_to_read=(
            "Every admin action and every important automatic action is written here: settings, rules, bans, "
            "resets, downloads, sign-ins and the credential. The newest entries come first.",
            "Search looks in the action, the target, who acted, the reason and the request id. The filters narrow "
            "the list to one kind of action, one actor, one target or a time window; a value ending in * matches "
            "everything that starts with it (setting:* for every setting).",
            "Open an entry to see its before and after side by side. A settings change can be put back with one "
            "click (that is itself audited); other changes link to the card that manages them.",
        ),
        cards=(
            _c("log", "Audit log", "Every audited action, newest first, with search and filters."),
            _c("entry", "Audit entry", "One entry: before and after, and how to undo it.", fragment_only=True),
        ),
    ),
    PageSpec(
        id="system",
        title="System",
        group="operate",
        icon="server",
        about="Workers, leader, jobs, errors and versions",
        purpose="Check the worker processes, the leader and its jobs, the metrics pipeline, the error log and the "
        "versions Roxy runs.",
        how_to_read=(
            "Roxy runs several worker processes; one of them is the leader and runs the scheduled jobs. During a "
            "deploy both colors (blue and green) show up for a short time.",
            "The metrics pipeline writes counters every few seconds; drops mean some numbers are missing. The "
            "error log groups errors by signature with their tracebacks (secrets removed).",
        ),
        cards=(
            _c("fleet", "Workers", "Every worker with its counters, memory and uptime."),
            _c("leader", "Leader", "Which worker leads, and since when."),
            _c("jobs", "Jobs", "Scheduled jobs and when each last ran."),
            _c("metrics-pipeline", "Metrics pipeline", "Queues, flushes and drops.", settings_open=True),
            _c("persistence", "Persistence", "Database files, checkpoints and disk growth."),
            _c("errors", "Error log", "Errors by signature, with tracebacks."),
            _c("alerts", "Alerts", "Alert channels and limits.", settings_open=True),
            _c("versions", "Versions", "Roxy, Python and library versions."),
            _c("environment", "Environment", "The non-secret startup settings."),
            _c("flush", "Forced flush", "Write every worker's counters now."),
        ),
    ),
    PageSpec(
        id="help",
        title="Help",
        group=HELP_GROUP,
        icon="help",
        about="Admin guide, glossary and keyboard shortcuts",
        purpose="Read the admin guide, look up a term, and learn the keyboard shortcuts.",
        how_to_read=(
            "The guide has one chapter per page. Every underlined term elsewhere in the dashboard links to its "
            "entry in the glossary here.",
        ),
        cards=(
            _c("guide", "Admin guide", "How to run Roxy, page by page."),
            _c("glossary", "Glossary", "Every term the dashboard uses."),
            _c("shortcuts", "Keyboard shortcuts", "Every shortcut."),
            _c("pages", "What each page does", "One sentence per page."),
        ),
    ),
)

PAGES: Final[tuple[PageSpec, ...]] = _PAGES
PAGE_IDS: Final[tuple[str, ...]] = tuple(p.id for p in _PAGES)
_BY_ID: Final[dict[str, PageSpec]] = {p.id: p for p in _PAGES}


def page(page_id: str) -> PageSpec:
    """The `PageSpec` of `page_id` (KeyError for an unknown id)."""
    return _BY_ID[page_id]


def known(page_id: str) -> bool:
    return page_id in _BY_ID


# ============================================================================================ settings on cards


def _anchor_settings() -> dict[str, tuple[SettingSpec, ...]]:
    placed: dict[str, list[SettingSpec]] = {}
    for spec in CATALOG.values():
        for anchor in spec.pages:
            placed.setdefault(anchor, []).append(spec)
    return {anchor: tuple(sorted(specs, key=lambda s: s.key)) for anchor, specs in placed.items()}


ANCHOR_SETTINGS: Final[dict[str, tuple[SettingSpec, ...]]] = _anchor_settings()
"""Catalog anchor (`cache#settings`, `topbar#pause`) -> the settings placed there (plan 15.6, sorted by key)."""


def settings_for(anchor: str) -> tuple[SettingSpec, ...]:
    """The catalog settings whose `pages` field names `anchor` (`<page>#<card>` or a non-page home)."""
    return ANCHOR_SETTINGS.get(anchor, ())


def anchor(page_id: str, card_id: str) -> str:
    return f"{page_id}#{card_id}"


def _generated_title(card_id: str) -> str:
    if card_id.startswith("rule-"):
        return f"Tune {card_id[5:].replace('_', '-').upper()}"
    if card_id.startswith("spam-"):
        return f"Spam detector: {card_id[5:]}"
    return card_id.replace("-", " ").capitalize()


@cache
def cards_for(page_id: str) -> tuple[CardSpec, ...]:
    """Every card of a page: the declared ones in order, then each catalog anchor of this page the declaration
    lacks (one rule's tuning drawer `rule-<slug>`, one spam detector `spam-<detector>`). Rule drawers are
    fragment-only; spam detectors sit on the page."""
    spec = page(page_id)
    cards = list(spec.cards)
    have = {card.id for card in cards}
    extra = sorted(
        {a.split("#", 1)[1] for a in ANCHOR_SETTINGS if a.split("#", 1)[0] == page_id} - have,
    )
    for card_id in extra:
        cards.append(
            CardSpec(
                card_id,
                _generated_title(card_id),
                "The settings of this part, from the settings catalog.",
                fragment_only=card_id.startswith("rule-"),
                settings_open=True,
            )
        )
    return tuple(cards)


def card(page_id: str, card_id: str) -> CardSpec:
    """One card of a page (KeyError when the page has no such card)."""
    for item in cards_for(page_id):
        if item.id == card_id:
            return item
    raise KeyError(f"{page_id}#{card_id}")


def page_anchors() -> frozenset[str]:
    """Every `<page>#<card>` the registry knows."""
    return frozenset(anchor(p.id, c.id) for p in _PAGES for c in cards_for(p.id))


def unplaced_anchors() -> list[str]:
    """Catalog anchors no page card or non-page home covers (always empty; a test pins it)."""
    known_anchors = page_anchors() | NON_PAGE_HOMES
    return sorted(a for a in ANCHOR_SETTINGS if a not in known_anchors)


# ============================================================================================ build state


@cache
def is_built(page_id: str) -> bool:
    """True when `roxy.admin.pages.<page_id>` exists (the page builder wrote it); False renders "coming soon"."""
    if page_id not in _BY_ID:
        return False
    return importlib.util.find_spec(f"{PAGE_PACKAGE}.{page_id}") is not None


def built_pages() -> tuple[str, ...]:
    return tuple(p.id for p in _PAGES if is_built(p.id))


# ============================================================================================ navigation


def nav_item(spec: PageSpec) -> dict[str, str]:
    return {"id": spec.id, "label": spec.nav_label, "icon": spec.icon, "keys": spec.keys, "about": spec.about}


@cache
def nav_model() -> dict[str, Any]:
    """The navigation for templates: `{"groups": [{id, label, items: [...]}], "help": {...}, "pages": [...]}`.

    `admin/_layout/nav.html` turns it into `NAV`, `HELP_PAGE` and `PAGES`, which the sidebar, the phone menu, the
    command palette and the shortcut overlay all read (plan 14.1, 14.6, 14.8).
    """
    groups = []
    for group_id, label in NAV_GROUPS:
        items = [nav_item(p) for p in _PAGES if p.group == group_id]
        groups.append({"id": group_id, "label": label, "items": items})
    help_page = nav_item(page("help"))
    pages = [item for group in groups for item in group["items"]] + [help_page]
    return {"groups": groups, "help": help_page, "pages": pages}


# ============================================================================================ v1 section map


@dataclass(frozen=True, slots=True)
class V1Check:
    """One place a v1 section must be found: a page (or `SHELL_PAGE`), a card id (or a CSS selector of the shell
    for `SHELL_PAGE`), and CSS selectors that must match inside it (key elements)."""

    page: str
    card: str
    selectors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class V1Section:
    """One row of the plan 14.1 v1 section to v2 page map (corrections from v1notes/dashboard.md included)."""

    row: int
    v1: str
    test: str
    checks: tuple[V1Check, ...]
    note: str = ""

    @property
    def pages(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(c.page for c in self.checks))


def _k(*keys: str) -> tuple[str, ...]:
    return tuple(f'[data-kpi="{key}"]' for key in keys)


def _t(*names: str) -> tuple[str, ...]:
    return tuple(f'[data-table="{name}"]' for name in names)


def _s(*keys: str) -> tuple[str, ...]:
    return tuple(f'[data-setting-key="{key}"]' for key in keys)


def _a(*names: str) -> tuple[str, ...]:
    return tuple(f'[data-action="{name}"]' for name in names)


CHART: Final = ("[data-chart]",)

V1_SECTIONS: Final[tuple[V1Section, ...]] = (
    V1Section(
        1,
        "Overview: Total Requests, 2xx Success, 4xx Client Errors, Served From Cache, Requests (Last Hour) and "
        "Failures (Last Hour) tiles",
        "overview_kpis",
        (
            V1Check(
                "overview",
                "kpis",
                _k("requests", "status_2xx", "status_4xx", "served_cache", "requests_last_hour", "failures_last_hour"),
            ),
        ),
        "Correction (v1notes 1.1): v1 had 11 tiles; Failures (Last Hour) is one of them.",
    ),
    V1Section(
        2,
        "Overview: Human Visitors, Crawler Visitors, Home Page Visits, Admin Page Visits, robots.txt Crawls tiles",
        "overview_visitors",
        (
            V1Check(
                "overview",
                "visitors",
                _k("human_visitors", "crawler_visitors", "home_visits", "admin_visits", "robots_crawls"),
            ),
        ),
    ),
    V1Section(
        3,
        "429s from Roblox, 429s from Roxy, 5xx from Roblox, 5xx from Roxy, Service Uptime",
        "overview_kpis_errors",
        (
            V1Check("overview", "kpis", _k("roblox_429", "roxy_429", "roblox_5xx", "service_uptime_s")),
            V1Check("traffic", "status", _t("traffic_status_sources")),
            V1Check("system", "fleet", _t("workers")),
        ),
        "Correction: in v1 the four status tiles sat in Status Codes (Who returned it?) and uptime in Service "
        "Health; v2 shows them on the Overview tiles, in Traffic > Status codes and in System > Workers.",
    ),
    V1Section(
        4,
        "Service Controls: pause and throttle-all with messages and banners, the throttle-all watch, bypass my IP, "
        "trusted devices, sessions",
        "topbar_controls",
        (
            V1Check(SHELL_PAGE, "#dlg-pause", _s("pause_message_default")),
            V1Check(SHELL_PAGE, "#dlg-throttle-all", _s("global_throttle_limit", "global_throttle_period")),
            V1Check(SHELL_PAGE, ".topbar", (".topbar__pause", ".topbar__limit")),
            V1Check("protection", "throttle-all", _t("throttle_all_watch")),
            V1Check("protection", "bypass", _a("bypass-my-ip")),
            V1Check("security", "trusted-devices"),
            V1Check("security", "sessions"),
        ),
        "Correction: v1 had no session invalidation control on the dashboard (the emailed link); Your current IP "
        "lives in Throttle Bypass.",
    ),
    V1Section(
        5,
        "Response Cache: hit rate, stored responses, memory tier, requests Roblox never saw, settings, rules, "
        "browser, purge, key spread",
        "cache_stats",
        (
            V1Check("cache", "stats", _k("hit_ratio", "served_cache")),
            V1Check("cache", "settings", _s("cache_enabled", "cache_ttl_seconds")),
            V1Check("cache", "rules", _t("cache_rules")),
            V1Check("cache", "browser", _t("cache_entries")),
            V1Check("cache", "purge"),
            V1Check("cache", "spread"),
        ),
    ),
    V1Section(
        6,
        "Throttle Rules: limits, ladder, strike board, reset to defaults, simulation",
        "protection_throttle",
        (
            V1Check("protection", "throttle", _s("allowed_requests_per_minute")),
            V1Check("protection", "ladder"),
            V1Check("protection", "strikes", _t("strike_board")),
        ),
    ),
    V1Section(7, "Traffic (Last 60 Minutes)", "traffic_requests", (V1Check("traffic", "requests", CHART),)),
    V1Section(8, "Live Requests", "live_tail", (V1Check("live", "tail", ("[data-live-tail]",)),)),
    V1Section(
        9,
        "Callers and Top Talkers, with Identify an experience",
        "clients_places",
        (
            V1Check("clients", "places", _t("client_places")),
            V1Check("clients", "ips", _t("client_ips")),
            V1Check("clients", "lookup"),
        ),
    ),
    V1Section(
        10,
        "Refusal Reasons (custom message or Roblox body)",
        "protection_refusals",
        (V1Check("protection", "refusals", _t("refusal_reasons")),),
    ),
    V1Section(
        11,
        "Top Endpoints",
        "endpoints_table",
        (V1Check("endpoints", "table", _t("endpoints")), V1Check("overview", "top-endpoints")),
    ),
    V1Section(
        12,
        "Endpoint Controls: blocks and endpoint rules",
        "protection_endpoint_blocks",
        (
            V1Check("protection", "endpoint-blocks", _t("endpoint_blocks")),
            V1Check("protection", "endpoint-rules", _t("endpoint_rules")),
        ),
    ),
    V1Section(
        13,
        "Throttle Bypass (testing)",
        "protection_bypass",
        (V1Check("protection", "bypass", (*_a("bypass-my-ip"), *_t("access_list"))),),
    ),
    V1Section(
        14,
        "Tarpit: requests held, held in the last hour, average hold, time between requests, categories, state",
        "protection_tarpit",
        (V1Check("protection", "tarpit", _s("tarpit_enabled")),),
    ),
    V1Section(
        15,
        "Request Filters (Header Blocking) with tester and presets",
        "protection_request_filters",
        (V1Check("protection", "request-filters", _t("header_rules")),),
    ),
    V1Section(
        16,
        "Blocked Endpoint Attempts",
        "protection_endpoint_blocks_attempts",
        (V1Check("protection", "endpoint-blocks", _t("refusal_attempts")),),
    ),
    V1Section(
        17,
        "Rate-Limited Attempts",
        "protection_endpoint_rules_attempts",
        (V1Check("protection", "endpoint-rules", _t("refusal_attempts")),),
    ),
    V1Section(
        18,
        "Header-Blocked Attempts",
        "protection_request_filters_attempts",
        (V1Check("protection", "request-filters", _t("refusal_attempts")),),
    ),
    V1Section(
        19,
        "Auth Tokens: Token, Tokens Loaded and Token Safety Budget tiles; set, check, revalidate",
        "credential_status",
        (
            V1Check("credential", "status"),
            V1Check("credential", "budget"),
            V1Check("credential", "allowlist", _t("credential_allowlist")),
        ),
        "Correction: the three tiles lived in Service Health and Force revalidate in Tools.",
    ),
    V1Section(20, "Requests (per verb)", "traffic_verbs", (V1Check("traffic", "verbs", _t("traffic_verbs")),)),
    V1Section(
        21,
        "Status Codes (Who returned it?)",
        "traffic_status",
        (V1Check("traffic", "status", _t("traffic_status_sources")),),
    ),
    V1Section(
        22, "Retries (by status, by reason, returned reasons)", "upstream_retries", (V1Check("upstream", "retries"),)
    ),
    V1Section(
        23,
        "Proxy Timings (split toggle)",
        "traffic_latency",
        (V1Check("traffic", "latency", _t("traffic_latency_split")),),
    ),
    V1Section(24, "Request Failures", "upstream_failures", (V1Check("upstream", "failures", _t("upstream_failures")),)),
    V1Section(25, "Crawler Activity", "security_crawls", (V1Check("security", "crawls", _t("crawls")),)),
    V1Section(
        26,
        "Throttled IPs (the throttled IP records)",
        "protection_throttle_watch",
        (V1Check("protection", "throttle", _t("throttle_watch", "throttled_history")),),
        "Correction: v1's Throttled IPs is the throttled-IP record table; who is refused right now under "
        "throttle-all is row 4 (the throttle-all watch).",
    ),
    V1Section(27, "Exploit / Probe Attempts", "security_probes", (V1Check("security", "probes", _t("probes")),)),
    V1Section(
        28,
        "Exploit / Probe Summary",
        "security_probe_summary",
        (V1Check("security", "probe-summary", _t("probe_summary")),),
    ),
    V1Section(
        29,
        "Request Fingerprints: header names, values, User-Agents, ignored headers",
        "security_fingerprints",
        (V1Check("security", "fingerprints", _t("fingerprint_headers", "fingerprint_user_agents", "ignored_headers")),),
    ),
    V1Section(
        30,
        "Blocked Request Fingerprints",
        "security_fingerprints_blocked",
        (V1Check("security", "fingerprints", _t("blocked_fingerprints")),),
    ),
    V1Section(31, "Error Log", "system_errors", (V1Check("system", "errors", _t("errors")),)),
    V1Section(32, "Admin Logins", "security_logins", (V1Check("security", "logins", _t("admin_logins")),)),
    V1Section(
        33,
        "Runtime Settings (also inline on each feature page)",
        "settings_editor",
        (V1Check("settings", "editor", ("[data-setting-key]",)),),
    ),
    V1Section(
        34,
        "Service Health: rotator, persistence tiles, health check button, workers fleet, routing state",
        "health_run",
        (
            V1Check("health", "run", _a("health-run")),
            V1Check("egress", "rotator"),
            V1Check("system", "fleet", _t("workers")),
            V1Check("system", "persistence"),
            V1Check("upstream", "cooldowns", _a("upstream-reset")),
        ),
        "Correction: Run health check lived in Tools in v1.",
    ),
    V1Section(35, "Internal Requests", "upstream_internal_calls", (V1Check("upstream", "internal-calls"),)),
    V1Section(36, "Rotation Exit IPs", "egress_exit_ips", (V1Check("egress", "exit-ips"),)),
    V1Section(
        37,
        "Tools: what's being stored, clears, exports, diagnostics download, refresh with flush",
        "data_storage",
        (
            V1Check("data", "storage", _t("storage_tables")),
            V1Check("data", "resets"),
            V1Check("data", "exports"),
            V1Check("system", "flush", _a("flush")),
        ),
    ),
)
"""The plan 14.1 map: one entry per row, `test` names `tests/e2e/test_v1_sections.py::test_<test>`."""


def v1_rows_for(page_id: str) -> list[V1Section]:
    """The v1 sections with at least one check on `page_id` (what a page builder must cover)."""
    return [row for row in V1_SECTIONS if any(check.page == page_id for check in row.checks)]


def required_cards(page_id: str) -> list[str]:
    """Card ids of `page_id` that a v1 section check names (always a subset of `cards_for`)."""
    return list(dict.fromkeys(check.card for row in V1_SECTIONS for check in row.checks if check.page == page_id))


def describe(pages: Iterable[str] | None = None) -> list[Mapping[str, Any]]:
    """A plain listing for docs and the Help page: each page with its cards (title and help)."""
    wanted = set(pages) if pages is not None else set(PAGE_IDS)
    return [
        {
            "id": p.id,
            "title": p.title,
            "purpose": p.purpose,
            "cards": [{"id": c.id, "title": c.title, "help": c.help} for c in cards_for(p.id) if not c.fragment_only],
        }
        for p in _PAGES
        if p.id in wanted
    ]


__all__ = [
    "ANCHOR_SETTINGS",
    "HELP_GROUP",
    "NAV_GROUPS",
    "PAGES",
    "PAGE_IDS",
    "SHELL_PAGE",
    "V1_SECTIONS",
    "CardSpec",
    "PageSpec",
    "V1Check",
    "V1Section",
    "anchor",
    "built_pages",
    "card",
    "cards_for",
    "describe",
    "is_built",
    "known",
    "nav_model",
    "page",
    "page_anchors",
    "required_cards",
    "settings_for",
    "unplaced_anchors",
    "v1_rows_for",
]
