"""Settings group K: public site text, caller compatibility, CORS, and dashboard preferences.

What this is
    `SETTINGS`, the list of `SettingSpec` declarations for plan 15.3 group K (Public site and compatibility)
    plus the two dashboard-wide preferences `ui_timezone` and `ui_default_theme` (group `dashboard`, edited from
    the user menu).

Why it exists
    Plan principle P3 (one declaration per tunable) and owner decision D18: the home page text that names people,
    prices and hosting facts used to be hard-coded in `templates/home_page.html` and drifted out of date (it
    still said "Python and Flask"). As settings, it can be corrected from the dashboard without a deploy. The
    caller-facing compatibility switches (D4, D20) live here too, because they change what the public sees.

How it works
    Plain data, collected and checked by `roxy/config/catalog.py`. The `site_*` defaults are the v1 home page
    text, carried over with the style rule C5 applied (no em or en dash characters, US spelling) and with the
    stale "Python and Flask" line rewritten. The owner confirmed them on 2026-10-14 (answers B13 and B15) with
    three changes: no bug bounty and no support links for now (both defaults are empty, and an empty text hides
    its part of the home page; v1's wording is kept in each setting's notes), and the contact names where to
    reach CeaselessQuokka. Format contract for every `site_*` value, which the public page renderer must honor:
    plain text, blank lines separate paragraphs, and links are written as `[label](https://...)`; only https
    links become links, and HTML is shown as text, never rendered. `site_contact_name` is the exception: it sits
    inside sentences, so it is always plain text.
    The three `public_*_under_construction` switches and `site_construction_text` (owner request, 2026-10-15) take
    the home page, the user guide or the status page off the public site while the owner reviews it: visitors get
    an "under construction" page with that message, and a signed-in admin still sees the real page with a banner
    (`roxy/public/construction.py`).

What to read next
    `roxy/config/spec.py` (field meanings), plan 16.1 (where each `site_*` text appears on `/`), plan 7.13 (the
    caller status table that `compat_collapse_upstream_errors` changes), plan 9.4 (CORS) and 6.4 (why the
    timezone matters for day and month rollups), then `roxy/public/construction.py` for the under-construction
    switches.
"""

from roxy.config.spec import Apply, Group, OptionSpec, Risk, RiskCondition, RiskOp, SettingSpec, SettingType

_PUBLIC_SITE = ("settings#public-site",)
_PREFERENCES = ("user-menu#preferences",)

# Every `site_*` text shares the plan's limit (15.3 K) and the same format notes.
_SITE_TEXT_MAX = 2000
_SITE_FORMAT_NOTE = (
    "Shown on the public home page. Plain text: blank lines separate paragraphs, and links are written as "
    "[label](https://...). Only https links are allowed, and HTML is shown as text, never rendered. Must not "
    "contain em or en dash characters (style rule C5)."
)
_SITE_KEYS = (
    "site_contact_name",
    "site_white_hats_text",
    "site_bug_bounty_text",
    "site_hosting_note",
    "site_support_links",
    "site_footer_text",
)


def _other_site_keys(key: str) -> tuple[str, ...]:
    """The other `site_*` keys, so each home page text links to its neighbors in the editor."""
    return tuple(k for k in _SITE_KEYS if k != key)


# --- v1 home page text, C5-checked (plan 16.1 says where each lands on the v2 `/` page) ---------------------

_WHITE_HATS_DEFAULT = (
    "You never need to log in to use Roxy: it signs requests with its own Roblox account, so you never send yours. "
    "Endpoints that act on an account or read its private data are blocked, and Roxy refuses any request that "
    "carries anything that looks like a Roblox .ROBLOSECURITY cookie or an Open Cloud API key.\n\n"
    "Never send your ROBLOSECURITY token to Roxy, or to any third-party proxy. Sharing it lets someone log in as "
    "you and take your account, Robux, and items; no exceptions, no matter how trustworthy a service looks or "
    "claims to be. Even a secure, open-source server can't prove what's actually running on it. The only safe "
    "token is one you never send."
)

# Owner answers B13 and B15 (2026-10-14): "No bug bounty, no support link, but if they need something extra or are
# having an issue to contact CeaselessQuokka on either the DevForums or Twitter". The contact therefore says where
# to reach the name, and the two texts below ship empty (hidden). v1's wording stays in their notes, so bringing a
# section back is a paste, not a rewrite.
_CONTACT_DEFAULT = "CeaselessQuokka on the DevForums or Twitter"

_BUG_BOUNTY_V1 = (
    "If you're a White Hat and find a vulnerability, I'm offering rewards from $10-$250 USD depending on "
    "severity. Any serious exploit report is always paid and appreciated. I'm still learning web development, so "
    "there may be a lot of issues."
)

# D18: the v1 text said "Roxy was made using Python and Flask", which is stale for v2. Only that sentence is
# rewritten; the hosting and cost facts are the owner's v1 text, confirmed by the owner on 2026-10-14 (B15).
_HOSTING_DEFAULT = (
    "Roxy is written in Python using FastAPI and Uvicorn. It is hosted using the second tier option of Lightsail "
    "on AWS, which means there is 2TB of transfer data per month. So if the site goes down that is probably why. "
    "Hopefully 2TB is enough, but I will monitor.\n\n"
    "If you're curious how much Roxy costs to maintain: as of right now, 7 USD per month (for the Lightsail "
    "instance) + 15 USD per year (for the domain). Which comes out to be exactly $99 per year."
)

# v1's "Support Me" paragraph. v1's plugin link was in the home page introduction, and it is there again
# (templates/public/home.html), so this text never needs it.
_SUPPORT_V1 = (
    "You never have to donate or pay anything; just using anything I make is enough support for me. If you ever "
    "make something with something I create, please tag me in it, I'd love to see it! :D"
)

_FOOTER_DEFAULT = "Roxy Proxy 2025-Present"

# --- pages under construction (owner request 2026-10-15) --------------------------------------------------------
# "can you please add an option in the admin panel somewhere for me to disable view of the home page, docs (guide),
# and status pages? It will replace them with an "under construction page" so I can take time to review the docs."

_CONSTRUCTION_KEYS = (
    "public_home_under_construction",
    "public_docs_under_construction",
    "public_status_under_construction",
    "site_construction_text",
)
_CONSTRUCTION_TEXT_MAX = 500
_CONSTRUCTION_TEXT_DEFAULT = "Roxy's site is being updated. Check back soon."
_CONSTRUCTION_SEEN_BY_ADMINS = (
    "While you are signed in to the dashboard you still see the real page, with a banner at the top saying what the "
    "public sees instead and a button that shows you exactly that. "
)
_CONSTRUCTION_ANSWER = (
    "HTTP 503 with Retry-After, which tells search engines the page is away for a while, not gone; a page left "
    "under construction for many days may still drop out of search results"
)
_CONSTRUCTION_NOT_AFFECTED = (
    "The proxy, /health, the sign-in page, robots.txt and the other public pages are not affected."
)


def _other_construction_keys(key: str) -> tuple[str, ...]:
    """The other under-construction settings, so each one links to its neighbors in the editor."""
    return tuple(k for k in _CONSTRUCTION_KEYS if k != key)


def _construction_switch(key: str, label: str, path: str, page_name: str, extra_note: str = "") -> SettingSpec:
    """One page's under-construction switch: the three differ only in the page they take off the public site."""
    return SettingSpec(
        key=key,
        group=Group.PUBLIC_SITE,
        label=label,
        type=SettingType.BOOL,
        default=0,
        description=(
            f"Takes the public {page_name} ({path}) off the public site while you review or rework it: visitors get "
            "a short 'under construction' page with the message in site_construction_text instead. "
            + _CONSTRUCTION_SEEN_BY_ADMINS
            + _CONSTRUCTION_NOT_AFFECTED
        ),
        pages=_PUBLIC_SITE,
        if_enabled=(
            f"Visitors to {path} get the under-construction page ({_CONSTRUCTION_ANSWER}), and {path} leaves "
            "sitemap.xml. Signed-in admins see the real page with the admin banner. Game servers calling the proxy "
            "see no change."
        ),
        if_disabled=f"Everyone sees the normal {page_name} at {path}.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=_other_construction_keys(key),
        notes=(
            "Owner request (2026-10-15): take a page off the public site while reviewing it, see it as an admin with "
            "a clear sign that the public sees something else, and see exactly what the public sees with one button. "
            "The admin is recognized by the dashboard's own session cookie, checked on the server on every visit, so "
            "signing out, revoking the session or the kill switch ends the admin view at once; the session must be "
            "live (an idle dashboard session expires after admin_session_idle_timeout_s). The deploy's smoke test "
            "accepts the under-construction page as the answer of / (it carries the header Roxy-Under-Construction: "
            "True). " + extra_note
        ).strip(),
    )


SETTINGS: list[SettingSpec] = [
    # ---------------------------------------------------------------- what callers receive
    SettingSpec(
        key="pause_message_default",
        group=Group.PUBLIC_SITE,
        label="Default pause message",
        type=SettingType.STRING,
        default="Service down for maintenance.",
        max_length=300,
        description=(
            "The text callers receive, with HTTP status 503, while the proxy is paused and the admin did not type "
            "a specific reason in the pause dialog. Throttle-all turned on without a reason sends the same text "
            "with its own refusal, as v1 did. Game developers see it in their scripts' error output, so keep it "
            "short and plain."
        ),
        pages=("topbar#pause",),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        v1_default="Service down for maintenance.",
        notes=(
            "Was the v1 constant DEFAULT_DOWNTIME_MESSAGE (not a v1 setting, so there is no key to import). v1 "
            "sent it as a JSON string, and also used it as the throttle-all message when no reason was given. "
            "Must not contain em or en dash characters (style rule C5)."
        ),
    ),
    SettingSpec(
        key="compat_collapse_upstream_errors",
        group=Group.PUBLIC_SITE,
        label="v1-style upstream errors (always 500)",
        type=SettingType.BOOL,
        default=0,
        description=(
            "Controls the status code callers get when Roblox fails or rejects a request. Off (the v2 behavior) "
            "passes the real status through, such as 404, or 429 with a Retry-After header saying how long to "
            "wait. On brings back v1 behavior, where every upstream failure became a 500."
        ),
        pages=_PUBLIC_SITE,
        if_enabled=(
            "Every Roblox 4xx, live or cached, reaches callers as a 500 that still carries Roblox's own body and "
            "content type, exactly as in v1: with ?prettyprint=true a 4xx answered from the cache is pretty printed "
            "and a live one is not, as v1 did. Every Roblox 5xx, 502 and 504 becomes a 500 with the text 'Upstream "
            "request failed; please try again later.'. Old scripts that only check for 200 or 500 keep working, "
            "but they usually retry at once, which sends more traffic to Roblox and causes more 429s. A Roblox "
            "429 that Roxy's own call received counts as a Roblox 4xx: callers get 500 with Roblox's body, and "
            "Retry-After is still sent. Roxy's own busy and cooldown answers that made no call (a cooling "
            "endpoint, a per-key 429 marker, a full queue) stay 429, and Roxy's own refusals (throttles, pause, "
            "invalid URLs) are unchanged."
        ),
        if_disabled=(
            "Callers see the real upstream status (404 stays 404, 429 stays 429 with Retry-After) plus a "
            "Roxy-Upstream-Status header, so well-written scripts can wait the right amount of time instead of "
            "retrying immediately."
        ),
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        notes=(
            "Owner decision D4: real upstream status by default. v1 always behaved as if this were on. The full "
            "status mapping is plan 7.13; its compat note gives a Roblox 4xx the failure text, but v1 relayed "
            "Roblox's body under the 500, and this setting exists to reproduce v1 (a lead decision)."
        ),
    ),
    SettingSpec(
        key="public_cors_allow_any_origin",
        group=Group.PUBLIC_SITE,
        label="Allow browsers on any website (CORS)",
        type=SettingType.BOOL,
        default=0,
        description=(
            "CORS (cross-origin resource sharing) headers tell a web browser whether a page on another website may "
            "read Roxy's responses. Roblox game servers do not need CORS at all; only browser pages do. Off sends "
            "no CORS headers, so web pages on other sites cannot use Roxy from their visitors' browsers."
        ),
        pages=_PUBLIC_SITE,
        if_enabled=(
            "Roxy adds 'Access-Control-Allow-Origin: *' to GET responses (never with credentials), so any website "
            "can call Roxy from its visitors' browsers. That turns Roxy into a free public API for the whole web, "
            "and the extra traffic counts against Roblox's rate limits for every caller."
        ),
        if_disabled=(
            "No CORS headers are sent. Roblox game servers and server-side scripts are unaffected; only browser "
            "pages on other websites are blocked from reading responses."
        ),
        risk=Risk.HIGH,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                1,
                "Browsers on any website can use Roxy as a free API, adding load that counts against Roblox's "
                "rate limits for every caller.",
            ),
        ),
        apply=Apply.LIVE,
        related_recommendations=("SEC-DEFAULTS",),
        pending_owner_verification=True,
        notes="Owner decision D20. The admin dashboard never sends CORS headers, whatever this is set to.",
    ),
    SettingSpec(
        key="public_status_page_enabled",
        group=Group.PUBLIC_SITE,
        label="Public status page",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Turns the public /status page on or off. It shows only coarse health (operational, degraded, paused "
            "or maintenance), a 24-hour uptime bar and plain-language notes, with no internal details, IP "
            "addresses or counts that would help an attacker."
        ),
        pages=_PUBLIC_SITE,
        if_enabled=(
            "Anyone can open /status to check whether Roxy is working before blaming their own script, which cuts "
            "down on 'is it down?' questions."
        ),
        if_disabled=(
            "/status returns 404 Not Found. The /health JSON endpoint that uptime monitors use is not affected."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
    ),
    # ---------------------------------------------------------------- pages under construction (2026-10-15)
    _construction_switch("public_home_under_construction", "Home page under construction", "/", "home page"),
    _construction_switch("public_docs_under_construction", "User guide under construction", "/docs", "user guide"),
    _construction_switch(
        "public_status_under_construction",
        "Status page under construction",
        "/status",
        "status page",
        extra_note=(
            "While public_status_page_enabled is off, /status answers 404 Not Found for everyone, admins included, "
            "whatever this switch says: a page that is turned off is not under construction."
        ),
    ),
    SettingSpec(
        key="site_construction_text",
        group=Group.PUBLIC_SITE,
        label="Under construction message",
        type=SettingType.STRING,
        default=_CONSTRUCTION_TEXT_DEFAULT,
        max_length=_CONSTRUCTION_TEXT_MAX,
        description=(
            "The message visitors read on the 'under construction' page that replaces a public page while its "
            "switch (home page, user guide or status page under construction) is on. Keep it short and plain; the "
            "page already says which page is under construction and that the proxy keeps working."
        ),
        pages=_PUBLIC_SITE,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=_other_construction_keys("site_construction_text"),
        notes=(
            "Owner request (2026-10-15); the default is the lead's wording in the owner's plain style. Shown on the "
            "under-construction page only. Plain text: blank lines separate paragraphs, and links are written as "
            "[label](https://...). Only https links are allowed, and HTML is shown as text, never rendered. Must not "
            "contain em or en dash characters (style rule C5)."
        ),
    ),
    # ---------------------------------------------------------------- home page text (D18)
    SettingSpec(
        key="site_contact_name",
        group=Group.PUBLIC_SITE,
        label="Contact name and where to reach them",
        type=SettingType.STRING,
        default=_CONTACT_DEFAULT,
        max_length=_SITE_TEXT_MAX,
        description=(
            "Who the public site tells visitors to contact, and where, when they need something extra, have an "
            "issue, found a vulnerability or need more request bandwidth. It completes sentences such as 'Contact "
            "CeaselessQuokka on the DevForums or Twitter.' on the home page and in the user guide, so write the "
            "name followed by where to reach it. Use public handles and places, never a private email address or "
            "phone number."
        ),
        pages=_PUBLIC_SITE,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=_other_site_keys("site_contact_name"),
        notes=(
            "Owner answers B13 and B15 (2026-10-14): contact CeaselessQuokka on the DevForums or Twitter. v1 named "
            "only 'CeaselessQuokka' (in its default throttle messages; the v1 home page spoke in the first person). "
            "The default throttle ladder's rungs 3 and 4 name the same contact in their own text, which is edited "
            "on the Protection page. Shown as plain text on the home page and in the user guide, so links are not "
            "supported here, and HTML is shown as text. Must not contain em or en dash characters (style rule C5)."
        ),
    ),
    SettingSpec(
        key="site_white_hats_text",
        group=Group.PUBLIC_SITE,
        label="No login required and white hats text",
        type=SettingType.STRING,
        default=_WHITE_HATS_DEFAULT,
        max_length=_SITE_TEXT_MAX,
        description=(
            "The 'No login required' section of the home page: it explains that Roxy signs requests with its own "
            "account and blocks account endpoints, and warns visitors never to send their .ROBLOSECURITY cookie to "
            "Roxy or any other proxy."
        ),
        pages=_PUBLIC_SITE,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=_other_site_keys("site_white_hats_text"),
        notes=(
            "v1 section 'No Login Required & White Hats', first half; confirmed by the owner on 2026-10-14 (B15); "
            "the first paragraph changed with D1 revised on 2026-10-16. " + _SITE_FORMAT_NOTE
        ),
    ),
    SettingSpec(
        key="site_bug_bounty_text",
        group=Group.PUBLIC_SITE,
        label="Bug bounty text",
        type=SettingType.STRING,
        default="",
        max_length=_SITE_TEXT_MAX,
        description=(
            "The bug bounty paragraph on the home page: what security researchers can earn for reporting a "
            "vulnerability. Empty (the default) means there is no bug bounty: the home page leaves the paragraph "
            "out and the user guide says there is no bug bounty at the moment. A text here names amounts of "
            "money, so keep it current."
        ),
        pages=_PUBLIC_SITE,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=_other_site_keys("site_bug_bounty_text"),
        notes=(
            "Owner answers B13 and B15 (2026-10-14): no bug bounty for now, so the default is empty. v1's "
            "paragraph, to paste back if the bounty returns: '" + _BUG_BOUNTY_V1 + "' " + _SITE_FORMAT_NOTE
        ),
    ),
    SettingSpec(
        key="site_hosting_note",
        group=Group.PUBLIC_SITE,
        label="Hosting and costs note",
        type=SettingType.STRING,
        default=_HOSTING_DEFAULT,
        max_length=_SITE_TEXT_MAX,
        description=(
            "The 'Roxy internals' section of the home page: what Roxy runs on and what it costs to keep online. "
            "Update it when the hosting plan or prices change."
        ),
        pages=_PUBLIC_SITE,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=_other_site_keys("site_hosting_note"),
        notes=(
            "v1 section 'Roxy Internals'. The v1 sentence 'Roxy was made using Python and Flask' was stale and is "
            "rewritten for v2 (owner decision D18); the owner confirmed the hosting tier, transfer allowance and "
            "costs on 2026-10-14 (B15). They do not include any rotating proxy plan. " + _SITE_FORMAT_NOTE
        ),
    ),
    SettingSpec(
        key="site_support_links",
        group=Group.PUBLIC_SITE,
        label="Support and 'also by the author' text",
        type=SettingType.STRING,
        default="",
        max_length=_SITE_TEXT_MAX,
        description=(
            "The 'Support me' section of the home page, for example how to support the author and 'Also by the "
            "author' links to the author's other projects. Empty (the default) leaves the whole section out."
        ),
        pages=_PUBLIC_SITE,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=_other_site_keys("site_support_links"),
        notes=(
            "Owner answers B13 and B15 (2026-10-14): no support links for now, so the default is empty and the "
            "section is hidden. v1's 'Support Me' text, to paste back if you want the section again: '"
            + _SUPPORT_V1
            + "' v1's plugin link is not part of it: it is in the home page introduction, where v1 had it "
            "(test_v1_home_links_survive). " + _SITE_FORMAT_NOTE
        ),
    ),
    SettingSpec(
        key="site_footer_text",
        group=Group.PUBLIC_SITE,
        label="Footer text",
        type=SettingType.STRING,
        default=_FOOTER_DEFAULT,
        max_length=_SITE_TEXT_MAX,
        description="The small line of text at the bottom of every public page.",
        pages=_PUBLIC_SITE,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=_other_site_keys("site_footer_text"),
        notes=(
            "v1 footer, unchanged (it already used a plain hyphen); the owner kept it on 2026-10-14 (B15). "
            + _SITE_FORMAT_NOTE
        ),
    ),
    # ---------------------------------------------------------------- dashboard-wide preferences
    SettingSpec(
        key="ui_timezone",
        group=Group.DASHBOARD,
        label="Dashboard timezone",
        type=SettingType.STRING,
        default="America/New_York",
        max_length=64,
        description=(
            "The timezone for every time shown in the dashboard and for where a 'day' and a 'month' begin in "
            "long-term charts and comparisons. Use an IANA zone name such as America/New_York, Europe/London "
            "or UTC."
        ),
        pages=_PREFERENCES,
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        related_settings=("maintenance_hour", "alert_digest_hour", "retention_day_days"),
        pending_owner_verification=True,
        notes=(
            "Must be a valid IANA zone name. Changing it affects only daily and monthly totals computed after the "
            "change: older days keep the zone they were computed in, and charts that span the change show a note. "
            "Minute and hour data are always stored in UTC. The default awaits the owner's preference (plan 6.4)."
        ),
    ),
    SettingSpec(
        key="ui_default_theme",
        group=Group.DASHBOARD,
        label="Default dashboard theme",
        type=SettingType.ENUM,
        default="dark",
        options=(
            OptionSpec(
                value="dark",
                label="Dark",
                description="Light text on a dark background, like the v1 dashboard and public site.",
            ),
            OptionSpec(
                value="light",
                label="Light",
                description="Dark text on a light background; easier to read in bright rooms and when printing.",
            ),
            OptionSpec(
                value="system",
                label="Follow the browser",
                description=(
                    "Uses the light or dark preference of each admin's operating system or browser, and switches "
                    "automatically when that preference changes."
                ),
            ),
        ),
        description=(
            "The color theme the dashboard uses for admins who have not picked one in their own preferences. An "
            "admin's own choice always wins over this default."
        ),
        pages=_PREFERENCES,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("ui_timezone",),
    ),
]
