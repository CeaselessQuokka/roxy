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
    stale "Python and Flask" line rewritten. Format contract for every `site_*` value, which the public page
    renderer must honor: plain text, blank lines separate paragraphs, and links are written as
    `[label](https://...)`; only https links become links, and HTML is shown as text, never rendered.

What to read next
    `roxy/config/spec.py` (field meanings), plan 16.1 (where each `site_*` text appears on `/`), plan 7.13 (the
    caller status table that `compat_collapse_upstream_errors` changes), plan 9.4 (CORS) and 6.4 (why the
    timezone matters for day and month rollups).
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
    "Roxy is built for public, unauthenticated Roblox web API calls only; it does not support requests that "
    "require you to be logged in, and it will refuse any request that carries anything that looks like a real "
    "Roblox .ROBLOSECURITY session cookie.\n\n"
    "Never send your ROBLOSECURITY token to Roxy, or to any third-party proxy. Sharing it lets someone log in as "
    "you and take your account, Robux, and items; no exceptions, no matter how trustworthy a service looks or "
    "claims to be. Even a secure, open-source server can't prove what's actually running on it. The only safe "
    "token is one you never send."
)

_BUG_BOUNTY_DEFAULT = (
    "If you're a White Hat and find a vulnerability, I'm offering rewards from $10-$250 USD depending on "
    "severity. Any serious exploit report is always paid and appreciated. I'm still learning web development, so "
    "there may be a lot of issues."
)

# D18: the v1 text said "Roxy was made using Python and Flask", which is stale for v2. Only that sentence is
# rewritten; the hosting and cost facts are the owner's v1 text, to be confirmed (pending_owner_verification).
_HOSTING_DEFAULT = (
    "Roxy is written in Python using FastAPI and Uvicorn. It is hosted using the second tier option of Lightsail "
    "on AWS, which means there is 2TB of transfer data per month. So if the site goes down that is probably why. "
    "Hopefully 2TB is enough, but I will monitor.\n\n"
    "If you're curious how much Roxy costs to maintain: as of right now, 7 USD per month (for the Lightsail "
    "instance) + 15 USD per year (for the domain). Which comes out to be exactly $99 per year."
)

_SUPPORT_DEFAULT = (
    "You never have to donate or pay anything; just using anything I make is enough support for me. If you ever "
    "make something with something I create, please tag me in it, I'd love to see it! :D\n\n"
    "Also by the author: [Bundle and Character/Outfit Inserter (shameful plug(in))]"
    "(https://devforum.roblox.com/t/bundle-and-characteroutfit-inserter-free-plugin/3972083)"
)

_FOOTER_DEFAULT = "Roxy Proxy 2025-Present"


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
            "a specific reason in the pause dialog. Game developers see it in their scripts' error output, so keep "
            "it short and plain."
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
            "Every Roblox 4xx, Roblox 5xx, 502 and 504 becomes a 500 with the text 'Upstream request failed; "
            "please try again later.', and cached Roblox 404s replay as 500, exactly as in v1. Old scripts that "
            "only check for 200 or 500 keep working, but they usually retry at once, which sends more traffic to "
            "Roblox and causes more 429s. Roxy's own refusals (throttles, pause, invalid URLs) are unchanged, and "
            "Retry-After is still sent."
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
            "status mapping is plan 7.13."
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
    # ---------------------------------------------------------------- home page text (D18)
    SettingSpec(
        key="site_contact_name",
        group=Group.PUBLIC_SITE,
        label="Contact name",
        type=SettingType.STRING,
        default="CeaselessQuokka",
        max_length=_SITE_TEXT_MAX,
        description=(
            "The name the public site tells visitors to contact about problems, vulnerability reports or more "
            "request bandwidth. Use a public handle, never a private email address or phone number."
        ),
        pages=_PUBLIC_SITE,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=_other_site_keys("site_contact_name"),
        pending_owner_verification=True,
        notes=(
            "Default is the name v1 used in its default throttle messages ('contact CeaselessQuokka'); the v1 "
            "home page itself spoke in the first person. " + _SITE_FORMAT_NOTE
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
            "The 'No login required' section of the home page: it explains that Roxy only handles public requests "
            "and warns visitors never to send their .ROBLOSECURITY cookie to Roxy or any other proxy."
        ),
        pages=_PUBLIC_SITE,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=_other_site_keys("site_white_hats_text"),
        pending_owner_verification=True,
        notes="v1 section 'No Login Required & White Hats', first half. " + _SITE_FORMAT_NOTE,
    ),
    SettingSpec(
        key="site_bug_bounty_text",
        group=Group.PUBLIC_SITE,
        label="Bug bounty text",
        type=SettingType.STRING,
        default=_BUG_BOUNTY_DEFAULT,
        max_length=_SITE_TEXT_MAX,
        description=(
            "The bug bounty paragraph on the home page: what security researchers can earn for reporting a "
            "vulnerability. It names amounts of money, so keep it current."
        ),
        pages=_PUBLIC_SITE,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=_other_site_keys("site_bug_bounty_text"),
        pending_owner_verification=True,
        notes=(
            "v1 section 'No Login Required & White Hats', reward paragraph. The '$10-$250' range already used a "
            "plain hyphen. " + _SITE_FORMAT_NOTE
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
        pending_owner_verification=True,
        notes=(
            "v1 section 'Roxy Internals'. The v1 sentence 'Roxy was made using Python and Flask' was stale and is "
            "rewritten for v2 (owner decision D18); the owner should confirm the hosting tier, transfer allowance "
            "and costs, which do not include any rotating proxy plan. " + _SITE_FORMAT_NOTE
        ),
    ),
    SettingSpec(
        key="site_support_links",
        group=Group.PUBLIC_SITE,
        label="Support and 'also by the author' text",
        type=SettingType.STRING,
        default=_SUPPORT_DEFAULT,
        max_length=_SITE_TEXT_MAX,
        description=(
            "The 'Support me' section of the home page, including the 'Also by the author' links to the "
            "author's other projects."
        ),
        pages=_PUBLIC_SITE,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=_other_site_keys("site_support_links"),
        pending_owner_verification=True,
        notes=(
            "v1 section 'Support Me' plus the plugin link from the v1 intro; test_v1_home_links_survive expects "
            "that link on the home page. " + _SITE_FORMAT_NOTE
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
        pending_owner_verification=True,
        notes="v1 footer, unchanged (it already used a plain hyphen). " + _SITE_FORMAT_NOTE,
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
