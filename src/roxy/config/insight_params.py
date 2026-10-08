"""Recommendation rule catalog: every rule id, its family, a one-line title, and its tunable thresholds.

What this is
    `INSIGHT_RULES`, a dict from rule id (for example `UP-429-ENDPOINT`) to an `InsightRuleSpec`. There is one
    entry for every rule in plan section 11.5, in the same order. Each spec lists the rule's named thresholds
    (`ParamSpec`) with the defaults from plan 15.3 J2. Rules that fire on any occurrence have no thresholds
    (`params=()`).

Why it exists
    Plan 11.1: no recommendation rule may hide a magic number in code. Every threshold is declared here once,
    with a unit, a safe range and plain-English text about what raising or lowering it does. The settings
    catalog turns each rule into ordinary runtime settings, so an admin can tune or silence any rule from the
    "Tune this rule" drawer on the Recommendations page, and every change is validated, audited and
    hot-reloaded like any other setting.

How it works
    `roxy/config/catalog.py` reads `INSIGHT_RULES` and, for each rule, generates:
      * `insight_<slug>_enabled` (0 or 1; 0 silences the rule),
      * `insight_<slug>_severity` (`auto`, `info`, `warn`, `critical`),
      * `insight_<slug>_<param.name>` for every `ParamSpec` below,
    where `<slug>` is the rule id in lowercase with dashes turned into underscores (`up_429_endpoint`).
    A rule module in `roxy/insights/rules/` then reads its thresholds from the runtime settings store, never
    from literals. `ParamSpec.is_int` is False only where a fractional value makes sense (1.3 calls per
    request, 0.5 percent). Where the generic help text ("fires less often" when raised) would be wrong, for
    example for a look-back window or a "check the top N endpoints" count, the param carries its own text.

What to read next
    `roxy/config/spec.py` (the `InsightRuleSpec` and `ParamSpec` shapes), `roxy/config/catalog.py` (how the
    settings are generated), then any rule in `roxy/insights/rules/` to see a threshold being read.
"""

from roxy.config.spec import InsightRuleSpec, ParamSpec

# --- Shared builders for look-back windows -------------------------------------------------------------------
#
# Windows behave differently depending on what the rule does with them, so the generic "fires less often when
# raised" text would be wrong for most of them. Three shapes appear in 11.5:
#   * count windows: "at least N things within the window". A longer window lets slow trickles add up, so the
#     rule fires MORE often, and it takes longer to clear.
#   * rate windows: "a rate or share measured over the window". A longer window averages out short spikes, so
#     the rule fires on fewer blips but reacts more slowly.
#   * sustain windows: "the condition must hold for the whole window". A longer window means the condition must
#     last longer, so short peaks are ignored.


def _count_window(default: int, what: str, *, maximum: int = 1440) -> ParamSpec:
    """A look-back window over which `what` (plural noun phrase, lowercase) is counted against a minimum."""
    return ParamSpec(
        name="window_min",
        default=default,
        min=1,
        max=maximum,
        unit="minutes",
        label="Look-back window",
        if_raised=(
            f"Counts {what} over a longer stretch, so slow trickles can add up to the threshold and the rule "
            "fires more often; it also takes longer to clear after the problem stops."
        ),
        if_lowered=(
            f"Counts only {what} close together in time, so only sharp bursts fire the rule, and it clears "
            "quickly once they stop."
        ),
    )


def _rate_window(default: int, what: str, *, maximum: int = 1440) -> ParamSpec:
    """A window over which `what` (a rate or share, lowercase) is measured against a threshold."""
    return ParamSpec(
        name="window_min",
        default=default,
        min=1,
        max=maximum,
        unit="minutes",
        label="Measurement window",
        if_raised=(
            f"Measures {what} over a longer stretch: short spikes are averaged out, so there are fewer false "
            "alarms, but the rule reacts more slowly to a new problem."
        ),
        if_lowered=(
            f"Measures {what} over a short stretch: the rule reacts quickly, but brief blips that fix "
            "themselves can fire it."
        ),
    )


def _sustain_window(default: int, subject: str, *, maximum: int = 240) -> ParamSpec:
    """A duration for which `subject` (capitalized noun phrase) must stay over its threshold."""
    return ParamSpec(
        name="window_min",
        default=default,
        min=1,
        max=maximum,
        unit="minutes",
        label="Minutes the condition must last",
        if_raised=(
            f"{subject} must stay over the threshold for longer before the rule fires, so short peaks are "
            "ignored, but a real problem is reported later."
        ),
        if_lowered=(
            f"{subject} only needs to be over the threshold briefly, so the rule fires sooner, including on "
            "short peaks that would have passed on their own."
        ),
    )


# --- The rules, in plan 11.5 order -----------------------------------------------------------------------------

_RULES: tuple[InsightRuleSpec, ...] = (
    # ---------------------------------------------------------------- upstream (Roblox answers and pacing)
    InsightRuleSpec(
        rule_id="UP-429-ENDPOINT",
        family="upstream",
        title="Roblox is rate-limiting (429) one endpoint far more than others",
        params=(
            ParamSpec(
                name="min_429s",
                default=20,
                min=1,
                max=100000,
                unit="responses",
                label="Roblox 429s on one endpoint",
                if_raised=(
                    "Needs more Roblox 429 responses on one endpoint within the window before it fires; "
                    "endpoints with only a few 429s are left alone."
                ),
                if_lowered=(
                    "Fires after fewer 429s on one endpoint, so a short burst can be enough; more "
                    "recommendations about endpoints that would have recovered on their own."
                ),
            ),
            ParamSpec(
                name="share_pct",
                default=2.0,
                min=0.1,
                max=100,
                unit="percent",
                label="Share of the endpoint's upstream calls answered with 429",
                if_raised=(
                    "Fires on this test only when a larger share of the endpoint's calls get 429; "
                    "low-traffic endpoints with a few 429s stay quiet."
                ),
                if_lowered=(
                    "Fires when even a small share of an endpoint's calls gets 429, catching problems early "
                    "but also reporting normal background noise."
                ),
                is_int=False,
            ),
            _count_window(60, "Roblox 429s on each endpoint"),
            ParamSpec(
                name="high_confidence_n",
                default=50,
                min=1,
                max=100000,
                unit="responses",
                label="429s needed to mark a recommendation high confidence",
                if_raised=(
                    "Recommendations are marked high confidence only with more 429s as evidence. It does not "
                    "change when the rule fires."
                ),
                if_lowered=(
                    "Recommendations are marked high confidence on less evidence. It does not change when "
                    "the rule fires."
                ),
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-429-HOST",
        family="upstream",
        title="Roblox 429s are spread across many endpoints of one host",
        params=(
            ParamSpec(
                name="min_templates",
                default=3,
                min=2,
                max=100,
                unit="endpoints",
                label="Endpoints of one host with 429s",
                if_raised=(
                    "Needs 429s on more endpoints of the same host before calling it a host-wide problem; "
                    "smaller clusters are left to the per-endpoint rule."
                ),
                if_lowered=(
                    "Calls it a host-wide problem when fewer endpoints are affected, which may suggest "
                    "slowing the whole host when only a couple of endpoints needed it."
                ),
            ),
            _count_window(15, "endpoints with 429s"),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-429-CREDENTIAL",
        family="upstream",
        title="Roblox is rate-limiting calls made with the credential",
        params=(
            ParamSpec(
                name="min_429s",
                default=1,
                min=1,
                max=1000,
                unit="responses",
                label="Credential 429s before it fires",
                if_raised=(
                    "Lets some credential 429s pass without a recommendation. Each one means Roblox is "
                    "limiting the account itself, so keep this at or near 1."
                ),
                if_lowered="1 is the lowest value: every credential 429 is reported.",
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-429-AMPLIFY",
        family="upstream",
        title="Retries are multiplying Roblox 429s",
        params=(
            ParamSpec(
                name="calls_per_request",
                default=1.3,
                min=1.0,
                max=10.0,
                unit="calls per request",
                label="Upstream calls per caller request during 429 episodes",
                if_raised=(
                    "Tolerates more retrying during 429 episodes before it fires. Every retry while Roblox is "
                    "limiting Roxy adds load and makes the limit last longer."
                ),
                if_lowered="Fires on milder retry amplification; at 1.0 any retry during a 429 episode counts.",
                is_int=False,
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-RETRYAFTER-IGNORED",
        family="upstream",
        title="Callers retry before the Retry-After time they were given",
        params=(
            ParamSpec(
                name="min_retries",
                default=20,
                min=1,
                max=100000,
                unit="retries",
                label="Early retries by one client in the window",
                if_raised=(
                    "Only clients that retry early many times are reported; occasional early retries are ignored."
                ),
                if_lowered=(
                    "Reports clients after a few early retries, including scripts that only slipped once or twice."
                ),
            ),
            _count_window(10, "early retries from each client"),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-4XX-SPIKE",
        family="upstream",
        title="Roblox is rejecting Roxy with 403, 401 or 400 more than usual",
        params=(
            ParamSpec(
                name="baseline_multiple",
                default=3.0,
                min=1.1,
                max=100,
                unit="times the 7-day baseline",
                label="Rise over the endpoint's 7-day rejection rate",
                if_raised=(
                    "Fires only when rejections rise far above the endpoint's normal level; gradual increases "
                    "go unreported."
                ),
                if_lowered="Fires on smaller rises over normal, including ordinary day-to-day variation.",
                is_int=False,
            ),
            ParamSpec(
                name="min_responses",
                default=20,
                min=1,
                max=100000,
                unit="responses",
                label="Rejections needed in the window",
                if_raised="Needs more rejected responses before it fires, so small blips are ignored.",
                if_lowered="Fires on fewer rejected responses, so small samples can trigger it.",
            ),
            ParamSpec(
                name="min_calls",
                default=100,
                min=1,
                max=1000000,
                unit="calls",
                label="Upstream calls needed on the endpoint",
                if_raised=(
                    "Needs more traffic on an endpoint before judging its rejection rate, so quiet endpoints "
                    "are skipped."
                ),
                if_lowered=(
                    "Judges endpoints on less traffic; with small samples the rate is noisy and false alarms "
                    "are more likely."
                ),
            ),
            _rate_window(30, "the rejection rate"),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-CSRF-LOOP",
        family="upstream",
        title="The CSRF token handshake with Roblox keeps failing to settle",
        params=(
            ParamSpec(
                name="retry_pct",
                default=20,
                min=1,
                max=100,
                unit="percent of write requests",
                label="CSRF retries as a share of write requests",
                if_raised=(
                    "Fires only when a large share of write requests (POST, PATCH, PUT, DELETE) need a CSRF "
                    "retry; milder token churn is ignored."
                ),
                if_lowered=(
                    "Fires when even a small share of write requests needs a CSRF retry, which is partly "
                    "normal because Roblox rotates the token."
                ),
            ),
            _rate_window(30, "the CSRF retry share"),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-CHALLENGE",
        family="upstream",
        title="Roblox is answering with challenge or block pages",
        params=(
            ParamSpec(
                name="min_pages",
                default=5,
                min=1,
                max=100000,
                unit="responses",
                label="Challenge or block pages in the window",
                if_raised="Needs more challenge or block pages before it fires; isolated ones are ignored.",
                if_lowered="Fires after fewer challenge or block pages; a single odd HTML answer can be enough.",
            ),
            _count_window(15, "challenge or block pages"),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-UA-EXPERIMENT",
        family="upstream",
        title="Which upstream User-Agent gets fewer Roblox 429s",
        params=(
            ParamSpec(
                name="min_calls_per_arm",
                default=10000,
                min=100,
                max=10000000,
                unit="calls per User-Agent",
                label="Calls per User-Agent before naming a winner",
                if_raised=(
                    "Waits for more calls with each User-Agent before naming the better one: a slower answer, "
                    "but a smaller chance that the difference is luck."
                ),
                if_lowered="Names a winner sooner on less data; the measured difference may be random noise.",
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-5XX",
        family="upstream",
        title="Roblox server errors (5xx) are spiking",
        params=(
            ParamSpec(
                name="rate_pct",
                default=5.0,
                min=0.1,
                max=100,
                unit="percent",
                label="5xx share of upstream calls",
                if_raised="Fires only on larger Roblox outages; small error bursts go unreported.",
                if_lowered="Fires on small error bursts, which Roblox often has and recovers from on its own.",
                is_int=False,
            ),
            _rate_window(10, "the 5xx rate"),
            ParamSpec(
                name="min_calls",
                default=100,
                min=1,
                max=1000000,
                unit="calls",
                label="Upstream calls needed in the window",
                if_raised="Needs more traffic before judging the error rate, so quiet periods are skipped.",
                if_lowered="Judges the error rate on less traffic, so a few errors can look like a spike.",
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-TIMEOUT",
        family="upstream",
        title="Upstream requests are timing out",
        params=(
            ParamSpec(
                name="rate_pct",
                default=2.0,
                min=0.1,
                max=100,
                unit="percent",
                label="Timeout share of upstream calls",
                if_raised="Fires only when many calls time out; occasional timeouts are ignored.",
                if_lowered="Fires when even a few calls time out, which can happen on any network.",
                is_int=False,
            ),
            _rate_window(10, "the timeout rate"),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-LATENCY",
        family="upstream",
        title="Upstream responses are slow",
        params=(
            ParamSpec(
                name="p95_ms",
                default=1500,
                min=50,
                max=60000,
                unit="ms",
                label="p95 upstream latency (95% of calls finish faster)",
                if_raised=(
                    "Fires only when the slowest 5% of upstream calls are slower than this; moderate slowness "
                    "goes unreported."
                ),
                if_lowered="Fires on smaller slowdowns, including normal variation in Roblox response times.",
            ),
            ParamSpec(
                name="p99_ms",
                default=4000,
                min=50,
                max=120000,
                unit="ms",
                label="p99 upstream latency (99% of calls finish faster)",
                if_raised="Fires only when the slowest 1% of calls are very slow; rare stalls are ignored.",
                if_lowered="Fires on rarer slow calls, which every network has now and then.",
            ),
            _rate_window(30, "upstream latency"),
            ParamSpec(
                name="min_calls",
                default=200,
                min=1,
                max=1000000,
                unit="calls",
                label="Upstream calls needed in the window",
                if_raised="Needs more calls before judging latency, so quiet periods are skipped.",
                if_lowered="Judges latency on fewer calls, so a handful of slow ones can fire it.",
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-QUEUE-SAT",
        family="upstream",
        title="Requests wait too long or are dropped in the upstream queue",
        params=(
            ParamSpec(
                name="drop_pct",
                default=0.5,
                min=0.01,
                max=100,
                unit="percent",
                label="Queue drops as a share of requests",
                if_raised="Tolerates more dropped requests before it fires; callers see more 429 busy answers.",
                if_lowered="Fires on very few drops, including brief bursts that cleared on their own.",
                is_int=False,
            ),
            ParamSpec(
                name="p95_wait_ms",
                default=2000,
                min=10,
                max=60000,
                unit="ms",
                label="p95 queue wait (95% of requests wait less)",
                if_raised="Tolerates longer queue waits before it fires; callers wait longer for answers.",
                if_lowered="Fires on shorter waits, some of which are normal pacing at busy times.",
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-BUCKET-TUNE",
        family="upstream",
        title="A pacing bucket is too tight or too loose",
        params=(
            ParamSpec(
                name="clean_hours",
                default=24,
                min=1,
                max=720,
                unit="hours",
                label="Hours with zero 429s before proposing a raise",
                if_raised=(
                    "Needs a longer record without Roblox 429s before proposing a higher rate, so raises are "
                    "rarer and safer."
                ),
                if_lowered=(
                    "Proposes raises after a shorter clean record; a higher rate is more likely to bring 429s back."
                ),
            ),
            ParamSpec(
                name="rejection_pct",
                default=1.0,
                min=0.1,
                max=100,
                unit="percent",
                label="Bucket rejections as a share of attempts",
                if_raised=(
                    "Proposes a raise only when the bucket turns away a large share of requests, so mild "
                    "pressure is tolerated."
                ),
                if_lowered="Proposes a raise when the bucket turns away even a few requests.",
                is_int=False,
            ),
            ParamSpec(
                name="raise_pct",
                default=10,
                min=1,
                max=100,
                unit="percent",
                label="Raise step for a too-tight bucket",
                if_raised=(
                    "Each recommendation raises the bucket rate by more: it reaches real demand in fewer steps, "
                    "but each step is a bigger jump in load on Roblox. It does not change when the rule fires."
                ),
                if_lowered=(
                    "Smaller, more cautious raises; more steps are needed to reach real demand. It does not "
                    "change when the rule fires."
                ),
            ),
            ParamSpec(
                name="lower_pct",
                default=30,
                min=1,
                max=90,
                unit="percent",
                label="Cut for a too-loose bucket",
                if_raised=(
                    "Each recommendation cuts the bucket rate more after a 429, which stops 429s faster but "
                    "may slow callers more than needed. It does not change when the rule fires."
                ),
                if_lowered=(
                    "Gentler cuts; 429s may continue for longer before the rate is low enough. It does not "
                    "change when the rule fires."
                ),
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="UP-BREAKER-FLAP",
        family="upstream",
        title="A circuit breaker keeps opening and closing",
        params=(
            ParamSpec(
                name="openings_per_hour",
                default=6,
                min=1,
                max=1000,
                unit="openings per hour",
                label="Breaker openings per hour on one key",
                if_raised="Fires only on breakers that open very often; occasional flapping is ignored.",
                if_lowered="Fires after a few openings, which a short Roblox hiccup can cause.",
            ),
        ),
    ),
    # ---------------------------------------------------------------- cache
    InsightRuleSpec(
        rule_id="CACHE-LOW-HIT",
        family="cache",
        title="A busy endpoint has a low cache hit ratio",
        params=(
            ParamSpec(
                name="top_n",
                default=10,
                min=1,
                max=200,
                unit="endpoints",
                label="Busiest endpoints checked",
                if_raised=(
                    "Checks more endpoints further down the busiest list, so the rule fires more often, "
                    "including on endpoints where better caching saves fewer calls."
                ),
                if_lowered=(
                    "Checks only the very busiest endpoints, where a better hit ratio saves the most calls; "
                    "the rule fires less often."
                ),
            ),
            ParamSpec(
                name="max_hit_ratio_pct",
                default=30,
                min=1,
                max=100,
                unit="percent",
                label="Hit ratio below which it fires",
                if_raised=(
                    "More endpoints count as low-hit, so the rule fires more often, including on endpoints "
                    "that are already cached reasonably well."
                ),
                if_lowered="Only endpoints with a very poor hit ratio are reported; the rule fires less often.",
            ),
            _rate_window(60, "the hit ratio"),
        ),
    ),
    InsightRuleSpec(
        rule_id="CACHE-TTL-TUNE",
        family="cache",
        title="An endpoint's cache time can safely rise, or must fall",
        params=(
            ParamSpec(
                name="identical_raise_pct",
                default=90,
                min=50,
                max=100,
                unit="percent",
                label="Identical refetches needed to propose a longer cache time",
                if_raised=(
                    "Proposes longer cache times only for data that almost never changes, so callers are less "
                    "likely to get outdated answers. Keep it above the 'shorter cache time' threshold."
                ),
                if_lowered=(
                    "Proposes longer cache times for data that changes more often, saving more calls but "
                    "serving outdated answers more often."
                ),
            ),
            ParamSpec(
                name="identical_lower_pct",
                default=50,
                min=0,
                max=100,
                unit="percent",
                label="Identical refetches below which it proposes a shorter cache time",
                if_raised=(
                    "Proposes shorter cache times more often, keeping data fresher at the cost of more upstream "
                    "calls. Keep it below the 'longer cache time' threshold."
                ),
                if_lowered="Proposes shorter cache times only when cached answers are very often outdated.",
            ),
            ParamSpec(
                name="min_refetches",
                default=50,
                min=2,
                max=1000000,
                unit="refetches",
                label="Refetches needed before judging an endpoint",
                if_raised="Needs more refetches as evidence, so proposals are rarer but better founded.",
                if_lowered="Judges endpoints on fewer refetches, so proposals come sooner but are noisier.",
            ),
            ParamSpec(
                name="window_h",
                default=24,
                min=1,
                max=720,
                unit="hours",
                label="Hours of refetches considered",
                if_raised=(
                    "Uses a longer stretch of refetches: steadier estimates, but slower to notice when an "
                    "endpoint starts changing faster or slower."
                ),
                if_lowered=(
                    "Uses only recent refetches: quicker to react, but estimates are noisier and fewer "
                    "endpoints reach the refetch minimum."
                ),
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="CACHE-KEYSPLIT",
        family="cache",
        title="A query parameter is splitting the cache (cache busting)",
        params=(
            ParamSpec(
                name="min_entries",
                default=5,
                min=2,
                max=100000,
                unit="cache entries",
                label="Cache entries needed for the endpoint",
                if_raised="Needs more cache entries before judging an endpoint, so small endpoints are skipped.",
                if_lowered="Judges endpoints with very few entries, where the pattern may be coincidence.",
            ),
            ParamSpec(
                name="distinct_pct",
                default=80,
                min=1,
                max=100,
                unit="percent",
                label="Share of distinct values in the top parameter",
                if_raised="Fires only when a parameter is almost always unique, a clear sign of cache busting.",
                if_lowered=(
                    "Fires on parameters that repeat more often, which may be meaningful values such as ids "
                    "rather than cache busters."
                ),
            ),
            ParamSpec(
                name="max_hit_pct",
                default=10,
                min=0,
                max=100,
                unit="percent",
                label="Hit ratio at or below which it fires",
                if_raised=(
                    "Endpoints with a better hit ratio also count, so the rule fires more often, including on "
                    "endpoints the cache already helps."
                ),
                if_lowered="Only endpoints whose cache almost never hits are reported; the rule fires less often.",
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="CACHE-PRESSURE",
        family="cache",
        title="The cache is too small and evicts entries before they expire",
        params=(
            ParamSpec(
                name="young_eviction_pct",
                default=5.0,
                min=0.1,
                max=100,
                unit="percent of stores",
                label="Early evictions as a share of stores",
                if_raised="Tolerates more entries being pushed out early before suggesting a bigger cache.",
                if_lowered="Suggests a bigger cache when only a few entries are pushed out early.",
                is_int=False,
            ),
            _rate_window(60, "early evictions"),
        ),
    ),
    InsightRuleSpec(
        rule_id="CACHE-OFF",
        family="cache",
        title="The cache is turned off while traffic is flowing",
    ),
    InsightRuleSpec(
        rule_id="CACHE-NEG",
        family="cache",
        title="Callers keep refetching the same Roblox 404 or 400 answers",
        params=(
            ParamSpec(
                name="min_404_per_hour",
                default=100,
                min=1,
                max=1000000,
                unit="refetches per hour",
                label="Identical 404 refetches per hour",
                if_raised="Fires only when the same missing item is refetched very often.",
                if_lowered="Fires on fewer repeated 404s, including ones that cost Roblox very little.",
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="HOT-ENDPOINT",
        family="cache",
        title="A newly busy endpoint has no cache rule",
        params=(
            ParamSpec(
                name="top_n",
                default=5,
                min=1,
                max=100,
                unit="endpoints",
                label="Busiest endpoints checked",
                if_raised=(
                    "Checks more endpoints further down the busiest list, so the rule fires more often, "
                    "including on endpoints where a cache rule saves fewer calls."
                ),
                if_lowered="Checks only the very busiest endpoints; the rule fires less often.",
            ),
        ),
    ),
    # ---------------------------------------------------------------- egress (the paid rotating proxy)
    InsightRuleSpec(
        rule_id="EGR-BURN",
        family="egress",
        title="The rotating proxy quota is being used up too fast",
        params=(
            ParamSpec(
                name="projected_pct",
                default=90,
                min=10,
                max=200,
                unit="percent of quota",
                label="Projected use of this billing cycle's quota",
                if_raised=(
                    "Warns later, when the projection is closer to (or past) the quota, leaving less time to "
                    "react before the rotator runs out."
                ),
                if_lowered=(
                    "Warns earlier with more time to react, but also in cycles that would have stayed in budget."
                ),
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="EGR-UNDERUSE",
        family="egress",
        title="The rotating proxy could take load off specific endpoints",
        params=(
            ParamSpec(
                name="direct_429_pct",
                default=2.0,
                min=0.1,
                max=100,
                unit="percent",
                label="Direct-path 429 rate on an endpoint",
                if_raised="Suggests the rotator only for endpoints with many direct-path 429s.",
                if_lowered="Suggests the rotator for endpoints with only a few direct-path 429s, spending more quota.",
                is_int=False,
            ),
            ParamSpec(
                name="rotator_429_max_pct",
                default=5.0,
                min=0.1,
                max=100,
                unit="percent",
                label="Highest rotator 429 rate still counted as healthy",
                if_raised=(
                    "Treats a rotator with more 429s as healthy, so the rule fires more often and may send "
                    "traffic to rotator exits that Roblox is already limiting."
                ),
                if_lowered="Requires a very clean rotator before suggesting it; the rule fires less often.",
                is_int=False,
            ),
            ParamSpec(
                name="quota_used_max_pct",
                default=30,
                min=0,
                max=100,
                unit="percent of quota",
                label="Most quota used for the rule to fire",
                if_raised=(
                    "Suggests the rotator even when more of the quota is spent, so the rule fires more often "
                    "and the rotator costs more."
                ),
                if_lowered="Suggests the rotator only when plenty of quota is left; the rule fires less often.",
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="EGR-POOL-BURNED",
        family="egress",
        title="The rotating proxy's exit addresses are already rate-limited by Roblox",
        params=(
            ParamSpec(
                name="rotator_429_pct",
                default=20.0,
                min=1,
                max=100,
                unit="percent",
                label="Rotator 429 rate",
                if_raised="Fires only when most rotator calls get 429; wasted rotator bytes go unreported longer.",
                if_lowered="Fires when a smaller share of rotator calls get 429, which some pools always have.",
                is_int=False,
            ),
            _rate_window(30, "the rotator 429 rate"),
        ),
    ),
    InsightRuleSpec(
        rule_id="EGR-CALIBRATE",
        family="egress",
        title="Roxy's rotator byte count differs from the provider's figure",
        params=(
            ParamSpec(
                name="diff_pct",
                default=10.0,
                min=1,
                max=100,
                unit="percent",
                label="Difference between Roxy's count and the provider's",
                if_raised="Tolerates a bigger gap before suggesting recalibration; budget projections drift more.",
                if_lowered="Suggests recalibration for small gaps that rounding on the provider side can explain.",
                is_int=False,
            ),
        ),
    ),
    # ---------------------------------------------------------------- credential (the one Roblox account)
    InsightRuleSpec(
        rule_id="CRED-EXPIRING",
        family="credential",
        title="The credential is rejected, expiring, or flagged by Roblox",
    ),
    InsightRuleSpec(
        rule_id="CRED-UNUSED",
        family="credential",
        title="An endpoint on the credential allowlist works just as well without it",
        params=(
            ParamSpec(
                name="min_comparisons",
                default=20,
                min=1,
                max=100000,
                unit="comparisons",
                label="Anonymous versus credential comparisons needed",
                if_raised="Needs more side-by-side comparisons before suggesting removal, so it is surer.",
                if_lowered="Suggests removal after fewer comparisons, which may miss rare differences.",
            ),
            ParamSpec(
                name="identical_pct",
                default=100,
                min=50,
                max=100,
                unit="percent",
                label="Share of identical answers needed",
                if_raised="Requires answers to match more closely; at 100 every comparison must match.",
                if_lowered=(
                    "Suggests removing endpoints whose anonymous answers sometimes differ, which can break "
                    "callers that need the logged-in answer."
                ),
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="CRED-ROTATOR-GUARD",
        family="credential",
        title="The credential leak guard blocked a request",
    ),
    # ---------------------------------------------------------------- abuse and protection tuning
    InsightRuleSpec(
        rule_id="ABUSE-SPAM",
        family="abuse",
        title="A spam detector found (or would have found) abusive traffic",
    ),
    InsightRuleSpec(
        rule_id="ABUSE-BOT",
        family="abuse",
        title="Bot-like clients are sending heavy traffic",
        params=(
            ParamSpec(
                name="min_requests_per_hour",
                default=500,
                min=1,
                max=10000000,
                unit="requests per hour",
                label="Requests per hour from one bot-like client",
                if_raised="Reports only heavy bot-like clients; lighter scrapers are left alone.",
                if_lowered="Reports lighter bot-like clients too, including small tools that cause little load.",
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="ABUSE-DIST",
        family="abuse",
        title="A distributed attack from many addresses is underway",
    ),
    InsightRuleSpec(
        rule_id="FILTER-ADD",
        family="filter",
        title="A client keeps hitting Roxy's limits",
        params=(
            ParamSpec(
                name="refusals_per_hour",
                default=1000,
                min=10,
                max=10000000,
                unit="refusals per hour",
                label="Refusals per hour for one client",
                if_raised="Suggests a ban or tarpit only for clients refused very often.",
                if_lowered="Suggests a ban or tarpit for clients refused less often, which may include busy games.",
            ),
            ParamSpec(
                name="hours",
                default=3,
                min=1,
                max=168,
                unit="hours",
                label="Consecutive hours over the refusal threshold",
                if_raised="The client must keep hitting limits for longer before a ban or tarpit is suggested.",
                if_lowered=(
                    "Suggests a filter after a shorter episode; a brief burst from a legitimate game can be enough."
                ),
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="FILTER-REMOVE",
        family="filter",
        title="A rule, ban or bypass entry looks stale or harmful",
        params=(
            ParamSpec(
                name="idle_rule_days",
                default=30,
                min=1,
                max=3650,
                unit="days",
                label="Days without hits before a rule counts as stale",
                if_raised="Waits longer before calling a rule stale, so rarely used but valid rules are kept.",
                if_lowered="Suggests removing rules sooner, including ones that only matter during rare attacks.",
            ),
            ParamSpec(
                name="idle_bypass_days",
                default=7,
                min=1,
                max=365,
                unit="days",
                label="Days unused before a bypass entry counts as stale",
                if_raised="Leaves unused bypass entries (clients that skip rate limits) in place for longer.",
                if_lowered="Suggests removing bypass entries sooner, including ones used only now and then.",
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="FILTER-COLLATERAL",
        family="filter",
        title="A filter is blocking legitimate traffic",
        params=(
            ParamSpec(
                name="served_pct",
                default=95,
                min=50,
                max=100,
                unit="percent",
                label="Served share that marks a place as legitimate",
                if_raised=(
                    "Only places whose other traffic is almost all served count as legitimate, so fewer rules "
                    "are reported."
                ),
                if_lowered=(
                    "Places with more refused traffic also count as legitimate, so more rules are reported, "
                    "including rules that are correctly blocking abuse."
                ),
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="TARPIT-TUNE",
        family="abuse",
        title="The tarpit is saturated, or holding requests does not help",
        params=(
            ParamSpec(
                name="skipped_pct",
                default=10.0,
                min=0.1,
                max=100,
                unit="percent",
                label="Skipped holds as a share of eligible holds",
                if_raised="Tolerates more skipped holds (tarpit full) before suggesting a change.",
                if_lowered="Suggests a change when only a few holds are skipped, which bursts can cause.",
                is_int=False,
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="THROTTLE-TUNE",
        family="abuse",
        title="The per-IP request limit looks too tight or too loose",
        params=(
            ParamSpec(
                name="legit_throttled_pct",
                default=5.0,
                min=0.1,
                max=100,
                unit="percent",
                label="Share of legitimate IPs throttled per day",
                if_raised="Tolerates more legitimate callers being throttled before suggesting a looser limit.",
                if_lowered="Suggests a looser limit when only a few legitimate callers are throttled.",
                is_int=False,
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="PLACE-HEAVY",
        family="abuse",
        title="One experience is taking most of the upstream calls",
        params=(
            ParamSpec(
                name="share_pct",
                default=40,
                min=1,
                max=100,
                unit="percent",
                label="One place's share of upstream calls",
                if_raised="Reports only experiences that dominate traffic heavily.",
                if_lowered="Reports experiences with a smaller share, which may simply be popular games.",
            ),
            _rate_window(60, "each experience's share of upstream calls"),
        ),
    ),
    # ---------------------------------------------------------------- system (Roxy's own health)
    InsightRuleSpec(
        rule_id="SYS-DISK",
        family="system",
        title="Disk use is growing toward the storage budget",
        params=(
            ParamSpec(
                name="budget_pct",
                default=70,
                min=10,
                max=100,
                unit="percent of budget",
                label="Storage used, as a share of the storage budget",
                if_raised="Warns later, closer to the budget, leaving less time to act.",
                if_lowered="Warns earlier, with more time to act, while plenty of budget is still left.",
            ),
            ParamSpec(
                name="free_disk_pct",
                default=15,
                min=1,
                max=90,
                unit="percent",
                label="Free disk below which it fires",
                if_raised="Fires while more disk is still free, giving earlier warnings.",
                if_lowered="Fires only when the disk is nearly full, leaving little time to act.",
            ),
            ParamSpec(
                name="dims_per_minute",
                default=1500,
                min=100,
                max=1000000,
                unit="rows per minute",
                label="Distinct metric rows written per minute",
                if_raised=(
                    "Allows more distinct metric combinations (endpoint, status, reason and so on) per minute "
                    "before warning that metrics storage will outgrow the disk plan."
                ),
                if_lowered="Warns sooner about growth in the number of distinct metric combinations per minute.",
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="SYS-WORKER-SAT",
        family="system",
        title="Worker processes are saturated",
        params=(
            ParamSpec(
                name="cpu_pct",
                default=85,
                min=10,
                max=100,
                unit="percent",
                label="CPU use",
                if_raised="Fires only when the CPU is close to fully busy; responses may already be slow.",
                if_lowered="Fires at moderate CPU use, which busy periods reach normally.",
            ),
            _sustain_window(10, "CPU use"),
        ),
    ),
    InsightRuleSpec(
        rule_id="SYS-LOOP-LAG",
        family="system",
        title="The event loop is lagging (something is blocking a worker)",
        params=(
            ParamSpec(
                name="p99_ms",
                default=100,
                min=5,
                max=10000,
                unit="ms",
                label="p99 event loop lag (99% of checks lag less)",
                if_raised="Fires only on severe stalls; smaller blocking calls go unreported.",
                if_lowered="Fires on small stalls, which garbage collection alone can cause.",
            ),
            _sustain_window(5, "Event loop lag"),
        ),
    ),
    InsightRuleSpec(
        rule_id="SYS-ERRORS",
        family="system",
        title="Roxy itself is throwing server errors",
        params=(
            ParamSpec(
                name="baseline_multiple",
                default=5.0,
                min=1.1,
                max=1000,
                unit="times the 7-day hourly baseline",
                label="Rise over a known error's usual hourly count",
                if_raised="Fires on known errors only when they jump far above their usual level.",
                if_lowered="Fires on smaller rises of known errors, including normal ups and downs.",
                is_int=False,
            ),
            ParamSpec(
                name="caller_500_pct",
                default=0.5,
                min=0.01,
                max=100,
                unit="percent",
                label="Caller-facing 500 errors as a share of requests",
                if_raised="Tolerates more callers getting 500 Internal Server Error before it fires.",
                if_lowered="Fires when even a handful of callers get 500 errors.",
                is_int=False,
            ),
            _rate_window(15, "the caller-facing 500 rate"),
        ),
    ),
    InsightRuleSpec(
        rule_id="SYS-METRICS-DROP",
        family="system",
        title="The metrics queue is dropping items",
    ),
    InsightRuleSpec(
        rule_id="SYS-CHANGE-REGRESSION",
        family="system",
        title="Errors, 429s or latency got worse right after a settings change",
        params=(
            ParamSpec(
                name="worse_pct",
                default=25,
                min=1,
                max=1000,
                unit="percent",
                label="How much worse a metric must get",
                if_raised="Suggests reverting a change only when it clearly made things worse.",
                if_lowered="Suggests reverting changes over small shifts that may be ordinary traffic swings.",
            ),
            ParamSpec(
                name="watch_min",
                default=30,
                min=5,
                max=1440,
                unit="minutes",
                label="Minutes after a change that are watched",
                if_raised=(
                    "Watches longer after each change, so the rule fires more often, and a later problem may be "
                    "blamed on a change that did not cause it."
                ),
                if_lowered=(
                    "Only problems that appear soon after a change are linked to it; slow-building regressions "
                    "are missed."
                ),
            ),
            ParamSpec(
                name="baseline_h",
                default=2,
                min=1,
                max=168,
                unit="hours",
                label="Hours before the change used as the baseline",
                if_raised=(
                    "Compares against a longer period before the change: a steadier baseline, but time-of-day "
                    "differences can skew the comparison."
                ),
                if_lowered="Compares against a short period right before the change: closer in time, but noisier.",
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="SYS-HEALTH-FAIL",
        family="system",
        title="A health check is failing",
    ),
    # ---------------------------------------------------------------- security, hosts, and the rest
    InsightRuleSpec(
        rule_id="SEC-ADMIN-ALLOWLIST",
        family="security",
        title="Admin logins always come from a few networks; an admin allowlist would help",
        params=(
            ParamSpec(
                name="max_networks",
                default=3,
                min=1,
                max=50,
                unit="networks",
                label="Most networks for an allowlist suggestion",
                if_raised=(
                    "Suggests an allowlist even when logins come from more networks, so the rule fires more "
                    "often and the suggested allowlist is longer and looser."
                ),
                if_lowered="Suggests an allowlist only when logins come from very few networks.",
            ),
            ParamSpec(
                name="days",
                default=30,
                min=1,
                max=365,
                unit="days",
                label="Days of login history considered",
                if_raised="Needs a longer login history before suggesting an allowlist, so it is better founded.",
                if_lowered=(
                    "Suggests an allowlist from a short history; a network you use only now and then may be "
                    "left out and lock you out."
                ),
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="SEC-BYPASS-FOREVER",
        family="security",
        title="A bypass entry never expires",
    ),
    InsightRuleSpec(
        rule_id="HOST-ADD",
        family="host",
        title="A real Roblox host is missing from the host allowlist",
        params=(
            ParamSpec(
                name="min_places",
                default=5,
                min=1,
                max=100000,
                unit="places",
                label="Distinct experiences requesting the host",
                if_raised="Needs more experiences asking for the host before suggesting it.",
                if_lowered="Suggests a host after fewer experiences ask for it, including one-off typos.",
            ),
            ParamSpec(
                name="min_ips",
                default=50,
                min=1,
                max=10000000,
                unit="IP addresses",
                label="Distinct client addresses requesting the host",
                if_raised="Needs more distinct callers asking for the host before suggesting it.",
                if_lowered="Suggests a host after fewer callers ask for it, including a single noisy script.",
            ),
            ParamSpec(
                name="window_h",
                default=24,
                min=1,
                max=720,
                unit="hours",
                label="Hours of requests considered",
                if_raised=(
                    "Counts callers over a longer stretch, so slowly growing demand for a host can reach the "
                    "thresholds and the rule fires more often."
                ),
                if_lowered="Only hosts requested by many callers in a short time are reported.",
            ),
        ),
    ),
    InsightRuleSpec(
        rule_id="CRED-PROBE-COST",
        family="credential",
        # Its threshold is the ordinary setting `insight_cred_probe_cost_max_per_hour` (15.3 J), not a param.
        title="Roxy's own credential checks are spending the account's call budget",
    ),
    InsightRuleSpec(
        rule_id="SEC-DEFAULTS",
        family="security",
        title="A setting is at a high-risk value",
    ),
)

INSIGHT_RULES: dict[str, InsightRuleSpec] = {rule.rule_id: rule for rule in _RULES}
"""Every recommendation rule from plan 11.5, keyed by rule id, in plan order."""

PARAM_DEFINITIONS: dict[str, str] = {
    # What each threshold measures, keyed "<rule id>.<param name>". The catalog opens each generated setting's
    # description with this sentence (spec review 10: the label alone did not say what is measured, over what
    # window, or whose value it is). A test keeps this dict complete.
    "UP-429-ENDPOINT.min_429s": (
        "How many 429 Too Many Requests answers Roblox must give on one endpoint template within the look-back "
        "window before the rule fires (the share threshold can also fire it on its own)."
    ),
    "UP-429-ENDPOINT.share_pct": (
        "The share of one endpoint template's upstream calls that Roblox answered with 429 within the look-back "
        "window; above it the rule fires even while the count stays below its minimum."
    ),
    "UP-429-ENDPOINT.window_min": "How many minutes of upstream answers the 429 count and share are taken over.",
    "UP-429-ENDPOINT.high_confidence_n": (
        "How many 429s on the endpoint make the resulting recommendation high confidence instead of medium."
    ),
    "UP-429-HOST.min_templates": (
        "How many distinct endpoint templates of one Roblox host must each get a 429 within the look-back window "
        "before the rule blames the host as a whole."
    ),
    "UP-429-HOST.window_min": "How many minutes of upstream answers are searched for a host's endpoints with 429s.",
    "UP-429-CREDENTIAL.min_429s": (
        "How many 429 answers to calls made with the Roblox account (the credential path) fire the rule; 1 means any."
    ),
    "UP-429-AMPLIFY.calls_per_request": (
        "The average number of upstream calls Roxy makes per caller request while Roblox is answering 429; above "
        "it, retries are multiplying the 429s instead of riding them out."
    ),
    "UP-RETRYAFTER-IGNORED.min_retries": (
        "How many times one client asks again for the same cache key before the Retry-After time Roxy gave it has "
        "passed, within the look-back window."
    ),
    "UP-RETRYAFTER-IGNORED.window_min": "How many minutes of one client's early retries are counted together.",
    "UP-4XX-SPIKE.baseline_multiple": (
        "How many times higher than its own 7-day average the 400, 401 and 403 rate of one endpoint template must "
        "be within the window (CSRF challenges excluded)."
    ),
    "UP-4XX-SPIKE.min_responses": (
        "How many 400, 401 or 403 answers the endpoint needs within the window, so a few errors on a quiet "
        "endpoint never count as a spike."
    ),
    "UP-4XX-SPIKE.min_calls": (
        "How many upstream calls the endpoint needs within the window before its rejection rate is judged at all."
    ),
    "UP-4XX-SPIKE.window_min": "How many minutes of upstream answers the rejection rate is measured over.",
    "UP-CSRF-LOOP.retry_pct": (
        "CSRF token retries as a share of the write requests (POST, PATCH, PUT, DELETE) sent upstream within the "
        "window; above it the token handshake is not settling."
    ),
    "UP-CSRF-LOOP.window_min": "How many minutes of write requests the CSRF retry share is measured over.",
    "UP-CHALLENGE.min_pages": (
        "How many Roblox challenge or block pages (a challenge header, or an HTML page where an API answers JSON) "
        "within the look-back window fire the rule."
    ),
    "UP-CHALLENGE.window_min": "How many minutes of upstream answers are searched for challenge pages.",
    "UP-UA-EXPERIMENT.min_calls_per_arm": (
        "How many upstream calls each of the two User-Agent profiles in the experiment needs before the rule names "
        "the one Roblox answers with fewer 429s."
    ),
    "UP-5XX.rate_pct": "The share of upstream calls Roblox answered with a 5xx server error within the window.",
    "UP-5XX.window_min": "How many minutes of upstream calls the 5xx share is measured over.",
    "UP-5XX.min_calls": (
        "How many upstream calls the window needs before its 5xx share is judged, so a few errors in a quiet "
        "hour never count as an outage."
    ),
    "UP-TIMEOUT.rate_pct": (
        "The share of upstream calls that ran out of time (request_timeout) without an answer within the window."
    ),
    "UP-TIMEOUT.window_min": "How many minutes of upstream calls the timeout share is measured over.",
    "UP-LATENCY.p95_ms": (
        "The time within which 95% of the upstream calls in the window got Roblox's answer: only the slowest 5% "
        "took longer than this."
    ),
    "UP-LATENCY.p99_ms": (
        "The time within which 99% of the upstream calls in the window got Roblox's answer. It must stay at or "
        "above the p95 threshold."
    ),
    "UP-LATENCY.window_min": "How many minutes of upstream calls the latency percentiles are computed over.",
    "UP-LATENCY.min_calls": "How many upstream calls the window needs before its latency percentiles are judged.",
    "UP-QUEUE-SAT.drop_pct": (
        "Requests dropped from Roxy's upstream queue (they waited too long for a free upstream slot), as a share of "
        "all requests that needed an upstream call."
    ),
    "UP-QUEUE-SAT.p95_wait_ms": (
        "How long requests waited in Roxy's upstream queue for a free slot: only the slowest 5% waited longer."
    ),
    "UP-BUCKET-TUNE.clean_hours": (
        "How many hours in a row a bucket must go without a Roblox 429 attributed to it before the rule may propose "
        "raising it."
    ),
    "UP-BUCKET-TUNE.rejection_pct": (
        "Attempts a bucket turned away (no token left) as a share of all attempts on it; above it, during a "
        "429-free stretch, real demand is above the bucket's rate."
    ),
    "UP-BUCKET-TUNE.raise_pct": "How much the proposed override raises a too-tight bucket, in percent of its rate.",
    "UP-BUCKET-TUNE.lower_pct": (
        "How much the proposed override cuts a too-loose bucket (one with a 429 attributed to it), in percent of "
        "its rate."
    ),
    "UP-BREAKER-FLAP.openings_per_hour": (
        "How many times the circuit breaker of one key (an endpoint, a host or an egress) opened within one hour."
    ),
    "CACHE-LOW-HIT.top_n": "How many of the busiest endpoints, by caller requests, are checked for a low hit ratio.",
    "CACHE-LOW-HIT.max_hit_ratio_pct": (
        "The share of an endpoint's requests answered from the cache, below which a busy endpoint fires the rule."
    ),
    "CACHE-LOW-HIT.window_min": "How many minutes of requests the hit ratio is measured over.",
    "CACHE-TTL-TUNE.identical_raise_pct": (
        "The share of refetches (an expired cache entry fetched again) that came back with exactly the same body; "
        "at or above it the data rarely changes, and the rule proposes a longer cache time."
    ),
    "CACHE-TTL-TUNE.identical_lower_pct": (
        "The share of identical refetches below which cached answers were usually outdated by the time they "
        "expired, so the rule proposes a shorter cache time. It must stay at or below the longer-cache threshold."
    ),
    "CACHE-TTL-TUNE.min_refetches": (
        "How many refetches of one endpoint are needed within the hours considered before its cache time is judged."
    ),
    "CACHE-TTL-TUNE.window_h": "How many hours of refetch observations the identical shares are computed over.",
    "CACHE-KEYSPLIT.min_entries": (
        "How many cache entries an endpoint needs before its keys are checked for a parameter that splits them."
    ),
    "CACHE-KEYSPLIT.distinct_pct": (
        "How many of the endpoint's entries carry a different value of its most varied query parameter, as a share "
        "of its entries; at or above it that parameter splits the cache (often a cache-busting value)."
    ),
    "CACHE-KEYSPLIT.max_hit_pct": (
        "The endpoint's cache hit ratio at or below which a key-splitting parameter is worth reporting."
    ),
    "CACHE-PRESSURE.young_eviction_pct": (
        "Cache entries evicted before their cache time ran out (because the cache was full), as a share of the "
        "entries stored within the window."
    ),
    "CACHE-PRESSURE.window_min": "How many minutes of cache stores and evictions the share is measured over.",
    "CACHE-NEG.min_404_per_hour": (
        "How many times per hour Roxy fetched the same key from Roblox again only to get the same 404 answer."
    ),
    "HOT-ENDPOINT.top_n": (
        "How many of the endpoints with the most upstream calls are checked for a missing cache rule."
    ),
    "EGR-BURN.projected_pct": (
        "The rotator traffic projected for the end of the current billing cycle at the current pace, as a share "
        "of the cycle's quota."
    ),
    "EGR-UNDERUSE.direct_429_pct": (
        "The share of direct-path calls to one endpoint template that Roblox answered with 429; above it the "
        "rotator could take that template's load."
    ),
    "EGR-UNDERUSE.rotator_429_max_pct": (
        "The highest 429 share the rotator may have on the same templates and still count as healthy enough to "
        "take more of them."
    ),
    "EGR-UNDERUSE.quota_used_max_pct": (
        "The most of the rotator's billing-cycle quota that may already be used for the rule to suggest sending "
        "more traffic through it."
    ),
    "EGR-POOL-BURNED.rotator_429_pct": (
        "The share of rotator calls Roblox answered with 429 within the window, a sign that the provider's exit "
        "addresses are flagged."
    ),
    "EGR-POOL-BURNED.window_min": "How many minutes of rotator calls the 429 share is measured over.",
    "EGR-CALIBRATE.diff_pct": (
        "How far Roxy's own count of rotator traffic may differ from the figure the admin entered from the "
        "provider's dashboard, in percent of the provider's figure."
    ),
    "CRED-UNUSED.min_comparisons": (
        "How many times one allowlisted endpoint must have been answered both anonymously and with the account, "
        "for comparison, before the rule judges whether it needs the account."
    ),
    "CRED-UNUSED.identical_pct": (
        "The share of those comparisons in which the anonymous answer had the same body as the account's; at or "
        "above it the endpoint does not need the account."
    ),
    "ABUSE-BOT.min_requests_per_hour": (
        "How many requests per hour a client whose bot score is above bot_score_abuse_min must send to be reported."
    ),
    "FILTER-ADD.refusals_per_hour": (
        "How many requests from one IP address Roxy refused (limits, filters, bans) within one hour."
    ),
    "FILTER-ADD.hours": "How many hours in a row the client must stay above the refusal threshold.",
    "FILTER-REMOVE.idle_rule_days": (
        "How many days a rule (a block, an endpoint rule, a User-Agent or header filter) may go without matching "
        "any request before it counts as stale."
    ),
    "FILTER-REMOVE.idle_bypass_days": "How many days a bypass entry may go unused before it counts as stale.",
    "FILTER-COLLATERAL.served_pct": (
        "The share of an experience's other requests that Roxy served; at or above it the experience counts as "
        "legitimate, so a rule refusing its requests may be hitting real players."
    ),
    "TARPIT-TUNE.skipped_pct": (
        "Refusals that should have been held by the tarpit but were not, because the fleet-wide hold cap was "
        "full, as a share of all refusals eligible for a hold."
    ),
    "THROTTLE-TUNE.legit_throttled_pct": (
        "Distinct client IP addresses with a bot score below bot_score_legit_max (likely legitimate) that the "
        "per-IP limit throttled at least once in a day, as a share of all such addresses that day."
    ),
    "PLACE-HEAVY.share_pct": "One experience's (place id's) share of all upstream calls within the window.",
    "PLACE-HEAVY.window_min": "How many minutes of upstream calls the share is measured over.",
    "SYS-DISK.budget_pct": "The space Roxy's databases and files use, as a share of storage_total_budget_gb.",
    "SYS-DISK.free_disk_pct": (
        "The free space left on the disk that holds Roxy's state directory, as a share of the disk's size."
    ),
    "SYS-DISK.dims_per_minute": (
        "How many distinct metric rows (combinations of endpoint, status, reason and the other dimensions) the "
        "rollups write per minute; this is what makes metrics.db grow."
    ),
    "SYS-WORKER-SAT.cpu_pct": (
        "CPU use of Roxy's worker processes on the server, as a share of the CPU time they can get, while the "
        "condition lasts."
    ),
    "SYS-WORKER-SAT.window_min": "How many minutes in a row the CPU use must stay above the threshold.",
    "SYS-LOOP-LAG.p99_ms": (
        "How late a worker's event loop ran its scheduled checks: only the slowest 1% of checks were later than "
        "this. Lag means something blocked the loop, so every request in that worker waited."
    ),
    "SYS-LOOP-LAG.window_min": "How many minutes in a row the loop lag must stay above the threshold.",
    "SYS-ERRORS.baseline_multiple": (
        "How many times its usual count for that hour of the day (the 7-day average) a known error signature must "
        "reach within the last hour."
    ),
    "SYS-ERRORS.caller_500_pct": (
        "Answers with status 500 (Roxy's own failures, not Roblox's) as a share of all caller requests within the "
        "window."
    ),
    "SYS-ERRORS.window_min": "How many minutes of caller requests the 500 share is measured over.",
    "SYS-CHANGE-REGRESSION.worse_pct": (
        "How much worse, in percent, the error rate, the 429 rate or the p95 latency must get after a "
        "configuration change, compared with the baseline before it."
    ),
    "SYS-CHANGE-REGRESSION.watch_min": (
        "How many minutes after a configuration change the metrics are compared with the baseline."
    ),
    "SYS-CHANGE-REGRESSION.baseline_h": "How many hours before the change make up the baseline for the comparison.",
    "SEC-ADMIN-ALLOWLIST.max_networks": (
        "The most distinct networks the admin logins may come from for the rule to suggest an admin allowlist of "
        "exactly those networks."
    ),
    "SEC-ADMIN-ALLOWLIST.days": "How many days of admin login history are looked at.",
    "HOST-ADD.min_places": (
        "How many distinct experiences (place ids) must request one roblox.com host that is not on the allowlist, "
        "within the hours considered (the address count can also fire the rule)."
    ),
    "HOST-ADD.min_ips": (
        "How many distinct client IP addresses must request that host within the hours considered (the place count "
        "can also fire the rule)."
    ),
    "HOST-ADD.window_h": "How many hours of requests to unlisted hosts the places and addresses are counted over.",
}
"""What each threshold measures, keyed "<rule id>.<param name>" (read by `catalog.insight_rule_settings`)."""
