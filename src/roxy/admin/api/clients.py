"""The Clients page API (`/admin/api/v1/clients`): places and IPs with rates, refusals, bot score and actions.

What this is
    The routes behind plan 14.1 "Clients" (parity rows 73 and 92):
      * `GET /clients/ips` and `GET /clients/places`: every client in the range with requests, refusals, served
        answers, bytes, Rate1/5/60 (trailing windows, no flapping at :00), the busiest endpoint, when it was last
        seen and its peer count (v1's "Places" of an IP and "IPs" of a place); IPs also carry the bot score and
        whether a ban or bypass entry covers them, places their cached experience name.
      * `GET /clients/ips/{ip}` and `GET /clients/places/{place}`: the per-client page: totals, timeline and busiest
        endpoints for the range, the last hour with its rates, refusals by reason, bans, bypass, strikes and the
        penalty in progress, the bot score with each signal and the recorded fleet score, its peers (the places an
        IP called as, the IPs a place was called from), recent probes and requests.
      * Actions: ban, bypass and a rule for an IP (a deny list entry); ban and a rule for a place (a request filter
        on its `Roblox-Id` header, v1's "Block" button).
      * `POST /clients/lookup` and `POST /clients/places/{place}/lookup`: "Identify an experience" (row 92), the
        place to universe to game details chain through `ctx.upstream` internal calls (paced by the upstream
        buckets at admin priority, never an unbudgeted fallback, row 38), cached 10 minutes per worker.

Why it exists
    v1's "Callers and Top Talkers" kept the 400 busiest IPs and 200 places per worker in memory; v2 reads the client
    activity tables for any range, pages on the server, and puts the actions the owner takes next to the numbers that
    justify them. Every action goes through the same services as the Protection page (audit row, `config_version`).

How it works
    - Tables come from `metrics/queries.py client_table` (sorted and paged there, `last_seen` and `peers` included;
      finding parity-7); a page's IPs then get their bot score: the per-worker tracker of `abuse/bot.py` (probe,
      refusal, timing and cache-busting history) plus the User-Agent of the client's newest live row (kept 15
      minutes). Without a recent request there is no User-Agent; then the score the fleet recorded for the address
      in the last 25 hours answers (`client_score_hour`, written once a minute off the request path by every worker;
      `metrics/read_client_extras.recorded_scores`), labeled `bot_score_source: "recorded"`, else it is `null`
      instead of a guess. Header order is not stored, so that live signal reads as "fits a known client" (0). The
      tracker is this worker's view (`bot_score_scope`).
    - Client pages read `metrics/read_clients.py` (range totals, timeline, busiest endpoints, refusals by reason),
      `metrics/read_client_extras.py` (peers, recorded scores), `metrics/activity.py client_detail` (the last
      hour), the rules snapshot (bans, bypass) and hot.db `strikes`.
    - Place ids are the `Roblox-Id` header (caller text), and so are the places in an IP's peer list: answers name
      such fields in `caller_text`, and a page shows them escaped, never as markup (plan 9.16).
    - Place names in tables come only from the lookup cache (no upstream call per row); a client page offers the
      lookup button instead.

What to read next
    `roxy/metrics/queries.py` (`client_table`), `roxy/metrics/read_clients.py`, `roxy/upstream/internal.py`
    (`PlaceLookup`), then `roxy/admin/api/protection.py` (the same actions in bulk).
"""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Annotated, Any, Final, Literal

from fastapi import Depends, Path, Request
from pydantic import Field

from roxy.abuse.bot import SIGNALS, has_game_server_signature, score
from roxy.abuse.bypass import add_bypass
from roxy.abuse.read_bans import ban_view
from roxy.abuse.throttle import decays_in, effective_strikes, load_strike_rows
from roxy.admin.api.common import (
    AdminSession,
    ApiBody,
    ApiError,
    Column,
    CsrfChecked,
    ExportFormat,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    TimeRange,
    TimeRangeDep,
    actor_for,
    add_caller_text,
    area_router,
    export_pages,
    not_found,
    request_id_of,
    run_mutation,
    service_errors,
    table_answer,
    table_params,
    unavailable,
    validation_error,
)
from roxy.admin.api.protection import audit_reason
from roxy.admin.auth.deps import AdminPrincipal
from roxy.config.constants import MAX_REASON_LENGTH
from roxy.core.client_ip import limit_key
from roxy.core.iphash import ip_hash
from roxy.deps import get_ctx
from roxy.metrics import queries, read_client_extras, read_clients, read_producers, security_events
from roxy.metrics.activity import client_detail
from roxy.rules.service import RuleChange, RulesService
from roxy.upstream.internal import LOOKUP_TTL_S, PlaceLookup, place_lookup_for

router = area_router("clients")

RECENT_WARNING_DAYS: Final = 7
RECENT_WARNING_VISITS: Final = 1000
"""v1 flagged an experience created less than 7 days ago with fewer than 1,000 visits (a throwaway place)."""
MAX_BAN_MINUTES: Final = 365 * 24 * 60
MAX_EXPIRY_HOURS: Final = 24 * 3650.0
RECENT_PROBES: Final = 20
RECENT_REQUESTS: Final = 10
PEER_ROWS: Final = 50
"""Peers listed on a client page (the count of all of them is `peers.total`)."""
SCORE_LOOKBACK_S: Final = 25 * 3600
"""Recorded bot scores of the last 25 hours answer (the same window the recommendation rules read)."""
SCORE_HISTORY_HOURS: Final = 168
"""Most recorded score hours a client page lists (a week of hours)."""
BOT_SCORE_LIVE_NOTE: Final = "this worker's tracker with the client's newest request of the last 15 minutes"
PLACE_PATTERN: Final = r"^[0-9]{1,20}$"
_LOOKUP_KEYS: Final[dict[str, str]] = {
    "Query": "query",
    "Kind": "kind",
    "PlaceId": "place_id",
    "UniverseId": "universe_id",
    "Name": "name",
    "Description": "description",
    "RootPlaceId": "root_place_id",
    "Created": "created",
    "Updated": "updated",
    "Playing": "playing",
    "Visits": "visits",
    "MaxPlayers": "max_players",
    "FavoritedCount": "favorited_count",
    "CreatorId": "creator_id",
    "CreatorName": "creator_name",
    "CreatorType": "creator_type",
    "CreatorVerified": "creator_verified",
    "Url": "url",
    "CreatorUrl": "creator_url",
    "Message": "message",
}


# =============================================================================================== helpers


CachedPlaceLookup = PlaceLookup
"""Kept as a name: `PlaceLookup` itself now has `peek` (a cached answer without any upstream call)."""


def _lookup(request: Request) -> PlaceLookup:
    """This worker's one place lookup (`upstream/internal.py place_lookup_for`), shared with `/lookup/place`."""
    upstream = getattr(get_ctx(request), "upstream", None)
    if upstream is None:
        raise unavailable("The upstream service is not running yet; try again in a moment.")
    return place_lookup_for(upstream)


def _rules(ctx: Any) -> RulesService:
    return RulesService(ctx.dbs.control, clock=ctx.clock, store=ctx.rules)


def _change(change: RuleChange) -> dict[str, Any]:
    return {
        "action": change.action,
        "key": change.key,
        "changed": change.changed,
        "item": change.after,
        "config_version": change.config_version,
        "audit_id": change.audit_id,
    }


def _ip(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        raise validation_error({"ip": "Not an IP address."}) from None


def _snake(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {_LOOKUP_KEYS.get(key, key): value for key, value in payload.items()}


def _recently_created(created: Any, visits: Any, now: float) -> bool:
    """v1's warning: created less than 7 days ago with fewer than 1,000 visits."""
    try:
        when = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
    except ValueError:
        return False
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    try:
        few = int(visits or 0) < RECENT_WARNING_VISITS
    except (TypeError, ValueError):
        return False
    return few and now - when.timestamp() < RECENT_WARNING_DAYS * 86_400


def bot_score_for(ctx: Any, ip: str, live: Mapping[str, Any] | None) -> dict[str, Any]:
    """The bot score of one address (plan 10.7) from this worker's tracker and its newest live row."""
    pipeline = getattr(ctx, "abuse", None)
    if pipeline is None or not live:
        return {
            "score": None,
            "signals": None,
            "note": "No request from this address in the last 15 minutes, so its User-Agent is unknown.",
        }
    settings = ctx.settings
    user_agent = str(live.get("user_agent") or "")
    place = live.get("place")
    cidrs = settings.get("roblox_egress_cidrs") or []
    game = has_game_server_signature(place_id=place, user_agent=user_agent, client_ip=ip, egress_cidrs=list(cidrs))
    key = limit_key(ip, int(settings.get("ipv6_limit_prefix")))
    signals = pipeline.bot.signals(key, now=ctx.clock.now(), user_agent=user_agent, game_server=game, header_names=[])
    weights = {name: float(settings.get(f"bot_weight_{name}")) for name in SIGNALS}
    return {
        "score": score(signals, weights),
        "signals": signals.as_dict(),
        "weights": weights,
        "game_server": game,
        "note": "Header order is not stored, so that signal reads as a known client (0).",
    }


async def _table(
    request: Request,
    admin: AdminPrincipal,
    spec: TableSpec,
    tq: TableQuery,
    fmt: ExportFormat | None,
    tr: TimeRange,
    client_type: str,
) -> Any:
    ctx = get_ctx(request)
    now = ctx.clock.now()
    upstream = getattr(ctx, "upstream", None)
    lookup = place_lookup_for(upstream) if upstream is not None else None

    async def fetch(page: int, size: int) -> tuple[Sequence[Any], int]:
        wanted = queries.Page(page=page, size=size, sort=tq.sort, descending=tq.descending, search=tq.q)
        data = await queries.client_table(ctx.dbs.metrics, tr.window, client_type, now=now, page=wanted, extras=True)
        rows = [dict(row) for row in data["rows"]]
        await _decorate(ctx, client_type, rows, lookup)
        return rows, int(data["total"])

    with service_errors():
        if fmt is not None:
            return await export_pages(request, admin, spec, fetch, fmt, tq=tq, tr=tr)
        items, total = await fetch(tq.page, tq.page_size)
    answer = table_answer(spec, tq, items, total)
    answer["range"] = tr.info()
    answer["peers_basis"] = read_client_extras.PEERS_BASIS
    if client_type == "ip":
        answer["bot_score_scope"] = "this_worker"
        answer["bot_score_sources"] = {"this_worker": BOT_SCORE_LIVE_NOTE, "recorded": read_client_extras.SCORE_BASIS}
        add_caller_text(answer, ["user_agent"])
    else:
        add_caller_text(answer, ["key", "name"])
    return answer


async def _decorate(ctx: Any, client_type: str, rows: list[dict[str, Any]], lookup: PlaceLookup | None) -> None:
    """Bans, bypass, bot scores (IPs) and cached names (places) for one page of client rows."""
    snapshot = ctx.rules.snapshot
    now = ctx.clock.now()
    if client_type == "ip":
        keys = [str(row["key"]) for row in rows]
        since = int(now) - SCORE_LOOKBACK_S

        def read(conn: Any) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
            return read_clients.latest_user_agents(conn, keys), read_client_extras.recorded_scores(conn, keys, since)

        live, recorded = await ctx.dbs.metrics.read(read)
        for row in rows:
            ip = str(row["key"])
            row["banned"] = snapshot.bans.match(ip=ip, place=None, ua_hash=None, now=now) is not None
            row["bypassed"] = snapshot.access.bypass.contains(ip, now)
            row["user_agent"] = (live.get(ip) or {}).get("user_agent")
            score = bot_score_for(ctx, ip, live.get(ip))["score"]
            source: str | None = "this_worker" if score is not None else None
            if score is None and ip in recorded:
                score, source = recorded[ip]["score"], "recorded"
            row["bot_score"] = score
            row["bot_score_source"] = source
        return
    for row in rows:
        place = str(row["key"])
        row["banned"] = snapshot.bans.match(ip=None, place=place, ua_hash=None, now=now) is not None
        cached = lookup.peek(place) if lookup is not None else None
        row["name"] = cached.get("Name") if cached else None


IP_SPEC: Final = TableSpec(
    name="client_ips",
    columns=(
        Column("key", "IP", "The client address as Roxy resolved it behind nginx.", ip=True),
        Column("requests", "Requests", "Requests in the range.", "requests"),
        Column("refused", "Refused", "Requests Roxy refused (limits, filters, bans).", "requests"),
        Column("refused_pct", "Refused %", "Refused share of its requests.", "percent"),
        Column("served", "Served", "Requests answered from Roblox or the cache.", "requests"),
        Column("bytes", "Bytes", "Bytes sent to this client.", "bytes"),
        Column("rate1", "Rate1", "Requests in the trailing 60 seconds.", "requests"),
        Column("rate5", "Rate5", "Requests in the trailing 5 minutes.", "requests"),
        Column("rate60", "Rate60", "Requests in the trailing hour.", "requests"),
        Column(
            "top_endpoint",
            "Top endpoint",
            "The busiest endpoint of its busiest minute.",
            sortable=False,
            caller_text=True,
        ),
        Column(
            "last_seen",
            "Last seen",
            "Its newest request in the range, to the minute (to the hour or day for older, compacted data).",
            "timestamp",
        ),
        Column(
            "peers",
            "Places",
            "Distinct places (Roblox-Id) it called as in the range: one IP behind many places looks like a scraper "
            "cycling ids (a lower bound under a flood, see peers_basis).",
            "count",
            sortable=False,
        ),
        Column(
            "bot_score",
            "Bot score",
            "0 to 100: this worker's view of its last 15 minutes, else the score the fleet recorded in the last 25 "
            "hours (bot_score_source); null when neither exists.",
            sortable=False,
        ),
        Column("bot_score_source", "Score source", "this_worker, recorded, or null.", sortable=False),
        Column("banned", "Banned", "Whether an active ban covers the address.", sortable=False),
        Column("bypassed", "Bypassed", "Whether a bypass entry covers the address.", sortable=False),
    ),
    default_sort="requests",
)
PLACE_SPEC: Final = TableSpec(
    name="client_places",
    columns=(
        Column("key", "Roblox-Id", "The place id callers sent in the Roblox-Id header (a claim).", caller_text=True),
        Column(
            "name",
            "Experience",
            "Its name, when it was looked up in the last 10 minutes.",
            sortable=False,
            caller_text=True,
        ),
        Column("requests", "Requests", "Requests in the range.", "requests"),
        Column("refused", "Refused", "Requests Roxy refused.", "requests"),
        Column("refused_pct", "Refused %", "Refused share of its requests.", "percent"),
        Column("served", "Served", "Requests answered from Roblox or the cache.", "requests"),
        Column("bytes", "Bytes", "Bytes sent for this place.", "bytes"),
        Column("rate1", "Rate1", "Requests in the trailing 60 seconds.", "requests"),
        Column("rate5", "Rate5", "Requests in the trailing 5 minutes.", "requests"),
        Column("rate60", "Rate60", "Requests in the trailing hour.", "requests"),
        Column(
            "top_endpoint",
            "Top endpoint",
            "The busiest endpoint of its busiest minute.",
            sortable=False,
            caller_text=True,
        ),
        Column(
            "last_seen",
            "Last seen",
            "Its newest request in the range, to the minute (to the hour or day for older, compacted data).",
            "timestamp",
        ),
        Column(
            "peers",
            "IPs",
            "Distinct client addresses that sent this place id in the range: one game's servers are many IPs (a "
            "lower bound under a flood, see peers_basis).",
            "count",
            sortable=False,
        ),
        Column("banned", "Banned", "Whether an active place ban covers it.", sortable=False),
    ),
    default_sort="requests",
)


# =============================================================================================== tables


@router.get("/ips")
async def ips_table(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(IP_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Every client address in the range with rates, refusals, bot score, ban and bypass state (row 73)."""
    return await _table(request, admin, IP_SPEC, tq, fmt, tr, "ip")


@router.get("/places")
async def places_table(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(PLACE_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Every place (`Roblox-Id`) in the range with rates and refusals (row 73)."""
    return await _table(request, admin, PLACE_SPEC, tq, fmt, tr, "place")


# =============================================================================================== client pages


async def _strikes(ctx: Any, key: str) -> dict[str, Any]:
    now = int(ctx.clock.now())
    decay = int(ctx.settings.get("throttle_strike_decay_seconds"))
    row = (await ctx.dbs.hot.read(lambda conn: load_strike_rows(conn, [key])))[key]
    return {
        "key": key,
        "strikes": effective_strikes(row.strikes, row.last_strike_at, now, decay) if row.exists else 0,
        "tier": row.tier if row.exists else 0,
        "throttled": row.exists and row.throttled_until > now,
        "penalty_ends_in_s": max(0, row.throttled_until - now) if row.exists else 0,
        "decays_in_s": decays_in(row.strikes, row.last_strike_at, now, decay) if row.exists else 0,
    }


def _ban(snapshot: Any, now: float, **subject: Any) -> dict[str, Any] | None:
    found = snapshot.bans.match(now=now, **subject)
    return None if found is None else ban_view(found.model_dump(), int(now))


@router.get("/ips/{ip}")
async def ip_page(
    request: Request, _admin: AdminSession, tr: TimeRangeDep, ip: Annotated[str, Path(max_length=64)]
) -> dict[str, Any]:
    """One address: range totals and timeline, the last hour, refusals, bans, bypass, strikes, bot score, probes."""
    ctx = get_ctx(request)
    address = _ip(ip)
    now = ctx.clock.now()
    start_ms, end_ms = tr.window.start * 1000, tr.window.end * 1000
    key_bytes = getattr(ctx.recorder, "ip_hash_key", None) or getattr(ctx, "ip_hash_key", None)
    hashed = ip_hash(address, key_bytes) if key_bytes else None
    since = int(now) - SCORE_LOOKBACK_S

    def read(conn: Any) -> dict[str, Any]:
        pieces = read_clients.client_pieces(conn, tr.window)
        return {
            "range": read_clients.client_range(conn, "ip", address, tr.window),
            "last_hour": client_detail(conn, "ip", address, now),
            "refusals": read_clients.client_refusals(conn, start_ms=start_ms, end_ms=end_ms, ip_hash=hashed)
            if hashed
            else [],
            "live": read_clients.recent_live(conn, ip=address, limit=RECENT_REQUESTS),
            "probes": security_events.ring(
                conn, security_events.PROBE, since_ms=start_ms, until_ms=end_ms, ip=address, limit=RECENT_PROBES
            ),
            "peers": read_client_extras.peer_list(conn, "ip", address, pieces, limit=PEER_ROWS),
            "recorded": read_client_extras.recorded_scores(conn, [address], since).get(address),
            "history": read_producers.client_score_history(conn, address, tr.window.start, limit=SCORE_HISTORY_HOURS),
        }

    with service_errors():
        data = await ctx.dbs.metrics.read(read)
        snapshot = ctx.rules.snapshot
        key = limit_key(address, int(ctx.settings.get("ipv6_limit_prefix")))
        strikes = await _strikes(ctx, key)
    last_hour = dict(data["last_hour"])
    last_hour.pop("minutes", None)
    live = data["live"]
    return {
        "kind": "ip",
        "key": address,
        "limit_key": key,
        "range": tr.info(),
        "totals": {k: v for k, v in data["range"].items() if k not in ("timeline", "top_endpoints")},
        "timeline": data["range"]["timeline"],
        "top_endpoints": data["range"]["top_endpoints"],
        "top_endpoints_basis": data["range"]["top_endpoints_basis"],
        "last_hour": last_hour,
        "refusals": data["refusals"],
        "refusals_note": None if hashed else "Refusal events are matched by a keyed hash; ip_hash_key is not set.",
        "ban": _ban(snapshot, now, ip=address),
        "bypassed": snapshot.access.bypass.contains(address, now),
        "denied": snapshot.access.deny.contains(address, now),
        "strikes": strikes,
        "bot_score": {
            **bot_score_for(ctx, address, live[0] if live else None),
            "scope": "this_worker",
            # The fleet's recorded score (lane_producers request 6): the latest scored hour of the last 25 hours,
            # and the hours of the range (oldest first), from every worker.
            "recorded": data["recorded"],
            "recorded_basis": read_client_extras.SCORE_BASIS,
            "recorded_history": data["history"],
        },
        "peers": data["peers"],
        "recent_probes": data["probes"]["items"],
        "recent_requests": live,
        "caller_text": ["peers.items.key", "recent_requests"],
    }


@router.get("/places/{place}")
async def place_page(
    request: Request, _admin: AdminSession, tr: TimeRangeDep, place: Annotated[str, Path(pattern=PLACE_PATTERN)]
) -> dict[str, Any]:
    """One place: range totals and timeline, the last hour, refusals, ban state and the cached lookup."""
    ctx = get_ctx(request)
    now = ctx.clock.now()
    start_ms, end_ms = tr.window.start * 1000, tr.window.end * 1000

    def read(conn: Any) -> dict[str, Any]:
        pieces = read_clients.client_pieces(conn, tr.window)
        return {
            "range": read_clients.client_range(conn, "place", place, tr.window),
            "last_hour": client_detail(conn, "place", place, now),
            "refusals": read_clients.client_refusals(conn, start_ms=start_ms, end_ms=end_ms, place=place),
            "live": read_clients.recent_live(conn, place=place, limit=RECENT_REQUESTS),
            "peers": read_client_extras.peer_list(conn, "place", place, pieces, limit=PEER_ROWS),
        }

    with service_errors():
        data = await ctx.dbs.metrics.read(read)
    cached = _lookup(request).peek(place) if getattr(ctx, "upstream", None) is not None else None
    last_hour = dict(data["last_hour"])
    last_hour.pop("minutes", None)
    return {
        "kind": "place",
        "key": place,
        "range": tr.info(),
        "totals": {k: v for k, v in data["range"].items() if k not in ("timeline", "top_endpoints")},
        "timeline": data["range"]["timeline"],
        "top_endpoints": data["range"]["top_endpoints"],
        "top_endpoints_basis": data["range"]["top_endpoints_basis"],
        "last_hour": last_hour,
        "refusals": data["refusals"],
        "ban": _ban(ctx.rules.snapshot, now, place=place),
        "lookup": _snake(cached) if cached else None,
        "peers": data["peers"],
        "recent_requests": data["live"],
        "caller_text": ["lookup", "recent_requests"],
    }


# =============================================================================================== actions


class BanBody(ApiBody):
    """Ban this client: `minutes` for a temporary ban, or `permanent: true`."""

    minutes: int | None = Field(None, ge=1, le=MAX_BAN_MINUTES)
    permanent: bool = False
    message: str = Field("", max_length=MAX_REASON_LENGTH)
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class BypassBody(ApiBody):
    """Bypass this address (`bypass_default_expiry_h` unless `expires_in_h`; `never` needs `confirm_never`)."""

    expires_in_h: float | None = Field(None, gt=0, le=MAX_EXPIRY_HOURS, allow_inf_nan=False)
    never: bool = False
    confirm_never: bool = False
    note: str = Field("", max_length=MAX_REASON_LENGTH)
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class RuleBody(ApiBody):
    """An IP's rule is a deny list entry; a place's rule is a request filter on its `Roblox-Id` header."""

    expires_in_h: float | None = Field(None, gt=0, le=MAX_EXPIRY_HOURS, allow_inf_nan=False)
    note: str = Field("", max_length=MAX_REASON_LENGTH)
    message: str = Field("", max_length=MAX_REASON_LENGTH)
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


async def _ban_action(
    request: Request, admin: AdminPrincipal, subject_type: str, subject: str, body: BanBody
) -> dict[str, Any]:
    ctx = get_ctx(request)
    if body.permanent == (body.minutes is not None):
        raise validation_error({"minutes": "Give the ban length in minutes, or set permanent (not both)."})
    expires_at = None if body.permanent else int(ctx.clock.now()) + int(body.minutes or 0) * 60
    row = {
        "subject_type": subject_type,
        "subject": subject,
        "reason_code": "admin",
        "reason_text": body.message,
        "expires_at": expires_at,
    }
    change = await run_mutation(
        _rules(ctx).create("bans", row, actor_for(admin), audit_reason(body.reason), request_id=request_id_of(request))
    )
    answer = _change(change)
    answer["ban"] = ban_view(change.after, int(ctx.clock.now())) if change.after else None
    answer["extended_existing"] = change.action == "update"
    return answer


@router.post("/ips/{ip}/ban")
async def ip_ban(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, ip: Annotated[str, Path(max_length=64)], body: BanBody
) -> dict[str, Any]:
    """Ban this address."""
    return await _ban_action(request, admin, "ip", _ip(ip), body)


@router.post("/places/{place}/ban")
async def place_ban(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    place: Annotated[str, Path(pattern=PLACE_PATTERN)],
    body: BanBody,
) -> dict[str, Any]:
    """Ban this place id (callers sending it in `Roblox-Id` are refused; place ids are claims, so this is manual)."""
    return await _ban_action(request, admin, "place", place, body)


@router.post("/ips/{ip}/bypass")
async def ip_bypass(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    ip: Annotated[str, Path(max_length=64)],
    body: BypassBody,
) -> dict[str, Any]:
    """Bypass this address (v1 "Bypass" button on Top Talkers), with the default expiry."""
    ctx = get_ctx(request)
    change = await run_mutation(
        add_bypass(
            _rules(ctx),
            _ip(ip),
            actor_for(admin),
            now=ctx.clock.now(),
            default_expiry_h=float(ctx.settings.get("bypass_default_expiry_h")),
            expires_in_h=body.expires_in_h,
            never=body.never,
            confirm_never=body.confirm_never,
            note=body.note or "Added from Clients",
            reason=audit_reason(body.reason),
            request_id=request_id_of(request),
        )
    )
    return _change(change)


@router.post("/ips/{ip}/rule")
async def ip_rule(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    ip: Annotated[str, Path(max_length=64)],
    body: RuleBody,
) -> dict[str, Any]:
    """Add this address to the deny list (refused before any limit, like a ban without hit counts)."""
    ctx = get_ctx(request)
    expires_at = None if body.expires_in_h is None else int(ctx.clock.now() + body.expires_in_h * 3600)
    row = {"kind": "deny", "cidr": _ip(ip), "note": body.note or "Added from Clients", "expires_at": expires_at}
    change = await run_mutation(
        _rules(ctx).create(
            "access_list", row, actor_for(admin), audit_reason(body.reason), request_id=request_id_of(request)
        )
    )
    return _change(change)


@router.post("/places/{place}/rule")
async def place_rule(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    place: Annotated[str, Path(pattern=PLACE_PATTERN)],
    body: RuleBody,
) -> dict[str, Any]:
    """A request filter on `Roblox-Id: <place>` (exact; v1's "Block" button). Empty message: a disguised 429."""
    ctx = get_ctx(request)
    if body.expires_in_h is not None:
        raise validation_error({"expires_in_h": "Request filters do not expire; remove the rule instead."})
    note = body.note or f"Blocked from Clients on {time.strftime('%Y-%m-%d', time.gmtime(ctx.clock.now()))}"
    row = {
        "header": "Roblox-Id",
        "scope": "value",
        "mode": "exact",
        "needle": place,
        "note": note,
        "message": body.message,
    }
    change = await run_mutation(
        _rules(ctx).create(
            "rules_header", row, actor_for(admin), audit_reason(body.reason), request_id=request_id_of(request)
        )
    )
    return _change(change)


# =============================================================================================== lookup


class LookupBody(ApiBody):
    """`id`: digits only; `kind`: a place id or a universe id."""

    id: str = Field(min_length=1, max_length=20)
    kind: Literal["place", "universe"] = "place"


async def _run_lookup(request: Request, raw_id: str, kind: str) -> dict[str, Any]:
    ctx = get_ctx(request)
    result = await _lookup(request).lookup(raw_id, kind)
    payload = _snake(result.payload)
    message = str(payload.pop("message", "") or "")
    if result.http_status == 400:
        raise validation_error({"id": message or "Enter a numeric place or universe ID."})
    if result.http_status == 404:
        raise not_found(message or "Roblox returned no experience for that ID.")
    if result.http_status != 200:
        raise ApiError(502, "upstream_failed", message or "Roblox could not be reached for this lookup.")
    payload["recently_created_warning"] = _recently_created(
        payload.get("created"), payload.get("visits"), ctx.clock.now()
    )
    return {"result": payload, "cached": result.cached, "cache_ttl_s": int(LOOKUP_TTL_S)}


@router.post("/lookup")
async def lookup(request: Request, _admin: AdminSession, _csrf: CsrfChecked, body: LookupBody) -> dict[str, Any]:
    """Identify an experience (row 92): place or universe id to name, owner, links and numbers."""
    return await _run_lookup(request, body.id, body.kind)


@router.post("/places/{place}/lookup")
async def place_lookup(
    request: Request, _admin: AdminSession, _csrf: CsrfChecked, place: Annotated[str, Path(pattern=PLACE_PATTERN)]
) -> dict[str, Any]:
    """Identify the experience behind this place id (v1 "Identify" button on Callers)."""
    return await _run_lookup(request, place, "place")


__all__ = ["CachedPlaceLookup", "bot_score_for", "router"]
