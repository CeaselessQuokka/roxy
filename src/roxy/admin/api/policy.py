"""Endpoint policy API (`/admin/api/v1/policy`): which Roblox endpoints callers may use, and with which account.

What this is
    The admin side of the endpoint policy (D1 revised 2026-10-16, `docs/endpoint_policy/BRIEF.md` section 8):
      * `GET /policy`: the summary (effective verdict counts, overrides, category switches, the three
        `endpoint_policy_*` settings, refusals, unknown endpoints and sign-in attempts in the last 24 hours, and the
        old credential allowlist rows with what the policy does for each now).
      * `GET /policy/categories` and `PUT /policy/categories/{category}`: the category switches.
      * `GET /policy/endpoints`: every documented Roblox operation with its default and effective verdict, filters
        (host, category, verdict, risk, method, Roblox sign-in kind, changed), search, and the two links to Roblox's
        documentation. `GET /policy/endpoints/detail?id=` is one row.
      * `PUT /policy/endpoints`: set the verdict of one or more operations (an override); `DELETE /policy/endpoints`
        puts them back to their default. `POST /policy/reset` removes every override and switch.
      * `GET /policy/test?target=&method=`: what the policy does with one request, step by step.
      * `GET /policy/unknown`, `/policy/attempts`, `/policy/would-block`: what callers asked for that Roblox does not
        document, who sent their own sign-in, and what shadow mode would have refused (time range).

Why it exists
    The owner wants to add or remove whole categories or single endpoints with sensible defaults and a link to
    Roblox's own documentation for each (2026-10-16). Loosening (anything that sends more to Roblox, or sends the
    account where it was not sent) needs a fresh second factor and a reason, like adding a credential allowlist row
    did; tightening needs the session and CSRF only, so it is never slowed down in an emergency (plan 9.6). Loosening
    a risk 4 operation (session, money, irreversible) also needs `confirm` equal to its path.

How it works
    Overrides and switches are rows of `endpoint_policy_override` and `endpoint_policy_category` written through
    `rules/service.py` (audit row and `config_version` bump in one transaction; every worker reloads within a
    second). Effective verdicts come from the rules snapshot's `EndpointPolicy`, the same object the proxy uses
    (plan P6: the same function, the same answer). Event counts come from the metrics database's per-minute
    counter events (`policy_blocked`, `policy_unknown`, `policy_would_block`) and the `auth_attempt` log.

What to read next
    `roxy/policy/engine.py`, `roxy/rules/models.py` (`EndpointPolicyOverrideIn`), `roxy/admin/pages/policy.py`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from typing import Annotated, Any, Final, Literal

from fastapi import Depends, Query, Request
from pydantic import Field, StrictBool

from roxy.abuse.checks.endpoint_policy import POLICY_BLOCKED_EVENT, POLICY_UNKNOWN_EVENT, POLICY_WOULD_BLOCK_EVENT
from roxy.admin.api import common
from roxy.admin.api.common import (
    AdminSession,
    ApiBody,
    Column,
    CsrfChecked,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    TimeRange,
    TimeRangeDep,
    table_params,
)
from roxy.admin.api.routing_rules import MAX_TARGET_CHARS, Note, Reason, rules_service
from roxy.admin.auth.deps import AdminPrincipal
from roxy.deps import get_ctx
from roxy.metrics import security_events
from roxy.metrics.read_protection import event_counts
from roxy.policy.engine import CREDENTIAL_METHODS, EndpointPolicy, PolicyDecision, unknown_id
from roxy.policy.seed import CATEGORIES, CATEGORY_STATES, LOOSENING, VERDICT_LABELS, SeedRow, Verdict
from roxy.rules.service import RulesService

router = common.area_router("policy")

OVERRIDES: Final = "endpoint_policy_override"
SWITCHES: Final = "endpoint_policy_category"
DAY_MS: Final = 86_400_000
MAX_BULK: Final = 200
STATE_STRICTNESS: Final[Mapping[str, int]] = {"defaults": 0, "strip_credential": 1, "block_all": 2}
LOOSEN_NOTE: Final = (
    "Loosening (sending more to Roblox, or sending Roxy's account where it was not sent) needs a fresh second factor "
    "and a reason. Tightening needs neither a fresh factor nor a wait."
)
STATE_WORDS: Final[Mapping[str, str]] = {
    "defaults": "Each endpoint's own default",
    "block_all": "Block every endpoint in this category",
    "strip_credential": "Send every allowed endpoint in this category without Roxy's account",
}
AUTH_WORDS: Final[Mapping[str, str]] = {
    "cookie-required": "Only answers signed-in users",
    "cookie-optional": "Answers anyone; a sign-in changes the answer",
    "none": "No sign-in listed",
    "apikey/oauth-only": "Open Cloud API key or OAuth only",
}

ENDPOINT_SPEC: Final = TableSpec(
    name="endpoint_policy",
    columns=(
        Column("method", "Method", "The HTTP method."),
        Column("host", "Host", "The Roblox host."),
        Column("path", "Path", "The path template from Roblox's reference.", caller_text=True),
        Column("summary", "What Roblox says it does", "Roblox's own summary of the operation.", sortable=False),
        Column("verdict", "Verdict", "What Roxy does with it now (overrides and switches applied)."),
        Column("default_verdict", "Default", "What Roxy ships with."),
        Column("risk", "Risk", "1 harmless to 4 critical: what a stranger could do with Roxy's account through it."),
        Column("category", "Category", "The toggle group it belongs to."),
        Column("roblox_auth", "Roblox sign-in", "What Roblox's reference says the endpoint accepts."),
        Column("refused_24h", "Refused (24 h)", "Caller requests Roxy refused for it in the last 24 hours.", "count"),
    ),
    default_sort="host",
    default_order="asc",
    extra_sort_keys=("id",),
)
UNKNOWN_SPEC: Final = TableSpec(
    name="endpoint_policy_unknown",
    columns=(
        Column("endpoint_id", "Endpoint", "The operation, as unknown:<METHOD>:<template>.", caller_text=True),
        Column("verdict", "Verdict given", "What Roxy did with it (unreviewed reads go without the account)."),
        Column("count", "Requests", "Requests in the range.", "count"),
        Column("last_ms", "Last seen", "The latest one.", "timestamp_ms"),
    ),
    default_sort="count",
)
WOULD_BLOCK_SPEC: Final = TableSpec(
    name="endpoint_policy_would_block",
    columns=(
        Column("endpoint_id", "Endpoint", "The operation the policy would refuse.", caller_text=True),
        Column("count", "Requests", "Requests in the range that shadow mode let through.", "count"),
        Column("last_ms", "Last seen", "The latest one.", "timestamp_ms"),
    ),
    default_sort="count",
)
ATTEMPT_SPEC: Final = TableSpec(
    name="auth_attempts",
    columns=(
        Column("at_ms", "When", "When it arrived (newest first).", "timestamp_ms"),
        Column("ip", "IP", "Who sent it.", ip=True, sortable=False),
        Column("kind", "What", "roblosecurity (a Roblox cookie), api_key, bearer or x_roblox_token.", sortable=False),
        Column("where", "Where", "header, cookie, query or body.", sortable=False),
        Column("name", "Name", "The header, cookie or parameter name.", sortable=False, caller_text=True),
        Column("looks_real", "Looks real", "The value had the warning prefix and a real cookie's length.",
               sortable=False),
        Column("fingerprint", "Fingerprint", "A keyed hash: the same secret sent twice has the same one.",
               sortable=False),
        Column("endpoint", "Endpoint", "The operation the request was for.", sortable=False, caller_text=True),
        Column("user_agent", "User-Agent", "Its User-Agent.", sortable=False, caller_text=True),
        Column("count", "Count", "1, or the attempts folded into this row over the event budget.", "count",
               sortable=False),
    ),
    default_sort="at_ms",
)  # fmt: skip

VerdictName = Literal["BLOCK", "ALLOW_TOKEN", "ALLOW_ANON"]
EndpointId = Annotated[str, Field(min_length=3, max_length=500)]
StateName = Literal["defaults", "block_all", "strip_credential"]


class OverrideBody(ApiBody):
    """`PUT /policy/endpoints`: one operation (`endpoint_id`) or several (`endpoint_ids`) to one verdict."""

    endpoint_id: EndpointId | None = None
    endpoint_ids: Annotated[list[EndpointId], Field(max_length=MAX_BULK)] | None = None
    verdict: VerdictName
    cache_private: StrictBool = False
    note: Note = ""
    reason: Reason
    confirm: Annotated[str, Field(max_length=600)] = ""


class ResetBody(ApiBody):
    """`DELETE /policy/endpoints` (back to defaults) and `POST /policy/reset`."""

    endpoint_id: EndpointId | None = None
    endpoint_ids: Annotated[list[EndpointId], Field(max_length=MAX_BULK)] | None = None
    reason: Reason = ""


class CategoryBody(ApiBody):
    """`PUT /policy/categories/{category}`."""

    state: StateName
    note: Note = ""
    reason: Reason


# ---------------------------------------------------------------------------------------------- shared helpers


def _policy(ctx: Any) -> EndpointPolicy:
    policy: EndpointPolicy = ctx.rules.snapshot.endpoint_policy
    return policy


def _service(request: Request) -> RulesService:
    return rules_service(request)


def effective(policy: EndpointPolicy, row: SeedRow) -> Verdict:
    """The verdict a seed row has now: its override, else its default with the category switch applied."""
    return policy.effective(row)


def _ids(body: OverrideBody | ResetBody) -> list[str]:
    ids = list(body.endpoint_ids or ())
    if body.endpoint_id:
        ids.insert(0, body.endpoint_id)
    unique = list(dict.fromkeys(i.strip() for i in ids if i.strip()))
    if not unique:
        raise common.validation_error({"endpoint_id": "Name at least one endpoint."})
    return unique


def _current(policy: EndpointPolicy, endpoint_id: str) -> tuple[Verdict, Verdict, SeedRow | None]:
    """(effective now, default without override, the seed row) of a seed id or an `unknown:` id."""
    row = policy.seed.by_id.get(endpoint_id)
    if row is not None:
        return effective(policy, row), policy.default_for(row), row
    if not endpoint_id.startswith("unknown:"):
        raise common.validation_error({"endpoint_id": f"No Roblox endpoint has the id {endpoint_id[:120]}."})
    _, method, template = endpoint_id.split(":", 2)
    host, _, rest = template.partition("/")
    plain = policy.decide(host, method, "/" + rest, template=template)
    default = plain.default_verdict or plain.verdict
    override = policy.overrides.get(endpoint_id)
    return (override.verdict if override is not None else default), default, None


async def _require_fresh(request: Request) -> None:
    await common.admin_fresh_mfa(request)


def item_of(policy: EndpointPolicy, row: SeedRow, refused: Mapping[str, int] | None = None) -> dict[str, Any]:
    """One operation as the API shows it."""
    override = policy.overrides.get(row.id)
    verdict = effective(policy, row)
    return {
        "id": row.id,
        "method": row.method,
        "host": row.host,
        "path": row.path,
        "summary": row.summary,
        "roblox_auth": row.roblox_auth,
        "roblox_auth_words": AUTH_WORDS.get(row.roblox_auth, row.roblox_auth),
        "requires_login": row.requires_login,
        "verdict": verdict.value,
        "verdict_words": VERDICT_LABELS[verdict],
        "default_verdict": row.verdict.value,
        "changed": verdict is not row.verdict,
        "source": "override" if override is not None else ("category" if verdict is not row.verdict else "default"),
        "override_note": override.note if override is not None else "",
        "cache_private": bool(override.cache_private) if override is not None else False,
        "category": row.category,
        "category_label": CATEGORIES[row.category].label,
        "risk": row.risk,
        "rationale": row.rationale,
        "notes": row.notes,
        "deprecated": row.deprecated,
        "feature_doc": row.feature_doc,
        "domain_doc": row.domain_doc,
        "refused_24h": int((refused or {}).get(row.id, 0)),
    }


async def _event_counts(ctx: Any, event_type: str, start_ms: int, end_ms: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = await ctx.dbs.metrics.read(
        lambda conn: event_counts(conn, event_type, start_ms, end_ms, keys=("endpoint_id", "verdict"))
    )
    return rows


async def refused_by_endpoint(ctx: Any, now_ms: int) -> dict[str, int]:
    """Refusals per operation in the last 24 hours (`policy_blocked` counter events)."""
    with common.service_errors():
        rows = await _event_counts(ctx, POLICY_BLOCKED_EVENT, now_ms - DAY_MS, now_ms + 1)
    out: dict[str, int] = {}
    for row in rows:
        key = str(row.get("endpoint_id") or "")
        out[key] = out.get(key, 0) + int(row.get("count") or 0)
    return out


def _now_ms(ctx: Any) -> int:
    return int(ctx.clock.now() * 1000)


def _whole(tq: TableQuery, rows: Sequence[Any]) -> TableQuery:
    """`tq` on one page holding every row: a download is the whole filtered table, never the page on screen."""
    return replace(tq, page=1, page_size=max(1, len(rows)))


# ---------------------------------------------------------------------------------------------- summary


@router.get("")
async def summary(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The Summary card: counts, switches, settings, the last 24 hours, and the old allowlist rows."""
    return await summary_answer(get_ctx(request))


async def summary_answer(ctx: Any) -> dict[str, Any]:
    """The answer of `GET /policy` (the page's Summary card renders the same)."""
    policy = _policy(ctx)
    now_ms = _now_ms(ctx)
    start = now_ms - DAY_MS
    with common.service_errors():
        refused = await _event_counts(ctx, POLICY_BLOCKED_EVENT, start, now_ms + 1)
        unknown = await _event_counts(ctx, POLICY_UNKNOWN_EVENT, start, now_ms + 1)
        would = await _event_counts(ctx, POLICY_WOULD_BLOCK_EVENT, start, now_ms + 1)
        attempts = await ctx.dbs.metrics.read(
            lambda conn: security_events.ring(conn, security_events.AUTH_ATTEMPT, since_ms=start, limit=1)
        )
    seed = policy.seed
    settings = ctx.settings
    return {
        "seed": {
            "operations": len(seed.rows),
            "hosts": len({row.host for row in seed.rows}),
            "generated_on": seed.generated_on,
            "source_commit": seed.source_commit[:12],
        },
        **policy.summary(),
        "settings": {
            "endpoint_policy_enforce": bool(settings.int("endpoint_policy_enforce")),
            "endpoint_policy_block_status": str(settings.get("endpoint_policy_block_status")),
            "endpoint_policy_block_message": str(settings.get("endpoint_policy_block_message")),
            "credential_enabled": bool(settings.int("credential_enabled")),
            "credential_bucket_per_min": settings.int("credential_bucket_per_min"),
        },
        "last_24h": {
            "refused": sum(int(r.get("count") or 0) for r in refused),
            "unknown_requests": sum(int(r.get("count") or 0) for r in unknown),
            "unknown_endpoints": len({r.get("endpoint_id") for r in unknown}),
            "would_block": sum(int(r.get("count") or 0) for r in would),
            "auth_attempts": int(attempts.get("total") or 0),
        },
        "legacy_allowlist": await legacy_allowlist(ctx, policy),
        "help": {"loosen": LOOSEN_NOTE},
    }


async def legacy_allowlist(ctx: Any, policy: EndpointPolicy) -> list[dict[str, Any]]:
    """The old `credential_allowlist` rows (no longer read) and what the policy does with each pattern now."""
    from roxy.admin.api.routing_rules import service_for

    try:
        rows = await service_for(ctx).list_rows("credential_allowlist")
    except Exception:  # the table is informational only here; a read failure must not break the summary
        return []
    out = []
    for row in rows[:50]:
        pattern = str(row.get("pattern") or "")
        host, _, rest = pattern.partition("/")
        decision = policy.decide(host, "GET", "/" + rest) if host.endswith("roblox.com") else None
        out.append(
            {
                "pattern": pattern,
                "enabled": bool(row.get("enabled")),
                "verdict": decision.verdict.value if decision is not None else None,
                "endpoint_id": decision.endpoint_id if decision is not None else None,
            }
        )
    return out


# ---------------------------------------------------------------------------------------------- categories


@router.get("/categories")
async def categories(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Every category with its switch, counts and highest risk."""
    return categories_answer(get_ctx(request))


def categories_answer(ctx: Any) -> dict[str, Any]:
    policy = _policy(ctx)
    items = []
    for key, category in CATEGORIES.items():
        rows = [row for row in policy.seed.rows if row.category == key]
        counts = {verdict.value: 0 for verdict in Verdict}
        defaults = {verdict.value: 0 for verdict in Verdict}
        for row in rows:
            counts[effective(policy, row).value] += 1
            defaults[row.verdict.value] += 1
        state = policy.category_state(key)
        items.append(
            {
                "key": key,
                "label": category.label,
                "description": category.description,
                "state": state,
                "state_words": STATE_WORDS[state],
                "operations": len(rows),
                "verdicts": counts,
                "default_verdicts": defaults,
                "max_risk": max((row.risk for row in rows), default=0),
                "states": [s for s in CATEGORY_STATES if s != "strip_credential" or defaults["ALLOW_TOKEN"]],
            }
        )
    return {"items": items, "help": {"loosen": LOOSEN_NOTE, "states": dict(STATE_WORDS)}}


@router.put("/categories/{category}")
async def set_category(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, category: str, body: CategoryBody
) -> dict[str, Any]:
    """Set one category's switch. Making it less strict needs a fresh second factor (module docstring)."""
    key = category.strip().lower()
    if key not in CATEGORIES:
        raise common.not_found("No category has that name.")
    reason = common.require_reason(body.reason, required=True)
    ctx = get_ctx(request)
    current = _policy(ctx).category_state(key)
    if STATE_STRICTNESS[body.state] < STATE_STRICTNESS[current]:
        await _require_fresh(request)
    service = _service(request)
    actor = common.actor_for(admin)
    rid = common.request_id_of(request)
    if body.state == "defaults":
        if current != "defaults":
            await common.run_mutation(service.delete(SWITCHES, key, actor, reason, request_id=rid))
    else:
        row = {"category": key, "state": body.state, "note": body.note}
        await common.run_mutation(service.upsert(SWITCHES, row, actor, reason, request_id=rid))
    return categories_answer(ctx)


# ---------------------------------------------------------------------------------------------- endpoints


def _matches(
    item: Mapping[str, Any],
    *,
    host: str | None,
    category: str | None,
    verdict: str | None,
    risk: int | None,
    method: str | None,
    auth: str | None,
    changed: bool | None,
) -> bool:
    return (
        (not host or item["host"] == host)
        and (not category or item["category"] == category)
        and (not verdict or item["verdict"] == verdict)
        and (risk is None or item["risk"] == risk)
        and (not method or item["method"] == method)
        and (not auth or item["roblox_auth"] == auth)
        and (changed is None or item["changed"] is changed)
    )


@router.get("/endpoints")
async def endpoints(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(ENDPOINT_SPEC))],
    fmt: ExportFormatDep,
    host: Annotated[str | None, Query(max_length=100)] = None,
    category: Annotated[str | None, Query(max_length=64)] = None,
    verdict: Annotated[VerdictName | None, Query()] = None,
    risk: Annotated[int | None, Query(ge=1, le=4)] = None,
    method: Annotated[str | None, Query(max_length=8)] = None,
    auth: Annotated[str | None, Query(max_length=32)] = None,
    changed: Annotated[bool | None, Query()] = None,
) -> Any:
    """Every documented operation, filtered, searched (path, summary, id) and paged."""
    ctx = get_ctx(request)
    items = await endpoint_items(
        ctx, host=host, category=category, verdict=verdict, risk=risk, method=method, auth=auth, changed=changed
    )
    if fmt is not None:
        everything, total = common.page_rows(items, _whole(tq, items), search_keys=SEARCH_KEYS)
        return await common.export_table(request, admin, ENDPOINT_SPEC, everything, fmt, total=total, tq=tq)
    page, total = common.page_rows(items, tq, search_keys=SEARCH_KEYS)
    answer = common.table_answer(ENDPOINT_SPEC, tq, page, total)
    answer["filters"] = {
        "hosts": sorted({row.host for row in _policy(ctx).seed.rows}),
        "categories": [{"key": k, "label": c.label} for k, c in CATEGORIES.items()],
        "verdicts": [{"key": v.value, "label": VERDICT_LABELS[v]} for v in Verdict],
        "auth": [{"key": k, "label": w} for k, w in AUTH_WORDS.items()],
    }
    return answer


SEARCH_KEYS: Final = ("id", "path", "summary", "host", "rationale")


async def endpoint_items(
    ctx: Any,
    *,
    host: str | None = None,
    category: str | None = None,
    verdict: str | None = None,
    risk: int | None = None,
    method: str | None = None,
    auth: str | None = None,
    changed: bool | None = None,
) -> list[dict[str, Any]]:
    """Every operation as `item_of` shows it, with the filters applied (the page's table reads this too)."""
    policy = _policy(ctx)
    refused = await refused_by_endpoint(ctx, _now_ms(ctx))
    items = [item_of(policy, row, refused) for row in policy.seed.rows]
    host_key = (host or "").strip().lower() or None
    category_key = (category or "").strip().lower() or None
    method_key = (method or "").strip().upper() or None
    auth_key = (auth or "").strip() or None
    return [
        item
        for item in items
        if _matches(
            item,
            host=host_key,
            category=category_key,
            verdict=verdict,
            risk=risk,
            method=method_key,
            auth=auth_key,
            changed=changed,
        )
    ]


@router.get("/endpoints/detail")
async def endpoint_detail(
    request: Request, _admin: AdminSession, endpoint_id: Annotated[str, Query(alias="id", max_length=500)]
) -> dict[str, Any]:
    """One operation with everything the drawer shows."""
    ctx = get_ctx(request)
    policy = _policy(ctx)
    row = policy.seed.by_id.get(endpoint_id)
    if row is None:
        raise common.not_found("No Roblox endpoint has that id.")
    refused = await refused_by_endpoint(ctx, _now_ms(ctx))
    return item_of(policy, row, refused) | {"help": {"loosen": LOOSEN_NOTE}}


@router.put("/endpoints")
async def set_endpoints(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: OverrideBody
) -> dict[str, Any]:
    """Set the verdict of one or more operations. Loosening needs a fresh second factor; a risk 4 one also needs
    `confirm` equal to its path (one at a time)."""
    reason = common.require_reason(body.reason, required=True)
    ctx = get_ctx(request)
    policy = _policy(ctx)
    ids = _ids(body)
    wanted = Verdict(body.verdict)
    if wanted is Verdict.ALLOW_TOKEN:
        # Refused before any second factor or typed path is asked for: the model refuses it anyway.
        writes = [i for i in ids if i.count(":") >= 2 and i.split(":", 2)[1].upper() not in CREDENTIAL_METHODS]
        if writes:
            raise common.validation_error(
                {"verdict": "Roxy's account is only ever sent with GET, HEAD or POST; choose another verdict."}
            )
    loosening = []
    for endpoint_id in ids:
        now, _default, row = _current(policy, endpoint_id)
        if LOOSENING[wanted] > LOOSENING[now]:
            loosening.append((endpoint_id, row))
    if loosening:
        await _require_fresh(request)
        critical = [(i, row) for i, row in loosening if row is not None and row.risk >= 4]
        if critical:
            if len(ids) > 1:
                raise common.validation_error(
                    {"endpoint_ids": "Loosen a risk 4 endpoint on its own, with its path typed in confirm."},
                    code="confirm_required",
                )
            path = critical[0][1].path if critical[0][1] is not None else ""
            if body.confirm.strip() != path:
                raise common.validation_error(
                    {"confirm": f"Type the endpoint's path ({path}) to loosen a risk 4 endpoint."},
                    code="confirm_required",
                )
    service = _service(request)
    actor = common.actor_for(admin)
    rid = common.request_id_of(request)
    changed = 0
    for endpoint_id in ids:
        values = {
            "endpoint_id": endpoint_id,
            "verdict": wanted.value,
            "cache_private": body.cache_private,
            "note": body.note,
            "enabled": True,
        }
        change = await common.run_mutation(service.upsert(OVERRIDES, values, actor, reason, request_id=rid))
        changed += int(change.changed)
    return {"changed": changed, "endpoints": [_one(ctx, endpoint_id) for endpoint_id in ids[:MAX_BULK]]}


@router.delete("/endpoints")
async def reset_endpoints(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: ResetBody) -> dict[str, Any]:
    """Put one or more operations back to their default (removes their overrides). When that loosens any of them,
    it needs a fresh second factor."""
    ctx = get_ctx(request)
    policy = _policy(ctx)
    ids = [i for i in _ids(body) if i in policy.overrides]
    for endpoint_id in ids:
        now, default, _row = _current(policy, endpoint_id)
        if LOOSENING[default] > LOOSENING[now]:
            await _require_fresh(request)
            break
    service = _service(request)
    actor = common.actor_for(admin)
    rid = common.request_id_of(request)
    for endpoint_id in ids:
        await common.run_mutation(service.delete(OVERRIDES, endpoint_id, actor, body.reason, request_id=rid))
    return {"reset": len(ids), "endpoints": [_one(ctx, endpoint_id) for endpoint_id in ids]}


def _one(ctx: Any, endpoint_id: str) -> dict[str, Any]:
    policy = _policy(ctx)
    row = policy.seed.by_id.get(endpoint_id)
    if row is not None:
        return item_of(policy, row)
    now, default, _ = _current(policy, endpoint_id)
    return {"id": endpoint_id, "verdict": now.value, "default_verdict": default.value}


@router.post("/reset")
async def reset_all(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: ResetBody) -> dict[str, Any]:
    """Remove every override and category switch: the shipped defaults again (fresh second factor, a reason)."""
    reason = common.require_reason(body.reason, required=True)
    await _require_fresh(request)
    ctx = get_ctx(request)
    policy = _policy(ctx)
    service = _service(request)
    actor = common.actor_for(admin)
    rid = common.request_id_of(request)
    for endpoint_id in list(policy.overrides):
        await common.run_mutation(service.delete(OVERRIDES, endpoint_id, actor, reason, request_id=rid))
    for key in list(policy.categories):
        await common.run_mutation(service.delete(SWITCHES, key, actor, reason, request_id=rid))
    return await summary_answer(ctx)


# ---------------------------------------------------------------------------------------------- the tester


def split_target(raw: str) -> tuple[str, str]:
    """(host, path) from a roblox.com URL, a Roxy URL (`https://<roxy>/<host>/<path>`) or `host/path`."""
    text = raw.strip()
    for prefix in ("https://", "http://"):
        if text.lower().startswith(prefix):
            text = text[len(prefix) :]
    text = text.split("#", 1)[0].split("?", 1)[0].lstrip("/")
    parts = [part for part in text.split("/") if part]
    if len(parts) >= 2 and not parts[0].lower().endswith("roblox.com") and parts[1].lower().endswith("roblox.com"):
        parts = parts[1:]  # a Roxy URL: drop Roxy's own host
    if not parts or not parts[0].lower().endswith("roblox.com"):
        raise common.validation_error({"target": "Give a Roblox URL such as users.roblox.com/v1/users/1."})
    return parts[0].lower().rstrip("."), "/" + "/".join(parts[1:])


def _query_of(raw: str) -> list[tuple[str, str]]:
    from urllib.parse import parse_qsl, urlsplit

    query = urlsplit(raw if "://" in raw else "https://x/" + raw.lstrip("/")).query
    return parse_qsl(query, keep_blank_values=True)


@router.get("/test")
async def check_target(
    request: Request,
    _admin: AdminSession,
    target: Annotated[str, Query(min_length=1, max_length=MAX_TARGET_CHARS)],
    method: Annotated[str, Query(max_length=8)] = "GET",
) -> dict[str, Any]:
    """What the policy does with `method` on `target` right now, step by step (the page's tester)."""
    return target_answer(get_ctx(request), target, method)


def target_answer(ctx: Any, target: str, method: str = "GET") -> dict[str, Any]:
    host, path = split_target(target)
    verb = method.strip().upper() or "GET"
    policy = _policy(ctx)
    decision = policy.decide(host, verb, path, _query_of(target))
    grant = policy.credential_grant(f"{host}{path}", verb) if decision.verdict is Verdict.ALLOW_TOKEN else None
    enforce = bool(ctx.settings.int("endpoint_policy_enforce"))
    allowed_hosts = set(ctx.settings.get("allowed_roblox_hosts") or ())
    return {
        "host": host,
        "path": path,
        "method": verb,
        "host_allowed": host in allowed_hosts,
        "endpoint_id": decision.endpoint_id,
        "known": decision.known,
        "row": item_of(policy, decision.row) if decision.row is not None else None,
        "verdict": decision.verdict.value,
        "verdict_words": VERDICT_LABELS[decision.verdict],
        "default_verdict": (decision.default_verdict or decision.verdict).value,
        "source": decision.source,
        "reason": decision.reason,
        "category": decision.category,
        "risk": decision.risk,
        "steps": steps_of(policy, decision),
        "credential": None
        if grant is None
        else {"cache_private": grant.cache_private, "anonymous_fallback": grant.identical_anonymous},
        "refused": decision.blocked and enforce,
        "shadow": decision.blocked and not enforce,
        "unknown_override_id": None if decision.known else decision.endpoint_id,
    }


def steps_of(policy: EndpointPolicy, decision: PolicyDecision) -> list[dict[str, str]]:
    """The precedence steps of `roxy/policy/engine.py`, each with what it said for this request."""
    row = decision.row
    override = policy.overrides.get(decision.endpoint_id)
    state = policy.category_state(decision.category)
    steps = [
        {"step": "Admin override", "says": override.verdict.value if override is not None else "none"},
        {"step": "Category switch", "says": STATE_WORDS[state] if row is not None else "not used for this request"},
        {"step": "Shipped verdict", "says": row.verdict.value if row is not None else "not in Roblox's reference"},
    ]
    if row is None:
        steps.append({"step": "Unknown endpoint rule", "says": decision.reason})
    if decision.source == "guard":
        steps.append({"step": "Query guard", "says": decision.reason})
    return steps


# ---------------------------------------------------------------------------------------------- logs


def _grouped(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (str(row.get("endpoint_id") or ""), str(row.get("verdict") or ""))
        item = merged.setdefault(key, {"endpoint_id": key[0], "verdict": key[1], "count": 0, "last_ms": None})
        item["count"] += int(row.get("count") or 0)
        last = row.get("last_ms")
        if last is not None and (item["last_ms"] is None or last > item["last_ms"]):
            item["last_ms"] = last
    return list(merged.values())


async def counted_items(ctx: Any, tr: TimeRange, event_type: str) -> list[dict[str, Any]]:
    """One row per operation (and verdict) of a counter event over the range: `endpoint_id`, `verdict`, `count`,
    `last_ms` (the Unknown endpoints and Shadow mode tables)."""
    with common.service_errors():
        rows = await _event_counts(ctx, event_type, tr.window.start * 1000, tr.window.end * 1000)
    return _grouped(rows)


async def counted_answer(ctx: Any, spec: TableSpec, tq: TableQuery, tr: TimeRange, event_type: str) -> dict[str, Any]:
    """The table answer of `/policy/unknown` and `/policy/would-block` (the page's cards read the same)."""
    page, total = common.page_rows(await counted_items(ctx, tr, event_type), tq, search_keys=("endpoint_id",))
    return common.table_answer(spec, tq, page, total) | {"range": tr.info()}


async def _counted(
    request: Request,
    admin: AdminPrincipal,
    spec: TableSpec,
    tq: TableQuery,
    fmt: Any,
    tr: TimeRange,
    event_type: str,
) -> Any:
    ctx = get_ctx(request)
    if fmt is not None:
        items = await counted_items(ctx, tr, event_type)
        everything, total = common.page_rows(items, _whole(tq, items), search_keys=("endpoint_id",))
        return await common.export_table(request, admin, spec, everything, fmt, total=total, tq=tq, tr=tr)
    return await counted_answer(ctx, spec, tq, tr, event_type)


def unknown_item(policy: EndpointPolicy, endpoint_id: str) -> dict[str, Any]:
    """An operation Roblox does not document (`unknown:<METHOD>:<template>`) as the page shows it: its verdict now,
    the verdict the unknown endpoint rule gives it, and its override (422 for an id of another shape)."""
    if not endpoint_id.startswith("unknown:") or endpoint_id.count(":") < 2:
        raise common.validation_error({"endpoint_id": "Give an unknown:<METHOD>:<host>/<path> endpoint id."})
    _, method, template = endpoint_id.split(":", 2)
    host, _, rest = template.partition("/")
    if not host.endswith("roblox.com") or not method.isalpha():
        raise common.validation_error({"endpoint_id": "Give an unknown:<METHOD>:<host>/<path> endpoint id."})
    plain = policy.decide(host, method, "/" + rest, template=template)
    default = plain.default_verdict or plain.verdict
    override = policy.overrides.get(endpoint_id)
    verdict = override.verdict if override is not None else default
    return {
        "id": endpoint_id,
        "method": method.upper(),
        "template": template,
        "known": plain.known,
        "verdict": verdict.value,
        "verdict_words": VERDICT_LABELS[verdict],
        "default_verdict": default.value,
        "default_words": VERDICT_LABELS[default],
        "default_reason": plain.reason if override is None else "",
        "changed": override is not None,
        "override_note": override.note if override is not None else "",
        "cache_private": bool(override.cache_private) if override is not None else False,
        "risk": plain.risk,
    }


async def attempts_answer(ctx: Any, tq: TableQuery, tr: TimeRange, *, ip: str | None = None) -> dict[str, Any]:
    """One page of caller sign-in attempts, newest first (the page's card reads what `/policy/attempts` answers)."""
    from roxy.admin.api.security import ring_fetch, table_page

    fetch = ring_fetch(ctx, security_events.AUTH_ATTEMPT, tr, ip=ip or None)
    with common.service_errors():
        return await table_page(ATTEMPT_SPEC, tq, fetch, tr=tr)


@router.get("/unknown")
async def unknown(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(UNKNOWN_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Operations callers asked for that Roblox does not document, with the verdict Roxy gave them."""
    return await _counted(request, admin, UNKNOWN_SPEC, tq, fmt, tr, POLICY_UNKNOWN_EVENT)


@router.get("/would-block")
async def would_block(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(WOULD_BLOCK_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """What shadow mode (endpoint_policy_enforce off) let through that the policy would refuse."""
    return await _counted(request, admin, WOULD_BLOCK_SPEC, tq, fmt, tr, POLICY_WOULD_BLOCK_EVENT)


@router.get("/attempts")
async def attempts(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(ATTEMPT_SPEC))],
    fmt: ExportFormatDep,
    ip: Annotated[str | None, Query(max_length=64)] = None,
) -> Any:
    """Callers who sent their own Roblox cookie, API key or sign-in token, newest first (never the value)."""
    from roxy.admin.api.security import _only_newest_first, _paged, ring_fetch

    _only_newest_first(tq)
    fetch = ring_fetch(get_ctx(request), security_events.AUTH_ATTEMPT, tr, ip=ip or None)
    return await _paged(request, admin, ATTEMPT_SPEC, tq, fmt, fetch, tr=tr, filters={"ip": ip})


def unknown_override_id(method: str, template: str) -> str:
    """The override id of an operation the seed does not list (for the page's "review" buttons)."""
    return unknown_id(method, template)


__all__ = [
    "ATTEMPT_SPEC",
    "ENDPOINT_SPEC",
    "LOOSEN_NOTE",
    "STATE_WORDS",
    "UNKNOWN_SPEC",
    "WOULD_BLOCK_SPEC",
    "attempts_answer",
    "categories_answer",
    "counted_answer",
    "counted_items",
    "endpoint_items",
    "item_of",
    "router",
    "split_target",
    "summary_answer",
    "target_answer",
    "unknown_item",
    "unknown_override_id",
]
