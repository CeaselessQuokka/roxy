"""The proxy route: `/{host}.roblox.com/{path}` for every caller, from raw request to recorded outcome.

What this is
    `router`, a plain Starlette `Router` with one catch-all route (included LAST by `roxy/main.py`, so it never
    shadows a real page, and never matching `/admin` or anything under it, so the admin surface can never fall
    into the proxy pipeline), and `ProxyFlow`, the object that runs the DESIGN.md 11.1 flow for one request.

Why it exists
    This is the hot path: every Roblox API call a game makes through Roxy runs here. It is a plain endpoint that
    reads `request.app.state.ctx` itself, without FastAPI dependency injection or Pydantic models, because both
    add measurable work per request (resolving the dependency graph, validating and copying models) and the proxy
    needs none of it: its inputs are a raw path, raw headers and raw bytes, which `validate.py` and `scrub.py`
    check more strictly than a model could. Keeping the whole flow in one short class also makes the order of
    the safety steps readable top to bottom, and that order is binding (DESIGN 11.1).

How it works
    1. The middleware stack already set the request id, the real client IP and the deadline, and refused
       oversized URLs, headers and bodies. The response is marked as proxied content (sandbox CSP, plan 9.2).
    2. OPTIONS is answered at once: 204 with `Allow`, no abuse checks, nothing upstream, never a probe (plan
       row 1, v1 parity). DESIGN 11.1 placed it after the abuse verdict; it runs first so an OPTIONS for an odd
       path can never be counted or logged as a probe by the URL checks.
    3. `validate.parse_target` parses the RAW path and query (never raises) and a `ProxyRequest` is built. HEAD
       becomes GET with `is_head=True`. The `Roblox-Id` place claim is scrubbed with `redact_label` here, once,
       because it becomes hot.db keys (place limits, spam windows) where no log filter looks.
    4. For a valid target, `ctx.cache.peek(req)` (memory and cache.db only, never upstream) sets `cache_key` and
       `fresh_cache_hit`. The abuse checks need that answer only for the throttled cache serve
       (`cache_serve_throttled` on) or when an admin sets `throttle_count_cache_hits` to 0 (by default cache hits
       count, owner decision 2026-10-07 reversing D10); only then does the peek run before the verdict. Otherwise
       it runs after an Allow, so a refused caller costs no cache read and no cache rule match. Steps 4 to 6 share
       one `regex_budget` (plan 9.9): the cache policy, every abuse pattern check and the upstream's allowlist and
       routing matches of one request together spend at most `REGEX_REQUEST_BUDGET_S`.
    5. `ctx.abuse.evaluate(req)` returns Allow or Refuse. Refuse: optionally serve a throttled caller from a fresh
       cache entry (`allow_fresh_cache_serve`, which the pipeline grants only when no later filter refuses the
       request), else ask the tarpit for a plan (never for bypass callers, whatever check refused them: the
       pipeline marks `req.bypass` before any check runs; the refusal's `detail` is the v1 per-hold reason), hold or
       jitter (`await plan.wait()`) or drip (a streaming response), and release the slot in `finally`. The one HTML
       refusal (the challenge page) is switched back to the page CSP, because its script runs with this response's
       nonce (`req.csp_nonce`).
    6. Allow: an invalid target is refused even if the pipeline let it through (defense in depth: the SSRF guard
       must not depend on another module's check order). The request's header names, values and User-Agent are
       counted (`record_fingerprint`, parity row 79; a request filter's refusal counts as a blocked fingerprint,
       row 134). Then `ctx.cache.serve(req, peek)` returns the result
       (falling back to `ctx.upstream.fetch` only while no cache service exists). A pacing failure that tells the
       caller to wait (`Retry-After` on a Roblox cooldown, upstream busy or queue full answer) is handed to
       `tarpit.plan_cooldown_retry`, which remembers it fleet-wide and, when this answer is itself a retry of the
       same key inside an earlier `Retry-After`, holds it with the `jitter` type (`upstream_cooldown_retry`, plan
       10.6; off by default).
    7. `respond.render` builds the answer; `ctx.recorder.record_outcome(event)` runs exactly once per request
       (for a drip, when the stream ends), with a `CaptureInput` when the recorder takes one (its capture policy
       decides whether the bodies are kept). `message_source` tells whose words the caller got (row 116): a
       refusal's `custom` or `default` (a refusal the upstream layer returned, such as an egress host refusal, is
       `default`), `roxy` for a 7.13 failure text Roxy wrote, `roblox` for an error answer that carries Roblox's
       own body. An exception still propagates to the middleware, which answers 500 (or the
       deadline middleware 504), but the fallback outcome record (`internal_error` or `deadline`) is written here
       first, because only this flow knows the request's endpoint and cache facts (DESIGN 7).
    Fail closed (plan C7): no context or no abuse pipeline means 503 `degraded` for valid targets (invalid ones
    are still refused with their own 404); shared state that cannot be read or written is 503 `degraded`.
    `/internal` and everything under it exist only on the internal Unix socket app; a request for them that reaches
    this public app gets v1's JSON `"Not Found"` 404 at once: no proxy pipeline, no tarpit, not counted as proxied
    (nginx answers 404 for `/internal/` in production before Roxy sees it).

What to read next
    `roxy/proxy/validate.py`, `roxy/proxy/respond.py`, then `roxy/abuse/pipeline.py` and `roxy/cache/service.py`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import functools
import hashlib
import inspect
import logging
import sqlite3
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Match, Route, Router
from starlette.types import Scope

from roxy.core.client_ip import UNKNOWN_IP, limit_key
from roxy.core.deadline import STATE_COMPAT_COLLAPSE
from roxy.core.errors import not_found_response
from roxy.core.reasons import AuthClass, Egress, Outcome, ReasonCode, Source
from roxy.core.redact import redact_label
from roxy.core.scope import catalog_default, get_app_context, get_state
from roxy.core.security_headers import KIND_PAGE, STATE_CSP_NONCE, STATE_RESPONSE_KIND, is_admin_path, mark_proxied
from roxy.internal_app import is_internal_path
from roxy.lifespan import optional_import
from roxy.proxy import respond, scrub, validate
from roxy.proxy.context import (
    MAX_PLACE_ID,
    FallbackOutcomeEvent,
    ProxyRequest,
    endpoint_template,
    is_browser,
    problem_template,
)
from roxy.rules.match import regex_budget
from roxy.storage.db import SharedStateUnavailable

log = logging.getLogger("roxy.proxy.router")

PROXY_ROUTE_PATH = "/{path:path}"

CACHE_ERRORS: tuple[type[BaseException], ...] = (SharedStateUnavailable, sqlite3.Error, OSError)
"""Failures of the disposable cache tier that turn a peek into a miss instead of failing the request."""

RETRY_PACING_REASONS: frozenset[ReasonCode] = frozenset(
    {ReasonCode.UPSTREAM_COOLDOWN, ReasonCode.UPSTREAM_BUSY, ReasonCode.QUEUE_OVERFLOW}
)
"""Failure answers whose `Retry-After` paces the caller: a retry inside it is `upstream_cooldown_retry` (10.6)."""

_FALLBACK_SETTINGS: dict[str, Any] = {
    "strict_host_allowlist": True,
    "allowed_roblox_hosts": list(validate.DEFAULT_ALLOWED_HOSTS),
    "max_url_length": validate.DEFAULT_MAX_URL_LENGTH,
    "ipv6_limit_prefix": 64,
    "request_deadline_s": 60,
    "compat_collapse_upstream_errors": False,
    "public_cors_allow_any_origin": False,
}


def setting(ctx: Any, key: str) -> Any:
    """A live setting, else the catalog default, else the fallback above (never raises)."""
    settings = getattr(ctx, "settings", None)
    if settings is not None:
        try:
            return settings.get(key)
        except (KeyError, LookupError, AttributeError):
            pass
    default = catalog_default(key)
    return _FALLBACK_SETTINGS.get(key) if default is None else default


def allowed_hosts(ctx: Any) -> frozenset[str]:
    """`allowed_roblox_hosts` as a set of lowercase host names (one trailing dot removed)."""
    value = setting(ctx, "allowed_roblox_hosts") or ()
    hosts = set()
    for entry in value:
        name = str(entry).strip().lower()
        hosts.add(name[:-1] if name.endswith(".") else name)
    return frozenset(hosts)


def peek_before_verdict(ctx: Any) -> bool:
    """True when an abuse check reads the cache's answer (`fresh_cache_hit`), so the peek must come first.

    Only two settings make a check look at it: `throttle_count_cache_hits` at 0 (fresh hits neither counted nor
    refused) and `cache_serve_throttled` at 1 (a throttled caller served from a fresh entry, plan row 60). Both
    are read live with their catalog defaults (1 and 0), so by default the peek waits for an Allow.
    """
    return not bool(setting(ctx, "throttle_count_cache_hits")) or bool(setting(ctx, "cache_serve_throttled"))


def caller_headers(scope: Mapping[str, Any]) -> tuple[dict[str, str], list[str]]:
    """Caller headers as {lowercase name: value} (repeats joined with ", ") and the names in arrival order."""
    headers: dict[str, str] = {}
    names: list[str] = []
    for raw_name, raw_value in scope.get("headers", []):
        name = bytes(raw_name).decode("latin-1").lower()
        value = bytes(raw_value).decode("latin-1")
        names.append(name)
        headers[name] = f"{headers[name]}, {value}" if name in headers else value
    return headers, names


def _is_refusal(verdict: Any) -> bool:
    """Refuse carries a status and a reason; Allow carries only headers (DESIGN 7)."""
    return hasattr(verdict, "status") and hasattr(verdict, "reason") and hasattr(verdict, "body")


@functools.cache
def _interactive_priority() -> Any:
    """`Priority.INTERACTIVE` (plan 7.8), looked up once; 0 while the upstream package does not exist."""
    module = optional_import("roxy.upstream.service")
    priority = getattr(module, "Priority", None) if module is not None else None
    return priority.INTERACTIVE if priority is not None else 0


@functools.cache
def _event_class() -> Any:
    """`metrics/recorder.py: OutcomeEvent`, looked up once; the fallback shape while metrics does not exist."""
    module = optional_import("roxy.metrics.recorder")
    found = getattr(module, "OutcomeEvent", None) if module is not None else None
    return found if found is not None else FallbackOutcomeEvent


@functools.cache
def _capture_class() -> Any:
    """`metrics/capture.py: CaptureInput`, looked up once (None while metrics does not exist)."""
    module = optional_import("roxy.metrics.capture")
    return getattr(module, "CaptureInput", None) if module is not None else None


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


async def _release(plan: Any) -> None:
    """Release a tarpit slot; a failure here is logged, never raised (the lease also expires on its own)."""
    release = getattr(plan, "release", None)
    if release is None:
        return
    try:
        await _maybe_await(release())
    except Exception:
        log.exception("tarpit_release_failed")


class ProxyFlow:
    """Runs DESIGN.md 11.1 for one request and records its outcome exactly once."""

    def __init__(self, ctx: Any, request: Request) -> None:
        self.ctx = ctx
        self.request = request
        self.scope = request.scope
        self.state = get_state(request.scope)
        self.recorded = False
        self.refusal: Any = None  # the refusal being answered, for the outcome record (check, message source)
        self.compat_collapse = bool(setting(ctx, "compat_collapse_upstream_errors"))
        # The deadline middleware answers with the same choice this flow renders and records with, so the wire
        # and the outcome record agree even if the setting changes mid-request (review finding spec-5).
        self.state[STATE_COMPAT_COLLAPSE] = self.compat_collapse
        self.cors_any_origin = bool(setting(ctx, "public_cors_allow_any_origin"))

    # --- steps --------------------------------------------------------------------------------------------------

    async def run(self) -> Response:
        method = self.request.method.upper()
        req = await self.build_request(method)
        if method == "OPTIONS":
            return await self.finish(req, respond.options_rendered(req))
        try:
            return await self.handle(req)
        except SharedStateUnavailable as exc:
            # C7: shared state is unreadable; fail closed with the 7.13 `degraded` row.
            log.warning("proxy_shared_state_unavailable", extra={"fields": {"error": str(exc)[:200]}})
            return await self.finish(req, self.render(req, respond.failure_result(ReasonCode.DEGRADED)))
        except asyncio.CancelledError:
            # The deadline middleware canceled this request (it answers 504 itself), or the server is stopping
            # past its graceful timeout. Either way the caller got no proxy answer: record the 7.13 deadline row
            # here, because nothing else knows this request's endpoint, egress and cache facts (DESIGN 7).
            await self.record_failure(req, ReasonCode.DEADLINE)
            raise
        except Exception:
            # The unhandled error middleware answers 500; the outcome record is ours (exactly once, DESIGN 7).
            await self.record_failure(req, ReasonCode.INTERNAL_ERROR)
            raise

    async def build_request(self, method: str) -> ProxyRequest:
        """Step 2: parse the target and gather every fact about the caller once."""
        scope = self.scope
        # The RAW path (still percent-encoded) when the server provides it; the decoded path re-encoded otherwise.
        raw_path = scope.get("raw_path") or quote(str(scope.get("path", "/")), safe="/")
        parse = validate.parse_target(
            raw_path,
            scope.get("query_string", b""),
            method,
            allowed_hosts=allowed_hosts(self.ctx),
            strict_host_allowlist=bool(setting(self.ctx, "strict_host_allowlist")),
            max_url_length=int(setting(self.ctx, "max_url_length")),
        )
        headers, names = caller_headers(scope)
        body = await self.request.body() if method in scrub.BODY_METHODS else b""
        client = scope.get("client")
        client_ip = str(self.state.get("client_ip") or (client[0] if client else UNKNOWN_IP))
        user_agent = headers.get("user-agent", "")
        # `Roblox-Id` is a caller claim that becomes hot.db keys (place limits, spam windows, place bans) where no log
        # filter looks: scrubbed like a log line (plan C1, 9.15), so a credential piece in it is never stored.
        place_id = redact_label(headers.get("roblox-id", "").strip()[:MAX_PLACE_ID]) or None
        received_monotonic = float(self.state.get("received_monotonic") or time.monotonic())
        deadline_at = self.state.get("deadline_at")
        if deadline_at is None:
            deadline_at = received_monotonic + float(setting(self.ctx, "request_deadline_s"))
        clock = getattr(self.ctx, "clock", None)
        received_ms = self.state.get("received_ms")
        if received_ms is None:
            received_ms = clock.now_ms() if clock is not None else int(time.time() * 1000)
        is_head = method == "HEAD"
        if parse.problem is None:
            template = endpoint_template(parse.host, parse.path)
        else:
            template = problem_template(parse.problem)  # a fixed bucket: scanners cannot add endpoint rows
        return ProxyRequest(
            request_id=str(self.state.get("request_id") or ""),
            received_ms=int(received_ms),
            deadline_at=float(deadline_at),
            client_ip=client_ip,
            limit_key=limit_key(client_ip, int(setting(self.ctx, "ipv6_limit_prefix"))),
            method="GET" if is_head else method,  # HEAD runs as GET; only the body is dropped at the end
            host=parse.host,
            path=parse.path,
            query=list(parse.query),
            prettyprint=parse.prettyprint,
            body=body,
            content_type=headers.get("content-type"),
            headers=headers,
            header_names_in_order=names,
            user_agent=user_agent,
            place_id=place_id,
            is_browser=is_browser(user_agent),
            template=template,
            target_problem=parse.problem,
            is_head=is_head,
            target=parse.target,
            target_detail=parse.detail,
            raw_query=parse.raw_query,
            received_monotonic=received_monotonic,
            raw_path=parse.raw_target,
            csp_nonce=self.state.get(STATE_CSP_NONCE),
        )

    async def handle(self, req: ProxyRequest) -> Response:
        """Steps 4 to 7 for a context that exists, every pattern match under one request budget (plan 9.9)."""
        with regex_budget():
            return await self._handle(req)

    async def _handle(self, req: ProxyRequest) -> Response:
        early = req.target_problem is None and peek_before_verdict(self.ctx)
        peek = await self.peek(req) if early else None
        abuse = getattr(self.ctx, "abuse", None)
        if abuse is None:
            if req.target_problem is not None:
                return await self.refuse(req, respond.target_refusal(req.target_problem), peek)
            return await self.finish(req, self.render(req, self.not_ready_result(req)))
        verdict = await abuse.evaluate(req)
        if _is_refusal(verdict):
            return await self.refuse(req, verdict, peek)
        if req.target_problem is not None:
            # Defense in depth: the pipeline should have refused this. Never fetch an invalid target (plan 9.10).
            log.error(
                "invalid_target_allowed",
                extra={"fields": {"problem": req.target_problem.value, "detail": req.target_detail}},
            )
            return await self.refuse(req, respond.target_refusal(req.target_problem), peek)
        # Passed every check: its header names, values and User-Agent are counted (parity row 79, v1 logged them
        # right before the cache lookup and the upstream call).
        self.note_fingerprint(req)
        if peek is None:
            peek = await self.peek(req)  # the late peek (step 4): only an allowed request pays for the cache read
        result = await self.serve(req, peek)
        rendered = self.render(req, result, extra_headers=getattr(verdict, "headers", None))
        plan = await self.cooldown_retry_plan(req, rendered)
        if plan is not None:
            try:
                await _maybe_await(plan.wait())  # jitter: a retry inside the Retry-After it was given (10.6)
            finally:
                await _release(plan)
        return await self.finish(req, rendered, result)

    async def peek(self, req: ProxyRequest) -> Any:
        """Step 3: the cache's view of this key (no upstream call). The cache is disposable: errors are misses."""
        cache = getattr(self.ctx, "cache", None)
        if cache is None:
            return None
        try:
            peek = await cache.peek(req)
        except CACHE_ERRORS as exc:
            log.warning("cache_peek_failed", extra={"fields": {"error": f"{type(exc).__name__}: {exc}"[:200]}})
            return None
        key = getattr(peek, "key", None)
        if key is not None and req.cache_key is None:
            req.cache_key = key
        if getattr(peek, "fresh", None) is not None:
            req.fresh_cache_hit = True
        return peek

    async def serve(self, req: ProxyRequest, peek: Any) -> Any:
        """Step 6: the cache serves (it calls upstream itself on a miss); upstream directly only without a cache."""
        cache = getattr(self.ctx, "cache", None)
        if cache is not None:
            return await cache.serve(req, peek)
        upstream = getattr(self.ctx, "upstream", None)
        if upstream is None:
            return self.not_ready_result(req)
        result = await upstream.fetch(req, priority=_interactive_priority(), stale_available=False)
        return respond.result_from_upstream(result)

    async def refuse(self, req: ProxyRequest, refusal: Any, peek: Any) -> Response:
        """Step 5: a refusal, possibly answered from a fresh cache entry or held by the tarpit first."""
        cache = getattr(self.ctx, "cache", None)
        if getattr(refusal, "allow_fresh_cache_serve", False) and req.fresh_cache_hit and cache is not None:
            # cache_serve_throttled (plan row 60): a throttled caller with a fresh cached answer gets it, no hold.
            result = await cache.serve(req, peek)
            snapshot = {
                name: value
                for name, value in (getattr(refusal, "headers", None) or {}).items()
                if name.lower() in {h.lower() for h in respond.THROTTLE_SNAPSHOT_HEADERS}
            }
            rendered = self.render(req, result, extra_headers=snapshot)
            reason = ReasonCode.THROTTLED_CACHE if rendered.outcome is Outcome.SERVED_CACHE else None
            return await self.finish(req, rendered, result, reason=reason)
        self.refusal = refusal
        if getattr(refusal, "reason", None) == ReasonCode.HEADER_RULE:
            self.note_fingerprint(req, blocked=True)  # a request filter's catch: the blocked fingerprints (row 134)
        rendered = respond.render_refusal(req, refusal, cors_any_origin=self.cors_any_origin)
        if rendered.page:
            # Roxy's own HTML page (the challenge): its script runs under the page CSP and this response's nonce.
            self.state[STATE_RESPONSE_KIND] = KIND_PAGE
        plan = await self.tarpit_plan(req, refusal)
        if plan is None:
            return await self.finish(req, rendered)
        if str(getattr(plan, "kind", "hold")) == "drip" and not req.is_head:

            async def on_close() -> None:
                try:
                    await _release(plan)
                finally:
                    await self.record(req, rendered, None, bytes_out=len(rendered.body))

            return respond.drip_response(rendered, plan, on_close=on_close)
        try:
            wait = getattr(plan, "wait", None)
            if wait is not None:
                await _maybe_await(wait())  # hold or jitter: the caller waits, then gets the same bytes
        finally:
            await _release(plan)
        return await self.finish(req, rendered)

    async def tarpit_plan(self, req: ProxyRequest, refusal: Any) -> Any:
        """The tarpit plan for this refusal, or None (no category, a bypass caller, tarpit off or full)."""
        category = getattr(refusal, "tarpit_category", None)
        tarpit = getattr(getattr(self.ctx, "abuse", None), "tarpit", None)
        if not category or req.bypass or tarpit is None:
            return None  # bypass callers are never held (v1 semantics, plan 10.6)
        detail = str(getattr(refusal, "detail", "") or "")
        try:
            if detail:
                # The v1 per-hold reason string (`Block rule: <pattern>`), shown on the Tarpit card (plan row 123).
                return await tarpit.plan(category, req, reason=detail)
            return await tarpit.plan(category, req)
        except SharedStateUnavailable:
            return None  # C7: without shared state the tarpit never holds; the refusal itself still works

    async def cooldown_retry_plan(self, req: ProxyRequest, rendered: respond.Rendered) -> Any:
        """The `upstream_cooldown_retry` hold for a pacing failure, or None (see step 6 of the module docstring)."""
        if req.bypass or rendered.outcome is not Outcome.FAILED or rendered.reason not in RETRY_PACING_REASONS:
            return None
        planner = getattr(getattr(getattr(self.ctx, "abuse", None), "tarpit", None), "plan_cooldown_retry", None)
        given = rendered.header(respond.RETRY_AFTER)
        if planner is None or given is None or not given.isdigit() or int(given) <= 0:
            return None
        cache_key = req.cache_key
        key_id = cache_key if isinstance(cache_key, str) else getattr(cache_key, "id", None)
        key = str(key_id) if key_id else f"{req.caller_method} {req.target}?{req.raw_query}"  # "the same key"
        try:
            return await planner(
                req, key=key, retry_after_s=int(given), reason=f"Retry inside Retry-After ({rendered.reason.value})"
            )
        except SharedStateUnavailable:
            return None  # C7: without shared state the tarpit never holds

    def note_fingerprint(self, req: ProxyRequest, *, blocked: bool = False) -> None:
        """Count this request's header names, values and User-Agent (v1 `log_request_fingerprint`).

        Every request that passed every check (parity row 79) and, as a blocked fingerprint, every request a
        request filter refused (row 134). In memory, flushed with the other metrics; the recorder hashes secret
        values and skips ignored headers. Never raises: metrics never fail a request.
        """
        record = getattr(getattr(self.ctx, "recorder", None), "record_fingerprint", None)
        if record is None:
            return
        try:
            record(list(req.headers.items()), req.user_agent or None, blocked=blocked)
        except Exception:
            log.exception("record_fingerprint_failed")

    # --- answers ------------------------------------------------------------------------------------------------

    def not_ready_result(self, req: ProxyRequest) -> Any:
        """Fail closed: without a context, a pipeline or an upstream path, a valid target gets 503 `degraded`."""
        log.warning("proxy_not_ready", extra={"fields": {"target": req.target[:120]}})
        return respond.failure_result(ReasonCode.DEGRADED)

    def render(self, req: ProxyRequest, result: Any, *, extra_headers: Mapping[str, Any] | None = None) -> Any:
        return respond.render(
            req,
            result,
            extra_headers=extra_headers,
            compat_collapse=self.compat_collapse,
            cors_any_origin=self.cors_any_origin,
        )

    async def finish(
        self, req: ProxyRequest, rendered: respond.Rendered, result: Any = None, *, reason: ReasonCode | None = None
    ) -> Response:
        """Step 7: the Response, then exactly one outcome record."""
        response = rendered.to_response(head=req.is_head)
        await self.record(req, rendered, result, bytes_out=0 if req.is_head else len(rendered.body), reason=reason)
        return response

    async def record_failure(self, req: ProxyRequest, reason: ReasonCode) -> None:
        """The fallback outcome record for a request that ends in an exception (a no-op if already recorded).

        Runs while an exception (possibly a cancellation) is propagating, so it must not suspend: the recorder's
        `record_outcome` is synchronous, and any error here is logged, never raised over the original one.
        """
        if self.recorded:
            return
        try:
            rendered = self.render(req, respond.failure_result(reason))
            await self.record(req, rendered, None, bytes_out=len(rendered.body))
        except Exception:
            log.exception("record_failure_failed")

    async def record(
        self,
        req: ProxyRequest,
        rendered: respond.Rendered,
        result: Any,
        *,
        bytes_out: int,
        reason: ReasonCode | None = None,
    ) -> None:
        """Hand one outcome event to the metrics recorder. Never twice, never raises (metrics never fail a request)."""
        if self.recorded:
            return
        self.recorded = True
        recorder = getattr(self.ctx, "recorder", None)
        if recorder is None:
            return
        try:
            event = build_outcome_event(req, rendered, result, bytes_out=bytes_out, reason=reason, refusal=self.refusal)
            record = recorder.record_outcome
            if _accepts_capture(record):
                # The recorder decides from its capture policy whether to keep the bodies (plan rows 126, 127).
                await _maybe_await(record(event, capture=capture_input(req, rendered, result)))
            else:
                await _maybe_await(record(event))
        except Exception:
            log.exception("record_outcome_failed")


@functools.lru_cache(maxsize=32)
def _function_accepts_capture(function: Any) -> bool:
    try:
        return "capture" in inspect.signature(function).parameters
    except (TypeError, ValueError):
        return False


def _accepts_capture(record: Any) -> bool:
    """True when `record_outcome` takes the optional `capture` argument (the P7 recorder does).

    The answer is cached per underlying function, so the signature is inspected once, not per request.
    """
    function = getattr(record, "__func__", record)
    try:
        return _function_accepts_capture(function)
    except TypeError:  # an unhashable callable object: inspect it directly
        return _function_accepts_capture.__wrapped__(function)


def capture_input(req: ProxyRequest, rendered: respond.Rendered, result: Any) -> Any:
    """`metrics/capture.py: CaptureInput` for this request (raw values; the recorder redacts and truncates)."""
    capture_class = _capture_class()
    if capture_class is None:
        return None
    return capture_class(
        request_id=req.request_id,
        at_ms=req.received_ms,
        method=req.caller_method,
        url=req.target,
        query=req.raw_query,
        ip=req.client_ip,
        place_id=req.place_id,
        user_agent=req.user_agent,
        outcome=str(rendered.outcome),
        reason=str(rendered.reason),
        status=rendered.status,
        upstream_status=getattr(result, "upstream_status", None),
        egress=str(getattr(result, "egress", Egress.NONE) or Egress.NONE),
        request_headers=dict(req.headers),
        request_body=req.body,
        response_headers=list(rendered.headers),
        response_body=rendered.body,
    )


MESSAGE_SOURCE_DEFAULT = "default"
MESSAGE_SOURCE_ROXY = "roxy"
MESSAGE_SOURCE_ROBLOX = "roblox"
_ROBLOX_BODY_SOURCES = frozenset({Source.ROBLOX, Source.RELAY, Source.CACHE})


def message_source(rendered: respond.Rendered, refusal: Any) -> str:
    """Whose words the caller got (parity row 116, v1 `reason_counts` "Roxy text" against "Roblox body").

    A refusal: its own `custom` or `default`. A refusal the cache or upstream layer returned as a result (a public
    credential marker at the egress guard, an egress host refusal; DESIGN 11.9 "Rows outside plan 7.13") has no
    refusal object, and its text is always Roxy's built-in v1 text: `default`. A failure Roxy wrote (a plan 7.13
    text): `roxy`. Any other error answer (status 400 or more) carries Roblox's own body, live, reshaped or from the
    cache: `roblox`. A success has no message: "".
    """
    if refusal is not None:
        return str(getattr(refusal, "message_source", "") or "") or MESSAGE_SOURCE_DEFAULT
    if rendered.outcome is Outcome.REFUSED:
        return MESSAGE_SOURCE_DEFAULT
    if rendered.outcome is Outcome.FAILED:
        return MESSAGE_SOURCE_ROXY
    if rendered.status >= 400 and rendered.source in _ROBLOX_BODY_SOURCES:
        return MESSAGE_SOURCE_ROBLOX
    return ""


BODY_HASH_CHARS = 16
"""Hex characters of a response body's SHA-256 kept in a request sample (the fixture format of plan 11.3)."""


def fetched_body_hash(rendered: respond.Rendered, result: Any) -> str | None:
    """The hash of the body this request fetched from Roblox, for the request sample, or None.

    The CACHE-TTL-TUNE estimate and the 11.3 dry run compare the bodies Roblox returned for one key over time: the
    same hash twice means the body did not change. So only an answer this request fetched itself counts: served
    from upstream, at least one upstream call, a 2xx. A cache serve, a refusal or a failure has no fetched body.
    (Before the wave 3b integration the sample held the cache key's hash of a POST request body instead.)
    """
    if rendered.outcome is not Outcome.SERVED_UPSTREAM or int(getattr(result, "upstream_calls", 0) or 0) < 1:
        return None
    status = getattr(result, "upstream_status", None) or rendered.status
    body = getattr(result, "body", None)
    if not 200 <= int(status) < 300 or not isinstance(body, bytes | bytearray | memoryview):
        return None
    return hashlib.sha256(body).hexdigest()[:BODY_HASH_CHARS]


def _trace_count(result: Any, name: str) -> int:
    value = getattr(getattr(result, "trace", None), name, 0)
    return int(value) if isinstance(value, int) else 0


def build_outcome_event(
    req: ProxyRequest,
    rendered: respond.Rendered,
    result: Any,
    *,
    bytes_out: int,
    reason: ReasonCode | None = None,
    refusal: Any = None,
) -> Any:
    """The DESIGN.md section 8 `OutcomeEvent` for one finished request, plus the optional fields the recorder has.

    `error` means an upstream or internal error happened, whether or not the caller saw it: a stale serve after a
    failed refresh counts (the metrics recorder's definition).
    """
    latency_ms = max(0.0, (time.monotonic() - req.received_monotonic) * 1000.0)
    fields: dict[str, Any] = {
        "at_ms": req.received_ms,
        "request_id": req.request_id,
        "endpoint_template": req.template,
        "host": req.host,
        "method": req.caller_method,
        "egress": Egress(getattr(result, "egress", Egress.NONE) or Egress.NONE),
        "outcome": rendered.outcome,
        "reason": reason or rendered.reason,
        "status": rendered.status,
        "source": rendered.source if isinstance(rendered.source, Source) else Source(rendered.source),
        "cache_state": rendered.cache_state,
        "auth_class": AuthClass(getattr(result, "auth_class", AuthClass.ANON) or AuthClass.ANON),
        "caller_bytes_in": len(req.body),
        "caller_bytes_out": bytes_out,
        "upstream_calls": int(getattr(result, "upstream_calls", 0) or 0),
        "upstream_bytes_in": int(getattr(result, "upstream_bytes_in", 0) or 0),
        "upstream_bytes_out": int(getattr(result, "upstream_bytes_out", 0) or 0),
        "latency_ms": latency_ms,
        "queue_wait_ms": float(getattr(result, "queue_wait_ms", 0.0) or 0.0),
        "upstream_ms": float(getattr(result, "upstream_ms", 0.0) or 0.0),
        "client_ip": req.client_ip,
        "place_id": req.place_id,
        "user_agent": req.user_agent,
        "bypass": req.bypass,
        "error": rendered.outcome is Outcome.FAILED
        or rendered.status >= 500
        or bool(getattr(result, "stale_after_failure", False)),
    }
    cache_key = req.cache_key
    age = getattr(result, "cache_age_s", None)
    optional: dict[str, Any] = {
        "path": req.target,
        "query": req.raw_query,
        "upstream_status": getattr(result, "upstream_status", None),
        "attempts": _trace_count(result, "attempts"),
        "retries": _trace_count(result, "retries"),
        "cache_age_s": max(0, int(age))
        if age is not None and rendered.cache_state in respond.CACHE_SERVE_STATES
        else None,
        "upstream_error": str(getattr(getattr(result, "trace", None), "upstream_error", "") or ""),
        "message_source": message_source(rendered, refusal),
        "check": str(getattr(refusal, "check", "") or "") if refusal is not None else "",
        "cache_key_id": getattr(cache_key, "id", None),
        "body_hash": fetched_body_hash(rendered, result),
    }
    event_class = _event_class()
    if dataclasses.is_dataclass(event_class):
        known = {item.name for item in dataclasses.fields(event_class)}
        fields.update({name: value for name, value in optional.items() if name in known})
    try:
        return event_class(**fields)
    except TypeError:
        # The metrics recorder grew a required field this module does not know yet: keep the record anyway.
        log.warning("outcome_event_shape_mismatch", extra={"fields": {"class": getattr(event_class, "__name__", "")}})
        known = {item.name for item in dataclasses.fields(FallbackOutcomeEvent)}
        return FallbackOutcomeEvent(**{name: value for name, value in fields.items() if name in known})


async def proxy_endpoint(request: Request) -> Response:
    """The catch-all proxy endpoint (a plain Starlette endpoint: no dependency injection on the hot path)."""
    path = str(request.scope.get("path", ""))
    if is_internal_path(path):
        # Defense in depth: the public app's first route (`internal_app.PublicInternalNotFound`) already answers
        # /internal; an app that mounts this router alone still never holds or proxies it (a plain 404).
        return not_found_response(path, headers={"Cache-Control": respond.CACHE_CONTROL_VALUE})
    mark_proxied(request.scope)  # sandbox CSP on every proxy answer, refusals included (plan 9.2)
    ctx = get_app_context(request.scope)
    counters = getattr(getattr(ctx, "heartbeat", None), "counters", None)
    if counters is not None:
        counters.proxied += 1  # v1 `count_proxied`: every request that reaches the proxy route (plan row 122)
    return await ProxyFlow(ctx, request).run()


class ProxyRoute(Route):
    """The catch-all route, except `/admin` and everything under it.

    The admin surface must never fall into the proxy pipeline, even for an admin path no admin route claims (that
    path gets the admin side's 404, plan row 15, never a proxy refusal or a tarpit hold), whatever order routes end
    up in.
    """

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        if scope.get("type") == "http" and is_admin_path(str(scope.get("path", ""))):
            return Match.NONE, {}
        return super().matches(scope)


router = Router(routes=[ProxyRoute(PROXY_ROUTE_PATH, endpoint=proxy_endpoint, methods=list(respond.ALLOWED_METHODS))])
"""Included LAST by `roxy/main.py`: every path no other route claims, for every proxied method."""
