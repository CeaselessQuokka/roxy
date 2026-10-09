"""Route discovery over the whole admin surface (plan 19.7, 9.5, 9.6, DESIGN.md section 13).

What this is
    Every route the running application serves under `/admin` (and the public `/csp-report`) is discovered from
    the app's own router, never from a hand-written list, and checked three ways:
      * signed out: an API route answers 401, a page redirects to the login page (`/admin`);
      * signed in without, with a wrong, or with another session's CSRF token: every POST, PUT, PATCH and DELETE
        answers 403 and changes nothing;
      * signed in with a second factor older than `admin_reauth_window_s`: every sensitive route answers 403 with
        `Roxy-Reauth: required` and the section 13 code `reauth_required`, including the routes that ask for the
        fresh factor only for their sensitive variant (a health run with the credential check, the full LLM export,
        applying a recommendation that touches the admin's security).
    The intentional exceptions are listed by name, each with its reason: the login steps, the kill-switch link,
    `/csp-report`, the enrollment routes a bootstrap session may use, the development-only component gallery and
    the admin catch-all. A new route that is not guarded, or a new fresh-MFA route, fails a test until it is
    listed here with a reason. The module also checks the assembly itself: every API module and the event stream
    are mounted, the OpenAPI document is served to a signed-in admin only and lists every module, the gallery
    exists only in development, the dashboard pages' include point refuses unguarded pages, and nested area
    prefixes are mounted before their parents.

Why it exists
    Plan 19.7: "CSRF on every state-changing admin route (auto-discovered from the router), auth required on every
    `/admin/api` route (auto-discovered; the public `/csp-report` is ... listed explicitly as intentionally
    unauthenticated)". About 280 routes from six authors: only discovery keeps that promise as the API grows.

What to read next
    `roxy/admin/router.py`, `roxy/admin/api/__init__.py` (mounting and `guard_scopes`), `roxy/admin/auth/deps.py`.
"""

from __future__ import annotations

import re
import subprocess
import sys
import types
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.routing import iter_route_contexts

import roxy.admin.router as admin_router
from roxy.admin import api as admin_api
from roxy.admin.api import API_MODULES, MOUNTED, SSE_MODULE, ApiMountError, build_api_router, guard_scopes
from roxy.admin.api.common import AdminSession, CsrfChecked, area_router
from roxy.admin.auth.deps import ENROLL_PATHS, require_admin
from roxy.admin.auth.testing import AuthHarness, TestAdmin, auth_harness
from roxy.config.insight_params import INSIGHT_RULES
from roxy.core.errors import is_admin_api_path
from roxy.core.ids import new_id
from roxy.insights.engine import write_recommendation
from roxy.insights.models import Evidence, ProposedChange, Recommendation, changes_digest, make_fingerprint

API = "/admin/api/v1"
AUTH = f"{API}/auth"
UNSAFE = frozenset({"POST", "PUT", "PATCH", "DELETE"})
CATCH_ALL = "/admin/{rest:path}"
GALLERY = "/admin/_gallery"

PUBLIC: dict[tuple[str, str], str] = {
    ("POST", "/csp-report"): "Browsers send CSP violation reports without credentials (plan 9.2); outside /admin.",
    ("GET", "/admin"): "The login page: it must load before anyone is signed in.",
    ("POST", f"{AUTH}/login"): "The password step of the login (answers a login transaction, not a session).",
    ("POST", f"{AUTH}/mfa"): "The second-factor step of the login, bound to its login transaction.",
    ("POST", f"{AUTH}/mfa/email"): "Sends the emailed code of a login transaction (off by default, D5).",
    ("POST", f"{AUTH}/mfa/passkey/options"): "The passkey challenge of a login transaction.",
    ("GET", "/admin/invalidate/{token}"): "The kill-switch link of the login alert: the owner may have no session "
    "(plan 9.5); the one-time token is the credential.",
    ("POST", "/admin/invalidate/{token}"): "Confirms the kill switch; the same one-time token is the credential.",
}
"""The only routes that answer without an admin session, each with its reason (plan 19.7)."""

ENROLLMENT: dict[str, str] = {
    "/admin/enroll": "The authenticator enrollment page of a first login (D5).",
    f"{AUTH}/totp/enroll/start": "Starts the TOTP enrollment.",
    f"{AUTH}/totp/enroll/confirm": "Confirms the TOTP enrollment and issues the recovery codes.",
    f"{AUTH}/session": "The enrollment page reads its session and CSRF token.",
    f"{AUTH}/logout": "A bootstrap session can always end itself.",
    f"{AUTH}/heartbeat": "Keeps the enrollment page's session alive while the admin types.",
}
"""Routes a bootstrap session (password plus emailed code, before TOTP enrollment) may use. They still need that
session: signed out they answer 401 or redirect like every other route."""

SENSITIVE: dict[tuple[str, str], str] = {
    ("POST", f"{AUTH}/recovery-codes/regenerate"): "Recovery codes (plan 9.6).",
    ("POST", f"{AUTH}/passkeys/register/options"): "Manage passkeys (plan 9.6).",
    ("POST", f"{AUTH}/passkeys/register/verify"): "Manage passkeys (plan 9.6).",
    ("POST", f"{AUTH}/passkeys/{{passkey_id}}/delete"): "Manage passkeys (plan 9.6).",
    ("PATCH", f"{API}/security/passkeys/{{passkey_id}}"): "Manage passkeys (plan 9.6).",
    ("DELETE", f"{API}/security/passkeys/{{passkey_id}}"): "Manage passkeys (plan 9.6).",
    ("POST", f"{API}/security/recovery-codes/regenerate"): "Recovery codes (plan 9.6).",
    ("POST", f"{API}/data/resets/factory"): "Factory reset, the full data reset (plan 9.6, 6.8).",
    ("POST", f"{API}/credential/replace"): "Replace the credential (plan 9.6, C1).",
    ("DELETE", f"{API}/credential/ui-value"): "Delete the credential's dashboard value (C1 account switch).",
    ("POST", f"{API}/credential/confirm-account"): "Confirm an account switch (C1).",
    ("POST", f"{API}/credential/check"): "Spends a call on the Roblox account (13.3).",
    ("POST", f"{API}/credential-allowlist"): "Widens what the credential is used for (D1, C1).",
    ("PATCH", f"{API}/credential-allowlist/{{row_id}}"): "Changes what the credential is used for (D1, C1).",
    ("PUT", f"{API}/rotator/url"): "Replace the rotator URL (plan 9.6).",
    ("DELETE", f"{API}/rotator/url"): "Revert the rotator URL (plan 9.6).",
    ("POST", f"{API}/egress/{{name}}/enable"): "Re-enable an egress the leak guard switched off (C2).",
    ("POST", f"{API}/protection/access/allow_admin"): "The admin network allowlist (D6).",
    ("DELETE", f"{API}/protection/access/allow_admin/{{entry_id}}"): "The admin network allowlist (D6).",
    ("POST", f"{API}/protection/spam/arm"): "Arms the spam auto-ban after the collateral preview (plan 10.3).",
}
"""Routes guarded by `require_admin("fresh_mfa")` itself, each with its reason."""

TASK_SENSITIVE: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", f"{API}/credential/replace"),
        ("DELETE", f"{API}/credential/ui-value"),
        ("PUT", f"{API}/rotator/url"),
        ("DELETE", f"{API}/rotator/url"),
        ("POST", f"{API}/egress/{{name}}/enable"),
        ("POST", f"{AUTH}/passkeys/register/options"),
        ("POST", f"{AUTH}/passkeys/{{passkey_id}}/delete"),
        ("DELETE", f"{API}/security/passkeys/{{passkey_id}}"),
        ("POST", f"{AUTH}/recovery-codes/regenerate"),
        ("POST", f"{API}/security/recovery-codes/regenerate"),
        ("POST", f"{API}/data/resets/factory"),
    }
)
"""The sensitive actions the assembly task names (plan 9.6 and DESIGN.md section 13); the LLM export's full detail
and health runs with the credential check are the conditional ones below."""

SAMPLES: dict[str, str] = {
    "bucket_key": "host:games.roblox.com",
    "dataset": "requests",
    "ip": "203.0.113.9",
    "key": "cache_ttl_seconds",
    "kind": "deny",
    "name": "direct",
    "op_id": "reset_0123456789abcdef",
    "place": "12345",
    "rec_id": "rec_01JABCDEFGHJKMNPQRSTVWXYZ0",
    "request_id": "01JABCDEFGHJKMNPQRSTVWXYZ0",
    "rest": "nothing-here",
    "rule": "UP-429-ENDPOINT",
    "rule_id": "1",
    "session_id": "a" * 16,
    "token": "x" * 43,
}
"""Path parameter values (`1` for everything else). The guards run before any parameter is validated."""

_PARAM_RE = re.compile(r"\{([^}:]+)(?::[^}]+)?\}")
_CONVERTOR_RE = re.compile(r"\{([^}:]+):[^}]+\}")
"""`{bucket_key:path}` in a route template is `{bucket_key}` in the OpenAPI document."""


def concrete(path: str) -> str:
    """A request path for a route template."""
    return _PARAM_RE.sub(lambda match: SAMPLES.get(match.group(1), "1"), path)


@dataclass(frozen=True, slots=True)
class AdminRoute:
    """One discovered route: its template, methods, guard scopes (`session`, `fresh_mfa`, `csrf`) and name."""

    path: str
    method: str
    scopes: frozenset[str]
    name: str

    @property
    def guarded(self) -> bool:
        return bool(self.scopes & {"session", "fresh_mfa"})

    @property
    def api(self) -> bool:
        return is_admin_api_path(self.path)

    @property
    def key(self) -> tuple[str, str]:
        return (self.method, self.path)


def discover(app: Any) -> list[AdminRoute]:
    """Every (method, path) the app serves under `/admin`, plus `/csp-report` (first occurrence wins, as routing)."""
    found: dict[tuple[str, str], AdminRoute] = {}
    for context in iter_route_contexts(app.router.routes):
        path = str(context.path or "")
        if not (path == "/admin" or path.startswith("/admin/") or path == "/csp-report"):
            continue
        dependant = getattr(context, "dependant", None) or getattr(context.original_route, "dependant", None)
        scopes = guard_scopes(dependant) if dependant is not None else frozenset()
        for method in sorted(context.methods or ()):
            found.setdefault((method, path), AdminRoute(path, method, scopes, str(context.name or "")))
    return list(found.values())


def checked(routes: list[AdminRoute]) -> list[AdminRoute]:
    """The routes the generic checks apply to: not the catch-all, not the development gallery."""
    return [r for r in routes if r.path != CATCH_ALL and not r.path.startswith(GALLERY)]


@dataclass
class Site:
    """The running app, a signed-in admin (fresh second factor) and a second session of the same admin."""

    harness: AuthHarness
    admin: TestAdmin
    other: httpx.AsyncClient
    routes: list[AdminRoute]

    def headers(self, *, csrf: str | None = None, **extra: str) -> dict[str, str]:
        out = self.harness.headers(csrf=csrf)
        out.update(extra)
        return out

    async def send(
        self,
        client: httpx.AsyncClient,
        method: str,
        path: str,
        *,
        csrf: str | None = None,
        json: Any = None,
        params: dict[str, str] | None = None,
    ) -> httpx.Response:
        body: Any = ({} if json is None else json) if method in UNSAFE else None
        return await client.request(method, path, headers=self.headers(csrf=csrf), json=body, params=params)

    def make_mfa_stale(self) -> None:
        self.harness.clock.advance(int(self.harness.ctx.settings.int("admin_reauth_window_s")) + 1)


@pytest.fixture
async def site(env: Any, fake_clock: Any, credentials_dir: Path, respx_mock: Any) -> AsyncIterator[Site]:
    for name in ("smtp_password", "alert_webhook_url"):
        (credentials_dir / name).unlink(missing_ok=True)  # the startup notifier only logs
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as harness:
        await harness.set_settings(tarpit_enabled=0, rotator_enabled=0)
        admin = harness.admin()
        assert (await harness.login(admin)).status_code == 200
        other = harness.new_client()
        assert (await harness.login(admin, client=other)).status_code == 200
        yield Site(harness, admin, other, discover(harness.app))


def _section13_code(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    error = body.get("error") if isinstance(body, dict) else None
    return error.get("code") if isinstance(error, dict) else None


# ============================================================================================ discovery


async def test_discovery_covers_every_mounted_module_and_the_catch_all_is_last(site: Site) -> None:
    paths = {route.path for route in site.routes}
    assert len(site.routes) > 250, len(site.routes)
    for name in MOUNTED:
        module = sys.modules[name]
        prefix = f"{API}{module.router.prefix}"
        assert any(path == prefix or path.startswith(prefix + "/") for path in paths), name
    for path in (f"{API}/stream", f"{API}/openapi.json", "/admin", f"{AUTH}/login", "/csp-report"):
        assert path in paths, path
    admin_routes = admin_router.router.routes
    assert getattr(admin_routes[-1], "name", "") == "admin_not_found"
    unknown_api = await site.harness.http.get(f"{API}/no-such-area", headers=site.headers())
    assert unknown_api.status_code == 404
    assert _section13_code(unknown_api) == "not_found"
    unknown_page = await site.harness.http.post("/admin/no-such-page", headers=site.headers())
    assert unknown_page.status_code == 404
    assert unknown_page.content == b'"Not Found"\n'


def test_every_api_module_and_the_event_stream_are_mounted() -> None:
    assert set(MOUNTED) == {f"roxy.admin.api.{name}" for name in API_MODULES} | {SSE_MODULE}
    prefixes = [sys.modules[name].router.prefix for name in MOUNTED]
    for index, prefix in enumerate(prefixes):
        nested_later = [p for p in prefixes[index + 1 :] if p.startswith(prefix + "/")]
        assert nested_later == [], f"{prefix} is mounted before {nested_later}, whose paths it could shadow"


def test_unguarded_routes_are_exactly_the_documented_exceptions(site: Site) -> None:
    unguarded = {route.key for route in checked(site.routes) if not route.guarded}
    assert unguarded == set(PUBLIC), (sorted(unguarded - set(PUBLIC)), sorted(set(PUBLIC) - unguarded))
    assert set(ENROLL_PATHS) == set(ENROLLMENT)
    for path in ENROLLMENT:
        assert any(route.path == path and route.guarded for route in site.routes), path
    unsafe_without_csrf = {
        route.key
        for route in checked(site.routes)
        if route.guarded and route.method in UNSAFE and "csrf" not in route.scopes
    }
    assert unsafe_without_csrf == set()


def test_fresh_mfa_routes_are_exactly_the_documented_sensitive_ones(site: Site) -> None:
    fresh = {route.key for route in site.routes if "fresh_mfa" in route.scopes}
    assert fresh == set(SENSITIVE), (sorted(fresh - set(SENSITIVE)), sorted(set(SENSITIVE) - fresh))
    assert set(SENSITIVE) >= TASK_SENSITIVE
    assert all(SENSITIVE.values())


# ============================================================================================ signed out


async def test_signed_out_requests_get_401_or_the_login_redirect(site: Site) -> None:
    anonymous = site.harness.new_client()
    failures: list[str] = []
    for route in checked(site.routes):
        if not route.guarded:
            continue
        response = await site.send(anonymous, route.method, concrete(route.path))
        if route.api:
            if response.status_code != 401:
                failures.append(f"{route.method} {route.path}: {response.status_code} {response.text[:120]}")
        elif response.status_code != 302 or response.headers.get("location") != "/admin":
            failures.append(f"{route.method} {route.path}: {response.status_code} {response.headers.get('location')}")
    assert failures == [], "\n".join(failures)


async def test_signed_out_api_answers_use_the_section13_body(site: Site) -> None:
    anonymous = site.harness.new_client()
    for path in (f"{API}/settings", f"{API}/stream", f"{AUTH}/sessions"):
        response = await anonymous.get(path, headers=site.headers())
        assert response.status_code == 401
        assert response.json() == {"error": {"code": "unauthorized", "message": "Session expired", "fields": {}}}


# ============================================================================================ CSRF


async def test_state_changing_routes_reject_missing_wrong_and_foreign_csrf_tokens(site: Site) -> None:
    harness = site.harness
    foreign = await harness.csrf(client=site.other)  # valid, but for the other session
    variants = {"missing": None, "garbage": "x" * 44, "other session": foreign}
    failures: list[str] = []
    unsafe = [r for r in checked(site.routes) if r.guarded and r.method in UNSAFE]
    assert len(unsafe) > 100, len(unsafe)
    for route in unsafe:
        for label, token in variants.items():
            response = await site.send(harness.http, route.method, concrete(route.path), csrf=token)
            if response.status_code != 403 or response.headers.get("roxy-reauth"):
                failures.append(f"{route.method} {route.path} ({label}): {response.status_code} {response.text[:120]}")
    assert failures == [], "\n".join(failures)
    # Nothing ran: the session was not logged out or revoked by any of the refused requests.
    assert (await harness.http.get(f"{AUTH}/session", headers=site.headers())).status_code == 200


# ============================================================================================ fresh MFA


async def _security_recommendation(site: Site) -> tuple[str, str]:
    """An open recommendation whose change touches admin security (its apply needs a fresh second factor), and the
    digest of its changes."""
    clock = site.harness.clock
    now = clock.now()
    rec = Recommendation(
        rule_id="SEC-DEFAULTS",
        family=INSIGHT_RULES["SEC-DEFAULTS"].family,
        subject="sessions",
        title="A safer session timeout",
        evidence=Evidence(sample_size=1),
        changes=[ProposedChange("setting", key="admin_session_idle_timeout_s", current=900, proposed=1800)],
    )
    rec.id, rec.fingerprint, rec.state = new_id("rec", clock), make_fingerprint(rec.rule_id, rec.subject), "open"
    rec.created_at = rec.updated_at = now
    await site.harness.ctx.dbs.metrics.write(lambda conn: write_recommendation(conn, rec))
    return rec.id, changes_digest(rec.changes)


async def test_sensitive_routes_answer_reauth_required_without_a_fresh_second_factor(site: Site) -> None:
    harness = site.harness
    rec_id, digest = await _security_recommendation(site)
    conditional: list[tuple[str, str, dict[str, Any], str]] = [
        ("POST", f"{API}/health/runs", {"json": {"include_credential": True}}, "health run with the credential check"),
        ("GET", f"{API}/export/llm", {"params": {"detail": "full"}}, "full LLM export (plan 12.2)"),
        ("POST", f"{API}/recommendations/{rec_id}/apply", {"json": {"changes_digest": digest}}, "security change"),
    ]
    token = await harness.csrf()
    site.make_mfa_stale()
    failures: list[str] = []
    requests: list[tuple[str, str, dict[str, Any], str]] = [
        (method, concrete(path), {}, path) for method, path in SENSITIVE
    ]
    requests += [(method, path, extra, label) for method, path, extra, label in conditional]
    for method, path, extra, label in requests:
        response = await site.send(harness.http, method, path, csrf=token, **extra)
        problems = []
        if response.status_code != 403:
            problems.append(f"status {response.status_code}")
        if response.headers.get("roxy-reauth") != "required":
            problems.append("no Roxy-Reauth header")
        if not path.startswith(AUTH) and _section13_code(response) != "reauth_required":
            problems.append(f"body {response.text[:120]}")
        if problems:
            failures.append(f"{method} {label}: {', '.join(problems)}")
    assert failures == [], "\n".join(failures)
    # The sensitive variants alone need the fresh factor: the summary export works with this session.
    summary = await site.send(harness.http, "GET", f"{API}/export/llm", params={"detail": "summary"})
    assert summary.status_code == 200, summary.text[:200]


async def test_auth_route_reauth_answers_use_the_section13_body(site: Site) -> None:
    token = await site.harness.csrf()
    site.make_mfa_stale()
    response = await site.send(site.harness.http, "POST", f"{AUTH}/recovery-codes/regenerate", csrf=token)
    assert response.status_code == 403
    assert _section13_code(response) == "reauth_required"


# ============================================================================================ OpenAPI


async def test_openapi_is_served_to_a_signed_in_admin_only_and_lists_every_module(site: Site) -> None:
    harness = site.harness
    anonymous = harness.new_client()
    assert (await anonymous.get(admin_api.OPENAPI_URL, headers=site.headers())).status_code == 401
    for public in ("/openapi.json", "/docs/openapi.json", "/redoc"):
        answer = await anonymous.get(public, headers=site.headers())
        assert not (answer.status_code == 200 and b'"openapi"' in answer.content[:200]), public
    response = await harness.http.get(admin_api.OPENAPI_URL, headers=site.headers())
    assert response.status_code == 200, response.text[:200]
    assert response.headers.get("cache-control") == "no-store"
    document = response.json()
    assert document["openapi"].startswith("3.")
    assert document["info"]["title"] == "Roxy admin API"
    paths: dict[str, dict[str, Any]] = document["paths"]
    assert all(path.startswith(API + "/") for path in paths)
    assert admin_api.OPENAPI_URL not in paths
    used_tags = {tag for operations in paths.values() for operation in operations.values() for tag in operation["tags"]}
    for name in MOUNTED:
        tag = sys.modules[name].router.tags[0]
        assert tag in used_tags, name
    documented = {(method.upper(), path) for path, operations in paths.items() for method in operations}
    prefixes = tuple(f"{API}{sys.modules[name].router.prefix}" for name in MOUNTED)
    area_routes = [route for route in site.routes if route.path.startswith(prefixes)]
    assert len(area_routes) > 200
    missing = [
        route.key for route in area_routes if (route.method, _CONVERTOR_RE.sub(r"{\1}", route.path)) not in documented
    ]
    assert missing == []  # every route of every area module and the stream (the login surface is not in the schema)
    again = await harness.http.get(admin_api.OPENAPI_URL, headers=site.headers())
    assert again.json() == document


# ============================================================================================ gallery and pages


async def test_the_gallery_exists_in_development_only(site: Site) -> None:
    from roxy.admin import gallery

    served = {route.path for route in site.routes if route.path.startswith(GALLERY)}
    assert served == set(gallery.gallery_routes())  # this app runs with ROXY_ENV=development
    assert getattr(site.harness.app.state, admin_router.GALLERY_STATE) is True
    assert admin_router.mount_development_gallery(site.harness.app) is True  # once per app
    assert len([r for r in discover(site.harness.app) if r.path.startswith(GALLERY)]) == len(
        [r for r in site.routes if r.path.startswith(GALLERY)]
    )

    production = FastAPI()
    production.state.env = types.SimpleNamespace(is_development=False)
    async with admin_router.admin_lifespan(production):
        pass
    assert not any(str(c.path or "").startswith(GALLERY) for c in iter_route_contexts(production.router.routes))
    assert getattr(production.state, admin_router.GALLERY_STATE, False) is False


def test_the_pages_include_point_refuses_unguarded_or_misplaced_pages() -> None:
    good = APIRouter()

    @good.get("/admin/overview")
    async def overview(_admin: AdminSession) -> dict[str, bool]:
        return {}

    @good.post("/admin/overview/note")
    async def note(_admin: AdminSession, _csrf: CsrfChecked) -> dict[str, bool]:
        return {}

    assert admin_router.check_page_router("pages", good) is good

    open_page = APIRouter()

    @open_page.get("/admin/leaky")
    async def leaky() -> dict[str, bool]:
        return {}

    no_csrf = APIRouter()

    @no_csrf.post("/admin/form")
    async def form(_admin: AdminSession) -> dict[str, bool]:
        return {}

    api_page = APIRouter()

    @api_page.get(f"{API}/settings/page")
    async def in_api(_admin: AdminSession) -> dict[str, bool]:
        return {}

    for bad, rule in ((open_page, "require_admin"), (no_csrf, "require_csrf"), (api_page, "not a dashboard page")):
        with pytest.raises(ApiMountError, match=rule):
            admin_router.check_page_router("pages", bad)
    with pytest.raises(ApiMountError, match="APIRouter"):
        admin_router.check_page_router("pages", object())


# ============================================================================================ mounting rules


@pytest.fixture
def nested_modules() -> Iterator[tuple[str, str]]:
    parent = area_router("zzparent")

    @parent.get("/{item}")
    async def item(item: str, _admin: AdminSession) -> dict[str, str]:
        return {"from": "parent"}

    child = APIRouter(prefix="/zzparent/child", tags=["zzchild"], route_class=parent.route_class)

    @child.get("")
    async def own(_admin: AdminSession) -> dict[str, str]:
        return {"from": "child"}

    names = ("zz_parent_area", "zz_child_area")
    for name, router in zip(names, (parent, child), strict=True):
        module = types.ModuleType(f"roxy.admin.api.{name}")
        module.router = router  # type: ignore[attr-defined]
        sys.modules[module.__name__] = module
    try:
        yield names
    finally:
        for name in names:
            sys.modules.pop(f"roxy.admin.api.{name}", None)


def test_a_nested_area_prefix_is_mounted_before_its_parent(nested_modules: tuple[str, str]) -> None:
    router, mounted = build_api_router(nested_modules, sse=None)
    assert mounted == ("roxy.admin.api.zz_child_area", "roxy.admin.api.zz_parent_area")
    order = [str(context.path) for context in iter_route_contexts(router.routes)]
    assert order == [f"{API}/zzparent/child", f"{API}/zzparent/{{item}}"]


def test_the_api_package_builds_its_router_lazily_whatever_is_imported_first() -> None:
    code = (
        "import roxy.admin.sse, roxy.admin.api.recommendations\n"
        "import roxy.admin.router as r\n"
        "from roxy.admin.api import MOUNTED\n"
        "assert 'roxy.admin.sse' in MOUNTED, MOUNTED\n"
        "print(len(MOUNTED))\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=90, check=False)
    assert result.returncode == 0, result.stderr[-2000:]
    assert int(result.stdout.strip()) == len(API_MODULES) + 1


def test_guard_scopes_reads_every_guard_form() -> None:
    router = area_router("zzscopes")

    @router.post("/x")
    async def change(_admin: AdminSession, _csrf: CsrfChecked) -> dict[str, bool]:
        return {}

    @router.get("/y", dependencies=[Depends(require_admin("fresh_mfa"))])
    async def read() -> dict[str, bool]:
        return {}

    @router.get("/z")
    async def open_read() -> dict[str, bool]:
        return {}

    scopes = {
        str(context.path): guard_scopes(getattr(context.original_route, "dependant", None))
        for context in iter_route_contexts(router.routes)
    }
    assert scopes == {
        "/zzscopes/x": frozenset({"session", "csrf"}),
        "/zzscopes/y": frozenset({"fresh_mfa"}),
        "/zzscopes/z": frozenset(),
    }
