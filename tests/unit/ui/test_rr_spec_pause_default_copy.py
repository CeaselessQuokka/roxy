"""Reviewer finding spec-3: the admin layout must not keep its own copy of the live `pause_message_default` text.

What this is
    Tests that the admin shell tells the owner exactly what paused or emergency-limited callers receive: the pause
    banner's and the emergency-limit banner's "Callers see:" lines, and the placeholder and hint of the message
    fields in the pause and emergency-limit dialogs. Their text comes from the `status` context, built by
    `roxy.admin.gallery.caller_texts` from the live setting, never from a copy inside a template.

Why it exists
    Fix pass 1 (spec F3) made the 503 body read the live setting `pause_message_default` (plan 7.13, 15.3 K), and
    throttle-all without a reason sends the same text (v1 B6). The banner still printed `st.pause_reason or "Service
    down for maintenance."` and the dialog repeated the catalog text, so after an admin changed the setting the owner
    was told callers see the old text while callers got the new one. Plan P3 (one source of truth) and plan 15.6
    (the setting's home is the top bar pause dialog, `topbar#pause`) ask for the live value on these surfaces.

How it works
    The source scan proves no admin template or component holds the catalog default. The render tests build the
    `status` context with `caller_texts` and a changed live default, render the real templates and read the
    quoted text, placeholders and hints. One test drives the gallery page with a stand-in settings store, the way a
    dashboard page reads the live value. Without the caller-text keys the layout must make no claim at all.

What to read next
    `src/roxy/templates/admin/_layout/banners.html`, `src/roxy/templates/admin/_layout/control_dialogs.html`,
    `roxy/admin/gallery.py` (`caller_texts`), `roxy/abuse/pause.py` (`PauseState.message`),
    `roxy/abuse/messages.py` (`downtime_default`).
"""

from __future__ import annotations

import html as html_lib
import re
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from roxy.abuse.pause import PauseState
from roxy.abuse.throttle_all import ThrottleAllState
from roxy.admin import gallery
from roxy.config.catalog import CATALOG
from roxy.config.env import EnvSettings
from roxy.core.templating import STATIC_DIR, AssetHasher, HashedStaticFiles, Templates

TEMPLATE_ROOT = Path(__file__).resolve().parents[3] / "src" / "roxy" / "templates"
TEMPLATE_DIR = TEMPLATE_ROOT / "admin" / "_layout"
CATALOG_DEFAULT = str(CATALOG["pause_message_default"].default)
LIVE_DEFAULT = "Back at 5 pm; follow the status page."
"""A value an admin could set: different from the catalog default, and with a character HTML must escape."""
NOW = 1_800_000_000.0

ENV = Templates().env


def render(name: str, status: Mapping[str, Any]) -> str:
    return ENV.get_template(f"admin/_layout/{name}").render({"status": dict(status)})


def texts(pause: PauseState, limit: ThrottleAllState, default: object = LIVE_DEFAULT) -> dict[str, str]:
    return gallery.caller_texts(pause, limit, now=NOW, pause_message_default=default)


def quoted(html: str) -> list[str]:
    """Every `<q>` text of a rendered fragment, unescaped."""
    return [html_lib.unescape(text) for text in re.findall(r"<q>(.*?)</q>", html, re.DOTALL)]


def field(html: str, field_id: str) -> tuple[str | None, str]:
    """(placeholder or None, hint text) of one message field of the control dialogs."""
    tag = re.search(rf'<input [^>]*id="{field_id}"[^>]*>', html)
    assert tag is not None, field_id
    placeholder = re.search(r'placeholder="([^"]*)"', tag.group(0))
    hint = re.search(rf'<p class="field__hint" id="{field_id}-hint">(.*?)</p>', html, re.DOTALL)
    assert hint is not None, f"{field_id} has no hint"
    assert f'aria-describedby="{field_id}-hint"' in tag.group(0)
    hint_text = html_lib.unescape(re.sub(r"<[^>]+>", "", hint.group(1)))
    return (html_lib.unescape(placeholder.group(1)) if placeholder else None), hint_text


# ------------------------------------------------------------------------------------------- no copy in templates


@pytest.mark.parametrize("name", ["banners.html", "control_dialogs.html"])
def test_spec_3_layout_has_no_copy_of_the_live_pause_default(name: str) -> None:
    source = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
    assert CATALOG_DEFAULT not in source


def test_spec_3_no_admin_template_or_component_copies_the_pause_default() -> None:
    """The whole shell and every component: the text lives in the catalog and reaches pages only as data."""
    sources = sorted((TEMPLATE_ROOT / "admin").rglob("*.html")) + sorted((TEMPLATE_ROOT / "components").glob("*.html"))
    assert len(sources) > 10
    offenders = [path.name for path in sources if CATALOG_DEFAULT in path.read_text(encoding="utf-8")]
    assert offenders == []


# ------------------------------------------------------------------------------------------- the banners


def test_spec_3_pause_banner_quotes_the_live_default_callers_get() -> None:
    status = {
        "paused": True,
        "pause_reason": "",
        "pause_drops": 3,
        **texts(PauseState(paused=True), ThrottleAllState()),
    }
    html = render("banners.html", status)
    assert "The proxy is paused." in html
    assert quoted(html) == [LIVE_DEFAULT]
    assert CATALOG_DEFAULT not in html


def test_spec_3_pause_banner_quotes_the_reason_and_the_scheduled_reason() -> None:
    manual = PauseState(paused=True, reason="  Moving servers.  ")
    assert quoted(render("banners.html", {"paused": True, **texts(manual, ThrottleAllState())})) == ["Moving servers."]
    window = PauseState(scheduled_start=int(NOW) - 60, scheduled_end=int(NOW) + 60, scheduled_reason="Planned work.")
    assert window.active(NOW)
    html = render("banners.html", {"paused": True, **texts(window, ThrottleAllState())})
    assert quoted(html) == ["Planned work."]  # inside a scheduled window callers get the scheduled reason


def test_spec_3_emergency_limit_banner_says_the_pause_default_when_no_reason_was_given() -> None:
    """v1 B6, kept: throttle-all without a reason sends the pause default, so the banner must say so."""
    status = {"throttle_all": True, "throttle_limit": 1, **texts(PauseState(), ThrottleAllState(enabled=True))}
    assert quoted(render("banners.html", status)) == [LIVE_DEFAULT]
    with_reason = texts(PauseState(), ThrottleAllState(enabled=True, reason="High load."))
    assert quoted(render("banners.html", {"throttle_all": True, **with_reason})) == ["High load."]


def test_spec_3_an_empty_live_default_is_quoted_as_callers_get_it() -> None:
    """A blank setting never sends a blank body (`downtime_default`), and the banner says the text actually sent."""
    status = {"paused": True, **texts(PauseState(paused=True), ThrottleAllState(), default="   ")}
    assert quoted(render("banners.html", status)) == [CATALOG_DEFAULT]


def test_spec_3_without_caller_texts_the_banners_make_no_claim() -> None:
    """A page that does not pass the keys gets no "Callers see" line rather than a guess."""
    html = render("banners.html", {"paused": True, "pause_drops": 3, "throttle_all": True, "throttle_limit": 5})
    assert "The proxy is paused." in html
    assert "Callers see" not in html
    assert quoted(html) == []


# ------------------------------------------------------------------------------------------- the dialogs


def test_spec_3_dialogs_name_the_live_default_for_an_empty_message() -> None:
    html = render("control_dialogs.html", texts(PauseState(), ThrottleAllState()))
    for field_id in ("dlg-pause-message", "dlg-limit-message"):
        placeholder, hint = field(html, field_id)
        assert placeholder == LIVE_DEFAULT, field_id
        assert hint == f"Leave it empty to send the default pause message: {LIVE_DEFAULT}.", field_id
    assert CATALOG_DEFAULT not in html


def test_spec_3_dialogs_keep_the_stored_reason_as_the_value() -> None:
    status = {
        "pause_reason": "Moving servers.",
        "throttle_reason": "High load.",
        **texts(PauseState(), ThrottleAllState()),
    }
    html = render("control_dialogs.html", status)
    assert re.search(r'id="dlg-pause-message" [^>]*value="Moving servers\."', html)
    assert re.search(r'id="dlg-limit-message" [^>]*value="High load\."', html)


def test_spec_3_without_caller_texts_the_dialogs_name_the_setting_only() -> None:
    html = render("control_dialogs.html", {})
    for field_id in ("dlg-pause-message", "dlg-limit-message"):
        placeholder, hint = field(html, field_id)
        assert placeholder is None, field_id
        assert hint == "Leave it empty to send the default pause message.", field_id


# ------------------------------------------------------------------------------------------- the producer


def test_spec_3_caller_texts_follow_the_abuse_message_code() -> None:
    """`caller_texts` asks the same functions the pause and throttle-all checks use for their bodies."""
    pause = PauseState(paused=True)
    limit = ThrottleAllState(enabled=True, reason="High load.")
    result = texts(pause, limit)
    assert result == {
        "pause_message": pause.message(NOW, LIVE_DEFAULT)[0],
        "pause_default": LIVE_DEFAULT,
        "throttle_message": limit.message(LIVE_DEFAULT)[0],
    }
    assert result["pause_message"] == LIVE_DEFAULT
    assert result["throttle_message"] == "High load."


class StubSettings:
    """The one method of `RuntimeSettings` a page reads here: `get(key)` over a snapshot."""

    def __init__(self, values: Mapping[str, Any]) -> None:
        self.values = dict(values)

    def get(self, key: str) -> Any:
        return self.values[key]


def _gallery_app(tmp_path: Path, settings: StubSettings | None) -> FastAPI:
    app = FastAPI()
    app.state.env = EnvSettings(env="development", state_dir=tmp_path, site_origin="http://localhost")
    hasher = AssetHasher(STATIC_DIR)
    app.state.templates = Templates(hasher=hasher)
    app.mount("/static", HashedStaticFiles(directory=STATIC_DIR, hasher=hasher), name="static")
    if settings is not None:
        app.state.ctx = SimpleNamespace(settings=settings)
    app.include_router(gallery.router)
    return app


@pytest.mark.parametrize("live", [LIVE_DEFAULT, None], ids=["changed_setting", "no_settings_store"])
async def test_spec_3_gallery_shell_quotes_the_live_setting(tmp_path: Path, live: str | None) -> None:
    """The gallery renders the real shell the way a page does: the live value, or the catalog's in a bare app."""
    settings = StubSettings({"pause_message_default": live}) if live is not None else None
    transport = httpx.ASGITransport(app=_gallery_app(tmp_path, settings))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        response = await client.get(gallery.GALLERY_PREFIX)
    assert response.status_code == 200
    expected = live if live is not None else CATALOG_DEFAULT
    for field_id in ("dlg-pause-message", "dlg-limit-message"):
        placeholder, hint = field(response.text, field_id)
        assert placeholder == expected, field_id
        assert hint.endswith(f": {expected}."), field_id
    banners = response.text.split('id="g-banners"', 1)[1].split('id="g-controls"', 1)[0]
    assert quoted(banners) == ["Back in about 10 minutes.", "High load; please slow down."]
