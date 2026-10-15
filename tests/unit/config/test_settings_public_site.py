"""Catalog content tests for settings group K (Public site and compatibility) plus `ui_timezone`/`ui_default_theme`.

These pin plan 15.3 K: every key is present with the plan default, every default is valid against its own
limits, the help text an admin needs is filled in, the `site_*` defaults follow the owner's answers B13 and B15
(2026-10-14: the contact says where, no bug bounty, no support links), the under-construction switches and their
message follow the owner's request of 2026-10-15, and nothing breaks the style rule C5. The v1 home page links are
checked on the page itself (tests/integration/test_public_pages.py).
"""

import dataclasses
import re
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from roxy.config.insight_params import INSIGHT_RULES
from roxy.config.settings import public_site
from roxy.config.spec import Apply, Group, Risk, SettingSpec, SettingType

EXPECTED_K_DEFAULTS: dict[str, Any] = {
    "pause_message_default": "Service down for maintenance.",
    "compat_collapse_upstream_errors": 0,  # D4, DESIGN.md section 0
    "public_cors_allow_any_origin": 0,
    "public_status_page_enabled": 1,
    "ui_timezone": "America/New_York",
    "ui_default_theme": "dark",
    # Owner request 2026-10-15: pages under construction, every switch off, and the page's message.
    "public_home_under_construction": 0,
    "public_docs_under_construction": 0,
    "public_status_under_construction": 0,
    "site_construction_text": "Roxy's site is being updated. Check back soon.",
}
CONSTRUCTION_SWITCHES = (
    "public_home_under_construction",
    "public_docs_under_construction",
    "public_status_under_construction",
)
EXPECTED_SITE_KEYS = [
    "site_contact_name",
    "site_bug_bounty_text",
    "site_hosting_note",
    "site_support_links",
    "site_white_hats_text",
    "site_footer_text",
]
EXPECTED_KEYS = set(EXPECTED_K_DEFAULTS) | set(EXPECTED_SITE_KEYS)
DASHBOARD_KEYS = {"ui_timezone", "ui_default_theme"}

# Owner answers B13 and B15 (2026-10-14): no bug bounty and no support links for now. An empty text hides its part
# of the home page, so these two ship empty; every other text has a default.
EMPTY_BY_DEFAULT = {"site_bug_bounty_text", "site_support_links"}

# DESIGN.md section 9 anchors that this group may use.
ALLOWED_PAGES = {"settings#public-site", "topbar#pause", "user-menu#preferences"}

DASHES = (chr(0x2014), chr(0x2013))  # em dash, en dash
BRITISH = [
    r"behavio[u]r",
    r"colo[u]r",
    r"favo[u]r",
    r"optimi[s]e",
    r"analy[s]e",
    r"normali[s]e",
    r"cancel[l]ed",
    r"label[l]ed",
    r"catalo[g]ue",
    r"licen[c]e",
    r"defen[c]e",
    r"whi[l]st",
    r"amon[g]st",
]


def _by_key() -> dict[str, SettingSpec]:
    return {spec.key: spec for spec in public_site.SETTINGS}


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return [s for f in dataclasses.fields(value) for s in _strings(getattr(value, f.name))]
    if isinstance(value, (tuple, list)):
        return [s for item in value for s in _strings(item)]
    return []


def test_every_group_k_key_present_once() -> None:
    keys = [spec.key for spec in public_site.SETTINGS]
    assert len(keys) == len(set(keys))
    assert set(keys) == EXPECTED_KEYS


@pytest.mark.parametrize("key", sorted(EXPECTED_K_DEFAULTS))
def test_defaults_match_plan(key: str) -> None:
    assert _by_key()[key].default == EXPECTED_K_DEFAULTS[key]


@pytest.mark.parametrize("spec", public_site.SETTINGS, ids=lambda s: s.key)
def test_spec_complete_and_default_valid(spec: SettingSpec) -> None:
    expected_group = Group.DASHBOARD if spec.key in DASHBOARD_KEYS else Group.PUBLIC_SITE
    assert spec.group == expected_group
    assert spec.label.strip()
    assert spec.description.strip()
    assert spec.pages
    assert set(spec.pages) <= ALLOWED_PAGES
    if spec.key in DASHBOARD_KEYS:
        assert spec.pages == ("user-menu#preferences",)
    assert spec.apply == Apply.LIVE
    assert spec.auto_apply_bounds is None
    assert not spec.sensitive
    assert set(spec.related_recommendations) <= set(INSIGHT_RULES)
    match spec.type:
        case SettingType.BOOL:
            assert spec.default in (0, 1)
            assert spec.if_enabled.strip()
            assert spec.if_disabled.strip()
        case SettingType.ENUM:
            assert spec.default in spec.option_values()
            assert len(set(spec.option_values())) == len(spec.options)
            for option in spec.options:
                assert option.label.strip()
                assert option.description.strip()
        case SettingType.STRING:
            assert isinstance(spec.default, str)
            assert (spec.default == "") if spec.key in EMPTY_BY_DEFAULT else spec.default.strip()
            assert spec.max_length is not None
            assert len(spec.default) <= spec.max_length
        case _:
            pytest.fail(f"unexpected type {spec.type} for {spec.key}")
    for condition in spec.high_risk_if:
        assert condition.why.strip()
    assert spec.is_high_risk_value(spec.default) is None
    for text in _strings(spec):
        for dash in DASHES:
            assert dash not in text, spec.key
        for pattern in BRITISH:
            assert not re.search(pattern, text, re.IGNORECASE), f"{spec.key}: {pattern}"


def test_site_text_limits_and_https_links() -> None:
    by_key = _by_key()
    for key in EXPECTED_SITE_KEYS:
        spec = by_key[key]
        assert spec.max_length == 2000
        assert not spec.pending_owner_verification  # D18 texts confirmed by the owner (B13, B15, 2026-10-14)
        for url in re.findall(r"https?://[^\s)\]]+", spec.default):
            assert url.startswith("https://"), f"{key}: {url}"
        assert "<" not in spec.default, f"{key}: HTML is not part of the format"
    assert "Flask" not in by_key["site_hosting_note"].default  # stale v1 text rewritten (D18)
    assert by_key["site_footer_text"].default == "Roxy Proxy 2025-Present"  # B15: the footer stays


def test_owner_answers_b13_b15_contact_no_bounty_no_support_links() -> None:
    """The owner's words: "No bug bounty, no support link, but if they need something extra or are having an issue
    to contact CeaselessQuokka on either the DevForums or Twitter"."""
    by_key = _by_key()
    assert by_key["site_contact_name"].default == "CeaselessQuokka on the DevForums or Twitter"
    for key in EMPTY_BY_DEFAULT:
        spec = by_key[key]
        assert spec.default == ""
        assert "Empty (the default)" in spec.description
    # v1's wording stays in the notes, so bringing a section back is a paste.
    assert "rewards from $10-$250 USD depending on severity" in by_key["site_bug_bounty_text"].notes
    assert "You never have to donate or pay anything" in by_key["site_support_links"].notes
    assert "https://devforum" not in by_key["site_support_links"].notes  # no link in the paste (v1 had none there)


def test_under_construction_switches_and_message() -> None:
    """Owner request (2026-10-15): three independent low-risk switches, all off, each naming its page, and a short
    message that follows the site text rules (https links only, no pasted secret, no dash)."""
    from roxy.config.catalog import SettingValidationError, validate_value
    from roxy.config.secret_text import PASTE_REFUSED_MESSAGE
    from roxy.core.redact import TOKEN_PREFIX

    by_key = _by_key()
    for key, path in zip(CONSTRUCTION_SWITCHES, ("/", "/docs", "/status"), strict=True):
        spec = by_key[key]
        assert spec.type == SettingType.BOOL
        assert spec.default == 0
        assert spec.risk == Risk.LOW
        assert spec.pages == ("settings#public-site",)
        assert f"({path})" in spec.description
        assert "under construction" in spec.label
        assert "site_construction_text" in spec.related_settings
        assert "503" in spec.if_enabled
        assert "Retry-After" in spec.if_enabled
    assert "404" in by_key["public_status_under_construction"].notes  # a switched-off status page stays 404
    message = by_key["site_construction_text"]
    assert message.max_length == 500
    assert message.risk == Risk.LOW
    assert set(message.related_settings) == set(CONSTRUCTION_SWITCHES)
    assert validate_value("site_construction_text", "Back soon. [News](https://example.com/news)")
    for bad in ("Back soon, see http://example.com", "javascript:alert(1)", "Back soon " + chr(0x2014) + " sorry"):
        with pytest.raises(SettingValidationError):
            validate_value("site_construction_text", bad)
    for pasted in (TOKEN_PREFIX + "A" * 60, ".ROBLOSECURITY=" + "B" * 40):
        with pytest.raises(SettingValidationError, match=re.escape(PASTE_REFUSED_MESSAGE[:40])):
            validate_value("site_construction_text", f"Back soon. {pasted}")


def test_pause_message_limit_and_v1_default() -> None:
    spec = _by_key()["pause_message_default"]
    assert spec.max_length == 300
    assert spec.v1_default == "Service down for maintenance."
    assert spec.pages == ("topbar#pause",)


def test_cors_any_origin_is_high_risk() -> None:
    spec = _by_key()["public_cors_allow_any_origin"]
    assert spec.risk == Risk.HIGH
    assert spec.is_high_risk_value(1)
    assert "SEC-DEFAULTS" in spec.related_recommendations


def test_timezone_default_is_a_real_zone_and_pending() -> None:
    spec = _by_key()["ui_timezone"]
    ZoneInfo(spec.default)  # raises if the IANA name is unknown
    assert spec.pending_owner_verification


def test_theme_options() -> None:
    assert _by_key()["ui_default_theme"].option_values() == ("dark", "light", "system")


def test_source_has_no_dash_characters() -> None:
    text = Path(public_site.__file__).read_text(encoding="utf-8")
    for dash in DASHES:
        assert dash not in text
