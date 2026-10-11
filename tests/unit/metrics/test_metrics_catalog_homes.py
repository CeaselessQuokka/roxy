"""Every metric of `metrics/catalog.py` names a dashboard card that shows it (gap G12, gap G3).

What this is
    The catalog's `pages` field is where a metric's help is shown (plan 14.7): each anchor must be a registry card
    (`registry.cards_for`) or one of the non-page homes of DESIGN.md section 9 (`config.catalog.NON_PAGE_HOMES`).
    Before the gaps lane three metrics named `upstream#calls`, six `traffic#status-codes` and one `upstream#429s`,
    cards that do not exist; `worker_cpu_pct` named the metrics pipeline card although the fleet table shows it.

What to read next
    `roxy/metrics/catalog.py`, `roxy/admin/pages/registry.py`.
"""

from __future__ import annotations

from roxy.admin.pages import registry
from roxy.config.catalog import NON_PAGE_HOMES
from roxy.metrics.catalog import METRICS


def test_every_metric_home_is_a_registry_card_or_a_non_page_home() -> None:
    cards = {f"{page.id}#{card.id}" for page in registry.PAGES for card in registry.cards_for(page.id)}
    wrong = {
        key: home for key, spec in METRICS.items() for home in spec.pages if home not in cards | set(NON_PAGE_HOMES)
    }
    assert wrong == {}


def test_the_moved_homes_point_at_the_cards_that_show_them() -> None:
    assert METRICS["upstream_calls"].pages == ("overview#kpis", "upstream#health")
    assert METRICS["timeouts"].pages == ("upstream#health",)
    assert "upstream#health" in METRICS["errors"].pages
    assert METRICS["roblox_429"].pages == ("overview#kpis", "upstream#429-timeline")
    assert "traffic#status" in METRICS["status_5xx"].pages
    assert METRICS["worker_cpu_pct"].pages == ("system#fleet",)
