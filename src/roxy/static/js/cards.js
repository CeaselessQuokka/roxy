/**
 * Page cards: refresh a card from its fragment after an action or a stream event (plan 14.11, P11 contract).
 *
 * What this is
 *   `refreshCard(card)` re-asks a card's fragment (`data-card-src`, built by roxy/admin/pages/kit.py) and swaps the
 *   card for the answer (htmx, outerHTML). `initCards()` wires two triggers: the `roxy:refresh-cards` event that
 *   api_forms.js raises after a successful action (`data-on-success="refresh"`, cards named in `data-refresh`, else
 *   the card holding the form), and the page-wide stream: a card with `data-refresh-on="kpi recommendation"` is
 *   refreshed when one of those event kinds arrives, at most once per `data-refresh-min-s` seconds.
 *
 * Why it exists
 *   A card's first paint and its refresh render the same server template, so refreshing a card is the honest way to
 *   show new numbers (one source of truth, plan P6). Stream events can be frequent (`kpi` every 2 s), so refreshes
 *   are throttled per card, skipped while the tab is hidden, and never replace a card the admin is working in
 *   (focus inside, an open menu, an unsaved setting), which would throw their input away.
 *
 * How it works
 *   One delegated listener per trigger; per-card timestamps in a WeakMap (monotonic `performance.now`). A card that
 *   could not refresh keeps its old content (htmx does not swap error answers) and is tried again next time.
 *
 * What to read next
 *   templates/components/page_card.html (`data-card-src`, `data-refresh-on`), static/js/api_forms.js.
 */

import htmx from "roxy/htmx_setup";
import { qs, qsa } from "roxy/dom";

const lastRefresh = new WeakMap();

function busy(card) {
  return Boolean(
    card.contains(document.activeElement) && document.activeElement !== document.body
      || qs("details[data-menu][open]", card)
      || qs(".setting[data-dirty]", card)
      || card.getAttribute("aria-busy") === "true",
  );
}

/** Re-render one card from its fragment URL (skipped while the admin is working in it, unless `force`). */
export function refreshCard(card, { force = false } = {}) {
  if (!(card instanceof Element) || !card.dataset.cardSrc) return null;
  if (!force && busy(card)) return null;
  lastRefresh.set(card, performance.now());
  return htmx.ajax("GET", card.dataset.cardSrc, { target: card, swap: "outerHTML", source: card });
}

function byIds(ids) {
  return ids.map((id) => document.getElementById(id)).filter((node) => node && node.matches("[data-card]"));
}

export function initCards() {
  document.addEventListener("roxy:refresh-cards", (event) => {
    const detail = event.detail || {};
    const named = Array.isArray(detail.cards) ? detail.cards : [];
    const targets = named.length ? byIds(named) : [detail.from instanceof Element ? detail.from.closest("[data-card]") : null];
    for (const card of targets) if (card) refreshCard(card, { force: true });
  });
  document.addEventListener("roxy:sse", (event) => {
    const kind = event.detail && event.detail.type;
    if (!kind || document.hidden) return;
    const now = performance.now();
    for (const card of qsa("[data-card][data-refresh-on]")) {
      const kinds = card.dataset.refreshOn.split(/\s+/);
      if (!kinds.includes(kind)) continue;
      const gap = Math.max(2, Number(card.dataset.refreshMinS) || 15) * 1000;
      if (now - (lastRefresh.get(card) || -Infinity) < gap) continue;
      refreshCard(card);
    }
  });
}
