/**
 * Page cards: refresh a card from its fragment after an action or a stream event (plan 14.11, P11 contract).
 *
 * What this is
 *   `refreshCard(card)` re-asks a card's fragment (`data-card-src`, built by roxy/admin/pages/kit.py) and swaps the
 *   card for the answer (htmx, outerHTML). `initCards()` wires two triggers: the `roxy:refresh-cards` event that
 *   api_forms.js raises after a successful action (`data-on-success="refresh"`, cards named in `data-refresh`, else
 *   the card holding the form), and the page-wide stream: a card with `data-refresh-on="kpi recommendation"` is
 *   refreshed when one of those event kinds arrives, at most once per `data-refresh-min-s` seconds. It also loads
 *   the page's lazy cards (`@page.card(..., lazy=True)`, placeholders with `hx-trigger="revealed"`) in the
 *   background: one at a time, top to bottom, starting right after the page has loaded.
 *
 * Why it exists
 *   A card's first paint and its refresh render the same server template, so refreshing a card is the honest way to
 *   show new numbers (one source of truth, plan P6). Stream events can be frequent (`kpi` every 2 s), so refreshes
 *   are throttled per card, skipped while the tab is hidden, and never replace a card the admin is working in
 *   (focus inside, an open menu, an unsaved setting), which would throw their input away.
 *   Lazy cards keep the first paint small on the 1 GB server, but htmx's `revealed` fires only for a card inside
 *   the window when scrolling stops: a reader who jumps (a link to `#tarpit`, the browser's find, a fast scroll on
 *   a phone) would meet placeholders that never load. Loading them in the background, one request at a time, means
 *   a card is usually ready before the reader gets there, and the server never renders a burst of fragments at once.
 *   Every page loads its lazy cards this way (it replaced five page-local copies of the idea).
 *
 * How it works
 *   One delegated listener per trigger; per-card timestamps (monotonic `performance.now`) kept by card id, not by
 *   element: a refresh swaps the card's element for a new one (outerHTML), and a timestamp kept on the old element
 *   was lost with it, so every `kpi` frame (every 2 s) re-rendered a card meant to refresh once a minute (found by
 *   tests/multiprocess/test_dashboard_sse_mp.py). A card that could not refresh keeps its old content (htmx does not
 *   swap error answers) and is tried again next time.
 *   The background loader waits for the `load` event and a short pause, then asks the first placeholder that is not
 *   already loading (scrolled into view meanwhile), waits for its answer (at most 15 s), pauses, and goes on; a hidden
 *   tab waits until it is shown again. A placeholder whose request failed is not asked again by the loader: it keeps
 *   its message and still loads when it scrolls into view.
 *
 * What to read next
 *   templates/components/page_card.html (`data-card-src`, `data-refresh-on`), static/js/api_forms.js.
 */

import htmx from "roxy/htmx_setup";
import { qs, qsa } from "roxy/dom";

const lastRefresh = new Map();  // card id -> when it last refreshed (bounded: one entry per card of the page)
const LAZY_DELAY_MS = 250;  // after the load event: the first paint and its scripts settle first
const LAZY_PAUSE_MS = 80;  // between two cards: one fragment at a time on the server
const LAZY_WAIT_MS = 15000;  // never wait on one card forever

function pause(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function whenVisible() {
  if (!document.hidden) return Promise.resolve();
  return new Promise((resolve) => {
    const onChange = () => {
      if (document.hidden) return;
      document.removeEventListener("visibilitychange", onChange);
      resolve();
    };
    document.addEventListener("visibilitychange", onChange);
  });
}

/** Load every lazy card still waiting, one at a time, top to bottom (see the module docstring). */
async function loadLazyCards() {
  const asked = new WeakSet();
  for (;;) {
    await whenVisible();
    const card = qsa("section.page-card--lazy[data-card-src]").find(
      (node) => !asked.has(node) && !node.classList.contains("htmx-request"),
    );
    if (!card) return;
    asked.add(card);
    try {
      await Promise.race([refreshCard(card, { force: true }), pause(LAZY_WAIT_MS)]);
    } catch {
      /* the placeholder stays and loads when it scrolls into view */
    }
    await pause(LAZY_PAUSE_MS);
  }
}

/** The key a card's refresh time is kept under: its id, which the swapped-in element keeps. */
function cardKey(card) {
  return card.id || card.dataset.cardSrc || "";
}

function busy(card) {
  return Boolean(
    card.contains(document.activeElement) && document.activeElement !== document.body
      || qs("details[data-menu][open]", card)
      || qs(".setting[data-dirty]", card)
      || card.getAttribute("aria-busy") === "true",
  );
}

/** A selector for the twin of the focused control in the swapped-in card: its id, else its action name. */
function focusTwin(card) {
  const active = document.activeElement;
  if (!(active instanceof HTMLElement) || active === card || !card.contains(active)) return null;
  if (active.id) return `#${CSS.escape(active.id)}`;
  if (active.dataset.action) return `[data-action="${CSS.escape(active.dataset.action)}"]`;
  return null;
}

/** Re-render one card from its fragment URL (skipped while the admin is working in it, unless `force`). */
export function refreshCard(card, { force = false } = {}) {
  if (!(card instanceof Element) || !card.dataset.cardSrc) return null;
  if (!force && busy(card)) return null;
  lastRefresh.set(cardKey(card), performance.now());
  const twin = focusTwin(card);
  const hadFocus = card.contains(document.activeElement);
  const id = card.id;
  const swap = htmx.ajax("GET", card.dataset.cardSrc, { target: card, swap: "outerHTML", source: card });
  if (hadFocus && id) {
    // A forced refresh (after an action in the card) keeps keyboard focus in the card: on the swapped-in twin of
    // the focused control, else on the card itself (htmx keeps it only for an element with an id; a11y-8).
    Promise.resolve(swap).then(() => window.setTimeout(() => {
      const fresh = document.getElementById(id);
      const active = document.activeElement;
      if (!fresh || fresh === card || (active && active !== document.body && fresh.contains(active))) return;
      const target = (twin && qs(twin, fresh)) || fresh;
      if (target === fresh && !fresh.hasAttribute("tabindex")) fresh.setAttribute("tabindex", "-1");
      target.focus();
    }, 30)).catch(() => {});
  }
  return swap;
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
      if (now - (lastRefresh.get(cardKey(card)) ?? -Infinity) < gap) continue;
      refreshCard(card);
    }
  });
  const start = () => window.setTimeout(loadLazyCards, LAZY_DELAY_MS);
  if (document.readyState === "complete") start();
  else window.addEventListener("load", start, { once: true });
}
