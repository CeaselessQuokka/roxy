/**
 * Helpers for page modules (`static/js/pages/<page>.js`), the one import a page's own script needs.
 *
 * What this is
 *   `onContent(selector, fn)` runs `fn(element)` for every element matching `selector` now and in every fragment
 *   htmx swaps in later (a refreshed card, a table page, the drawer); `refreshCard(cardOrId)` re-renders a card from
 *   its fragment; `pageParams()` is the page URL's query (the time range and filters, plan 14.2); plus re-exports
 *   of what pages use most: `toast`, `request`, `getJSON`, `postJSON`, `submitApiForm`, `confirmIdentity`,
 *   `downloadFrom`, `copyTextFrom`, `openDrawerFrom`.
 *
 * Why it exists
 *   A page module loads after app.js (module scripts run in document order) and must work for content that
 *   arrives later through htmx. Giving every page the same two or three entry points keeps page scripts short and
 *   keeps them away from the shell's internals.
 *
 * How it works
 *   `onContent` remembers which elements it already handled (a WeakSet per call), so a fragment swapped twice runs
 *   `fn` once per new element. Nothing here builds HTML from strings (CSP, plan 9.16: use dom.js `el`).
 *
 * What to read next
 *   static/js/pages/audit.js (the reference page's script), static/js/cards.js, static/js/api_forms.js.
 */

import { qsa } from "roxy/dom";
import { openDrawerFrom } from "roxy/dialog";
import { refreshCard as refresh } from "roxy/cards";
import { getJSON, postJSON, request } from "roxy/net";
import { submitApiForm } from "roxy/api_forms";
import { confirmIdentity } from "roxy/reauth";
import { copyTextFrom, downloadFrom } from "roxy/exports";
import { toast } from "roxy/toast";

/** Run `fn(element)` for every element matching `selector`, now and in content htmx swaps in later. */
export function onContent(selector, fn) {
  const done = new WeakSet();
  const run = (root) => {
    const found = root instanceof Element && root.matches(selector) ? [root] : [];
    for (const node of [...found, ...qsa(selector, root)]) {
      if (done.has(node)) continue;
      done.add(node);
      fn(node);
    }
  };
  run(document);
  document.addEventListener("htmx:load", (event) => {
    const root = event.detail && event.detail.elt;
    if (root instanceof Element) run(root);
  });
}

/** Re-render a card (an element or its id) from its fragment. */
export function refreshCard(cardOrId, options = {}) {
  const card = typeof cardOrId === "string" ? document.getElementById(cardOrId) : cardOrId;
  return refresh(card, { force: true, ...options });
}

/** The page URL's query parameters (time range, filters). */
export function pageParams() {
  return new URLSearchParams(window.location.search);
}

export {
  confirmIdentity,
  copyTextFrom,
  downloadFrom,
  getJSON,
  openDrawerFrom,
  postJSON,
  request,
  submitApiForm,
  toast,
};
