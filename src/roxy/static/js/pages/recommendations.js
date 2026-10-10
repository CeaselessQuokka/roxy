/**
 * The Recommendations page's own script (templates/admin/pages/recommendations*).
 *
 * What this is
 *   * `?rec=<id>` (links from the Overview, the bell, the palette and the health report) opens that
 *     recommendation's detail drawer as soon as the page has loaded.
 *   * After an action in the drawer succeeds (Apply, Undo, Snooze, Dismiss: forms with `data-reopen`), the drawer
 *     api_forms.js closed is opened again on the same recommendation, so the admin sees its new state, its watch
 *     window and the Undo button at once (the list and history cards refresh behind it).
 *   * When the preview panel arrives, focus moves to its heading, so keyboard and screen reader users land on it.
 *   * Tables: a table answer is the whole card (the kit renders one template per card), so a table swap keeps only
 *     the table out of it (`selectOverride`), and the card's refresh address follows the table's state, so a refresh
 *     after an action keeps the filters, search and page the admin chose.
 *
 * Why it exists
 *   Everything else on the page (cards, tables, the drawer, the forms, inline settings) is the shared design system;
 *   these few behaviors belong to this page's flows (plan 11.3, 14.8: apply from a phone without losing your place).
 *
 * How it works
 *   Ids are checked against the API's own id shape before they go into a URL. Nothing builds HTML from strings.
 *
 * What to read next
 *   static/js/page.js, static/js/api_forms.js, roxy/admin/pages/recommendations.py.
 */

import { onContent, openDrawerFrom, pageParams } from "roxy/page";

const REC_ID = /^rec_[0-9A-Za-z]{1,64}$/;
const REOPEN_DELAY_MS = 350;

function detailUrl(id) {
  return `/admin/recommendations/detail?${new URLSearchParams({ rec: id }).toString()}`;
}

const wanted = pageParams().get("rec") || "";
if (REC_ID.test(wanted)) openDrawerFrom(detailUrl(wanted), "Recommendation", document.body);

document.addEventListener("roxy:api-success", (event) => {
  const form = event.target instanceof Element ? event.target.closest("form[data-reopen]") : null;
  if (!form) return;
  const url = form.dataset.reopen || "";
  if (!url.startsWith("/admin/recommendations/detail?")) return;
  window.setTimeout(() => openDrawerFrom(url, "Recommendation", document.body), REOPEN_DELAY_MS);
});

document.addEventListener("htmx:afterSwap", (event) => {
  const target = event.detail && event.detail.target;
  if (!(target instanceof Element) || !target.matches("[data-rec-preview]")) return;
  const heading = target.querySelector(".rec-preview__title");
  if (heading) heading.focus();
});

// A table's answer is its whole card: keep only the table (see the module docstring).
document.addEventListener("htmx:beforeSwap", (event) => {
  const target = event.detail && event.detail.target;
  if (!(target instanceof Element) || !target.matches("[data-dt]") || !target.id) return;
  if (!event.detail.selectOverride && target.closest("[data-card]")) event.detail.selectOverride = `#${CSS.escape(target.id)}`;
});

onContent("[data-dt]", (table) => {
  const card = table.closest("[data-card]");
  const form = table.querySelector("[data-dt-state]");
  if (!card || !form || !table.dataset.dtSrc) return;
  const params = new URLSearchParams();
  for (const [name, value] of new FormData(form)) if (typeof value === "string" && value !== "") params.append(name, value);
  card.dataset.cardSrc = `${table.dataset.dtSrc}?${params.toString()}`;
});
