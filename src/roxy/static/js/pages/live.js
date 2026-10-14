/**
 * The Live page's own script (templates/admin/pages/live.html): filters from the address, and a request named
 * in it.
 *
 * What this is
 *   `/admin/live?endpoint=games.roblox.com/...&outcome=refused` (the Endpoints page's "Watch it live", a shared
 *   link) puts those values in the live tail's filter fields once the tail has started, then tells the tail they
 *   changed, so the list and the server-side stream filter both apply them. `/admin/live?request=<id>` opens that
 *   request's details in the drawer on load. Everything else (the stream, pausing, filtering, the drawer of a
 *   clicked row, the inline settings, the reset) is the shared design system and needs no page code.
 *
 * Why it exists
 *   A link to "this endpoint's requests" should land on them, not on every request.
 *
 * How it works
 *   The server checked the address's filters with the Live API's own parser and wrote the good ones as JSON in
 *   `data-live-filters` (plain values, set as field values, never as markup): one value per select, in the form the
 *   tail compares (a list is left out with a notice). A value a select does not list (a status code such as 404)
 *   gets an option of its own built with `el()` (its text is a text node), so it applies. The tail
 *   (static/js/live_tail.js) starts after its module loads and marks its root with `data-state`; this script waits
 *   for that mark (at most 10 seconds), sets the fields, and raises `change` on one of them: the tail reads every
 *   field at once
 *   (`readFilters`) and reconnects its stream with them. The request id is checked to be letters, digits, `-` or
 *   `_` before it goes into the drawer URL (the drawer route checks it again).
 *
 * What to read next
 *   static/js/page.js, static/js/live_tail.js, roxy/admin/pages/live.py.
 */

import { el } from "roxy/dom";
import { openDrawerFrom, pageParams } from "roxy/page";

const WAIT_MS = 10000;
const STEP_MS = 50;

function readFilters() {
  const holder = document.querySelector("[data-live-filters]");
  if (!holder) return {};
  try {
    const value = JSON.parse(holder.dataset.liveFilters || "{}");
    return value && typeof value === "object" ? value : {};
  } catch {
    return {};
  }
}

function applyFilters(tail, filters) {
  let last = null;
  for (const [name, value] of Object.entries(filters)) {
    const field = tail.querySelector(`[data-tail-filter="${CSS.escape(name)}"]`);
    if (!field || typeof value !== "string" || !value) continue;
    if (field.tagName === "SELECT" && ![...field.options].some((option) => option.value === value)) {
      // A value the API takes but the select does not list (`?status=404`): the server sent it in the form the tail
      // compares, so it gets an option of its own and applies like any other (finding docs_a-16).
      field.append(el("option", { value, dataset: { fromAddress: "" } }, `${value} (from the address)`));
    }
    field.value = value;
    last = field;
  }
  // One change event: the tail reads all its fields at once and reconnects the stream with them.
  if (last) last.dispatchEvent(new Event(last.tagName === "SELECT" ? "change" : "input", { bubbles: true }));
}

const filters = readFilters();
if (Object.keys(filters).length) {
  const started = performance.now();
  const timer = window.setInterval(() => {
    const tail = document.querySelector("[data-live-tail][data-state]");
    if (tail) {
      window.clearInterval(timer);
      applyFilters(tail, filters);
    } else if (performance.now() - started > WAIT_MS) {
      window.clearInterval(timer);
    }
  }, STEP_MS);
}

const requestId = pageParams().get("request") || "";
if (/^[A-Za-z0-9_-]{1,64}$/.test(requestId)) {
  const params = new URLSearchParams({ id: requestId });
  openDrawerFrom(`/admin/live/request?${params.toString()}`, `Request ${requestId}`, document.body);
}
