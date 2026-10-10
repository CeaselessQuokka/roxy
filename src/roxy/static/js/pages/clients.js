/**
 * The Clients page's own script (templates/admin/pages/clients.html, clients/*.html).
 *
 * What this is
 *   * "Identify an experience": when a lookup form (`[data-lookup-form]`) succeeds, the API's JSON answer is drawn
 *     into the nearest `[data-lookup-result]`: name, universe, owner, numbers, description, the experience's and
 *     owner's Roblox addresses (as text with a copy button: a dashboard script never links to another site) and
 *     v1's throwaway-place warning. Every text goes in with `textContent` (the name, owner and description are
 *     Roblox's, and so possibly a caller's, words).
 *   * The client view in the drawer: after an action succeeds (ban, bypass, deny, block, reset), the drawer loads
 *     the client again so it shows the new state; the ban dialog's "permanently" switch turns the length off.
 *   * Reset dialogs (`[data-reset-dialog]`) ask `POST /admin/api/v1/data/resets/preview` for the exact rows when
 *     they open and show the API's own summary (the same helper as the Cache page's script).
 *
 * Why it exists
 *   The lookup answer is JSON from the admin API (a POST, because it spends upstream budget), so it is drawn in the
 *   browser; building it from DOM nodes, never HTML strings, keeps hostile names inert (plan 9.16).
 *
 * How it works
 *   api_forms.js raises `roxy:api-success` on the form with the answer; this module listens on document.
 *
 * What to read next
 *   static/js/page.js, static/js/api_forms.js, roxy/admin/api/clients.py (`_run_lookup`), roxy/admin/pages/clients.py.
 */

import { onContent, openDrawerFrom, postJSON, refreshCard } from "roxy/page";
import { el, icon, qs, qsa } from "roxy/dom";

const DIGITS = /^[0-9]{1,20}$/;
const MAX_DESCRIPTION = 400;

function text(value, fallback = "n/a") {
  return value === null || value === undefined || value === "" ? fallback : String(value);
}

function count(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString() : text(value);
}

function when(value) {
  const date = new Date(String(value || ""));
  return Number.isNaN(date.getTime()) ? text(value) : date.toLocaleString();
}

/** A Roblox page address as text with a copy button. The dashboard never links to another site from data, so
 *  the address Roxy built from the experience's ids is shown and copied, never opened (plan 9.16). */
function robloxAddress(label, address) {
  return el("p", { class: "clients-lookup__address" }, [
    el("span", { class: "muted", text: `${label}: ` }),
    el("span", { class: "caller-text mono", dir: "ltr", translate: "no", text: address }),
    el("button", { type: "button", class: "btn btn--sm btn--ghost", "data-copy": address }, [
      icon("copy"),
      el("span", { text: "Copy" }),
      el("span", { class: "sr-only", text: ` the ${label.toLowerCase()} address` }),
    ]),
  ]);
}

/** Draw a lookup answer (`{result, cached}`) into `box` (text nodes only). */
function renderLookup(box, answer, warning) {
  const r = (answer && answer.result) || {};
  const nodes = [];
  nodes.push(el("p", { class: "clients-lookup__head" }, [
    el("strong", { class: "caller-text", dir: "auto", translate: "no", text: text(r.name, "Unnamed experience") }),
    el("span", { class: "muted", text: ` universe ${text(r.universe_id)}` }),
  ]));
  const owner = `${text(r.creator_name)} (${text(r.creator_type, "owner")} ${text(r.creator_id, "")})`.replace(" )", ")");
  const facts = [
    ["Owner", owner],
    ["Place id", text(r.root_place_id || r.place_id)],
    ["Created", when(r.created)],
    ["Visits", count(r.visits)],
    ["Playing now", count(r.playing)],
    ["Max players", count(r.max_players)],
    ["Favorites", count(r.favorited_count)],
  ];
  const list = el("dl", { class: "kv clients-lookup__facts" });
  for (const [label, value] of facts) {
    list.append(el("dt", { text: label }), el("dd", { class: "caller-text", dir: "auto", text: value }));
  }
  nodes.push(list);
  const description = String(r.description || "").slice(0, MAX_DESCRIPTION);
  if (description) nodes.push(el("p", { class: "caller-text caller-text--block clients-lookup__desc", dir: "auto", text: description }));
  // The API builds these from the numeric ids (upstream/internal.py); shown only when the ids are digits.
  if (DIGITS.test(String(r.root_place_id || "")) && typeof r.url === "string" && r.url) {
    nodes.push(robloxAddress("Experience", r.url));
  }
  if (DIGITS.test(String(r.creator_id || "")) && typeof r.creator_url === "string" && r.creator_url) {
    nodes.push(robloxAddress("Owner", r.creator_url));
  }
  if (r.recently_created_warning && warning) {
    nodes.push(el("div", { class: "alert alert--warn", role: "note" }, [
      el("span", { class: "alert__icon" }, [icon("alert-triangle")]),
      el("div", { class: "alert__text" }, [el("p", { class: "alert__title", text: warning })]),
    ]));
  }
  if (answer && answer.cached) nodes.push(el("p", { class: "muted", text: "From the 10 minute lookup cache of this worker." }));
  box.replaceChildren(...nodes);
}

function lookupBox(form) {
  const scope = form.closest("[data-client-view]") || form.closest("[data-card]") || document;
  return qs("[data-lookup-result]", scope);
}

async function previewReset(dialog) {
  const form = qs("form[data-reset-preview]", dialog);
  const summary = qs("[data-reset-summary]", dialog);
  if (!form || !summary) return;
  const scope = {};
  for (const input of qsa("input[type=hidden]", form)) {
    if (input.name === "preview") continue;
    scope[input.name] = input.dataset.json === "list" ? [input.value] : input.value;
  }
  summary.textContent = "Counting the rows this would touch.";
  try {
    const response = await postJSON(form.dataset.resetPreview, scope);
    if (!response.ok) throw new Error(String(response.status));
    const answer = await response.json();
    if (typeof answer.summary === "string") summary.textContent = answer.summary;
    const digest = qs("[data-reset-digest]", form);
    if (digest && typeof answer.preview === "string" && /^[0-9a-f]{64}$/.test(answer.preview)) digest.value = answer.preview;
  } catch {
    summary.textContent = "The rows could not be counted just now; the reset still does exactly what is listed above.";
  }
}

/**
 * Load the lazy cards one at a time right after the first paint, top to bottom, so scrolling never meets a
 * "Loading" card and the server renders one fragment at a time (the 1 GB box). A card that cannot load keeps its
 * placeholder (and loads again when it scrolls into view, as htmx's `revealed` trigger does).
 */
async function loadLazyCards() {
  const tried = new Set();
  for (;;) {
    const card = qsa(".page-card--lazy").find((node) => !tried.has(node.id) && !node.classList.contains("htmx-request"));
    if (!card) return;
    tried.add(card.id);
    try {
      await refreshCard(card);
    } catch {
      /* the placeholder stays; htmx loads it when it is revealed */
    }
  }
}

if (document.readyState === "complete") window.setTimeout(loadLazyCards, 50);
else window.addEventListener("load", () => window.setTimeout(loadLazyCards, 50), { once: true });

// The places card's own refresh (after an action) asks for the view in the address bar (kept by tables.js).
onContent("#client-places", () => {
  const card = document.getElementById("places");
  if (card && card.dataset.card === "places") card.dataset.cardSrc = `/admin/clients/fragment/places${window.location.search}`;
});

document.addEventListener("roxy:api-success", (event) => {
  const form = event.target instanceof HTMLFormElement ? event.target : null;
  if (!form) return;
  if (form.matches("[data-lookup-form]")) {
    const box = lookupBox(form);
    if (box) renderLookup(box, event.detail && event.detail.answer, form.dataset.throwaway || "");
    return;
  }
  // An action inside the client view in the drawer: show the client's new state.
  const view = form.closest("#drawer-body [data-client-view]");
  if (view && view.dataset.clientSrc && view.dataset.clientSrc.startsWith("/admin/clients/client?")) {
    const title = qs("#drawer-title");
    openDrawerFrom(view.dataset.clientSrc, title ? title.textContent : "Client", document.body);
  }
});

document.addEventListener("change", (event) => {
  const box = event.target instanceof HTMLInputElement ? event.target : null;
  if (!box || !box.matches("[data-ban-permanent]")) return;
  const minutes = box.form ? box.form.elements.namedItem("minutes") : null;
  if (minutes) minutes.disabled = box.checked;  // a disabled field is not sent: the API takes one or the other
});

document.addEventListener("reset", (event) => {
  const form = event.target instanceof HTMLFormElement ? event.target : null;
  const minutes = form && qs("[data-ban-permanent]", form) ? form.elements.namedItem("minutes") : null;
  if (minutes) minutes.disabled = false;  // the form is cleared after a ban: the length is offered again
});

document.addEventListener("click", (event) => {
  const opener = event.target instanceof Element ? event.target.closest("[data-dialog-open]") : null;
  if (!opener) return;
  const dialog = document.getElementById(opener.dataset.dialogOpen);
  if (dialog && dialog.matches("[data-reset-dialog]")) previewReset(dialog);
}, true);
