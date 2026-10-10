/**
 * The Cache page's own script (templates/admin/pages/cache.html and cache/*.html).
 *
 * What this is
 *   Small glue between the server-rendered cards and the shared confirm dialogs:
 *   * `data-fill`: a button that opens a shared dialog (`data-dialog-open`) carries the values it sends as JSON
 *     built on the server; they are copied into the dialog's form before it opens (`_url`, a path under
 *     /admin/api/v1/, becomes the form's API URL; `_label` is shown as text in `[data-fill-label]`). A button with
 *     `data-fill-form` fills a form on the page instead (the ignored parameters form).
 *   * "Purge matching" follows the browser's search box: after every table swap its value and state are set from
 *     the search the table was drawn with, so the purge removes exactly what the list shows.
 *   * The purge card's form fills the shared purge dialog ("Review the purge") instead of sending at once.
 *   * Reset dialogs (`[data-reset-dialog]`) ask `POST /admin/api/v1/data/resets/preview` for the exact rows when
 *     they open and show the API's own summary; `[data-refresh-card]` re-renders a card from its fragment.
 *
 * Why it exists
 *   One dialog per action, shared by every row and drawer, keeps the page small; the values a dialog sends are
 *   always the server's (never HTML: text goes in with textContent, values with `.value`), and the API judges them
 *   again. Nothing here builds markup from strings (plan 9.2, 9.16).
 *
 * How it works
 *   Delegated listeners on document in the capture phase, so the dialog is filled before static/js/dialog.js opens
 *   it; a fill that is not valid (an empty purge value) stops the click there and says why next to the field.
 *
 * What to read next
 *   static/js/page.js (the helpers), static/js/api_forms.js (how the dialogs send), roxy/admin/pages/cache.py.
 */

import { onContent, postJSON, refreshCard } from "roxy/page";
import { qs, qsa } from "roxy/dom";

const API_PREFIX = "/admin/api/v1/";
const SCOPE_WORDS = {
  pattern: "every stored answer whose endpoint matches the pattern",
  host: "every stored answer of the host",
  rule: "every stored answer kept under cache rule",
  search: "every stored answer whose question contains",
  expired: "every expired answer",
};

function parseFill(node) {
  try {
    const value = JSON.parse(node.dataset.fill || "{}");
    return value && typeof value === "object" ? value : {};
  } catch {
    return {};
  }
}

/** Copy `values` into the form of `dialog` (see the module docstring). */
function fillDialog(dialog, values) {
  const form = qs("form", dialog);
  if (!form) return;
  for (const input of qsa("input[type=hidden]", form)) input.value = input.defaultValue;
  for (const [name, value] of Object.entries(values)) {
    if (name === "_url") {
      if (typeof value === "string" && value.startsWith(API_PREFIX)) form.dataset.apiUrl = value;
    } else if (name === "_label") {
      const label = qs("[data-fill-label]", dialog);
      if (label) label.textContent = String(value);
    } else {
      const input = form.elements.namedItem(name);
      if (input && "value" in input) input.value = String(value);
    }
  }
}

function fillForm(form, values) {
  let first = null;
  for (const [name, value] of Object.entries(values)) {
    const input = form.elements.namedItem(name);
    if (input && "value" in input) {
      input.value = String(value);
      first = first || input;
    }
  }
  if (first) {
    first.scrollIntoView({ block: "center" });
    first.focus();
  }
}

/** Preview a reset when its dialog opens: the exact rows, in the API's own words. */
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
    if (!response.ok) {
      summary.textContent = "The rows could not be counted just now; the reset still does exactly what is listed above.";
      return;
    }
    const answer = await response.json();
    if (typeof answer.summary === "string") summary.textContent = answer.summary;
    const digest = qs("[data-reset-digest]", form);
    if (digest && typeof answer.preview === "string" && /^[0-9a-f]{64}$/.test(answer.preview)) digest.value = answer.preview;
  } catch {
    summary.textContent = "The rows could not be counted just now; the reset still does exactly what is listed above.";
  }
}

function purgeFromForm(form) {
  const scope = form.elements.namedItem("scope").value;
  const value = form.elements.namedItem("value").value.trim();
  const type = form.elements.namedItem("type").value;
  const includeStale = form.elements.namedItem("include_stale").checked;
  const error = qs("[data-purge-error]", form);
  const valueInput = form.elements.namedItem("value");
  if (scope !== "expired" && !value) {
    if (error) {
      error.textContent = "Give the value to purge by (a pattern, host, rule number or search text).";
      error.hidden = false;
    }
    valueInput.setAttribute("aria-invalid", "true");
    valueInput.focus();
    return null;
  }
  if (error) error.hidden = true;
  valueInput.removeAttribute("aria-invalid");
  const words = SCOPE_WORDS[scope] || "the stored answers";
  let label = scope === "expired" ? words : `${words}: ${value}`;
  if (scope === "pattern") label += type === "regex" ? " (regex)" : " (wildcard)";
  if (scope === "expired" && includeStale) label += ", including those still inside their stale window";
  return {
    scope,
    value: scope === "expired" ? "" : value,
    type,
    include_stale: includeStale ? "true" : "false",
    _label: label,
  };
}

document.addEventListener("click", (event) => {
  const target = event.target instanceof Element ? event.target : null;
  if (!target) return;
  const refresher = target.closest("[data-refresh-card]");
  if (refresher) {
    refreshCard(refresher.dataset.refreshCard);
    return;
  }
  const filler = target.closest("[data-fill-form][data-fill]");
  if (filler) {
    const form = document.getElementById(filler.dataset.fillForm);
    if (form) fillForm(form, parseFill(filler));
    return;
  }
  const opener = target.closest("[data-dialog-open]");
  if (!opener || opener.disabled) return;
  const dialog = document.getElementById(opener.dataset.dialogOpen);
  if (!dialog) return;
  if (opener.matches("[data-purge-open]")) {
    const values = purgeFromForm(opener.closest("form"));
    if (!values) {
      event.stopPropagation();  // nothing to purge yet: the dialog stays closed, the field says why
      event.preventDefault();
      return;
    }
    fillDialog(dialog, values);
  } else if (opener.dataset.fill) {
    fillDialog(dialog, parseFill(opener));
  }
  if (dialog.matches("[data-reset-dialog]")) previewReset(dialog);
}, true);

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (form instanceof HTMLFormElement && form.matches("[data-purge-prepare]")) {
    event.preventDefault();  // Enter in the value field: open the review dialog, as the button does
    const button = qs("[data-purge-open]", form);
    if (button) button.click();
  }
});

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

// "Purge matching" sends the search the browser was drawn with (read after every table swap).
onContent("#cache-browser", (table) => {
  const button = qs("[data-purge-matching]");
  const search = qs("input[name=q]", table);
  if (!button || !search) return;
  const q = search.value.trim();
  button.dataset.fill = JSON.stringify({
    scope: "search",
    type: "glob",
    value: q,
    _label: `every stored answer whose question contains: ${q}`,
  });
  button.disabled = q === "";
  // The card's own refresh (after a purge) asks for the view in the address bar, which tables.js keeps in step.
  const card = document.getElementById("browser");
  if (card && card.dataset.card === "browser") card.dataset.cardSrc = `/admin/cache/fragment/browser${window.location.search}`;
});
