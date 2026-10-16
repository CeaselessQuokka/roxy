/**
 * The Endpoint policy page's own script (templates/admin/pages/policy.html): the bulk selection of the Endpoints
 * table, the "this loosens" hints of a verdict form, and the drawer after a save.
 *
 * What this is
 *   * Bulk selection: each row of the Endpoints table has a select box (`[data-policy-pick]`) and the header one for
 *     the whole page (`[data-policy-pick-all]`). The count under the table says how many are chosen, and just before
 *     a bulk form (`form[data-policy-bulk]`, "Block selected" or "Reset selected to default") is sent, the chosen
 *     ids are written into its `endpoint_ids` field (one per line, `data-json="list"`), so the shared form handler
 *     sends them as a list.
 *   * A verdict form (`form[data-policy-verdict]`, in a drawer) knows how open the current verdict is
 *     (`data-current-rank`); when the chosen verdict is looser, the note that a code will be asked for shows, and on
 *     a risk 4 endpoint the typed path field (`[data-policy-confirm]`) shows too.
 *   * A form saved from inside the drawer closes it (the cards it changed are refreshed by the shared handler).
 *
 * Why it exists
 *   HTML forms cannot reach inputs inside the table (it is redrawn on every page and search), and the admin should
 *   see before saving that a change loosens the policy. Everything else (the forms, the second factor prompt, the
 *   dialogs, the table) is the shared design system.
 *
 * How it works
 *   Event delegation on the document, so tables and drawers swapped in later work without setup. The submit
 *   listener runs in the capture phase, before static/js/api_forms.js builds the body. Text only (`textContent`).
 *
 * What to read next
 *   static/js/api_forms.js, static/js/tables.js, static/js/pages/credential.js.
 */

import { onContent } from "roxy/page";

function picks(root = document) {
  return [...root.querySelectorAll("input[data-policy-pick]")];
}

function chosen() {
  return picks().filter((box) => box.checked).map((box) => box.value);
}

function showCount() {
  const count = chosen().length;
  for (const node of document.querySelectorAll("[data-policy-picked-count]")) node.textContent = String(count);
  for (const all of document.querySelectorAll("input[data-policy-pick-all]")) {
    const table = all.closest("[data-dt]");
    const boxes = table ? picks(table) : [];
    const on = boxes.filter((box) => box.checked).length;
    all.checked = boxes.length > 0 && on === boxes.length;
    all.indeterminate = on > 0 && on < boxes.length;
  }
}

document.addEventListener("change", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) return;
  if (target.matches("[data-policy-pick-all]")) {
    const table = target.closest("[data-dt]");
    for (const box of table ? picks(table) : []) box.checked = target.checked;
    showCount();
  } else if (target.matches("[data-policy-pick]")) {
    showCount();
  }
});

// A redrawn table (a new page, a search) starts with nothing chosen.
onContent("[data-dt]", () => showCount());

document.addEventListener(
  "submit",
  (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.matches("form[data-policy-bulk]")) return;
    const field = form.querySelector("[data-policy-picked]");
    if (field) field.value = chosen().join("\n");
  },
  true,
);

function looser(form) {
  const select = form.querySelector('select[name="verdict"]');
  const option = select ? select.selectedOptions[0] : null;
  const rank = option ? Number(option.dataset.rank) : Number.NaN;
  return Number.isFinite(rank) && rank > Number(form.dataset.currentRank);
}

function showLoosening(form) {
  const loosens = looser(form);
  for (const node of form.querySelectorAll("[data-policy-loosen]")) node.hidden = !loosens;
  for (const node of form.querySelectorAll("[data-policy-confirm]")) node.hidden = !loosens;
}

onContent("form[data-policy-verdict]", (form) => showLoosening(form));

document.addEventListener("change", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLSelectElement) || target.name !== "verdict") return;
  const form = target.closest("form[data-policy-verdict]");
  if (form) showLoosening(form);
});

// A form saved from inside the drawer closes the drawer: the cards it changed are refreshed by the shared form
// handler, and the drawer would otherwise show the old verdict.
document.addEventListener("roxy:api-success", (event) => {
  const form = event.target instanceof Element ? event.target : null;
  if (!form || !form.closest("#drawer")) return;
  const close = document.querySelector("#drawer .drawer__head [data-dialog-close]");
  if (close instanceof HTMLElement) close.click();
});
