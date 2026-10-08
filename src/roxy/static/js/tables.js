/**
 * Data tables: server-side paging and sorting controls, remembered preferences, row details (plan 14.5).
 *
 * What this is
 *   Behavior for templates/components/table.html. The table block is server-rendered; this module only turns
 *   clicks into one consistent request (by setting the hidden page, size, sort and dir inputs of the table's state
 *   form and having htmx send that form: `GET src?...` and an outerHTML swap), remembers this browser's
 *   choices per table, and opens row details in the drawer. It also runs the heatmap's "Show numbers" switch.
 *
 * Why it exists
 *   Every control going through the one form means there is exactly one request shape for the server to
 *   handle, no duplicated parameters, and the search box keeps its text and focus across swaps (htmx refocuses an
 *   element with the same id). Remembering rows per page and hidden columns per table is a v1 convenience kept
 *   (parity row 89); it is stored in this browser only, wrapped so a blocked storage never breaks the page.
 *
 * How it works
 *   Delegated listeners on document handle every table, including tables htmx swaps in later; `initTables(root)`
 *   re-applies hidden columns after each swap. A row with `data-drawer-src` opens that fragment in the drawer; a
 *   row without one opens a definition list built from its cells (this is also how phones see the columns their
 *   card layout hides, plan 14.8).
 *
 * What to read next
 *   templates/components/table.html, static/js/dialog.js (the drawer).
 */

import htmx from "roxy/htmx_setup";
import { el, qs, qsa, store } from "roxy/dom";
import { openDrawer, openDrawerFrom } from "roxy/dialog";

const appliedSize = new Set();

function tableOf(node) {
  return node instanceof Element ? node.closest("[data-dt]") : null;
}

function field(table, name) {
  return qs(`[data-dt-field="${name}"]`, table);
}

/**
 * Ask the server for the table again with the state form's values. Always through htmx.ajax, never a native
 * form submission: before htmx has processed the page (the remembered page size is applied at startup), a native
 * submit would navigate the whole page to the fragment URL, and on a page that renders the default size it would
 * do so again on every load.
 */
function submit(table) {
  const form = qs("[data-dt-state]", table);
  if (!form || !table.dataset.dtSrc) return;
  htmx.ajax("GET", table.dataset.dtSrc, { source: form, target: table, swap: "outerHTML" });
}

function applyColumns(table) {
  const hidden = new Set(store.get(`dt.${table.dataset.dtId}.hidden`, []) || []);
  for (const box of qsa("[data-dt-col]", table)) {
    const key = box.dataset.dtCol;
    if (hidden.has(key) && !box.disabled) box.checked = false;
    const show = box.checked;
    for (const cell of qsa(`[data-col="${CSS.escape(key)}"]`, table)) cell.hidden = !show;
  }
}

function rememberColumns(table) {
  const hidden = qsa("[data-dt-col]", table).filter((box) => !box.checked).map((box) => box.dataset.dtCol);
  store.set(`dt.${table.dataset.dtId}.hidden`, hidden);
}

export function initTables(root = document) {
  const tables = root instanceof Element && root.matches("[data-dt]") ? [root] : qsa("[data-dt]", root);
  for (const table of tables) {
    applyColumns(table);
    // A remembered page size different from the rendered one: ask once for the preferred size.
    const id = table.dataset.dtId;
    const preferred = store.get(`dt.${id}.size`);
    const size = field(table, "size");
    if (preferred && size && String(preferred) !== size.value && !appliedSize.has(id) && table.dataset.dtSrc) {
      appliedSize.add(id);
      size.value = String(preferred);
      field(table, "page").value = "1";
      submit(table);
    }
    appliedSize.add(id);
  }
}

function rowDetails(row) {
  const table = tableOf(row);
  const headers = new Map(qsa("thead th[data-col]", table).map((th) => [th.dataset.col, th.textContent.trim()]));
  const list = el("dl", { class: "kv" });
  for (const cell of qsa("td[data-col]", row)) {
    list.append(el("dt", { text: headers.get(cell.dataset.col) || cell.dataset.label || "" }),
      el("dd", { text: cell.textContent.trim() || "n/a" }));
  }
  return list;
}

function openRow(row, opener) {
  const firstCell = qs("td", row);
  const title = firstCell ? firstCell.textContent.trim() : "Details";
  if (row.dataset.drawerSrc) openDrawerFrom(row.dataset.drawerSrc, title, opener);
  else openDrawer(title, rowDetails(row), opener);
}

export function initTableEvents() {
  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    const table = tableOf(target);
    if (!table) {
      const toggle = target ? target.closest("[data-heatmap-numbers]") : null;
      if (toggle) {
        const figure = toggle.closest(".heatmap");
        const on = !figure.classList.contains("heatmap--numbers");
        figure.classList.toggle("heatmap--numbers", on);
        toggle.setAttribute("aria-pressed", String(on));
        toggle.textContent = on ? "Show colors" : "Show numbers";
      }
      return;
    }
    const sort = target.closest("[data-dt-sort]");
    if (sort) {
      field(table, "sort").value = sort.dataset.dtSort;
      field(table, "dir").value = sort.dataset.dtNextDir || "desc";
      field(table, "page").value = "1";
      submit(table);
      return;
    }
    const page = target.closest("[data-dt-page]");
    if (page && !page.disabled) {
      field(table, "page").value = page.dataset.dtPage;
      submit(table);
      return;
    }
    const opener = target.closest("[data-dt-open]");
    const row = target.closest("tbody tr");
    if (opener && row) {
      openRow(row, opener);
      return;
    }
    // A click anywhere on a row with details (but not on its links or controls) opens them too.
    if (row && row.dataset.drawerSrc && !target.closest("a, button, input, select, label, summary")) {
      openRow(row, qs("[data-dt-open]", row) || row);
    }
  });

  document.addEventListener("change", (event) => {
    const target = event.target;
    const table = tableOf(target);
    if (!table) return;
    if (target.matches("[data-dt-size]")) {
      field(table, "size").value = target.value;
      field(table, "page").value = "1";
      store.set(`dt.${table.dataset.dtId}.size`, Number(target.value));
      submit(table);
    } else if (target.matches("[data-dt-col]")) {
      for (const cell of qsa(`[data-col="${CSS.escape(target.dataset.dtCol)}"]`, table)) cell.hidden = !target.checked;
      rememberColumns(table);
    }
  });

  // A new search or filter starts again from page 1 (capture: runs before htmx reads the form).
  const resetPage = (event) => {
    const form = event.target instanceof Element ? event.target.closest("[data-dt-state]") : null;
    if (form && event.target.type !== "hidden") {
      const page = qs('[data-dt-field="page"]', form);
      if (page) page.value = "1";
    }
  };
  document.addEventListener("input", resetPage, true);
  document.addEventListener("change", resetPage, true);
}
