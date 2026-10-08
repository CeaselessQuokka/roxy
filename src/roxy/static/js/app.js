/**
 * Dashboard entry module: the one script every admin page loads (templates/admin/base.html).
 *
 * What this is
 *   Imports htmx (configured by htmx_setup.js) and Alpine (CSP build), registers the Alpine components, and starts
 *   every behavior the shell needs: theme, toasts, tooltips, dialogs and menus, the command palette and
 *   shortcuts, the session heartbeat, data tables, the sidebar, remembered <details>, copy buttons, the time range
 *   form and the page-wide live stream. Charts and live tails are loaded only on pages that have them.
 *
 * Why it exists
 *   Under the CSP (plan 9.2) the page carries exactly two script elements, both with the response nonce: the
 *   import map and this module. Everything else arrives through `import`, which the browser trusts because the
 *   importing module was trusted ('strict-dynamic'); the import map pins each vendored library's SRI hash, so a
 *   modified file on the server is refused by the browser. No inline handlers, no eval, no string timers.
 *
 * How it works
 *   Module scripts run after the document is parsed and before DOMContentLoaded, so the DOM is ready here and htmx
 *   has not processed the page yet. Content that htmx swaps in later raises `htmx:load`; `enhance()` runs the
 *   per-fragment setup (tables, charts, live tails) on it. Alpine watches the DOM itself, so components inside
 *   swapped fragments start on their own. Charts and live tails release themselves when they leave the page.
 *   The tooltip, the toasts and the two live regions join whichever modal dialog is open (dom.js overlay layer),
 *   and leaving the page while a setting or a dialog form holds an unsaved edit asks the browser's own "Leave
 *   site?" question first (`beforeunload`; the browser shows it only after the admin has used the page).
 *
 * What to read next
 *   static/js/htmx_setup.js, static/js/components.js, then any module named below.
 */

import "roxy/htmx_setup";
import Alpine from "vendor/alpine";
import { registerComponents } from "roxy/components";
import { hasUnsavedChanges, initOverlayLayer, qs, qsa, store } from "roxy/dom";
import { initDialogs, initMenus } from "roxy/dialog";
import { initPalette } from "roxy/palette";
import { initSession } from "roxy/session";
import { initStream } from "roxy/sse";
import { initTableEvents, initTables } from "roxy/tables";
import { initTheme } from "roxy/theme";
import { initToasts, toast } from "roxy/toast";
import { initTooltips } from "roxy/tooltip";

function initSidebar() {
  const shell = qs("[data-shell]");
  const button = qs("[data-sidebar-toggle]");
  if (!shell || !button) return;
  const apply = (collapsed) => {
    if (collapsed) shell.dataset.sidebar = "collapsed";
    else delete shell.dataset.sidebar;
    button.setAttribute("aria-expanded", String(!collapsed));
    button.setAttribute("aria-label", collapsed ? "Expand the sidebar" : "Collapse the sidebar");
  };
  apply(store.get("sidebar") === "collapsed");
  button.addEventListener("click", () => {
    const collapsed = shell.dataset.sidebar !== "collapsed";
    apply(collapsed);
    store.set("sidebar", collapsed ? "collapsed" : "open");
  });
}

/** <details data-remember="key"> keeps its open or closed state in this browser (the "How to read" panels). */
function initRemember(root = document) {
  for (const details of qsa("details[data-remember]", root)) {
    const key = `details.${details.dataset.remember}`;
    const saved = store.get(key);
    if (typeof saved === "boolean") details.open = saved;
    details.addEventListener("toggle", () => store.set(key, details.open));
  }
}

function initCopy() {
  document.addEventListener("click", async (event) => {
    const button = event.target instanceof Element ? event.target.closest("[data-copy]") : null;
    if (!button) return;
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      toast(`Copied ${button.dataset.copy}`, { tone: "info" });
    } catch {
      toast("Copying is blocked in this browser; select the text instead.", { tone: "warn" });
    }
  });
}

/** The time range form keeps the page's other query parameters (filters) when it is applied (plan 14.2). */
function initRangeForm() {
  const form = qs("[data-range-form]");
  if (!form) return;
  form.addEventListener("change", (event) => {
    const target = event.target;
    if (target instanceof HTMLInputElement && target.name === "range" && target.value !== "custom") form.requestSubmit();
    if (target instanceof HTMLInputElement && target.name === "compare") form.requestSubmit();
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const url = new URL(window.location.href);
    const data = new FormData(form);
    for (const name of ["range", "compare", "from", "to"]) url.searchParams.delete(name);
    const range = data.get("range") || "24h";
    url.searchParams.set("range", range);
    const compare = data.get("compare") || "off";
    if (compare !== "off") url.searchParams.set("compare", compare);
    if (range === "custom") {
      if (data.get("from")) url.searchParams.set("from", data.get("from"));
      if (data.get("to")) url.searchParams.set("to", data.get("to"));
    }
    window.location.assign(url.pathname + url.search + url.hash);
  });
}

/** The browser's "Leave site?" question while an edit is unsaved (links, reloads, the range form, closing the tab). */
function initLeaveGuard() {
  window.addEventListener("beforeunload", (event) => {
    if (!hasUnsavedChanges()) return;
    event.preventDefault();
    event.returnValue = "";  // older browsers show the question only when returnValue is set
  });
}

async function enhance(root) {
  initTables(root);
  if (root.querySelector("[data-chart]") || (root.matches && root.matches("[data-chart]"))) {
    const { initCharts } = await import("roxy/charts");
    initCharts(root);
  }
  if (root.querySelector("[data-live-tail]") || (root.matches && root.matches("[data-live-tail]"))) {
    const { initLiveTails } = await import("roxy/live_tail");
    initLiveTails(root);
  }
}

registerComponents(Alpine);
Alpine.start();

initOverlayLayer(["#roxy-tip", "#toasts", "#sr-polite", "#sr-assertive"]);
initTheme();
initToasts();
initTooltips();
initDialogs();
initMenus();
initPalette();
initSession();
initTableEvents();
initSidebar();
initRemember();
initCopy();
initRangeForm();
initLeaveGuard();
initStream();
enhance(document.body);

document.addEventListener("htmx:load", (event) => {
  const root = event.detail && event.detail.elt;
  if (root instanceof Element && root !== document.body) enhance(root);
});

document.documentElement.dataset.ready = "1";
