/**
 * Command palette and keyboard shortcuts (plan 14.6).
 *
 * What this is
 *   `initPalette()` wires the palette dialog (templates/admin/_layout/palette.html) and the global shortcuts:
 *   Ctrl+K (or Cmd+K) and / open the palette; ? opens the shortcut list; G then a letter goes to a page
 *   (G O overview, G R recommendations, G U upstream, G C cache, G P protection, G L live, G S settings); T cycles
 *   the time range; C turns the comparison on or off; Escape closes (the native dialog does that).
 *
 * Why it exists
 *   A dashboard with 18 pages and about 500 settings needs a way to get anywhere without hunting through menus.
 *   Shortcuts are single keys, so they must never fire while the admin types into a field (a search box, a
 *   setting), and they are listed in one overlay so they are discoverable. WCAG 2.1.4 (Level A) also asks for a
 *   way to turn single-character shortcuts off: speech input users and anyone with a tremor trigger them by
 *   accident. The switch ("Single-key shortcuts", in the ? overlay and the account menu) is remembered in this
 *   browser; Ctrl+K, which needs a modifier, always works. A shortcut that would leave the page (G then a
 *   letter, T, C) never discards an unsaved setting: it says so instead (the browser's own "Leave site?" guard
 *   in app.js covers links and everything else).
 *
 * How it works
 *   The input is an ARIA combobox that owns a listbox. Typing filters the rendered options (pages and actions)
 *   by a simple score (label starts with the text, then a word starts with it, then contains it), and, when the
 *   dialog has `data-search-url`, asks the server for matching settings, endpoints, clients and recommendations
 *   (JSON list of {group, label, hint, href, icon}; at most 20; the request is canceled when the text changes).
 *   A result whose link is not a path under /admin on this site is dropped (net.js localAdminHref), so a bad
 *   search answer can never send the admin to another site.
 *   Up and Down move the active option (aria-activedescendant), Enter follows it: a link (`data-href`), a dialog
 *   (`data-open`), a POST through htmx (`data-post`, so the CSRF header is added), or a built-in action. While
 *   the session-expired alert is open every shortcut, Ctrl+K included, is ignored.
 *
 * What to read next
 *   templates/admin/_layout/palette.html, templates/admin/_layout/shortcuts.html, static/js/dialog.js.
 */

import htmx from "roxy/htmx_setup";
import { el, hasUnsavedChanges, icon, isTyping, qs, qsa, store } from "roxy/dom";
import { closeDialog, openDialog, sessionOverlayOpen } from "roxy/dialog";
import { copyTextFrom, downloadFrom } from "roxy/exports";
import { errorMessage, isReauthRequired, localAdminHref, request } from "roxy/net";
import { confirmIdentity } from "roxy/reauth";
import { cycleTheme } from "roxy/theme";
import { toast } from "roxy/toast";

const G_TIMEOUT_MS = 1500;
const MAX_REMOTE = 20;
const SHORTCUTS_KEY = "shortcuts";

/** Whether single-key shortcuts are on in this browser (on unless the admin turned them off). */
export function shortcutsEnabled() {
  return store.get(SHORTCUTS_KEY, "on") !== "off";
}

function reflectShortcuts() {
  for (const box of qsa("[data-shortcuts-toggle]")) box.checked = shortcutsEnabled();
}

function setShortcuts(on) {
  store.set(SHORTCUTS_KEY, on ? "on" : "off");
  reflectShortcuts();
  toast(on ? "Single-key shortcuts are on." : "Single-key shortcuts are off. Ctrl+K still opens the palette.", {
    tone: "info",
  });
}

/** False (and a toast saying why) when leaving the page now would throw away an unsaved edit. */
function navigateAllowed() {
  if (!hasUnsavedChanges()) return true;
  toast("A changed setting is not saved yet. Save it or put the old value back first.", { tone: "warn" });
  return false;
}

/** Leave the page for `href`, unless that would throw away an unsaved edit. */
function navigate(href) {
  if (navigateAllowed()) window.location.assign(href);
}

let dialog;
let input;
let list;
let emptyNote;
let statusNote;
let activeId = "";
let originalOrder = [];
let remoteController = null;
let remoteTimer = 0;

function options() {
  return qsa('[role="option"]', list).filter((option) => !option.hidden);
}

function setActive(option) {
  for (const item of qsa('[role="option"][aria-selected="true"]', list)) item.setAttribute("aria-selected", "false");
  activeId = option ? option.id : "";
  input.setAttribute("aria-activedescendant", activeId);
  if (option) {
    option.setAttribute("aria-selected", "true");
    option.scrollIntoView({ block: "nearest" });
  }
}

function score(option, query) {
  const label = (qs(".palette__label", option)?.textContent || "").toLowerCase();
  const haystack = `${label} ${option.dataset.search || ""}`.toLowerCase();
  if (!query) return 1;
  if (label.startsWith(query)) return 4;
  if (label.split(/\s+/).some((word) => word.startsWith(query))) return 3;
  if (label.includes(query)) return 2;
  return query.split(/\s+/).every((part) => haystack.includes(part)) ? 1 : 0;
}

function regroup() {
  for (const header of qsa(".palette__group", list)) header.remove();
  const seen = new Set();
  for (const option of options()) {
    const group = option.dataset.group || "Results";
    if (seen.has(group)) continue;
    seen.add(group);
    option.before(el("li", { class: "palette__group", role: "presentation", text: group }));
  }
}

function filter() {
  const query = input.value.trim().toLowerCase();
  const ranked = [];
  for (const option of qsa('[role="option"]', list)) {
    const value = score(option, query);
    option.hidden = value === 0;
    if (value) ranked.push([value, option]);
  }
  // Stable sort by score within groups: pages and actions keep their order unless the text ranks them.
  if (query) {
    ranked.sort((a, b) => b[0] - a[0]);
    for (const [, option] of ranked) list.append(option);
  } else {
    for (const option of originalOrder) list.append(option);
  }
  regroup();
  const visible = options();
  emptyNote.hidden = visible.length > 0;
  setActive(visible[0] || null);
  statusNote.textContent = `${visible.length} result${visible.length === 1 ? "" : "s"}`;
  scheduleRemote(query);
}

function scheduleRemote(query) {
  window.clearTimeout(remoteTimer);
  if (remoteController) remoteController.abort();
  for (const option of qsa("[data-remote]", list)) option.remove();
  const url = dialog.dataset.searchUrl;
  if (!url || query.length < 2) return;
  remoteTimer = window.setTimeout(async () => {
    remoteController = new AbortController();
    try {
      const target = new URL(url, window.location.href);
      target.searchParams.set("q", query);
      const response = await request(target.pathname + target.search, { signal: remoteController.signal });
      if (!response.ok) return;
      const answer = await response.json();
      const results = (Array.isArray(answer) ? answer : []).slice(0, MAX_REMOTE);
      results.forEach((result, index) => {
        const href = localAdminHref(result && result.href);
        if (!href) return;  // only paths under /admin on this site (see the module docstring)
        list.append(el("li", {
          class: "palette__item", role: "option", id: `pal-remote-${index}`, "aria-selected": "false",
          "data-remote": "1", "data-group": result.group || "Results", "data-href": href,
          "data-search": query,
        }, [icon(result.icon || "search"), el("span", { class: "palette__label", text: result.label }),
          el("span", { class: "palette__hint", text: result.hint || "" })]));
      });
      regroup();
      const visible = options();
      emptyNote.hidden = visible.length > 0;
      if (!activeId) setActive(visible[0] || null);
      statusNote.textContent = `${visible.length} result${visible.length === 1 ? "" : "s"}`;
    } catch {
      /* canceled or offline: the local results stay */
    }
  }, 200);
}

/**
 * POST a JSON body to an admin API action (the palette's Run health check): the CSRF header, "Confirm it is you"
 * on a 403 `reauth_required`, then the page named by `data-then` (where the result shows).
 */
async function postAction(option, retried = false) {
  const url = localAdminHref(option.dataset.postJson);
  if (!url) return;
  let response;
  try {
    response = await request(url, {
      method: "POST",
      body: option.dataset.jsonBody || "{}",
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    toast("Roxy could not be reached. Nothing was started.", { tone: "bad" });
    return;
  }
  const then = localAdminHref(option.dataset.then || "");
  if (response.ok || response.status === 409) {
    // 409 run_in_progress: a run is already going; following it is what the admin wants (the Health page).
    toast(response.ok ? "Started. Follow it on the Health page." : "A health run is already running; showing it.", {
      tone: "info",
    });
    if (then) navigate(then);
    return;
  }
  const text = await response.text().catch(() => "");
  if (!retried && isReauthRequired(response.status, response.headers.get("Roxy-Reauth"), text)) {
    if (await confirmIdentity()) postAction(option, true);
    return;
  }
  if (response.status !== 401) toast(errorMessage(text) || `Refused (${response.status}).`, { tone: "bad" });
}

function run(option) {
  if (!option) return;
  if (option.dataset.href) {
    const href = localAdminHref(option.dataset.href);
    if (href) navigate(href);
  } else if (option.dataset.open) {
    closeDialog(dialog);
    openDialog(option.dataset.open);
  } else if (option.dataset.postJson) {
    closeDialog(dialog);
    postAction(option);
  } else if (option.dataset.post) {
    closeDialog(dialog);
    htmx.ajax("POST", option.dataset.post, { swap: "none", source: document.body });
    toast("Started. Results appear on the Health page.", { tone: "info" });
  } else if (option.dataset.action === "llm-copy") {
    closeDialog(dialog);
    copyTextFrom(option.dataset.url || "");
  } else if (option.dataset.action === "llm-download") {
    closeDialog(dialog);
    downloadFrom(option.dataset.url || "");
  } else if (option.dataset.action === "theme") {
    const theme = cycleTheme();
    toast(`Theme: ${theme === "system" ? "follow the system" : theme}`, { tone: "info" });
  }
}

export function openPalette(opener) {
  if (!dialog) return;
  input.value = "";
  filter();
  if (openDialog(dialog, opener)) input.focus();
}

function cycleRange() {
  const form = qs("[data-range-form]");
  if (!form || !navigateAllowed()) return;
  const radios = qsa('input[name="range"]', form).filter((radio) => radio.value !== "custom");
  const index = radios.findIndex((radio) => radio.checked);
  radios[(index + 1) % radios.length].checked = true;
  form.requestSubmit();
}

function toggleCompare() {
  const form = qs("[data-range-form]");
  if (!form || !navigateAllowed()) return;
  const current = qs('input[name="compare"]:checked', form);
  const target = qs(`input[name="compare"][value="${current && current.value !== "none" ? "none" : "previous"}"]`, form);
  if (target) target.checked = true;
  form.requestSubmit();
}

export function initPalette() {
  dialog = document.getElementById("palette");
  if (!dialog) return;
  input = qs("#palette-input", dialog);
  list = qs("#palette-list", dialog);
  emptyNote = qs("[data-palette-empty]", dialog);
  statusNote = qs("[data-palette-status]", dialog);
  originalOrder = qsa('[role="option"]', list);
  const pageKeys = new Map();
  for (const option of qsa("[data-keys]", list)) {
    const parts = option.dataset.keys.split(" ");
    if (parts.length === 2 && parts[0] === "g") pageKeys.set(parts[1], option.dataset.href);
  }

  input.addEventListener("input", filter);
  input.addEventListener("keydown", (event) => {
    const visible = options();
    const index = visible.findIndex((option) => option.id === activeId);
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      setActive(visible[(index + step + visible.length) % visible.length] || null);
    } else if (event.key === "Home" && visible.length) {
      event.preventDefault();
      setActive(visible[0]);
    } else if (event.key === "End" && visible.length) {
      event.preventDefault();
      setActive(visible[visible.length - 1]);
    } else if (event.key === "Enter") {
      event.preventDefault();
      run(visible[index] || visible[0]);
    }
  });
  list.addEventListener("click", (event) => {
    const option = event.target instanceof Element ? event.target.closest('[role="option"]') : null;
    if (option) run(option);
  });
  list.addEventListener("pointermove", (event) => {
    const option = event.target instanceof Element ? event.target.closest('[role="option"]') : null;
    if (option && option.id !== activeId) setActive(option);
  });

  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;
    const opener = target.closest("[data-palette-open]");
    if (opener) {
      event.preventDefault();
      openPalette(opener);
    }
    if (target.closest("[data-shortcuts-open]")) {
      event.preventDefault();
      openDialog("shortcuts", target.closest("[data-shortcuts-open]"));
    }
  });

  // The off switch for single-key shortcuts (WCAG 2.1.4), in the ? overlay and the account menu.
  reflectShortcuts();
  document.addEventListener("change", (event) => {
    if (event.target instanceof HTMLInputElement && event.target.matches("[data-shortcuts-toggle]")) {
      setShortcuts(event.target.checked);
    }
  });

  let gPressedAt = -Infinity;
  document.addEventListener("keydown", (event) => {
    if (sessionOverlayOpen()) return;  // the session-expired alert keeps the keyboard to itself
    const key = event.key.toLowerCase();
    if ((event.ctrlKey || event.metaKey) && !event.altKey && key === "k") {
      event.preventDefault();
      if (dialog.open) closeDialog(dialog);
      else openPalette(document.activeElement);
      return;
    }
    if (event.ctrlKey || event.metaKey || event.altKey || isTyping(event.target) || qs("dialog[open]")) return;
    if (!shortcutsEnabled()) return;
    if (event.target instanceof Element && event.target.closest("[data-live-tail]") && key === "p") return;
    if (key === "/") {
      event.preventDefault();
      openPalette(document.activeElement);
    } else if (event.key === "?") {
      event.preventDefault();
      openDialog("shortcuts", document.activeElement);
    } else if (performance.now() - gPressedAt < G_TIMEOUT_MS && pageKeys.has(key)) {
      gPressedAt = -Infinity;
      navigate(pageKeys.get(key));
    } else if (key === "g") {
      gPressedAt = performance.now();
    } else if (key === "t") {
      cycleRange();
    } else if (key === "c") {
      toggleCompare();
    }
  });
}
