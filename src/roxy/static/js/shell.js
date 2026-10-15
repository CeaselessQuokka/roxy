/**
 * The shell's live status: notice a pause or emergency limit switched or changed from another tab, worker or admin.
 *
 * What this is
 *   `initShellStatus()` listens for the page-wide stream's `settings_changed` event (a switch change bumps
 *   `config_version` like a setting change) and asks `GET /admin/ui/status` (`data-status-url` on <body>) for the
 *   switches' signature and the digest of everything the shell prints about them (the limit, the period, the
 *   messages, a scheduled window). When either differs from what this page was rendered with (`data-status-sig`,
 *   `data-status-digest`), the banners, the top bar buttons and the pause dialogs are out of date. A switch turned
 *   on or off reloads the page at once when nothing would be lost (cards show the state too); otherwise, and for a
 *   change that leaves the switches as they were (a new limit or message), the shell's parts are redrawn in place
 *   from `GET /admin/ui/status/parts` (with a toast when a reload had to wait). It also keeps the recommendations bell current after a recommendation event or an action
 *   on a recommendation, and checks again when a scheduled maintenance window starts or ends (no event marks those
 *   moments: `data-status-next`).
 *
 * Why it exists
 *   Plan 14.1: the banners and the Pause and Emergency Limit toggles must say what callers get right now, on every
 *   open dashboard, within seconds of the change (v1 refreshed its whole dashboard on a timer). Review findings
 *   functional-6 (a new limit never reached the banner: the old signature knew only the two switches), functional-8
 *   (a page kept by "Leave site?" offered Pause while the proxy was paused) and functional-11 (the bell kept its
 *   count after a dismiss).
 *
 * How it works
 *   At most one check per second; nothing while the tab is hidden (the check runs on `visibilitychange` instead).
 *   "Nothing would be lost": no unsaved setting, no open dialog with typed text (dom.js `hasUnsavedChanges`), no open
 *   dialog at all. Redrawing in place swaps every `[data-shell-part]` element and each control dialog that is not
 *   open (an open one is swapped when it closes), keeps keyboard focus on the swapped element, and takes the new
 *   signature, digest and next change time from the parts' root. A reload the admin refused (`roxy:reload-kept`,
 *   dom.js) redraws at once.
 *
 * What to read next
 *   roxy/admin/pages/shell.py (`status_signature`, `status_parts_context`), templates/admin/_layout/status_parts.html.
 */

import htmx from "roxy/htmx_setup";
import { hasUnsavedChanges, qs, qsa, reloadPage, reloadPending } from "roxy/dom";
import { getJSON, request } from "roxy/net";
import { toast } from "roxy/toast";

const MIN_GAP_MS = 1000;
const BELL_GAP_MS = 2000;
const CONTROL_DIALOGS = ["dlg-pause", "dlg-throttle-all"];
const MAX_TIMER_MS = 24 * 60 * 60 * 1000;
let lastCheck = -Infinity;
let lastBell = -Infinity;
let warned = false;
let staleWhileHidden = false;
let nextTimer = 0;

function differs(answer) {
  const data = document.body.dataset;
  if (typeof answer.signature === "string" && answer.signature !== data.statusSig) return true;
  return typeof answer.digest === "string" && Boolean(data.statusDigest) && answer.digest !== data.statusDigest;
}

/** Swap the shell's state parts in place from `GET /admin/ui/status/parts`; `only` limits it to some parts. */
async function redraw(only = null) {
  const url = document.body.dataset.statusPartsUrl;
  if (!url) return false;
  let response;
  try {
    response = await request(url, { accept: "text/html" });
  } catch {
    return false;
  }
  if (!response.ok) return false;
  const html = await response.text();
  // Our own server-rendered, autoescaped template; parsed into an inert document, never run as script.
  const parsed = new DOMParser().parseFromString(html, "text/html");
  const root = qs("[data-shell-parts]", parsed);
  if (!root) return false;
  const swapped = [];
  for (const fresh of qsa("[data-shell-part]", root)) {
    const name = fresh.dataset.shellPart;
    if (only && !only.includes(name)) continue;
    const current = qs(`[data-shell-part="${CSS.escape(name)}"]`);
    if (!current) continue;
    const focused = current === document.activeElement || current.contains(document.activeElement);
    const node = document.importNode(fresh, true);
    current.replaceWith(node);
    swapped.push(node);
    if (focused) node.focus();
  }
  if (!only) {
    for (const id of CONTROL_DIALOGS) {
      const fresh = qs(`#${id}`, root);
      const current = document.getElementById(id);
      if (!fresh || !current) continue;
      if (current.open) {
        current.addEventListener("close", () => redraw(), { once: true });  // never under the admin's hands
        continue;
      }
      const node = document.importNode(fresh, true);
      current.replaceWith(node);
      swapped.push(node);
    }
    const data = document.body.dataset;
    data.statusSig = root.dataset.statusSig || "";
    data.statusDigest = root.dataset.statusDigest || "";
    data.statusNext = root.dataset.statusNext || "";
    scheduleNext();
  }
  for (const node of swapped) htmx.process(node);
  return true;
}

async function check() {
  const url = document.body.dataset.statusUrl;
  const mine = document.body.dataset.statusSig;
  if (!url || !mine || reloadPending()) return;
  if (document.hidden) {
    staleWhileHidden = true;
    return;
  }
  const now = performance.now();
  if (now - lastCheck < MIN_GAP_MS) return;
  lastCheck = now;
  let answer;
  try {
    answer = await getJSON(url);
  } catch {
    return;
  }
  if (!answer || typeof answer.signature !== "string" || !differs(answer)) return;
  if (answer.signature === document.body.dataset.statusSig) {
    // The switches are as they were; only what the shell prints about them changed (a new limit, a new message):
    // the top bar, banners and dialogs are redrawn in place, the cards stay.
    await redraw();
    return;
  }
  if (!hasUnsavedChanges() && !qs("dialog[open]")) {
    // One reload, even when the action that made this change already asked for its own (dom.js `reloadPage`).
    reloadPage();
    return;
  }
  // The page must stay (an edit or a dialog in progress): the top bar, banners and closed dialogs are redrawn.
  await redraw();
  if (!warned) {
    warned = true;
    const what = answer.paused ? "The proxy is paused" : answer.throttle_all ? "The emergency limit changed" : "The proxy state changed";
    toast(`${what}. The top bar and banners show it now; reload the page to update the cards.`, { tone: "warn" });
  }
}

/** Check again when a scheduled maintenance window starts or ends (`data-status-next`, epoch seconds). */
function scheduleNext() {
  window.clearTimeout(nextTimer);
  const at = Number(document.body.dataset.statusNext);
  if (!Number.isFinite(at) || at <= 0) return;
  const delay = at * 1000 - Date.now() + 1000;
  if (delay <= 0 || delay > MAX_TIMER_MS) return;
  nextTimer = window.setTimeout(() => {
    lastCheck = -Infinity;
    check();
  }, delay);
}

/** The bell after a recommendation changed (an event, or an action on one in this tab); throttled. */
function refreshBell() {
  const now = performance.now();
  if (now - lastBell < BELL_GAP_MS) return;
  lastBell = now;
  redraw(["topbar-recs", "mobile-recs"]);
}

export function initShellStatus() {
  document.addEventListener("roxy:sse:settings_changed", check);
  document.addEventListener("roxy:sse:recommendation", refreshBell);
  document.addEventListener("roxy:api-success", (event) => {
    const form = event.target instanceof Element ? event.target.closest("form[data-api-url]") : null;
    if (form && /\/recommendations(\/|$)/.test(new URL(form.dataset.apiUrl, window.location.href).pathname)) {
      lastBell = -Infinity;
      refreshBell();
    }
  });
  // A reload the admin refused at the browser's "Leave site?": the page stays, so redraw what changed.
  document.addEventListener("roxy:reload-kept", () => {
    lastCheck = -Infinity;
    redraw();
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && staleWhileHidden) {
      staleWhileHidden = false;
      check();
    }
  });
  scheduleNext();
}
