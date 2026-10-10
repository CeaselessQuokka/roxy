/**
 * The shell's live status: notice a pause or emergency limit switched from another tab, worker or admin.
 *
 * What this is
 *   `initShellStatus()` listens for the page-wide stream's `settings_changed` event (a switch change bumps
 *   `config_version` like a setting change) and asks `GET /admin/ui/status` (`data-status-url` on <body>) for the
 *   switches' signature. When it differs from the one this page was rendered with (`data-status-sig`), the banners,
 *   the top bar buttons and the pause dialogs are out of date: the page reloads at once when nothing would be lost,
 *   and otherwise says so with a toast and waits.
 *
 * Why it exists
 *   Plan 14.1: the banners and the Pause and Emergency Limit toggles must say what callers get right now, on every
 *   open dashboard, within seconds of the change (v1 refreshed its whole dashboard on a timer).
 *
 * How it works
 *   At most one check per second; nothing while the tab is hidden (the check runs on `visibilitychange` instead).
 *   "Nothing would be lost": no unsaved setting, no open dialog with typed text (dom.js `hasUnsavedChanges`), no open
 *   dialog at all.
 *
 * What to read next
 *   roxy/admin/pages/shell.py (`status_signature`), templates/admin/_layout/banners.html.
 */

import { hasUnsavedChanges, qs } from "roxy/dom";
import { getJSON } from "roxy/net";
import { toast } from "roxy/toast";

const MIN_GAP_MS = 1000;
let lastCheck = -Infinity;
let warned = false;
let staleWhileHidden = false;

async function check() {
  const url = document.body.dataset.statusUrl;
  const mine = document.body.dataset.statusSig;
  if (!url || !mine) return;
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
  if (!answer || typeof answer.signature !== "string" || answer.signature === mine) return;
  if (!hasUnsavedChanges() && !qs("dialog[open]")) {
    window.location.reload();
    return;
  }
  if (!warned) {
    warned = true;
    const what = answer.paused ? "The proxy was paused" : answer.throttle_all ? "The emergency limit changed" : "The proxy state changed";
    toast(`${what} elsewhere. Reload the page to see the current state.`, { tone: "warn" });
  }
}

export function initShellStatus() {
  document.addEventListener("roxy:sse:settings_changed", check);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && staleWhileHidden) {
      staleWhileHidden = false;
      check();
    }
  });
}
