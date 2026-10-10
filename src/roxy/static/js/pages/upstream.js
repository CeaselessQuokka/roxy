/**
 * The Upstream page's own script (templates/admin/pages/upstream.html): countdowns and the drawer after a save.
 *
 * What this is
 *   - Countdowns: every `[data-countdown]` (an open cooldown, a breaker's next test call) shows "42 s left" and
 *     counts down once a second from the server's `data-ends-at-ms` and `data-now-ms`, so a browser clock that is
 *     off by minutes still shows the right time. At zero it says "ended" (the card refreshes itself on the
 *     stream's `cooldown` and `breaker` events).
 *   - A form saved from inside the drawer (a bucket override, a routing rule) closes the drawer: the card it
 *     changed is refreshed by the shared form handler, and the drawer would otherwise show the old values.
 *   Everything else (tables, drawers, settings, the reset dialog, the trace lookup) is the shared design system.
 *
 * Why it exists
 *   A countdown that never moves reads as "stuck"; a drawer that keeps old values after a save reads as "not
 *   saved". Both are small, so they live here instead of in the shared modules.
 *
 * How it works
 *   One timer for the whole page, ticking only while the tab is visible; each countdown remembers when it was
 *   first seen (`performance.now`, monotonic) and subtracts the time since. Text only (`textContent`); no HTML.
 *
 * What to read next
 *   static/js/page.js (the helpers every page module uses), roxy/admin/pages/upstream.py.
 */

import { onContent } from "roxy/page";

const seen = new WeakMap();
const live = new Set();

function words(seconds) {
  if (seconds <= 0) return "ended";
  const whole = Math.ceil(seconds);
  if (whole < 60) return `${whole} s left`;
  const minutes = Math.floor(whole / 60);
  const rest = whole % 60;
  return rest ? `${minutes} min ${rest} s left` : `${minutes} min left`;
}

function tick() {
  if (document.hidden) return;
  const now = performance.now();
  for (const node of [...live]) {
    if (!node.isConnected) {
      live.delete(node);
      continue;
    }
    const start = seen.get(node);
    const ends = Number(node.dataset.endsAtMs);
    const server = Number(node.dataset.nowMs);
    if (!Number.isFinite(ends) || !Number.isFinite(server) || start === undefined) continue;
    const remaining = (ends - server - (now - start)) / 1000;
    const text = words(remaining);
    if (node.textContent !== text) node.textContent = text;
  }
}

onContent("[data-countdown]", (node) => {
  seen.set(node, performance.now());
  live.add(node);
});

window.setInterval(tick, 1000);

document.addEventListener("roxy:api-success", (event) => {
  const form = event.target instanceof Element ? event.target : null;
  if (!form || !form.closest("#drawer")) return;
  const close = document.querySelector("#drawer .drawer__head [data-dialog-close]");
  if (close instanceof HTMLElement) close.click();
});
