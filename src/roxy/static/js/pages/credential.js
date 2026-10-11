/**
 * The Credential page's own script (templates/admin/pages/credential.html): the cooldown countdown, and the drawer
 * after a save.
 *
 * What this is
 *   The credential's cooldown (`[data-countdown]` on the Status card) shows "42 s left" and counts down once a second
 *   from the server's `data-ends-at-ms` and `data-now-ms` (so a browser clock that is off still shows the right
 *   time). A form saved from inside the drawer closes the drawer. Everything else (the forms, the dialogs with the
 *   typed confirmations, the second factor prompt, the allowlist table and its drawer) is the shared design system.
 *
 * Why it exists
 *   A cooldown that never moves reads as "stuck"; the owner wants to know when the account is usable again.
 *
 * How it works
 *   One timer for the page, ticking only while the tab is visible; each countdown remembers when it was first seen
 *   (`performance.now`, monotonic) and subtracts the time since. Text only (`textContent`).
 *
 * What to read next
 *   static/js/pages/upstream.js (the same countdown), static/js/page.js.
 */

import { onContent, toast } from "roxy/page";

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
    const text = words((ends - server - (now - start)) / 1000);
    if (node.textContent !== text) node.textContent = text;
  }
}

onContent("[data-countdown]", (node) => {
  seen.set(node, performance.now());
  live.add(node);
});

window.setInterval(tick, 1000);

// A form saved from inside the drawer (an allowlist row's edit form or its remove dialog) closes the drawer: the
// allowlist card is refreshed by the shared form handler, and the drawer would otherwise show the old row.
document.addEventListener("roxy:api-success", (event) => {
  const form = event.target instanceof Element ? event.target : null;
  if (!form) return;
  // A replace or a delete probes the new value at once, but the API waits at most 40 s for it: `pending` means the
  // probe is still running, so the Status card shows its result only after a later refresh.
  const answer = event.detail && event.detail.answer;
  if (answer && answer.pending === true) {
    toast("The probe of the credential is still running; refresh the Status card in a minute to see its result.", {
      tone: "info",
    });
  }
  if (!form.closest("#drawer")) return;
  const close = document.querySelector("#drawer .drawer__head [data-dialog-close]");
  if (close instanceof HTMLElement) close.click();
});
