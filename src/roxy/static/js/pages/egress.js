/**
 * The Egress page's own script (templates/admin/pages/egress.html): verify rotation, reveal exit addresses.
 *
 * What this is
 *   - "Verify rotation now" (`[data-action="rotator-verify"]`): POST /admin/api/v1/egress/rotator/probe (CSRF added
 *     by net.js), then a toast that says what happened, in v1's words ("Rotation working: exit IP ...", "Rotation
 *     FAILED: ...", "Rotation is not configured"), and the Exit IPs card is refreshed from its fragment.
 *   - "Show full addresses" (`[data-action="exit-ips-reveal"]`): GET /admin/api/v1/egress/exit-ips?reveal=true,
 *     which writes an audit row before it answers (no audit row, no reveal), then the table's address cells are
 *     filled with the full addresses, in the same newest-first order, as text.
 *   Everything else (tables, dialogs, settings, forms) is the shared design system.
 *
 * Why it exists
 *   The probe's answer is the point of the button: a plain form could only say "done". The reveal must stay an
 *   explicit, audited act of the admin, never part of the first paint.
 *
 * How it works
 *   Delegated click listeners (cards are swapped by htmx). The URLs come from the server's own attributes; the
 *   answers are written with `textContent` only. A refused or failed request says so in a toast.
 *
 * What to read next
 *   static/js/page.js, roxy/admin/api/egress.py (`probe_rotator`, `exit_ips`).
 */

import { el } from "roxy/dom";
import { getJSON, refreshCard, request, toast } from "roxy/page";

async function verify(button) {
  const url = button.dataset.probeUrl;
  if (!url || button.disabled) return;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try {
    const response = await request(url, { method: "POST", body: "{}", headers: { "Content-Type": "application/json" } });
    if (response.status === 401) return;
    if (!response.ok) {
      toast(`Rotation check failed (${response.status}). Nothing was changed.`, { tone: "bad" });
      return;
    }
    const answer = await response.json();
    if (!answer.configured) toast("Rotation is not configured", { tone: "warn" });
    else if (answer.ok) toast(`Rotation working: exit IP ${answer.exit_ip}`, { tone: "ok" });
    else toast(`Rotation FAILED: ${answer.error || "no IP returned"}`, { tone: "bad" });
    refreshCard("exit-ips");
  } catch {
    toast("Rotation check failed: Roxy could not be reached.", { tone: "bad" });
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}

async function reveal(button) {
  const url = button.dataset.revealUrl;
  const card = button.closest("[data-card]");
  if (!url || !card) return;
  button.disabled = true;
  try {
    const answer = await getJSON(url);
    const cells = [...card.querySelectorAll("[data-exit-ip]")];
    const items = Array.isArray(answer.items) ? answer.items : [];
    if (items.length === cells.length) {
      cells.forEach((cell, index) => {
        const item = items[index];
        if (item && typeof item.ip === "string") cell.textContent = item.ip;
      });
    } else {
      // A probe added an exit since the card was drawn: rebuild the rows from the answer (text only).
      const body = card.querySelector("[data-exit-ips] tbody");
      if (body) {
        body.replaceChildren(...items.map((item) => el("tr", {}, [
          el("td", { class: "mono", "data-exit-ip": "", text: String(item.ip || "") }),
          el("td", { text: String(item.source || "") }),
          el("td", { text: Number.isFinite(item.at) ? new Date(item.at * 1000).toLocaleString("en-US") : "n/a" }),
        ])));
      }
    }
    toast("Full exit addresses shown; the reveal is in the audit log.", { tone: "info" });
    button.hidden = true;
  } catch {
    toast("The addresses could not be revealed (the audit log may be busy). Try again shortly.", { tone: "bad" });
    button.disabled = false;
  }
}

document.addEventListener("click", (event) => {
  const target = event.target instanceof Element ? event.target : null;
  if (!target) return;
  const probe = target.closest('[data-action="rotator-verify"]');
  if (probe) {
    verify(probe);
    return;
  }
  const show = target.closest('[data-action="exit-ips-reveal"]');
  if (show) reveal(show);
});
