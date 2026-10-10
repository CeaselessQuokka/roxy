/**
 * The Overview page's own script (templates/admin/pages/overview.html): the Check Proxy Health button.
 *
 * What this is
 *   The button in the page header (plan 13.1: "Button on the Overview page header") starts a health run through
 *   `POST /admin/api/v1/health/runs` and opens it on the Health page, where the checklist fills in live. Everything
 *   else on the page (cards, tiles, the chart, the events table) is the shared design system.
 *
 * Why it exists
 *   A plain API form cannot follow the answer: a started run answers 202 with its id, and a run already going
 *   anywhere in the fleet answers 409 `run_in_progress` with that run's id in the `Roxy-Health-Run` header (the page
 *   then follows that run instead of failing). This button runs every check except the credential check, so one
 *   click never spends a call on the Roblox account or asks for the second factor; the Health page offers both.
 *
 * How it works
 *   `request()` sends the JSON body with the CSRF header. A 403 that asks for a fresh second factor (it cannot
 *   happen without the credential check, but the API decides) opens "Confirm it is you" and retries once. The run
 *   id from the answer or the header is checked to be a plain number before it goes into the address.
 *
 * What to read next
 *   static/js/pages/health.js (the same start flow on the Health page), roxy/admin/api/health.py.
 */

import { confirmIdentity, onContent, request, toast } from "roxy/page";

const RUN_ID = /^[0-9]{1,15}$/;
const MAX_ERROR_TEXT = 4096;

function errorOf(text) {
  try {
    const data = JSON.parse(String(text || "").slice(0, MAX_ERROR_TEXT));
    if (data && data.error && typeof data.error === "object") {
      return { code: String(data.error.code || ""), message: String(data.error.message || "").slice(0, 300) };
    }
  } catch {
    /* not JSON */
  }
  return { code: "", message: "" };
}

function follow(page, runId) {
  const id = RUN_ID.test(String(runId || "")) ? String(runId) : "";
  window.location.assign(`${page}${id ? `?run=${id}` : ""}#run`);
}

async function startRun(form) {
  const url = form.dataset.runUrl || "";
  const page = form.dataset.healthPage || "/admin/health";
  if (!url.startsWith("/admin/api/v1/")) return;
  const field = form.querySelector('[name="include_credential"]');
  const body = JSON.stringify({ include_credential: Boolean(field && field.value === "true") });
  let response = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    response = await request(url, { method: "POST", body, headers: { "Content-Type": "application/json" } });
    if (response.status !== 403 || attempt > 0) break;
    const problem = errorOf(await response.clone().text().catch(() => ""));
    if (problem.code !== "reauth_required" && response.headers.get("Roxy-Reauth") !== "required") break;
    if (!(await confirmIdentity())) {
      toast("No run was started: it needs your second factor.", { tone: "warn" });
      return;
    }
  }
  if (!response || response.status === 401) return;  // the session overlay is showing (net.js)
  if (response.status === 202) {
    const answer = await response.json().catch(() => ({}));
    toast("Health run started. Opening it on the Health page.", { tone: "ok" });
    follow(page, answer && answer.run_id);
    return;
  }
  if (response.status === 409) {
    toast("A health run is already running; opening it.", { tone: "info" });
    follow(page, response.headers.get("Roxy-Health-Run"));
    return;
  }
  const problem = errorOf(await response.text().catch(() => ""));
  const retry = response.headers.get("Retry-After");
  toast(`${problem.message || `The run could not start (${response.status}).`}${retry ? ` Try again in ${retry} seconds.` : ""}`, {
    tone: "bad",
  });
}

// The events table's answer is its whole card (the kit renders one template per card): keep only the table out of
// it, and let the card's refresh address follow the table's state, so a stream refresh keeps the admin's search.
document.addEventListener("htmx:beforeSwap", (event) => {
  const target = event.detail && event.detail.target;
  if (!(target instanceof Element) || !target.matches("[data-dt]") || !target.id) return;
  if (!event.detail.selectOverride && target.closest("[data-card]")) event.detail.selectOverride = `#${CSS.escape(target.id)}`;
});

onContent("[data-dt]", (table) => {
  const card = table.closest("[data-card]");
  const form = table.querySelector("[data-dt-state]");
  if (!card || !form || !table.dataset.dtSrc) return;
  const params = new URLSearchParams();
  for (const [name, value] of new FormData(form)) if (typeof value === "string" && value !== "") params.append(name, value);
  card.dataset.cardSrc = `${table.dataset.dtSrc}?${params.toString()}`;
});

document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || !form.matches("form[data-health-start]")) return;
  event.preventDefault();
  const button = form.querySelector('button[type="submit"]');
  if (!button || button.disabled) return;
  button.disabled = true;
  form.setAttribute("aria-busy", "true");
  try {
    await startRun(form);
  } catch {
    toast("Roxy could not be reached, so no run was started.", { tone: "bad" });
  } finally {
    button.disabled = false;
    form.removeAttribute("aria-busy");
  }
});
