/**
 * The Health page's own script (templates/admin/pages/health*): start a run, follow it live, copy and download.
 *
 * What this is
 *   * The Run button posts `{include_credential}` to `POST /admin/api/v1/health/runs`. 202: the Run card switches to
 *     the new run in place (the address gets `?run=<id>`); 409 `run_in_progress`: it follows the run already going
 *     (its id is in `Roxy-Health-Run`); 403 `reauth_required` (the credential check needs a fresh second factor):
 *     "Confirm it is you", then one retry.
 *   * Live run view: every `health` event of the page-wide stream (`health_run_started`, `health_result`,
 *     `health_run_finished`) for the run on screen re-renders the Run card from the server (at most once a second),
 *     so the checklist fills in as checks finish; when the run finishes the history card refreshes too and a toast
 *     says how it went. While a run shows as running and no event came for a few seconds (the stream reconnecting,
 *     or not connected), the card asks the server itself. When the card follows the newest run (no `?run=` in the
 *     address), a run started anywhere else (the palette, another admin, the schedule) replaces it.
 *   * "Copy for LLM" (`data-copy-llm`) copies the run's or one check's LLM text; `data-download` saves the JSON or
 *     the printable report. Both go through the audited export route (static/js/exports.js handles 429 and the
 *     second factor).
 *   * Tables: as on every page of this builder, a table swap keeps only the table out of its card's answer, and the
 *     card's refresh address follows the table's state.
 *
 * Why it exists
 *   Plan 13.1: "results stream back over SSE as each check finishes (a checklist filling in with spinners turning
 *   into pass, warn, or fail badges)"; plan 14.8: the owner runs it from a phone. Live regions are not flooded: the
 *   start and the end are announced (toasts), the progress is on screen.
 *
 * How it works
 *   Run ids are checked to be plain numbers, export URLs to be this page's API routes, before they are used. The
 *   card refresh is the server's own fragment (one source of truth for every number), never DOM built from events.
 *
 * What to read next
 *   static/js/page.js, static/js/sse.js, roxy/admin/pages/health.py, roxy/admin/api/health.py.
 */

import { confirmIdentity, copyTextFrom, downloadFrom, onContent, refreshCard, request, toast } from "roxy/page";

const RUN_ID = /^[0-9]{1,15}$/;
const EXPORT = /^\/admin\/api\/v1\/health\/runs\/[0-9]{1,15}\/export\?format=(json|html|llm)(&focus=[A-Za-z0-9._%-]{1,160})?$/;
const MIN_GAP_MS = 1000;
const POLL_MS = 4000;
const MAX_ERROR_TEXT = 4096;

let lastRefresh = 0;
let pending = 0;
let lastEvent = 0;

function runCard() {
  return document.getElementById("run");
}

function shownRun() {
  const node = document.querySelector("#run [data-run-id]");
  return node ? { id: node.dataset.runId, state: node.dataset.runState, pinned: node.dataset.runPinned === "true" } : null;
}

function refreshRun() {
  const card = runCard();
  if (!card) return;
  const wait = MIN_GAP_MS - (performance.now() - lastRefresh);
  if (wait > 0) {
    if (!pending) pending = window.setTimeout(() => { pending = 0; refreshRun(); }, wait);
    return;
  }
  lastRefresh = performance.now();
  refreshCard(card);
}

/** Show run `id` in the Run card: its refresh address and the page address name it, then it re-renders. */
function follow(id) {
  if (!RUN_ID.test(String(id || ""))) {
    refreshRun();
    return;
  }
  const card = runCard();
  if (!card) return;
  card.dataset.cardSrc = `/admin/health/fragment/run?run=${id}`;
  const url = new URL(window.location.href);
  url.searchParams.set("run", String(id));
  url.searchParams.delete("with");
  url.hash = "run";
  window.history.replaceState(window.history.state, "", url.href);
  lastRefresh = 0;
  refreshRun();
}

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

async function startRun(form) {
  const url = form.dataset.runUrl || "";
  if (!url.startsWith("/admin/api/v1/")) return;
  const box = form.querySelector('[name="include_credential"]');
  const withCredential = Boolean(box && (box.type === "checkbox" ? box.checked : box.value === "true"));
  const body = JSON.stringify({ include_credential: withCredential });
  let response = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    response = await request(url, { method: "POST", body, headers: { "Content-Type": "application/json" } });
    if (response.status !== 403 || attempt > 0) break;
    const problem = errorOf(await response.clone().text().catch(() => ""));
    if (problem.code !== "reauth_required" && response.headers.get("Roxy-Reauth") !== "required") break;
    if (!(await confirmIdentity())) {
      toast("No run was started: the credential check needs your second factor. Untick it to run the rest.", {
        tone: "warn",
      });
      return;
    }
  }
  if (!response || response.status === 401) return;
  if (response.status === 202) {
    const answer = await response.json().catch(() => ({}));
    toast(`Health run ${answer && answer.run_id ? answer.run_id : ""} started; the checks fill in below.`, { tone: "ok" });
    follow(answer && answer.run_id);
    return;
  }
  if (response.status === 409) {
    const running = response.headers.get("Roxy-Health-Run");
    toast("A health run is already running; showing it instead.", { tone: "info" });
    follow(running);
    return;
  }
  const problem = errorOf(await response.text().catch(() => ""));
  const retry = response.headers.get("Retry-After");
  toast(`${problem.message || `The run could not start (${response.status}).`}${retry ? ` Try again in ${retry} seconds.` : ""}`, {
    tone: "bad",
  });
}

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

document.addEventListener("roxy:sse:health", (event) => {
  const payload = event.detail && event.detail.data;
  const detail = payload && typeof payload === "object" ? payload.detail || {} : {};
  const runId = String(detail.run_id || "");
  if (!RUN_ID.test(runId)) return;
  lastEvent = performance.now();
  const shown = shownRun();
  if (payload.type === "health_run_started" && (!shown || (!shown.pinned && shown.state !== "running"))) {
    refreshRun();  // the card follows the newest run
    return;
  }
  if (!shown || shown.id !== runId) return;
  refreshRun();
  if (payload.type === "health_run_finished") {
    const history = document.getElementById("history");
    if (history) refreshCard(history);
    const parts = [`${Number(detail.passed) || 0} passed`, `${Number(detail.warned) || 0} warned`, `${Number(detail.failed) || 0} failed`];
    toast(`Health run ${runId} finished: ${parts.join(", ")}.`, { tone: Number(detail.failed) ? "warn" : "ok" });
  }
});

// Without stream events (not connected yet, reconnecting), a running run is still followed.
window.setInterval(() => {
  const shown = shownRun();
  if (!shown || shown.state !== "running" || document.hidden) return;
  if (performance.now() - lastEvent < POLL_MS) return;
  refreshRun();
}, POLL_MS);

document.addEventListener("click", (event) => {
  const target = event.target instanceof Element ? event.target : null;
  if (!target) return;
  const copy = target.closest("[data-copy-llm]");
  if (copy && EXPORT.test(copy.dataset.copyLlm || "")) {
    event.preventDefault();
    copyTextFrom(copy.dataset.copyLlm);
    return;
  }
  const save = target.closest("[data-download]");
  if (save && EXPORT.test(save.dataset.download || "")) {
    event.preventDefault();
    downloadFrom(save.dataset.download);
  }
});

// A table's answer is its whole card: keep only the table, and let the card's refresh address follow its state.
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
