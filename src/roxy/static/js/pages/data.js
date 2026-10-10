/**
 * The Data page's own script (templates/admin/pages/data.html): the reset flow, long operations, the LLM export.
 *
 * What this is
 *   * Resets (plan 6.8): the reset form shows only the fields its scope uses; "Preview" posts it to
 *     `POST /data/resets/preview` and shows the exact rows per table, what stays and the snapshot plan; "Run this
 *     reset" opens the confirmation (data.html `#dlg-reset-run`), which asks for a reason and, for a destructive
 *     full reset, the typed phrase the preview named; the run posts the previewed digest to `POST /data/resets`
 *     (the factory reset to `/data/resets/factory`, after "Confirm it is you").
 *   * Long operations: a reset, Back up now or VACUUM answers either its result or 202 with an operation; the
 *     operation is followed (`GET /data/operations/{id}`) until it ends, then its card is refreshed and the result
 *     is said in words in that card.
 *   * The LLM export: Copy for LLM and Download JSON for the window and detail chosen (static/js/exports.js does the
 *     download, the 429 and the "Confirm it is you" for the full detail).
 *
 * Why it exists
 *   A reset must never run without its preview (the API refuses a digest it did not preview: 409
 *   `preview_required`), and the admin must see what will go before anything goes. The shared dialog cannot hold a
 *   phrase that depends on the preview, so this page fills its own confirmation.
 *
 * How it works
 *   Only `roxy/page` is imported (P11 contract). Every text from the API (summaries, notes, table names) is set with
 *   `textContent`, never as HTML (plan 9.16). Errors are section 13 objects: their message shows next to the field
 *   it names, or in the form's error line.
 *
 * What to read next
 *   roxy/admin/api/data.py (the routes), templates/admin/pages/data/resets.html, static/js/exports.js.
 */

import { confirmIdentity, copyTextFrom, downloadFrom, getJSON, onContent, postJSON, refreshCard, toast } from "roxy/page";

const POLL_MS = 1500;
const POLL_TRIES = 160;  // four minutes; a longer operation is still in the audit log
const results = new Map();  // card id -> the words of its last operation's result

function text(node, value) {
  if (node) node.textContent = value == null ? "" : String(value);
}

function make(tag, value, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  text(node, value);
  return node;
}

function fmtCount(n) {
  return Number(n || 0).toLocaleString("en-US");
}

function fmtBytes(n) {
  let size = Number(n || 0);
  for (const [unit, step] of [["TiB", 1024 ** 4], ["GiB", 1024 ** 3], ["MiB", 1024 ** 2], ["KiB", 1024]]) {
    if (Math.abs(size) >= step) return `${(size / step).toFixed(1)} ${unit}`;
  }
  return `${size.toFixed(0)} B`;
}

function fmtTime(seconds) {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds <= 0) return "n/a";
  return new Date(seconds * 1000).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" });
}

async function readError(response) {
  const body = await response.text().catch(() => "");
  try {
    const data = JSON.parse(body);
    if (data && data.error && typeof data.error === "object") {
      return {
        code: String(data.error.code || ""),
        message: String(data.error.message || `The server refused this (${response.status}).`).slice(0, 400),
        fields: data.error.fields && typeof data.error.fields === "object" ? data.error.fields : {},
      };
    }
    if (typeof data === "string") return { code: "", message: data.slice(0, 400), fields: {} };
  } catch {
    // not JSON
  }
  return { code: "", message: `The server refused this (${response.status}). Nothing was changed.`, fields: {} };
}

async function needsReauth(response) {
  if (response.status !== 403) return false;
  if ((response.headers.get("Roxy-Reauth") || "").toLowerCase() === "required") return true;
  const body = await response.clone().text().catch(() => "");
  try {
    const data = JSON.parse(body);
    return Boolean(data && data.error && data.error.code === "reauth_required");
  } catch {
    return false;
  }
}

/** POST JSON; on "confirm it is you" ask for the code once and send it again (null when the admin canceled). */
async function post(url, body) {
  let response = await postJSON(url, body);
  if (await needsReauth(response)) {
    if (!(await confirmIdentity())) return null;
    response = await postJSON(url, body);
  }
  return response;
}

// ------------------------------------------------------------------------------------------------ operations

function showResult(cardId, words) {
  results.set(cardId, words);
  const region = document.querySelector(`[data-op-result="${cardId}"]`);
  if (region) fillResult(region);
}

function fillResult(region) {
  const words = results.get(region.dataset.opResult);
  if (!words) return;
  const box = make("div", "", "alert alert--info");
  box.append(make("p", words.title, "alert__title"));
  for (const line of words.lines || []) box.append(make("p", line, "alert__body"));
  region.replaceChildren(box);
}

onContent("[data-op-result]", fillResult);

/** Follow an operation (`GET /data/operations/{id}`) until it ends; resolves the final view (or null). */
async function follow(view) {
  if (!view || view.status !== "running" || typeof view.url !== "string") return view;
  for (let i = 0; i < POLL_TRIES; i += 1) {
    await new Promise((resolve) => window.setTimeout(resolve, POLL_MS));
    let next;
    try {
      next = await getJSON(view.url);
    } catch {
      continue;  // a busy moment: try again
    }
    if (next && next.status && next.status !== "running" && next.status !== "started") return next;
  }
  return null;
}

function backupWords(result) {
  const lines = [];
  const request = result.request || {};
  lines.push(request.written
    ? "The nightly backup was asked to run now; it skips the request if its last good backup is under 10 minutes old."
    : `The request for the nightly backup could not be written (${request.error || "unknown error"}).`);
  const made = (result.snapshots || []).map((s) => `${s.db}.db (${fmtBytes(s.bytes)})`);
  if (made.length) lines.push(`Copied here: ${made.join(", ")}.`);
  for (const skip of result.skipped || []) lines.push(`Not copied: ${skip.db}.db. ${skip.reason}`);
  if ((result.replaced || []).length) lines.push(`Replaced older Back up now copies: ${result.replaced.join(", ")}.`);
  return { title: "Back up now finished", lines };
}

function vacuumWords(result) {
  return {
    title: `VACUUM of ${result.database}.db finished`,
    lines: [`It gave back ${fmtBytes(result.reclaimed_bytes)} (${fmtBytes(result.bytes_before)} before, ${fmtBytes(result.bytes_after)} after) in ${(Number(result.duration_ms || 0) / 1000).toFixed(1)} s.`],
  };
}

document.addEventListener("roxy:api-success", async (event) => {
  const form = event.target instanceof Element ? event.target : null;
  if (!form) return;
  const isBackup = Boolean(form.closest("#dlg-backup"));
  const isVacuum = form.hasAttribute("data-operation") && Boolean(form.closest("[id^='dlg-vacuum-']"));
  if (!isBackup && !isVacuum) return;
  const cardId = isBackup ? "backups" : "vacuum";
  const answer = event.detail && event.detail.answer;
  const done = await follow(answer);
  if (!done) {
    toast("The operation is still running; its end will be in the audit log.", { tone: "info" });
    return;
  }
  if (done.status === "failed") {
    showResult(cardId, { title: "The operation failed", lines: [String(done.error || "See the audit log.")] });
  } else if (done.result) {
    showResult(cardId, isBackup ? backupWords(done.result) : vacuumWords(done.result));
  }
  if (answer && answer.status === "running") {
    toast(isBackup ? "Back up now finished." : "VACUUM finished.", { tone: "ok" });
    refreshCard(cardId);
    if (!isBackup) refreshCard("storage");
  }
});

// ------------------------------------------------------------------------------------------------ resets

let current = null;  // {body, preview} of the preview on screen

function formOf() {
  return document.querySelector("[data-reset-form]");
}

function scopeOf(form) {
  const select = form.querySelector("[data-reset-scope]");
  return select ? select.value : "family";
}

function applyScope(form) {
  const scope = scopeOf(form);
  for (const set of form.querySelectorAll("[data-scope-fields]")) {
    set.hidden = !set.dataset.scopeFields.split(/\s+/).includes(scope);
  }
  const select = form.querySelector("[data-reset-scope]");
  const option = select ? select.selectedOptions[0] : null;
  text(form.querySelector("[data-reset-scope-desc]"), option ? option.dataset.description || "" : "");
}

function value(form, name) {
  const field = form.querySelector(`[name="${name}"]`);
  if (!field || field.closest("[data-scope-fields][hidden]")) return "";
  return String(field.value || "").trim();
}

/** The reset scope as `POST /data/resets/preview` takes it, from the visible fields only. */
function scopeBody(form) {
  const scope = scopeOf(form);
  const body = { scope };
  const visible = (selector) => [...form.querySelectorAll(selector)].filter((node) => !node.closest("[data-scope-fields][hidden]"));
  if (scope === "family" || scope === "date_range") {
    body.families = visible('input[name="families"]:checked').map((box) => box.value);
  }
  const start = value(form, "from");
  const end = value(form, "to");
  if (start || end) {
    body.from = start;
    body.to = end;
  }
  if (scope === "client") {
    body.client_type = value(form, "client_type") || "ip";
    body.client = value(form, "client");
  } else if (scope === "endpoint") {
    body.template = value(form, "template");
  } else if (scope === "cache") {
    body.cache = value(form, "cache") || "all";
    const target = value(form, "value");
    if (target) body.value = target;
    body.pattern_type = value(form, "pattern_type") || "glob";
    const stale = visible('input[name="include_stale"]')[0];
    body.include_stale = Boolean(stale && stale.checked);
  } else if (scope === "bans") {
    body.bans = value(form, "bans") || "all";
    const detector = value(form, "detector");
    if (detector) body.detector = detector;
  } else if (scope === "recommendations") {
    body.recommendations = value(form, "recommendations") || "history";
  }
  return body;
}

function clearErrors(root) {
  for (const box of root.querySelectorAll("[data-field-error], [data-run-error]")) {
    box.hidden = true;
    text(box, "");
  }
  for (const field of root.querySelectorAll("[aria-invalid='true']")) field.removeAttribute("aria-invalid");
  for (const box of root.querySelectorAll("[data-reset-error], [data-reset-run-error]")) box.hidden = true;
}

function showErrors(root, error, { general, attr = "data-field-error" } = {}) {
  let placed = false;
  for (const [name, message] of Object.entries(error.fields || {})) {
    const box = root.querySelector(`[${attr}="${CSS.escape(name)}"]`);
    if (box && !box.closest("[hidden]")) {
      text(box, message);
      box.hidden = false;
      placed = true;
    }
    const field = root.querySelector(`[name="${CSS.escape(name)}"]`);
    if (field) field.setAttribute("aria-invalid", "true");
  }
  const line = root.querySelector(general);
  if (line && (!placed || error.code === "confirmation_required")) {
    text(line, error.message);
    line.hidden = false;
  }
}

function tableRow(item) {
  const row = document.createElement("tr");
  const what = { delete: "Deleted", clear_latency: "Latency histograms emptied", clear_cache_state: "Cache state cleared" };
  row.append(
    make("td", `${item.db}.${item.table}`, "mono"),
    make("td", what[item.action] || String(item.action || "")),
    make("td", fmtCount(item.rows), "num"),
    make("td", fmtTime(item.oldest)),
    make("td", fmtTime(item.newest)),
  );
  const labels = ["Table", "What happens", "Rows", "Oldest", "Newest"];
  [...row.children].forEach((cell, i) => cell.setAttribute("data-label", labels[i]));
  return row;
}

function previewLines(preview) {
  const lines = [];
  for (const action of preview.actions || []) {
    if (action.action === "cache_purge") lines.push(action.skipped ? `Cached answers (${action.scope}): ${action.skipped}.` : `Cached answers (${action.scope}) are removed on every worker.`);
    else if (action.action === "upstream_reset") lines.push(String(action.note || "Upstream cooldowns and breakers are cleared."));
    else if (action.action === "settings_reset") lines.push(`${fmtCount(action.overrides)} changed settings go back to their defaults.`);
    else if (action.action === "rules_reset") lines.push(String(action.note || "The rule tables go back to the shipped defaults."));
    else if (action.action === "memory_reset") lines.push(`Each worker clears its own ${action.family} counters.`);
  }
  for (const snap of preview.snapshots || []) {
    lines.push(snap.feasible ? `A snapshot of ${snap.db}.db is taken first, so this can be undone.` : `No snapshot of ${snap.db}.db: ${snap.reason}`);
  }
  for (const note of preview.notes || []) lines.push(String(note));
  return lines;
}

function renderPreview(form, preview) {
  const section = document.querySelector("[data-reset-preview]");
  if (!section) return;
  text(section.querySelector("[data-preview-summary]"), preview.summary);
  const body = section.querySelector("[data-preview-tables]");
  if (body) body.replaceChildren(...(preview.tables || []).filter((t) => Number(t.rows) > 0).map(tableRow));
  if (body && !body.children.length) {
    const row = document.createElement("tr");
    const cell = make("td", "No row matches this scope: the reset would change nothing.", "muted");
    cell.colSpan = 5;
    row.append(cell);
    body.append(row);
  }
  const notes = section.querySelector("[data-preview-notes]");
  if (notes) notes.replaceChildren(...previewLines(preview).map((line) => make("li", line)));
  section.hidden = false;
  section.focus();
  fillRunDialog(preview);
}

function fillRunDialog(preview) {
  const dialog = document.getElementById("dlg-reset-run");
  if (!dialog) return;
  const form = dialog.querySelector("[data-reset-run]");
  form.reset();
  clearErrors(form);
  text(dialog.querySelector("[data-reset-run-title]"), `Reset ${preview.label}?`);
  text(dialog.querySelector("[data-reset-run-summary]"), preview.summary);
  const list = dialog.querySelector("[data-reset-run-consequences]");
  const lines = previewLines(preview);
  lines.push("The exact rows deleted per table are written to the audit log, and every chart over this time shows a reset marker.");
  if (list) list.replaceChildren(...lines.map((line) => make("li", line)));
  const phraseBox = dialog.querySelector("[data-reset-run-phrase]");
  const phrase = preview.confirm_phrase || "";
  if (phraseBox) phraseBox.hidden = !phrase;
  text(dialog.querySelector("[data-reset-run-phrase-text]"), phrase);
  const needsReason = Boolean(phrase) || Boolean(preview.fresh_mfa_required);
  const reason = dialog.querySelector('textarea[name="reason"]');
  if (reason) {
    reason.required = needsReason;
    reason.setAttribute("aria-required", needsReason ? "true" : "false");
  }
  text(dialog.querySelector("[data-reset-run-reason-hint]"), needsReason ? "(needed; saved in the audit log)" : "(optional, saved in the audit log)");
  syncRunButton(dialog);
}

function syncRunButton(dialog) {
  const submit = dialog.querySelector("[data-reset-run-submit]");
  if (!submit || !current) return;
  const phrase = current.preview.confirm_phrase || "";
  const typed = String((dialog.querySelector('input[name="confirm"]') || {}).value || "").trim().toLowerCase();
  submit.disabled = Boolean(phrase) && typed !== phrase;
}

function resultWords(view) {
  const result = view.result || {};
  const lines = [`${fmtCount(result.total_rows)} rows changed in ${Object.keys(result.deleted || {}).filter((k) => result.deleted[k]).length} tables.`];
  for (const snap of result.snapshots || []) lines.push(`Snapshot kept: ${snap.file || snap.db}.`);
  for (const skip of result.snapshots_skipped || []) lines.push(`No snapshot of ${skip.db}.db: ${skip.reason}`);
  return lines;
}

function renderResult(view) {
  const region = document.querySelector("[data-reset-result]");
  if (!region) return;
  const tone = { failed: "alert alert--bad", running: "alert alert--info" }[view.status] || "alert alert--ok";
  const title = {
    failed: `The reset of ${view.label} failed`,
    running: `The reset of ${view.label} is running (now: ${view.step || "starting"})`,
  }[view.status] || `The reset of ${view.label} is done`;
  const box = make("div", "", tone);
  const textBox = make("div", "", "alert__text");
  textBox.append(make("p", title, "alert__title"));
  if (view.status === "failed") textBox.append(make("p", String(view.error || "See the audit log."), "alert__body"));
  else if (view.status !== "running") for (const line of resultWords(view)) textBox.append(make("p", line, "alert__body"));
  const audit = view.result && view.result.audit_id ? view.result.audit_id : view.audit_id;
  if (audit) {
    const link = make("a", "Open its audit entry");
    link.href = `/admin/audit?entry=${encodeURIComponent(String(audit))}`;
    const p = make("p", "", "alert__actions");
    p.append(link);
    textBox.append(p);
  }
  box.append(textBox);
  region.replaceChildren(box);
}

async function runPreview(form) {
  clearErrors(form);
  const body = scopeBody(form);
  let response;
  try {
    response = await postJSON(form.dataset.previewUrl, body);
  } catch {
    showErrors(form, { message: "Roxy could not be reached. Nothing was changed.", fields: {} }, { general: "[data-reset-error]" });
    return;
  }
  if (response.status === 401) return;
  if (!response.ok) {
    showErrors(form, await readError(response), { general: "[data-reset-error]" });
    return;
  }
  const preview = await response.json();
  current = { body, preview };
  renderPreview(form, preview);
}

async function runReset(dialogForm) {
  if (!current) return;
  const dialog = dialogForm.closest("dialog");
  clearErrors(dialogForm);
  const data = new FormData(dialogForm);
  const reason = String(data.get("reason") || "").trim();
  const confirm = String(data.get("confirm") || "").trim();
  const factory = current.body.scope === "factory";
  const form = formOf();
  const url = factory ? form.dataset.factoryUrl : form.dataset.runUrl;
  const submit = dialogForm.querySelector("[data-reset-run-submit]");
  if (submit) submit.disabled = true;
  let response;
  try {
    response = await post(url, { ...current.body, preview: current.preview.preview, reason, confirm: confirm || null });
  } catch {
    response = undefined;
  } finally {
    if (submit) submit.disabled = false;
  }
  if (response === null) {
    showErrors(dialogForm, { message: "Nothing was changed: the factory reset needs your second factor.", fields: {} }, { general: "[data-reset-run-error]", attr: "data-run-error" });
    return;
  }
  if (!response) {
    showErrors(dialogForm, { message: "Roxy could not be reached. Nothing was changed.", fields: {} }, { general: "[data-reset-run-error]", attr: "data-run-error" });
    return;
  }
  if (response.status === 401) return;
  if (!response.ok) {
    const error = await readError(response);
    if (error.code === "preview_required") error.message = "The scope changed since the preview (or was never previewed): close this, preview again, then run it.";
    showErrors(dialogForm, error, { general: "[data-reset-run-error]", attr: "data-run-error" });
    return;
  }
  const view = await response.json();
  if (dialog && dialog.open) dialog.close();
  const section = document.querySelector("[data-reset-preview]");
  if (section) section.hidden = true;
  current = null;
  if (view.status === "running") {
    toast("The reset is running; this page will say when it is done.", { tone: "info" });
    renderResult(view);
  }
  const done = await follow(view);
  if (!done) {
    toast("The reset is still running; its end will be in the audit log.", { tone: "info" });
    return;
  }
  renderResult(done.status === "done" || done.status === "failed" ? done : { ...view, ...done });
  toast(done.status === "failed" ? "The reset failed." : "The reset is done.", { tone: done.status === "failed" ? "bad" : "ok" });
  for (const card of ["storage", "retention", "backups"]) {
    if (document.getElementById(card)) refreshCard(card);
  }
}

onContent("[data-reset-form]", (form) => {
  applyScope(form);
  form.addEventListener("change", (event) => {
    if (event.target instanceof Element && event.target.matches("[data-reset-scope]")) applyScope(form);
    const section = document.querySelector("[data-reset-preview]");
    if (section && current) {
      section.hidden = true;  // a preview of another scope must never be run
      current = null;
    }
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    runPreview(form);
  });
});

document.addEventListener("click", (event) => {
  const target = event.target instanceof Element ? event.target : null;
  if (!target) return;
  if (target.closest("[data-reset-discard]")) {
    const section = document.querySelector("[data-reset-preview]");
    if (section) section.hidden = true;
    current = null;
    return;
  }
  if (target.closest("[data-reset-open-run]")) {
    // static/js/dialog.js opens the dialog (and gives focus back to this button when it closes); fill it now.
    const dialog = document.getElementById("dlg-reset-run");
    if (dialog && current) {
      fillRunDialog(current.preview);
      const reason = dialog.querySelector('textarea[name="reason"]');
      if (reason) reason.focus();
    }
    return;
  }
  const llm = target.closest("[data-llm-action]");
  if (llm) {
    const section = llm.closest("[data-llm-export]");
    const window_ = (section.querySelector("[data-llm-window]") || {}).value || "24h";
    const detail = (section.querySelector("[data-llm-detail]") || {}).value || "summary";
    const params = new URLSearchParams({ window: window_, detail });
    if (llm.dataset.llmAction === "copy") {
      params.set("format", "text");
      copyTextFrom(`${section.dataset.llmUrl}?${params}`);
    } else {
      params.set("download", "true");
      downloadFrom(`${section.dataset.llmUrl}?${params}`);
    }
  }
});

document.addEventListener("input", (event) => {
  const dialog = event.target instanceof Element ? event.target.closest("#dlg-reset-run") : null;
  if (dialog) syncRunButton(dialog);
});

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || !form.matches("[data-reset-run]")) return;
  event.preventDefault();
  if (form.checkValidity && !form.checkValidity()) {
    form.reportValidity();
    return;
  }
  runReset(form);
});
