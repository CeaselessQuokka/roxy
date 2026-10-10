/**
 * The Protection page's own script (templates/admin/pages/protection*): tabs, testers, the ladder editor, and the
 * few form behaviors the shared form module does not cover.
 *
 * What this is
 *   * Tabs (`[data-prot-tabs]`, the ARIA tabs pattern): click or arrow keys, Home and End move between a card's
 *     tabs; the chosen tab is kept when the card refreshes (an action, the event stream).
 *   * Query fields: a few admin API routes take their `reason` (and `pattern`, `confirm_lockout`) in the query
 *     string of a DELETE. A field marked `data-query` in a `form[data-api-form]` is moved into the URL just before
 *     static/js/api_forms.js sends the form (it never goes in the body: it is `data-json="never"`).
 *   * Drawer actions: a confirm dialog opened from a row's drawer closes the drawer after it worked (the card
 *     behind it has been refreshed, so the drawer would show the old row).
 *   * The ladder editor (`[data-ladder-form]`): add and remove rungs, mark unsaved changes, and save the whole
 *     ladder with `PUT /admin/api/v1/protection/ladder` as `{tiers: [...], reason}` (a 403 asks for the second
 *     factor and retries once; errors show in the form).
 *   * The testers (`[data-prot-tester="ua"|"header"]`): send the User-Agent or the pasted headers (and the draft
 *     rule, when its text is filled) to the admin API's dry-run route and show the verdict and every rule's result.
 *     A recent request's headers or v1's example lines fill the header box.
 *   * Small form helpers: a User-Agent rule shows the fields of its kind (burst or cooldown); "Permanent" switches
 *     off a ban's length; "Use my IP" fills the bypass form.
 *
 * Why it exists
 *   Everything else on the page is the shared design system. These behaviors are specific to Protection, and they
 *   must work for content htmx swaps in later (lazy cards, refreshed cards, the drawer), so each is a delegated
 *   listener or an `onContent` hook.
 *
 * How it works
 *   No HTML strings: results are built with roxy/dom `el`, so a User-Agent or a header value from a tester is only
 *   ever text (plan 9.16). Requests go through roxy/page `request` (same origin, the CSRF header on writes).
 *
 * What to read next
 *   static/js/page.js, static/js/api_forms.js, roxy/admin/pages/protection.py, roxy/admin/api/protection.py.
 */

import { confirmIdentity, onContent, refreshCard, request, toast } from "roxy/page";
import { el, qs, qsa } from "roxy/dom";

const MAX_ERROR_TEXT = 4096;
const chosenTabs = new Map();

// ------------------------------------------------------------------------------------------------ lazy cards

// The pipeline renders with the page; every other card is a lazy fragment that loads when it scrolls into view.
// This page is long (27 cards), so after the first paint the cards still waiting load in the background, two at
// a time, in page order: a link to #tarpit, the browser's find, and a phone scrolling fast then find their card
// ready instead of a spinner. A card already loading (it was scrolled into view) is skipped.
const BACKGROUND_LOADS = 2;
const BACKGROUND_DELAY_MS = 300;

async function loadWaitingCards() {
  const queue = qsa("section.page-card--lazy[data-card-src]");
  const worker = async () => {
    while (queue.length) {
      const card = queue.shift();
      if (!card.isConnected || !card.classList.contains("page-card--lazy") || card.classList.contains("htmx-request")) {
        continue;
      }
      try {
        await refreshCard(card);
      } catch {
        /* the card keeps its placeholder and loads when it scrolls into view */
      }
    }
  };
  await Promise.all(Array.from({ length: BACKGROUND_LOADS }, worker));
}

if (document.readyState === "complete") window.setTimeout(loadWaitingCards, BACKGROUND_DELAY_MS);
else window.addEventListener("load", () => window.setTimeout(loadWaitingCards, BACKGROUND_DELAY_MS), { once: true });

// ------------------------------------------------------------------------------------------------ tabs

function selectTab(tabs, key, { focus = false } = {}) {
  const buttons = qsa('[role="tab"]', tabs).filter((button) => button.closest("[data-prot-tabs]") === tabs);
  const target = buttons.find((button) => button.dataset.tab === key) || buttons[0];
  if (!target) return;
  for (const button of buttons) {
    const on = button === target;
    button.setAttribute("aria-selected", String(on));
    button.tabIndex = on ? 0 : -1;
    const panel = document.getElementById(button.getAttribute("aria-controls") || "");
    if (panel) panel.hidden = !on;
  }
  if (focus) target.focus();
  if (tabs.id) chosenTabs.set(tabs.id, target.dataset.tab);
}

onContent("[data-prot-tabs]", (tabs) => {
  const remembered = tabs.id ? chosenTabs.get(tabs.id) : null;
  if (remembered) selectTab(tabs, remembered);
});

document.addEventListener("click", (event) => {
  const tab = event.target instanceof Element ? event.target.closest('[data-prot-tabs] [role="tab"]') : null;
  if (tab) selectTab(tab.closest("[data-prot-tabs]"), tab.dataset.tab);
});

document.addEventListener("keydown", (event) => {
  const tab = event.target instanceof Element ? event.target.closest('[data-prot-tabs] [role="tab"]') : null;
  if (!tab) return;
  const tabs = tab.closest("[data-prot-tabs]");
  const buttons = qsa('[role="tab"]', tabs).filter((button) => button.closest("[data-prot-tabs]") === tabs);
  const at = buttons.indexOf(tab);
  let next = null;
  if (event.key === "ArrowRight") next = buttons[(at + 1) % buttons.length];
  else if (event.key === "ArrowLeft") next = buttons[(at - 1 + buttons.length) % buttons.length];
  else if (event.key === "Home") next = buttons[0];
  else if (event.key === "End") next = buttons[buttons.length - 1];
  if (!next) return;
  event.preventDefault();
  selectTab(tabs, next.dataset.tab, { focus: true });
});

// ------------------------------------------------------------------------------------------------ query fields

// Capture phase on document runs before api_forms.js reads the form (it listens in the bubble phase).
document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || !form.matches("form[data-api-form]")) return;
  const fields = qsa("[data-query]", form);
  if (!fields.length) return;
  if (!form.dataset.apiBase) form.dataset.apiBase = form.dataset.apiUrl || "";
  const url = new URL(form.dataset.apiBase, window.location.origin);
  for (const field of fields) {
    if (field.disabled || field.closest("[data-confirm-field][hidden]")) continue;
    if (field.type === "checkbox") {
      if (field.checked) url.searchParams.set(field.name, "true");
      continue;
    }
    const value = String(field.value || "").trim();
    if (value) url.searchParams.set(field.name, value);
  }
  form.dataset.apiUrl = url.pathname + url.search;
}, true);

// ------------------------------------------------------------------------------------------------ drawer actions

document.addEventListener("roxy:api-success", (event) => {
  const form = event.target instanceof Element ? event.target : null;
  const drawer = document.getElementById("drawer");
  if (!form || !drawer || !drawer.contains(form) || !drawer.open) return;
  const inner = form.closest("dialog");
  if (inner && inner !== drawer) window.setTimeout(() => drawer.open && drawer.close(), 0);
});

// ------------------------------------------------------------------------------------------------ small helpers

document.addEventListener("change", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (target.matches('select[name="kind"]')) {
    const form = target.closest("form");
    for (const group of qsa("[data-kind-fields]", form)) group.hidden = group.dataset.kindFields !== target.value;
  } else if (target.matches("[data-prot-permanent]")) {
    const minutes = qs('[name="minutes"]', target.closest("form"));
    if (minutes) minutes.disabled = target.checked;
  } else if (target.matches("[data-tester-sample]")) {
    const box = qs('[name="headers"]', target.closest("form"));
    if (box && target.value) {
      box.value = target.value;
      toast("Loaded the headers of that request.", { tone: "info" });
    }
  }
});

document.addEventListener("click", (event) => {
  const target = event.target instanceof Element ? event.target : null;
  const example = target ? target.closest("[data-tester-example]") : null;
  if (example) {
    const box = qs('[name="headers"]', example.closest("form"));
    if (box) box.value = example.dataset.testerExample || "";
    return;
  }
  const mine = target ? target.closest("[data-use-my-ip]") : null;
  if (mine) {
    // The dialog opens through its own data-dialog-open; fill the field once it is there.
    window.setTimeout(() => {
      const input = document.getElementById(mine.dataset.target || "");
      if (input) input.value = mine.dataset.useMyIp || "";
    }, 0);
  }
});

// ------------------------------------------------------------------------------------------------ errors

async function readError(response) {
  const text = (await response.text().catch(() => "")).slice(0, MAX_ERROR_TEXT);
  try {
    const data = JSON.parse(text);
    const error = data && data.error ? data.error : {};
    const fields = error.fields && typeof error.fields === "object" ? Object.values(error.fields).map(String) : [];
    const message = typeof error.message === "string" ? error.message : "";
    return [message, ...fields].filter(Boolean).join(" ") || `The server refused this (${response.status}).`;
  } catch {
    return `The server refused this (${response.status}).`;
  }
}

function isReauth(response, text) {
  if (response.status !== 403) return false;
  if ((response.headers.get("Roxy-Reauth") || "").toLowerCase() === "required") return true;
  return text.includes('"reauth_required"');
}

function showError(form, message) {
  const box = qs("[data-dialog-error], [data-tester-error]", form);
  if (box) {
    box.textContent = message;
    box.hidden = false;
  } else {
    toast(message, { tone: "bad" });
  }
}

/** Send JSON with the admin API rules: one retry after "Confirm it is you" on a 403 `reauth_required`. */
async function sendJSON(url, method, body) {
  const send = () => request(url, { method, body: JSON.stringify(body), headers: { "Content-Type": "application/json" } });
  let response = await send();
  if (response.status === 403) {
    const text = await response.clone().text().catch(() => "");
    if (isReauth(response, text) && (await confirmIdentity())) response = await send();
  }
  return response;
}

// ------------------------------------------------------------------------------------------------ ladder editor

function ladderRows(form) {
  return qsa("[data-ladder-row]", qs("[data-ladder-rows]", form));
}

function renumber(form) {
  const rows = ladderRows(form);
  rows.forEach((row, index) => {
    const n = index + 1;
    const label = qs("[data-rung-label]", row);
    if (label) label.textContent = `Rung ${n}`;
    for (const input of qsa("[data-tier]", row)) {
      input.id = `ladder-${input.dataset.tier}-${n}`;
      const forLabel = qs(`[data-rung-for="${input.dataset.tier}"]`, row);
      if (forLabel) {
        forLabel.setAttribute("for", input.id);
        forLabel.textContent = forLabel.textContent.replace(/^Rung \d+/, `Rung ${n}`);
      }
    }
    const remove = qs("[data-ladder-remove]", row);
    if (remove) remove.setAttribute("aria-label", `Remove rung ${n}`);
  });
  const empty = qs("[data-ladder-empty]", form);
  if (empty) empty.hidden = rows.length > 0;
  const add = qs("[data-ladder-add]", form);
  if (add) add.disabled = rows.length >= Number(form.dataset.maxRungs || 12);
}

function markDirty(form) {
  form.dataset.dirty = "1";
  const note = qs("[data-ladder-dirty]", form);
  if (note) note.hidden = false;
}

document.addEventListener("click", (event) => {
  const target = event.target instanceof Element ? event.target : null;
  const form = target ? target.closest("[data-ladder-form]") : null;
  if (!form) return;
  if (target.closest("[data-ladder-add]")) {
    const template = qs("[data-ladder-template]", form);
    const rows = ladderRows(form);
    if (!template || rows.length >= Number(form.dataset.maxRungs || 12)) return;
    const row = template.content.firstElementChild.cloneNode(true);
    const last = rows[rows.length - 1];
    const lastMultiplier = last ? Number.parseFloat(qs('[data-tier="multiplier"]', last).value) : 0;
    qs('[data-tier="multiplier"]', row).value = lastMultiplier > 0 ? String(lastMultiplier * 2) : "1";
    qs("[data-ladder-rows]", form).append(row);
    renumber(form);
    markDirty(form);
    qs('[data-tier="multiplier"]', row).focus();
  } else if (target.closest("[data-ladder-remove]")) {
    const row = target.closest("[data-ladder-row]");
    if (row) row.remove();
    renumber(form);
    markDirty(form);
    const add = qs("[data-ladder-add]", form);
    if (add) add.focus();
  }
});

document.addEventListener("input", (event) => {
  const form = event.target instanceof Element ? event.target.closest("[data-ladder-form]") : null;
  if (form && event.target.closest("[data-ladder-row]")) markDirty(form);
});

function ladderBody(form) {
  const tiers = ladderRows(form).map((row) => {
    const value = (name) => String(qs(`[data-tier="${name}"]`, row).value || "").trim();
    const multiplier = Number.parseFloat(value("multiplier"));
    const action = value("action") || "throttle";
    const minutes = Number.parseInt(value("ban_minutes"), 10);
    return {
      multiplier: Number.isFinite(multiplier) ? multiplier : 0,
      message: value("message"),
      note: value("note"),
      action,
      ban_minutes: action === "ban" && Number.isFinite(minutes) ? minutes : null,
    };
  });
  const reason = String(qs('[name="reason"]', form).value || "").trim();
  return reason ? { tiers, reason } : { tiers };
}

document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || !form.matches("[data-ladder-form]")) return;
  event.preventDefault();
  if (form.getAttribute("aria-busy") === "true") return;
  const error = qs("[data-dialog-error]", form);
  if (error) error.hidden = true;
  form.setAttribute("aria-busy", "true");
  let response;
  try {
    response = await sendJSON(form.dataset.apiUrl, form.dataset.apiMethod || "PUT", ladderBody(form));
  } catch {
    showError(form, "Roxy could not be reached. Nothing was changed; try again.");
    return;
  } finally {
    form.removeAttribute("aria-busy");
  }
  if (response.status === 401) return;
  if (!response.ok) {
    showError(form, await readError(response));
    return;
  }
  delete form.dataset.dirty;
  toast("Escalation ladder saved.", { tone: "ok" });
  for (const id of (form.dataset.refresh || "").split(/\s+/).filter(Boolean)) refreshCard(id);
});

// ------------------------------------------------------------------------------------------------ testers

const RESULT_TONES = { blocks: "bad", applies: "bad", also: "warn", none: "neutral", off: "neutral" };

function badge(text, key) {
  return el("span", { class: `badge badge--${RESULT_TONES[key] || "neutral"}` }, [el("span", { text })]);
}

function code(text) {
  return el("code", { class: "caller-text", dir: "auto", translate: "no", text: String(text || "").slice(0, 300) });
}

function verdict(tone, title, details) {
  return el("div", { class: `alert alert--${tone}`, role: "status" }, [
    el("div", { class: "alert__text" }, [el("p", { class: "alert__title", text: title }), ...details]),
  ]);
}

function draftOf(form, keys) {
  const draft = {};
  for (const input of qsa("[data-draft]", form)) {
    const value = String(input.value || "").trim();
    if (value && keys.includes(input.dataset.draft)) draft[input.dataset.draft] = value;
  }
  return draft.needle ? draft : null;
}

function uaResult(answer) {
  const parts = [];
  const limiting = (answer.rules || []).find((rule) => rule.is_first_match);
  if (!answer.rules_enabled) {
    parts.push(verdict("info", "Client rules are paused", [el("p", { class: "alert__body", text: "The master switch is off, so no rule limits anyone right now (the result below shows what would match)." })]));
  }
  if (answer.limited && limiting) {
    parts.push(verdict("warn", "This client would be rate-limited", [
      el("p", { class: "alert__body" }, ["By the rule matching ", code(limiting.needle), ` (${limiting.kind}, ${limiting.scope === "global" ? "shared" : "per IP"}).`]),
    ]));
  } else {
    parts.push(verdict("ok", "No client rule applies", [el("p", { class: "alert__body", text: "This caller gets the ordinary per-IP limits." })]));
  }
  if (answer.draft) {
    const draft = answer.draft;
    const text = !draft.valid
      ? `The rule you are writing is not valid: ${draft.error}`
      : `The rule you are writing ${draft.matched ? "would" : "would not"} catch this client.${draft.matched && draft.already_matched ? " A saved rule already covers it, so adding this would change nothing for this caller." : ""}`;
    parts.push(el("p", { class: "prot-result__draft", text }));
  }
  parts.push(ruleList("Every saved rule", (answer.rules || []).map((rule) => {
    const key = !rule.enabled ? "off" : rule.is_first_match ? "applies" : rule.matched ? "also" : "none";
    const label = { off: "off", applies: "this one applies", also: "also matches", none: "no match" }[key];
    return el("li", {}, [badge(label, key), " ", code(rule.needle), el("span", { class: "muted", text: ` ${rule.mode}` })]);
  })));
  return parts;
}

function sideOf(field) {
  return field === "key" ? "header name" : "header value";
}

function describeRule(rule) {
  const scopes = { key: "Header name", value: "Header value", either: "Name or value" };
  const target = rule.header ? `"${rule.header}" value` : scopes[rule.scope] || rule.scope;
  const verb = rule.mode === "exact" ? "is" : rule.mode === "regex" ? "matches" : "contains";
  return `${target} ${verb} "${rule.needle}"`;
}

function headerResult(answer) {
  const parts = [];
  const blocking = (answer.rules || []).find((rule) => rule.is_first_match);
  if (answer.blocked && blocking) {
    parts.push(verdict("bad", "This request would be BLOCKED", [
      el("p", { class: "alert__body" }, ["Caught by ", code(describeRule(blocking)), `: the ${sideOf(blocking.matched_field)} `, code(blocking.matched_text), " on header ", code(blocking.matched_header), "."]),
    ]));
  } else {
    parts.push(verdict("ok", "This request would be allowed through", [
      el("p", { class: "alert__body", text: `None of your ${(answer.rules || []).length} saved filters match these ${answer.header_count} headers.` }),
    ]));
  }
  if (answer.draft) {
    const draft = answer.draft;
    if (!draft.valid) parts.push(el("p", { class: "prot-result__draft", text: `Draft filter is invalid: ${draft.error}` }));
    else if (draft.matched) {
      parts.push(el("p", { class: "prot-result__draft" }, [
        `Your draft filter WOULD catch this: it matched the ${sideOf(draft.matched_field)} `, code(draft.matched_text), " on header ", code(draft.matched_header), ".",
        draft.already_blocked ? " A saved filter already blocks this request, so adding it would change nothing here." : "",
      ]));
    } else parts.push(el("p", { class: "prot-result__draft", text: "Your draft filter would NOT catch this. Check the header name, or try Contains instead of Exact." }));
  }
  parts.push(ruleList("Every saved filter", (answer.rules || []).map((rule) => {
    const key = !rule.enabled ? "off" : rule.is_first_match ? "blocks" : rule.matched ? "also" : "none";
    const label = { off: "off", blocks: "blocks it", also: "also matches", none: "no match" }[key];
    const detail = rule.matched ? [" on ", code(rule.matched_header), ": ", code(rule.matched_text)] : [];
    return el("li", {}, [badge(label, key), " ", code(describeRule(rule)), ...detail]);
  })));
  return parts;
}

function ruleList(title, items) {
  if (!items.length) return el("p", { class: "muted", text: "There are no saved rules yet." });
  return el("div", { class: "prot-result__list" }, [el("p", { class: "prot-result__title", text: title }), el("ul", { class: "prot-list" }, items)]);
}

document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || !form.matches("[data-prot-tester]")) return;
  event.preventDefault();
  const kind = form.dataset.protTester;
  const out = qs("[data-tester-result]", form);
  for (const box of qsa("[data-field-error]", form)) box.hidden = true;
  let body;
  if (kind === "ua") {
    const value = String(qs('[name="user_agent"]', form).value || "").trim();
    if (!value) {
      const box = qs('[data-field-error="user_agent"]', form);
      box.textContent = "Paste a User-Agent to test against.";
      box.hidden = false;
      return;
    }
    body = { user_agent: value };
    const draft = draftOf(form, ["needle", "mode"]);
    if (draft) body.draft = draft;
  } else {
    const value = String(qs('[name="headers"]', form).value || "");
    if (!value.trim()) {
      const box = qs('[data-field-error="headers"]', form);
      box.textContent = "Paste some headers to test against.";
      box.hidden = false;
      return;
    }
    body = { headers: value };
    const draft = draftOf(form, ["header", "scope", "mode", "needle"]);
    if (draft) body.draft = draft;
  }
  out.replaceChildren(el("p", { class: "muted", text: "Testing" }));
  let response;
  try {
    response = await sendJSON(form.dataset.apiUrl, "POST", body);
  } catch {
    out.replaceChildren(verdict("bad", "Could not run the test.", [el("p", { class: "alert__body", text: "Roxy could not be reached." })]));
    return;
  }
  if (response.status === 401) return;
  if (!response.ok) {
    out.replaceChildren(verdict("bad", "Could not run the test.", [el("p", { class: "alert__body", text: await readError(response) })]));
    return;
  }
  const answer = await response.json().catch(() => null);
  if (!answer) {
    out.replaceChildren(verdict("bad", "Could not run the test.", []));
    return;
  }
  out.replaceChildren(...(kind === "ua" ? uaResult(answer) : headerResult(answer)));
});
