/**
 * Toasts and screen reader announcements (plan 14.5: "Toasts and inline alerts; accessible live region").
 *
 * What this is
 *   `toast(message, {tone})` shows a short confirmation in the corner; `announce(text)` speaks text to screen
 *   readers without showing anything. `initToasts()` wires the declarative triggers: buttons with
 *   `data-toast="..."`, `[data-dismiss]` close buttons on inline alerts, and the `roxy:toast` event a server
 *   response raises with the header `HX-Trigger: {"roxy:toast": {"message": "Saved", "tone": "ok"}}`.
 *
 * Why it exists
 *   A toast that only appears visually is invisible to a screen reader user, and a live region that fires for
 *   every streamed row drowns them (plan 14.9). Here every toast is announced exactly once through the polite
 *   region (errors through the assertive one), and announcements are throttled.
 *
 * How it works
 *   Toast nodes are built with textContent (never HTML), at most 5 are kept, and they leave after 5 s (8 s for
 *   warnings); errors stay until dismissed, and hovering or focusing a toast pauses its timer (WCAG 2.2.1).
 *
 * What to read next
 *   static/js/htmx_setup.js (error toasts for failed requests), templates/components/alert.html.
 */

import { el, icon, qs } from "roxy/dom";

const ICONS = { ok: "check-circle", warn: "alert-triangle", bad: "alert-octagon", info: "info" };
const TIMEOUTS = { ok: 5000, info: 5000, warn: 8000, bad: 0 };
const MAX_TOASTS = 5;
const lastSpoken = { polite: 0, assertive: 0 };

/** Speak `text` through a live region. Polite messages within 400 ms of each other replace each other. */
export function announce(text, politeness = "polite") {
  const region = qs(politeness === "assertive" ? "#sr-assertive" : "#sr-polite");
  if (!region) return;
  const now = performance.now();
  const delay = now - lastSpoken[politeness] < 400 ? 400 : 30;
  lastSpoken[politeness] = now;
  // Clearing first and writing a moment later makes screen readers announce a repeated message again.
  region.textContent = "";
  window.setTimeout(() => {
    region.textContent = text;
  }, delay);
}

export function toast(message, { tone = "ok", timeout } = {}) {
  const container = qs("#toasts");
  if (!container || !message) return null;
  const node = el("div", { class: `toast toast--${tone}` }, [
    icon(ICONS[tone] || "info", "toast__icon"),
    el("p", { class: "toast__text", text: message }),
  ]);
  const close = el("button", { type: "button", class: "icon-btn icon-btn--sm", "aria-label": "Dismiss notification" }, [
    icon("x"),
  ]);
  node.append(close);
  container.append(node);
  while (container.children.length > MAX_TOASTS) container.firstElementChild.remove();
  announce(message, tone === "bad" ? "assertive" : "polite");

  const life = timeout ?? TIMEOUTS[tone] ?? 5000;
  let timer = 0;
  const remove = () => {
    window.clearTimeout(timer);
    node.remove();
  };
  const arm = () => {
    if (life > 0) timer = window.setTimeout(remove, life);
  };
  close.addEventListener("click", remove);
  node.addEventListener("pointerenter", () => window.clearTimeout(timer));
  node.addEventListener("pointerleave", arm);
  node.addEventListener("focusin", () => window.clearTimeout(timer));
  node.addEventListener("focusout", arm);
  arm();
  return node;
}

export function initToasts() {
  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-toast]");
    if (trigger) toast(trigger.dataset.toast, { tone: trigger.dataset.toastTone || "ok" });
    const dismiss = event.target.closest("[data-dismiss]");
    if (dismiss) {
      const box = dismiss.closest(".alert");
      if (box) box.remove();
    }
  });
  // htmx turns `HX-Trigger: {"roxy:toast": {...}}` into this event on the element that made the request.
  document.addEventListener("roxy:toast", (event) => {
    const detail = event.detail || {};
    const message = typeof detail === "string" ? detail : detail.message || detail.value;
    toast(message, { tone: detail.tone || "ok" });
  });
}
