/**
 * Tooltips, help dots and glossary terms (plan 14.5, 14.7, parity row 87).
 *
 * What this is
 *   One shared tooltip element (`#roxy-tip`) shown for three kinds of triggers: `[data-help]` ("?" help buttons),
 *   `.gloss[data-def]` (glossary terms, components/glossary.html), and `[data-tip]` (short labels, such as the
 *   page names on the collapsed sidebar and the cells of a heatmap).
 *
 * Why it exists
 *   Plan principle P2 puts an explanation one hover away from everything. WCAG 1.4.13 sets the rules for content
 *   that appears on hover or focus: it can be dismissed without moving the pointer (Escape), the pointer can move
 *   onto it without it vanishing (hoverable), and it stays until the person moves away (persistent). Keyboard
 *   users get the same text on focus, and while it is visible the trigger points at it with aria-describedby.
 *   Clicking a help dot also speaks the text, because a screen reader does not re-read a description on click.
 *
 * How it works
 *   Delegated pointer and focus listeners (so content swapped in by htmx works without setup), text set with
 *   textContent (help text is data, never HTML), and CSSOM positioning (below the trigger, flipped above when there
 *   is no room, clamped 8 px inside the viewport). One tooltip at a time keeps it cheap and predictable. When the
 *   page scrolls, a tooltip shown for keyboard focus moves with its trigger (focus itself often scrolls the page)
 *   and a tooltip shown for a hover is hidden.
 *   While a modal dialog is open the tooltip lives inside it (dom.js overlay layer), so it is drawn above the
 *   dialog; positions are measured against the tooltip's actual containing block, which is the viewport except
 *   for the moment a dialog is still animating in.
 *   Escape while the tooltip shows dismisses only the tooltip: the key event is handled first (window, capture
 *   phase) and its default action is prevented, which is what stops the browser from also closing the dialog or
 *   menu the trigger sits in (WCAG 1.4.13); the next Escape closes the dialog as usual.
 *
 * What to read next
 *   templates/components/badges.html (help_dot), templates/components/glossary.html (term).
 */

import { qs, rafThrottle } from "roxy/dom";
import { announce } from "roxy/toast";

const SHOW_DELAY_MS = 120;
const HIDE_DELAY_MS = 120;
const SELECTOR = "[data-help], .gloss[data-def], [data-tip]";

let tip = null;
let current = null;
let showTimer = 0;
let hideTimer = 0;
let dismissedAt = -Infinity;

function textFor(trigger) {
  return trigger.dataset.help || trigger.dataset.def || trigger.dataset.tip || "";
}

function labelIsHidden(trigger) {
  // Sidebar links only need a tooltip when their label is visually hidden (collapsed sidebar).
  const label = trigger.querySelector(".nav-link__label");
  return !label || getComputedStyle(label).position === "absolute";
}

function place(trigger) {
  const gap = 8;
  const margin = 8;
  const box = trigger.getBoundingClientRect();
  tip.style.left = "0px";
  tip.style.top = "0px";
  // Where (0, 0) really is: the viewport, or a dialog that is still animating in (a transform moves the origin).
  const origin = tip.getBoundingClientRect();
  const width = tip.offsetWidth;
  const height = tip.offsetHeight;
  let top = box.bottom + gap;
  if (top + height > window.innerHeight - margin) top = Math.max(margin, box.top - gap - height);
  let left = box.left + box.width / 2 - width / 2;
  left = Math.min(Math.max(margin, left), window.innerWidth - width - margin);
  tip.style.left = `${Math.round(left - origin.left)}px`;
  tip.style.top = `${Math.round(top - origin.top)}px`;
}

function show(trigger) {
  window.clearTimeout(hideTimer);
  const text = textFor(trigger);
  if (!text || !tip) return;
  if (trigger.matches(".nav-link") && !labelIsHidden(trigger)) return;
  if (current && current !== trigger) unlink(current);
  current = trigger;
  tip.textContent = text;
  tip.hidden = false;
  place(trigger);
  const described = (trigger.getAttribute("aria-describedby") || "").split(/\s+/).filter(Boolean);
  if (!described.includes("roxy-tip")) {
    trigger.dataset.tipLinked = "1";
    trigger.setAttribute("aria-describedby", [...described, "roxy-tip"].join(" "));
  }
}

function unlink(trigger) {
  if (trigger.dataset.tipLinked) {
    const rest = (trigger.getAttribute("aria-describedby") || "").split(/\s+/).filter((id) => id && id !== "roxy-tip");
    if (rest.length) trigger.setAttribute("aria-describedby", rest.join(" "));
    else trigger.removeAttribute("aria-describedby");
    delete trigger.dataset.tipLinked;
  }
}

export function hideTip() {
  window.clearTimeout(showTimer);
  if (!tip) return;
  tip.hidden = true;
  if (current) unlink(current);
  current = null;
}

function scheduleHide() {
  window.clearTimeout(showTimer);
  window.clearTimeout(hideTimer);
  hideTimer = window.setTimeout(hideTip, HIDE_DELAY_MS);
}

export function initTooltips() {
  tip = qs("#roxy-tip");
  if (!tip) return;

  document.addEventListener("pointerover", (event) => {
    const trigger = event.target instanceof Element ? event.target.closest(SELECTOR) : null;
    if (event.target instanceof Element && event.target.closest("#roxy-tip")) {
      window.clearTimeout(hideTimer);  // hoverable: moving onto the tooltip keeps it (WCAG 1.4.13)
      return;
    }
    if (!trigger) return;
    window.clearTimeout(showTimer);
    showTimer = window.setTimeout(() => show(trigger), trigger.matches("[data-help]") ? 0 : SHOW_DELAY_MS);
  });
  document.addEventListener("pointerout", (event) => {
    const leaving = event.target instanceof Element ? event.target.closest(`${SELECTOR}, #roxy-tip`) : null;
    if (!leaving) return;
    const into = event.relatedTarget instanceof Element ? event.relatedTarget : null;
    if (into && (into.closest("#roxy-tip") || (current && current.contains(into)))) return;
    scheduleHide();
  });
  document.addEventListener("focusin", (event) => {
    const trigger = event.target instanceof Element ? event.target.closest(SELECTOR) : null;
    if (trigger) show(trigger);
  });
  document.addEventListener("focusout", (event) => {
    if (current && event.target instanceof Element && current.contains(event.target)) scheduleHide();
  });
  document.addEventListener("click", (event) => {
    const help = event.target instanceof Element ? event.target.closest("button[data-help]") : null;
    if (!help) return;
    event.preventDefault();
    event.stopPropagation();
    if (current === help && !tip.hidden) {
      hideTip();
      return;
    }
    show(help);
    announce(help.dataset.help);
  }, true);
  window.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || tip.hidden) return;
    hideTip();
    event.preventDefault();  // this Escape was for the tooltip: no dialog close, no menu close (WCAG 1.4.13)
    dismissedAt = performance.now();
  }, true);
  // Belt and braces for browsers that raise the dialog's close request anyway: cancel that one close.
  document.addEventListener("cancel", (event) => {
    if (performance.now() - dismissedAt < 50) event.preventDefault();
  }, true);
  // A scroll moves the trigger: a tooltip shown for keyboard focus follows it (focus often scrolls the page, and
  // the tip must persist, WCAG 1.4.13); one shown for a hover goes away, since the pointer has left the trigger.
  const follow = rafThrottle(() => {
    if (current && !tip.hidden) place(current);
  });
  window.addEventListener("scroll", () => {
    if (tip.hidden) return;
    if (current && current.isConnected && current.contains(document.activeElement)) follow();
    else hideTip();
  }, { capture: true, passive: true });
}
