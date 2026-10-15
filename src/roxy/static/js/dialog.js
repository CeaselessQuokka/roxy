/**
 * Dialogs, the details drawer, the phone bottom sheet, and dropdown menus.
 *
 * What this is
 *   `openDialog(idOrNode, opener)` and `closeDialog(node)` for every native <dialog> on the page, plus the click
 *   wiring: `data-dialog-open="id"` opens, `data-dialog-close` closes, a click on the dimmed backdrop closes, and
 *   `data-drawer-src="url"` opens the drawer and loads that fragment into it. `openDrawer(title, content)` shows
 *   content built in the browser (table row details). `initMenus()` makes <details data-menu> dropdowns close on
 *   Escape, on a click elsewhere, and when another menu opens.
 *
 * Why it exists
 *   A modal <dialog> opened with showModal() gives us the hard accessibility parts for free: focus moves into it,
 *   Tab stays inside, the rest of the page is inert, and Escape closes it. What the browser does not do is give
 *   focus back to the button that opened it, which keyboard users rely on (WCAG 2.4.3); that is done here.
 *
 * How it works
 *   The opener is remembered per dialog and refocused on the `close` event. Dialog forms posting with htmx
 *   (`data-dialog-form`) close after a 2xx answer and show the server's error text (as text, never HTML) after a
 *   failure, so the person can fix the input without losing it. The drawer loads its fragment with itself as the
 *   htmx source, so a failed load writes the error into the drawer instead of leaving "Loading" there.
 *   Opening a dialog closes the others (a sheet, the palette and a confirm dialog never stack), with one
 *   exception: the session-expired alert (`#session-expired`) opens ON TOP and closes nothing, so a half-written
 *   form underneath survives "Stay on this page"; while it is open no other dialog may open over it.
 *
 * What to read next
 *   templates/components/dialog.html, templates/admin/_layout/overlays.html, static/js/tables.js (drawer content).
 */

import htmx from "roxy/htmx_setup";
import { el, icon, qs, qsa } from "roxy/dom";
import { errorMessage, isReauthRequired } from "roxy/net";

const openers = new WeakMap();
const lastClosed = new WeakMap();
const REOPEN_MS = 10000;
const SESSION_DIALOG_ID = "session-expired";
const STACKING_IDS = new Set([SESSION_DIALOG_ID, "reauth"]);
// Dialogs that open ON TOP of an open one without closing it: the session alert, and "Confirm it is you", whose
// retried request still needs the form underneath (static/js/reauth.js).

function resolve(target) {
  return typeof target === "string" ? document.getElementById(target) : target;
}

/** True while the session-expired alert is showing (nothing else may open or take keys then). */
export function sessionOverlayOpen() {
  const overlay = document.getElementById(SESSION_DIALOG_ID);
  return Boolean(overlay && overlay.open);
}

/** Where focus goes back to when a dialog closes: the opener itself, and enough to find its successor when a
 *  refresh replaced it (the table row it sat in, the card around it). */
function describeOpener(opener) {
  if (!(opener instanceof HTMLElement) || opener === document.body) return null;
  // An item of a dropdown menu is hidden once the menu closes (it closes as the dialog opens), so neither this
  // script nor the browser could focus it again: the menu's own button takes its place (WCAG 2.4.3, a11y-6).
  const menu = opener.closest("details[data-menu]");
  const summary = menu ? qs(":scope > summary", menu) : null;
  const target = summary && opener !== summary ? summary : opener;
  const row = target.closest("[data-row-id]");
  const card = target.closest("[data-card]");
  return { opener: target, rowId: row ? row.dataset.rowId : "", cardId: card ? card.id : "" };
}

/** The element to give focus back to: the opener, else its row's or its card's successor, else the main area. */
function returnTarget(record) {
  if (!record) return null;
  if (record.opener && record.opener.isConnected && record.opener.getClientRects().length) return record.opener;
  const card = record.cardId ? document.getElementById(record.cardId) : null;
  const scope = card || document;
  if (record.rowId) {
    const row = qs(`[data-row-id="${CSS.escape(record.rowId)}"]`, scope);
    const control = row ? qs("[data-dt-open], a[href], button:not([disabled])", row) || row : null;
    if (control && control.getClientRects().length) return control;
  }
  if (card && card.getClientRects().length) {
    if (!card.hasAttribute("tabindex")) card.setAttribute("tabindex", "-1");
    return card;
  }
  return document.getElementById("main");
}

export function openDialog(target, opener = document.activeElement) {
  const dialog = resolve(target);
  if (!dialog || typeof dialog.showModal !== "function") return null;
  if (dialog.open) return dialog;
  const isSessionOverlay = dialog.id === SESSION_DIALOG_ID;
  if (!isSessionOverlay && sessionOverlayOpen()) return null;
  // The opener is described before the menus close, while the item still sits in its menu (a11y-6). A dialog
  // reopened by a script right after an action (no opener of its own: `document.body`) keeps the opener of its
  // previous opening, so closing it still returns focus to the page (a11y-7).
  let record = describeOpener(opener);
  const previous = lastClosed.get(dialog);
  if (!record && previous && performance.now() - previous.at < REOPEN_MS) record = previous.record;
  // Only one menu sheet or palette at a time: close any other open modal first (they would stack). The session
  // alert and the re-authentication dialog are the exceptions: they stack over whatever is open, so nothing the
  // admin typed is thrown away.
  if (!STACKING_IDS.has(dialog.id)) {
    for (const other of qsa("dialog[open]")) {
      if (other !== dialog && !other.contains(dialog)) other.close();
    }
  }
  for (const menu of qsa("details[data-menu][open]")) menu.open = false;
  openers.set(dialog, record);
  dialog.showModal();
  const autofocus = dialog.querySelector("[autofocus], input:not([type=hidden]):not([disabled]), select, textarea");
  if (autofocus && !dialog.classList.contains("dialog--danger")) autofocus.focus();
  return dialog;
}

export function closeDialog(target) {
  const dialog = resolve(target);
  if (dialog && dialog.open) dialog.close();
}

/** Show browser-built content (a Node) in the drawer. */
export function openDrawer(title, content, opener) {
  const drawer = document.getElementById("drawer");
  if (!drawer) return;
  qs("#drawer-title", drawer).textContent = title || "Details";
  const body = qs("#drawer-body", drawer);
  body.replaceChildren(content);
  openDialog(drawer, opener);
}

/** Open the drawer and load a server fragment into it with htmx. */
export function openDrawerFrom(src, title, opener) {
  const drawer = document.getElementById("drawer");
  if (!drawer || !src) return;
  qs("#drawer-title", drawer).textContent = title || "Details";
  const body = qs("#drawer-body", drawer);
  body.replaceChildren(el("p", { class: "muted" }, [el("span", { class: "spinner", "aria-hidden": "true" }), " Loading"]));
  if (!openDialog(drawer, opener)) return;
  // The drawer body is the request's source too, so its errors are reported here (see drawerFailed below).
  htmx.ajax("GET", src, { source: body, target: body, swap: "innerHTML" });
}

function drawerFailed(body, xhr) {
  const status = xhr ? xhr.status : 0;
  let text;
  if (status === 0) text = "Roxy could not be reached, so the details could not be loaded.";
  else if (status === 401) text = "Your session ended, so the details could not be loaded.";
  else if (isReauthRequired(status, xhr.getResponseHeader("Roxy-Reauth"), xhr.responseText)) {
    text = "These details need your second factor again, so they could not be loaded.";
  } else text = `The details could not be loaded (${status}). ${errorMessage(xhr.responseText)}`.trim();
  body.replaceChildren(el("div", { class: "alert alert--bad", role: "alert" }, [
    el("span", { class: "alert__icon" }, [icon("alert-octagon")]),
    el("div", { class: "alert__text" }, [
      el("p", { class: "alert__title", text }),
      el("p", { class: "alert__body", text: "Close the details and open them again to retry." }),
    ]),
  ]));
}

export function initDialogs() {
  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;

    const opener = target.closest("[data-dialog-open]");
    if (opener) {
      event.preventDefault();
      openDialog(opener.dataset.dialogOpen, opener);
      return;
    }
    const closer = target.closest("[data-dialog-close]");
    if (closer) {
      closeDialog(closer.closest("dialog"));
      return;
    }
    // A click on the backdrop lands on the <dialog> element itself, outside its box.
    if (target.tagName === "DIALOG" && target.open) {
      const box = target.getBoundingClientRect();
      const inside = event.clientX >= box.left && event.clientX <= box.right && event.clientY >= box.top
        && event.clientY <= box.bottom;
      if (!inside && !target.matches(".session-expired")) target.close();
      return;
    }
    const drawerTrigger = target.closest("button[data-drawer-src], a[data-drawer-src]");
    if (drawerTrigger) {
      event.preventDefault();
      openDrawerFrom(drawerTrigger.dataset.drawerSrc, drawerTrigger.dataset.drawerTitle || drawerTrigger.textContent.trim(),
        drawerTrigger);
    }
  });

  // Give focus back to whatever opened the dialog, or to its successor after a refresh (WCAG 2.4.3). The browser
  // fires `close` in a later task, after the dialog has already lost its `open` attribute; in between, focus would
  // sit on a control of the closed dialog. So the `open` attribute is watched too (a mutation observer runs right
  // after the task that closed the dialog), and `close` only finishes what the observer did not (a11y-6).
  const settleFocus = (dialog) => {
    if (openers.has(dialog)) {
      const record = openers.get(dialog);
      openers.delete(dialog);
      if (record) lastClosed.set(dialog, { record, at: performance.now() });
      const back = returnTarget(record);
      if (back && back !== document.body) {
        back.focus();
        return;
      }
    }
    if (dialog.contains(document.activeElement)) {
      // Nothing to return to: never leave focus on a field inside a closed dialog (keys would go nowhere, and
      // the single-key shortcuts would think the admin is still typing).
      document.activeElement.blur();
    }
  };
  new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      const dialog = mutation.target;
      if (dialog instanceof HTMLDialogElement && !dialog.open && mutation.oldValue !== null) settleFocus(dialog);
    }
  }).observe(document.documentElement, {
    subtree: true, attributes: true, attributeFilter: ["open"], attributeOldValue: true,
  });
  document.addEventListener("close", (event) => {
    const dialog = event.target;
    if (dialog instanceof HTMLDialogElement && !dialog.open) settleFocus(dialog);
  }, true);

  document.addEventListener("htmx:afterRequest", (event) => {
    const elt = event.detail.elt instanceof Element ? event.detail.elt : null;
    if (elt && elt.id === "drawer-body") {
      if (!event.detail.successful) drawerFailed(elt, event.detail.xhr);
      return;
    }
    const form = elt ? elt.closest("form[data-dialog-form]") : null;
    if (!form) return;
    const error = qs("[data-dialog-error]", form);
    const xhr = event.detail.xhr;
    if (event.detail.successful) {
      if (error) error.hidden = true;
      form.reset();
      closeDialog(form.closest("dialog"));
    } else if (error && xhr && xhr.status !== 401) {
      let text;
      if (xhr.status === 0) text = "Roxy could not be reached. Nothing was changed; try again.";
      else if (isReauthRequired(xhr.status, xhr.getResponseHeader("Roxy-Reauth"), xhr.responseText)) {
        text = "This needs your second factor again: confirm it is you, then try again. Nothing was changed.";
      } else text = errorMessage(xhr.responseText) || `The server refused this (${xhr.status}). Nothing was changed.`;
      error.textContent = text;
      error.hidden = false;
    }
  });
}

export function initMenus() {
  const closeAll = (except) => {
    for (const menu of qsa("details[data-menu][open]")) if (menu !== except) menu.open = false;
  };
  document.addEventListener("toggle", (event) => {
    const menu = event.target;
    if (menu instanceof HTMLDetailsElement && menu.matches("[data-menu]") && menu.open) closeAll(menu);
  }, true);
  document.addEventListener("click", (event) => {
    const inside = event.target instanceof Element ? event.target.closest("details[data-menu]") : null;
    closeAll(inside);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || event.defaultPrevented) return;  // prevented: the Escape closed a tooltip
    const open = qs("details[data-menu][open]");
    if (open && !qs("dialog[open]")) {
      open.open = false;
      const summary = qs("summary", open);
      if (summary) summary.focus();
    }
  });
}
