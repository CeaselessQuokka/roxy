/**
 * The Help page's own script (templates/admin/pages/help*): runbook links, the glossary filter, the contents list.
 *
 * What this is
 *   1. An alert email links to `/admin/help#runbook-<name>`: the runbook index entry with that id carries the
 *      runbook's address (`data-runbook-href`), and the page goes on to it at once, so the link lands on the runbook
 *      itself. Without scripts the entry and its link are shown.
 *   2. The glossary filter hides the terms that do not contain the typed text and says how many are left. The count
 *      is announced politely, once typing pauses (a live region must not chatter, plan 14.9).
 *   3. On a phone, a document's contents list starts closed so the text comes first.
 *
 * Why it exists
 *   These are the only behaviors of the Help page that need a script; everything else is server-rendered.
 *
 * How it works
 *   The runbook address is checked against its fixed shape before it is followed (`/admin/help/runbooks#<slug>`),
 *   so nothing in the page can send the browser elsewhere. The filter compares lowercase text content only.
 *
 * What to read next
 *   static/js/page.js (the helpers every page module uses), roxy/admin/pages/help.py.
 */

import { onContent } from "roxy/page";

const RUNBOOK_HREF = /^\/admin\/help\/runbooks#[a-z0-9-]{1,80}$/;
const ANNOUNCE_AFTER_MS = 600;

function followRunbookLink() {
  const name = decodeURIComponent(window.location.hash.slice(1));
  if (!name.startsWith("runbook-") || name === "runbook-index") return;
  const entry = document.getElementById(name);
  const href = entry ? entry.dataset.runbookHref || "" : "";
  if (RUNBOOK_HREF.test(href)) window.location.replace(href);
}

function glossaryFilter(input) {
  const card = input.closest("[data-card]") || document;
  const terms = [...card.querySelectorAll("[data-term]")];
  const count = card.querySelector("[data-glossary-count]");
  const empty = card.querySelector("[data-glossary-empty]");
  const total = terms.length;
  let timer = 0;
  const apply = () => {
    const needle = input.value.trim().toLowerCase();
    let shown = 0;
    for (const term of terms) {
      const match = !needle || term.textContent.toLowerCase().includes(needle);
      term.hidden = !match;
      if (match) shown += 1;
    }
    if (empty) empty.hidden = shown !== 0;
    window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      if (count) count.textContent = needle ? `${shown} of ${total} terms` : `${total} terms`;
    }, ANNOUNCE_AFTER_MS);
  };
  input.addEventListener("input", apply);
}

function contentsList(details) {
  if (window.matchMedia("(max-width: 1099px)").matches) details.open = false;
}

followRunbookLink();
window.addEventListener("hashchange", followRunbookLink);
onContent("[data-glossary-filter]", glossaryFilter);
onContent("[data-doc-toc]", contentsList);
