/**
 * The Audit page's own script (templates/admin/pages/audit.html): open an entry named in the address.
 *
 * What this is
 *   `/admin/audit?entry=<id>` (the links of chart annotations and recommendation histories) opens that entry's
 *   details in the drawer as soon as the page has loaded. Everything else on the page (the table, its filters, the
 *   drawer for a clicked row, the revert form) is the shared design system and needs no page code.
 *
 * Why it exists
 *   A link to one audit entry should land on that entry, not on page one of the log.
 *
 * How it works
 *   The id is checked to be a plain number before it goes into the fragment URL (it is a query value, and the
 *   fragment route checks it again). The drawer loads `/admin/audit/fragment/entry?entry=<id>` like a row click.
 *
 * What to read next
 *   static/js/page.js (the helpers every page module uses), roxy/admin/pages/audit.py.
 */

import { openDrawerFrom, pageParams } from "roxy/page";

const entry = pageParams().get("entry") || "";
if (/^[0-9]{1,18}$/.test(entry)) {
  const params = pageParams();
  params.delete("entry");
  params.set("entry", entry);
  openDrawerFrom(`/admin/audit/fragment/entry?${params.toString()}`, `Audit entry #${entry}`, document.body);
}
