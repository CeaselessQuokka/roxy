/* Roxy Admin Dashboard — wiring for diagnostics-backed UI
   - Consumes GET /admin/diagnostics -> get_diagnostics() shape provided
   - Keeps the session alive while the page is open (heartbeat); the server
     invalidates the session ~30s after the page is left.
   - Updates KPI cards, traffic chart, tables, health, tokens, attempts
   - Handles: Refresh, Export CSV, Submit Tokens, Clear Probes, Filters
   - No frameworks; resilient to missing fields
*/
const print = console.log;
(() => {
	// -----------------------------
	// Helpers
	// -----------------------------
	const $ = (sel, ctx = document) => ctx.querySelector(sel);
	const $$ = (sel, ctx = document) => Array.from(ctx.querySelectorAll(sel));

	const toastEl = $("#toast");
	function showToast(msg, ms = 2200) {
		if (!toastEl) return;
		toastEl.textContent = msg;
		toastEl.classList.add("is-visible");
		clearTimeout(showToast._t);
		showToast._t = setTimeout(() => toastEl.classList.remove("is-visible"), ms);
	}

	function toTS(ts) {
		if (typeof ts !== "number" || !isFinite(ts) || ts <= 0) return "—";
		try {
			return new Date(ts * 1000).toLocaleString();
		} catch {
			return String(ts);
		}
	}
	function timeAgo(ts) {
		if (typeof ts !== "number" || !isFinite(ts) || ts <= 0) return "—";
		const s = Math.max(0, Date.now() / 1000 - ts);
		if (s < 10) return "just now";
		if (s < 60) return `${Math.floor(s)}s ago`;
		if (s < 3600) return `${Math.floor(s / 60)}m ago`;
		if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m ago`;
		return `${Math.floor(s / 86400)}d ago`;
	}
	// A timestamp cell: relative time as text, exact time on hover. The raw epoch
	// rides along as a sort value, because "3m ago" sorts alphabetically as
	// nonsense — 3m, 30s and 3h would order 30s, 3h, 3m.
	function tsNode(ts) {
		const span = document.createElement("span");
		span.textContent = timeAgo(ts);
		if (typeof ts === "number" && isFinite(ts) && ts > 0) {
			span.title = toTS(ts);
			span.dataset.sortValue = String(ts);
		} else {
			span.dataset.sortValue = "";
		}
		return span;
	}

	// A cell whose displayed text and sort key differ (a formatted duration, a
	// badge, a bar). Wrap the value so the sorter reads the number, not the label.
	function sortable(node, value) {
		const el = node instanceof Node ? node : document.createTextNode(String(node ?? ""));
		const span = document.createElement("span");
		span.appendChild(el);
		span.dataset.sortValue = value === null || value === undefined ? "" : String(value);
		return span;
	}
	function fmtNum(x, digits = 0) {
		if (x === Infinity || x === -Infinity || Number.isNaN(x)) return "—";
		if (typeof x !== "number") return "0";
		return digits ? x.toFixed(digits) : String(Math.trunc(x));
	}
	function fmtDuration(s) {
		s = Math.max(0, Math.floor(s));
		const d = Math.floor(s / 86400);
		const h = Math.floor((s % 86400) / 3600);
		const m = Math.floor((s % 3600) / 60);
		if (d) return `${d}d ${h}h`;
		if (h) return `${h}h ${m}m`;
		return `${m}m ${s % 60}s`;
	}

	// Graceful text setter
	function setText(id, val) {
		const el = typeof id === "string" ? document.getElementById(id) : id;
		if (el) el.textContent = val;
	}

	// Build a <tr> with cells. A cell node carrying data-sort-value hands it up to
	// its <td>, which is where the table sorter looks — so tsNode()/sortable()
	// make a column sort correctly wherever they are used, with no per-table work.
	function tr(cells = []) {
		const tr = document.createElement("tr");
		cells.forEach(c => {
			const td = document.createElement("td");
			if (c instanceof Node) {
				td.appendChild(c);
				if (c.dataset && c.dataset.sortValue !== undefined) td.dataset.sortValue = c.dataset.sortValue;
			} else td.textContent = c;
			tr.appendChild(td);
		});
		return tr;
	}

	// -----------------------------
	// Sortable tables
	// -----------------------------
	// Sorting happens on the rendered DOM rather than inside each renderer. That
	// is a deliberate trade: the thirty-odd tables here build their rows in thirty
	// different ways (chevrons, badges, inline buttons, nested detail rows), and
	// threading a sort key through every one of them would be thirty chances to
	// get it subtly wrong. Reading the rows back gives every table the same
	// behaviour from one implementation.
	//
	// Two rules keep it honest:
	//   - a <td> may carry data-sort-value to sort by something other than its
	//     text (an epoch behind "3m ago", a number behind a bar);
	//   - a <tr data-sort-skip> is a detail/expansion row and stays welded to the
	//     row above it, so expanding a row and then re-sorting cannot orphan it.
	//
	// State is per table and survives re-renders, which is the point: the poll
	// redraws every table every few seconds, and a sort that did not survive that
	// would be useless on exactly the live data it exists for.
	const SORT_STATE = new Map(); // table selector -> {key, dir}
	const SORT_RERENDER = new Map(); // table selector -> redraw from last payload

	function sortState(sel) {
		return SORT_STATE.get(sel);
	}

	function paintSortHeaders(sel) {
		const table = $(sel);
		if (!table) return;
		const cfg = SORT_STATE.get(sel) || {};
		for (const th of $$("thead th[data-sort]", table)) {
			const active = th.dataset.sort === cfg.key;
			th.classList.toggle("is-sorted", active);
			th.dataset.dir = active ? cfg.dir : "";
			th.setAttribute("aria-sort", active ? (cfg.dir === "asc" ? "ascending" : "descending") : "none");
		}
	}

	// Wire one table's headers. `rerender` redraws from the data already in hand
	// so clicking a header never costs a round-trip.
	function initSortable(sel, rerender) {
		const table = $(sel);
		if (!table || table.dataset.sortReady === "1") return;
		table.dataset.sortReady = "1";
		if (rerender) SORT_RERENDER.set(sel, rerender);
		const headers = $$("thead th[data-sort]", table);
		if (!headers.length) return;
		if (!SORT_STATE.has(sel)) {
			const initial = headers.find(th => th.dataset.sortDefault) || null;
			SORT_STATE.set(sel, {
				key: initial ? initial.dataset.sort : "",
				dir: initial ? initial.dataset.sortDefault : "desc",
			});
		}
		const cfg = SORT_STATE.get(sel);
		for (const th of headers) {
			th.classList.add("th--sortable");
			th.tabIndex = 0;
			th.setAttribute("role", "columnheader");
			const activate = () => {
				if (cfg.key === th.dataset.sort) cfg.dir = cfg.dir === "asc" ? "desc" : "asc";
				else {
					cfg.key = th.dataset.sort;
					// Text columns read best A→Z; counts and times read best
					// biggest/newest first, which is what they are looked at for.
					cfg.dir = th.dataset.sortDefault || (th.dataset.sortType === "text" ? "asc" : "desc");
				}
				paintSortHeaders(sel);
				const redraw = SORT_RERENDER.get(sel);
				if (redraw) redraw();
				else sortTable(sel);
			};
			th.addEventListener("click", activate);
			th.addEventListener("keydown", e => {
				if (e.key === "Enter" || e.key === " ") {
					e.preventDefault();
					activate();
				}
			});
		}
		paintSortHeaders(sel);
	}

	const isBlankSort = v => v === undefined || v === null || v === "" || v === "—";

	function cellSortValue(row, index) {
		const td = row.children[index];
		if (!td) return "";
		const raw = td.dataset.sortValue !== undefined ? td.dataset.sortValue : td.textContent.trim();
		if (isBlankSort(raw)) return "";
		// Strip the thousands separators the tables render with, so a count column
		// sorts as a number rather than as the string "1,004" < "999".
		const numeric = Number(String(raw).replace(/,/g, ""));
		return Number.isFinite(numeric) && String(raw).trim() !== "" ? numeric : String(raw).toLowerCase();
	}

	function compareSort(a, b) {
		if (typeof a === "number" && typeof b === "number") return a - b;
		return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" });
	}

	// Reorder a table's rows in place using its current sort state.
	function sortTable(sel) {
		const table = $(sel);
		const cfg = SORT_STATE.get(sel);
		if (!table || !cfg || !cfg.key) return;
		const tbody = $("tbody", table);
		const headers = $$("thead th", table);
		const index = headers.findIndex(th => th.dataset.sort === cfg.key);
		if (!tbody || index < 0) return;

		// Group each visible row with the detail rows that trail it, so the pair
		// travels together.
		const groups = [];
		for (const row of Array.from(tbody.children)) {
			if (row.dataset.sortSkip === "1" && groups.length) groups[groups.length - 1].rows.push(row);
			else groups.push({ rows: [row], value: cellSortValue(row, index) });
		}
		// A single "nothing here yet" placeholder row must not be shuffled.
		if (groups.length < 2) return;
		const dir = cfg.dir === "asc" ? 1 : -1;
		groups.sort((a, b) => {
			const ab = isBlankSort(a.value);
			const bb = isBlankSort(b.value);
			// Blanks sink in BOTH directions. A column sorted ascending should
			// start with its smallest real value, not with every empty cell.
			if (ab !== bb) return ab ? 1 : -1;
			if (ab) return 0;
			return compareSort(a.value, b.value) * dir;
		});
		const frag = document.createDocumentFragment();
		for (const group of groups) for (const row of group.rows) frag.appendChild(row);
		tbody.appendChild(frag);
	}

	// Re-apply every table's sort after a render pass.
	function sortAllTables() {
		for (const sel of SORT_STATE.keys()) sortTable(sel);
	}

	function escapeHtml(s) {
		return String(s)
			.replaceAll("&", "&amp;")
			.replaceAll("<", "&lt;")
			.replaceAll(">", "&gt;")
			.replaceAll('"', "&quot;")
			.replaceAll("'", "&#39;"); // Also single quotes, so single-quoted attributes are safe too.
	}

	// A count with thousands separators, for the many "N distinct" labels.
	const fmtCount = n => Number(n || 0).toLocaleString();

	function fmtBytes(n) {
		n = Number(n || 0);
		if (n < 1024) return `${n} B`;
		if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
		return `${(n / 1024 / 1024).toFixed(1)} MB`;
	}

	// Puts a button into a "working…" state and guarantees it comes back, so a
	// slow action (a health check can take tens of seconds) never looks hung.
	async function withBusy(btn, busyLabel, fn) {
		if (!btn) return fn();
		if (btn.dataset.busy === "1") return; // Already in flight.
		const original = btn.textContent;
		btn.dataset.busy = "1";
		btn.disabled = true;
		btn.textContent = busyLabel;
		try {
			return await fn();
		} finally {
			delete btn.dataset.busy;
			btn.disabled = false;
			btn.textContent = original;
		}
	}

	// -----------------------------
	// Session presence (heartbeat)
	// -----------------------------
	// The server keeps the session alive only while it keeps hearing from this
	// page. We ping every HEARTBEAT_MS while the tab is visible; once the admin
	// leaves (tab hidden / closed / navigated away) the pings stop and the
	// server invalidates the session ~30s later.
	const HEARTBEAT_MS = 10000;
	let sessionAlive = true;

	function setSessionChip(state, text) {
		const chip = $("#sessionChip");
		if (!chip) return;
		chip.classList.toggle("chip--ok", state === "ok");
		chip.classList.toggle("chip--warn", state === "warn");
		chip.classList.toggle("chip--danger", state === "expired");
		chip.textContent = text;
	}

	function sessionExpired() {
		if (!sessionAlive) return;
		sessionAlive = false;
		setSessionChip("expired", "● Session expired");
		const overlay = $("#expiredOverlay");
		if (overlay) overlay.hidden = false;
		setTimeout(() => {
			window.location.href = "/admin";
		}, 3000);
	}

	// Every dashboard request goes through api(): it tags itself as JSON so the
	// server answers 401 (not a redirect) when the session has died.
	async function api(path, opts = {}) {
		const res = await fetch(path, {
			...opts,
			headers: { Accept: "application/json", ...(opts.headers || {}) },
		});
		if (res.status === 401) {
			sessionExpired();
			throw new Error("Session expired");
		}
		return res;
	}

	async function heartbeat() {
		if (!sessionAlive || document.hidden) return;
		try {
			const res = await api("/admin/heartbeat", { method: "POST" });
			if (!res.ok) throw new Error(String(res.status));
			setSessionChip("ok", "● Session active");
			const hb = await res.json().catch(() => null);
			if (hb && hb.IdleTimeout) {
				// Keep UI copy in sync with the server's actual policy.
				const chip = $("#sessionChip");
				if (chip) {
					chip.title = `Your session stays alive while this page is open and expires ~${hb.IdleTimeout}s after you leave.`;
				}
				setText(
					"expiredOverlayMsg",
					`You were away for more than ${hb.IdleTimeout} seconds, so this session was invalidated for safety.`,
				);
			}
		} catch (err) {
			if (sessionAlive) setSessionChip("warn", "● Connection issue");
		}
	}
	setInterval(heartbeat, HEARTBEAT_MS);
	document.addEventListener("visibilitychange", () => {
		// Coming back to the tab: check in immediately (the server may have
		// already expired the session if we were gone >30s).
		if (!document.hidden) heartbeat();
	});
	window.addEventListener("focus", () => heartbeat());
	window.addEventListener("pagehide", () => {
		// Final "I'm leaving now" ping so the 30s countdown starts exactly at
		// the moment the page is left.
		try {
			navigator.sendBeacon("/admin/heartbeat");
		} catch {}
	});
	heartbeat();

	// -----------------------------
	// Renderers
	// -----------------------------
	function renderOverview(d) {
		const rc = d.RequestCounts || {};
		const total = ["GET", "POST", "PATCH", "PUT", "DELETE"].reduce((acc, m) => {
			const row = rc[m] || {};
			return acc + (row.Successful || 0) + (row.Failed || 0);
		}, 0);
		setText("kpi_total_requests", String(total));

		const sc = d.StatusCodeCounts || {};
		setText("kpi_2xx", String(sc["2xx"] || 0));
		setText("kpi_4xx", String(sc["4xx"] || 0));
	}

	function renderPageVisits(d) {
		const pv = d.PageVisits || {};
		setText("home_page_visits", String(pv.home ?? 0));
		setText("admin_page_visits", String(pv.admin ?? 0));
		setText("robots_page_visits", String(pv.robots ?? 0));
	}

	function renderTraffic(d) {
		const chart = $("#trafficChart");
		if (!chart) return;
		const tm = d.TrafficMinutes || {};
		const serverNow = Number(d.ServerTime) || Date.now() / 1000;
		const nowMinute = Math.floor(serverNow / 60);
		let maxTotal = 1;
		let hourTotal = 0;
		let hourFailed = 0;
		const bars = [];
		for (let i = 59; i >= 0; i--) {
			const minute = nowMinute - i;
			const bucket = tm[String(minute)] || {};
			const ok = Number(bucket.Successful || 0);
			const bad = Number(bucket.Failed || 0);
			bars.push({ minute, ok, bad });
			maxTotal = Math.max(maxTotal, ok + bad);
			hourTotal += ok + bad;
			hourFailed += bad;
		}
		setText("kpi_hour_requests", String(hourTotal));
		setText("kpi_hour_failed", String(hourFailed));
		// Traffic pills mirror the chart's window (last 60 minutes).
		setText("trafficTotalOk", (hourTotal - hourFailed).toLocaleString());
		setText("trafficTotalFail", hourFailed.toLocaleString());
		setText("trafficTotalAll", hourTotal.toLocaleString());

		chart.innerHTML = "";
		for (const bar of bars) {
			const col = document.createElement("div");
			col.className = "traffic-chart__bar";
			const label = new Date(bar.minute * 60000).toLocaleTimeString([], {
				hour: "2-digit",
				minute: "2-digit",
			});
			col.title = `${label} — ${bar.ok} successful, ${bar.bad} failed`;
			if (bar.ok + bar.bad === 0) {
				col.classList.add("is-empty");
			} else {
				const badSeg = document.createElement("div");
				badSeg.className = "traffic-chart__seg traffic-chart__seg--bad";
				badSeg.style.height = `${(bar.bad / maxTotal) * 100}%`;
				const okSeg = document.createElement("div");
				okSeg.className = "traffic-chart__seg traffic-chart__seg--ok";
				okSeg.style.height = `${(bar.ok / maxTotal) * 100}%`;
				col.appendChild(badSeg);
				col.appendChild(okSeg);
			}
			chart.appendChild(col);
		}
	}

	// A horizontal 100%-stacked bar + legend (method mix, success split...).
	function renderSplitBar(barId, legendId, parts) {
		const bar = document.getElementById(barId);
		const legend = document.getElementById(legendId);
		if (!bar || !legend) return;
		const total = parts.reduce((acc, p) => acc + p.value, 0);
		bar.innerHTML = "";
		legend.innerHTML = "";
		if (!total) {
			const empty = document.createElement("div");
			empty.className = "split-bar__seg split-bar__seg--empty";
			empty.style.width = "100%";
			bar.appendChild(empty);
			legend.textContent = "No requests yet";
			return;
		}
		for (const p of parts) {
			if (!p.value) continue;
			const pct = (p.value / total) * 100;
			const seg = document.createElement("div");
			seg.className = `split-bar__seg ${p.cssClass}`;
			seg.style.width = `${pct}%`;
			seg.title = `${p.label}: ${p.value} (${Math.round(pct)}%)`;
			bar.appendChild(seg);
			const item = document.createElement("span");
			item.className = "split-legend__item";
			const dot = document.createElement("span");
			dot.className = `legend-dot ${p.cssClass}`;
			item.append(dot, ` ${p.label} ${Math.round(pct)}%`);
			legend.appendChild(item);
		}
	}

	function renderRequests(d) {
		const rc = d.RequestCounts || {};
		const methods = ["GET", "POST", "PATCH", "PUT", "DELETE"];
		const perMethod = {};
		let totalS = 0,
			totalF = 0;
		for (const m of methods) {
			const row = rc[m] || { Successful: 0, Failed: 0 };
			const s = Number(row.Successful || 0);
			const f = Number(row.Failed || 0);
			perMethod[m] = s + f;
			setText(`mc_${m.toLowerCase()}_s`, String(s));
			setText(`mc_${m.toLowerCase()}_f`, String(f));
			setText(`mc_${m.toLowerCase()}_t`, String(s + f));
			totalS += s;
			totalF += f;
		}
		setText("mc_total_s", String(totalS));
		setText("mc_total_f", String(totalF));
		setText("mc_total_t", String(totalS + totalF));

		renderSplitBar(
			"methodMixBar",
			"methodMixLegend",
			methods.map(m => ({ label: m, value: perMethod[m], cssClass: `fill-${m.toLowerCase()}` })),
		);
		renderSplitBar("successSplitBar", "successSplitLegend", [
			{ label: "Successful", value: totalS, cssClass: "fill-ok" },
			{ label: "Failed", value: totalF, cssClass: "fill-bad" },
		]);

		const sc = d.StatusCodeCounts || {};
		setText("count_2xx", String(sc["2xx"] || 0));
		setText("count_4xx", String(sc["4xx"] || 0));
	}

	function renderBudget(d) {
		const b = d.TokenBudget || {};
		const used = Number(b.Used || 0);
		const limit = Number(b.Limit || 0);
		setText("budget_value", `${used} / ${limit || "—"}`);
		setText("budget_window", String(b.Window ?? "—"));
		setText("budget_reset", String(b.ResetIn ?? 0));
		setText("budget_rejections", String(d.TokenBudgetRejections ?? 0));
		setText("budget_peak_1h", String(d.BudgetPeak1h ?? 0));
		setText("budget_peak_24h", String(d.BudgetPeak24h ?? 0));
		const gauge = $("#budget_gauge");
		if (gauge && limit) {
			const pct = Math.min(100, (used / limit) * 100);
			gauge.style.width = `${pct}%`;
			gauge.classList.toggle("gauge__fill--warn", pct >= 70 && pct < 95);
			gauge.classList.toggle("gauge__fill--bad", pct >= 95);
		}
	}

	function renderPersistence(d) {
		const p = d.Persistence || {};
		const broken = !p.Writable || (p.LastErrorAt && p.LastErrorAt > (p.LastWriteOK || 0)) || Boolean(p.Oversize);
		setText("persist_status", broken ? "PROBLEM" : "OK");
		// Stats-file size against its hard limit. Every record store is capped,
		// so this should sit still; a rising number means something new is not.
		const bytes = Number(p.DataBytes || 0);
		const limit = Number(p.DataLimitBytes || 0);
		setText("persist_size", limit ? `${fmtBytes(bytes)} of ${fmtBytes(limit)}` : fmtBytes(bytes));
		const gauge = $("#persist_gauge");
		if (gauge && limit) {
			const pct = Math.min(100, (bytes / limit) * 100);
			gauge.style.width = `${Math.max(pct, 1)}%`;
			gauge.classList.toggle("gauge__fill--warn", pct >= 50 && pct < 80);
			gauge.classList.toggle("gauge__fill--bad", pct >= 80);
		}
		const over = $("#persist_oversize");
		if (over) {
			over.hidden = !p.Oversize;
			if (p.Oversize) {
				over.textContent =
					`The stats file reached ${fmtBytes(p.Oversize.Bytes)} and was set aside to protect memory` +
					(p.Oversize.MovedTo ? ` (saved as ${p.Oversize.MovedTo})` : "") +
					". Statistics restarted from empty; settings and rules were untouched.";
			}
		}
		$("#persist_status")?.classList.toggle("text-danger", Boolean(broken));
		setText("persist_last", p.LastWriteOK ? timeAgo(p.LastWriteOK) : "never");
		setText("persist_file", p.DataFile || "—");
		const err = $("#persist_error");
		if (err) err.textContent = broken && p.LastError ? ` • ${p.LastError}` : "";
	}

	// --- Latency tables -------------------------------------------------------
	// Every timing record carries a combined total plus a Success/Failed split.
	// The split is the useful part: a 15s "failure" is a timeout and a 0.2s one is
	// Roblox declining, and a single blended average shows neither.
	const emptyTiming = () => ({ TotalTime: 0, Count: 0, Min: 0, Max: 0, LastRequestTime: 0 });

	function foldTiming(into, row) {
		const count = Number(row.Count || 0);
		const min = row.Min === Infinity ? 0 : Number(row.Min || 0);
		into.TotalTime += Number(row.TotalTime || 0);
		into.Count += count;
		into.Max = Math.max(into.Max, Number(row.Max || 0));
		if (min && (!into.Min || min < into.Min)) into.Min = min;
		into.LastRequestTime = Math.max(into.LastRequestTime, Number(row.LastRequestTime || 0));
		return into;
	}

	// The split can be turned off — with no failures recorded, three rows per
	// requester is just noise, so the admin can collapse back to one.
	const splitTimings = () => $("#timingSplitToggle")?.checked !== false;

	function timingCells(label, outcome, row, outcomeClass) {
		const count = Number(row.Count || 0);
		const min = row.Min === Infinity ? 0 : Number(row.Min || 0);
		const badge = document.createElement("span");
		badge.className = `badge ${outcomeClass}`;
		badge.textContent = outcome;
		return tr([
			label,
			badge,
			String(count),
			count ? fmtNum(row.TotalTime / count, 3) : "—",
			count ? fmtNum(min, 3) : "—",
			count ? fmtNum(Number(row.Max || 0), 3) : "—",
			row.LastRequestTime ? tsNode(row.LastRequestTime) : "—",
		]);
	}

	function appendTimingRows(tbody, label, record) {
		const combined = record || emptyTiming();
		const all = timingCells(label, "All", combined, "badge--muted");
		all.classList.add("row--emph");
		tbody.appendChild(all);
		if (!splitTimings()) return;
		// Indented under the combined row so the relationship is obvious.
		tbody.appendChild(timingCells("↳", "Success", record?.Success || emptyTiming(), "badge--ok"));
		tbody.appendChild(timingCells("↳", "Failed", record?.Failed || emptyTiming(), "badge--bad"));
	}

	function renderTimingTable(selector, rows) {
		const tbody = $(`${selector} tbody`);
		if (!tbody) return;
		tbody.innerHTML = "";
		const totals = { All: emptyTiming(), Success: emptyTiming(), Failed: emptyTiming() };
		for (const [label, record] of rows) {
			appendTimingRows(tbody, label, record);
			foldTiming(totals.All, record || {});
			foldTiming(totals.Success, record?.Success || {});
			foldTiming(totals.Failed, record?.Failed || {});
		}
		const totalRow = timingCells("Total", "All", totals.All, "badge--muted");
		totalRow.style.fontWeight = "700";
		tbody.appendChild(totalRow);
		if (splitTimings()) {
			tbody.appendChild(timingCells("↳", "Success", totals.Success, "badge--ok"));
			tbody.appendChild(timingCells("↳", "Failed", totals.Failed, "badge--bad"));
		}
	}

	function renderProxyTimings(d) {
		if (d.ProxyRequestCounts) renderProxyTimings._last = d.ProxyRequestCounts;
		const pc = renderProxyTimings._last || {};
		renderTimingTable(
			"#proxyTimingsTable",
			["GET", "POST", "PATCH", "PUT", "DELETE"].map(m => [m, pc[m]]),
		);
	}

	// Per-requester upstream timings (Token/Rotate) + a running Total row.
	function renderMethodTimings(d) {
		if (d.MethodTimings) renderMethodTimings._last = d.MethodTimings;
		const mt = renderMethodTimings._last || {};
		renderTimingTable(
			"#methodTimingsTable",
			["Token", "Rotate"].map(name => [name, mt[name]]),
		);
	}

	const expandedFailures = new Set();
	function renderRequestFailures(d) {
		const tbody = $("#requestFailuresTable tbody");
		if (!tbody) return;
		if (d.RequestFailures) renderRequestFailures._last = d.RequestFailures;
		const entries = Object.entries(renderRequestFailures._last || {});
		entries.sort((a, b) => (b[1].Count || 0) - (a[1].Count || 0));
		let total = 0;
		tbody.innerHTML = "";
		if (entries.length === 0) {
			tbody.appendChild(tr(["No failures recorded 🎉", "—", "—", "—", "—", "—", "—"]));
			setText("requestFailuresTotal", "0 failures");
			return;
		}
		for (const [sig, info] of entries) {
			total += Number(info.Count || 0);
			// "Method: reason" — split the leading method off for its own column.
			const reason = sig.includes(":") ? sig.slice(sig.indexOf(":") + 1).trim() : sig;
			const row = tr([
				info.Method || "—",
				reason,
				String(info.Count || 0),
				String(info.LastStatus ?? "—"),
				info.LastEndpoint || "—",
				tsNode(info.FirstSeen),
				tsNode(info.LastSeen),
			]);
			row.style.cursor = "pointer";
			const detail = document.createElement("tr");
			detail.dataset.sortSkip = "1"; // Expansion row: stays with its parent when the table is sorted.
			const td = document.createElement("td");
			td.colSpan = 7;
			const pre = document.createElement("pre");
			pre.className = "error-detail__pre";
			pre.textContent = info.LastDetail || "(no detail)";
			td.appendChild(pre);
			detail.appendChild(td);
			detail.style.display = expandedFailures.has(sig) ? "" : "none";
			row.addEventListener("click", () => {
				const showing = detail.style.display !== "none";
				detail.style.display = showing ? "none" : "";
				showing ? expandedFailures.delete(sig) : expandedFailures.add(sig);
			});
			tbody.appendChild(row);
			tbody.appendChild(detail);
		}
		setText("requestFailuresTotal", `${total} failures`);
	}

	function renderRotateIps(d) {
		const tbody = $("#rotateIpsTable tbody");
		if (!tbody) return;
		const list = Array.isArray(d.RotateIps) ? d.RotateIps : [];
		tbody.innerHTML = "";
		setText("rotateIpsTotal", `${list.length} seen`);
		if (list.length === 0) {
			tbody.appendChild(tr(["No exit IPs recorded yet — click “Verify rotation now”", "—", "—"]));
			return;
		}
		for (const item of list) {
			tbody.appendChild(tr([item.IP || "—", item.Source || "—", tsNode(item.Date)]));
		}
	}

	function renderTokens(d) {
		const tbody = $("#tokensTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const list = Array.isArray(d.Tokens) ? d.Tokens : [];
		if (list.length === 0) {
			tbody.appendChild(tr(["—", "No tokens loaded", "—", "—", "—"]));
			return;
		}
		list.forEach((t, i) => {
			const masked = t?.Masked ?? "…***";
			const being = Boolean(t?.BeingValidated);
			const uses = Number(t?.Uses || 0);
			tbody.appendChild(tr([String(i + 1), masked, being ? "Yes" : "No", String(uses), tsNode(t?.LastUsedAt)]));
		});
	}

	function renderThrottled(d) {
		const tbody = $("#throttledTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const data = d.ThrottledIPs || d.throttled_ips || {}; // handle either casing
		const entries = Object.entries(data);
		entries.sort((a, b) => (b[1].LastThrottleTime || 0) - (a[1].LastThrottleTime || 0));
		for (const [ip, info] of entries) {
			tbody.appendChild(tr([ip, String(info.Count ?? 0), tsNode(info.LastThrottleTime)]));
		}
	}

	function renderProbes(d) {
		const tbody = $("#probeTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const items = Array.isArray(d.ExploitAttempts) ? d.ExploitAttempts : [];
		// Newest first reads better for an incident log.
		[...items].reverse().forEach(row => {
			tbody.appendChild(tr([tsNode(row?.Date), row?.IP || "—", row?.UserAgent || "—", row?.Reason || "—"]));
		});
	}

	function renderLogins(d) {
		const tbody = $("#loginsTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const items = Array.isArray(d.LoginAttempts) ? d.LoginAttempts : [];
		[...items].reverse().forEach(row => {
			const badge = document.createElement("span");
			badge.className = `badge ${row?.Successful ? "badge--ok" : "badge--bad"}`;
			badge.textContent = row?.Successful ? "success" : "fail";
			tbody.appendChild(tr([tsNode(row?.Date), row?.IP || "—", badge]));
		});
	}

	function renderCrawls(d) {
		const tbody = $("#crawlsTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const crawls = d.Crawls || {};
		const entries = Object.entries(crawls);
		entries.sort((a, b) => (b[1].Count || 0) - (a[1].Count || 0));
		for (const [ip, info] of entries) {
			tbody.appendChild(tr([ip, String(info.Count || 0), tsNode(info.LastRequestTime)]));
		}
	}

	function setStateWord(id, word, good) {
		setText(id, word);
		const el = document.getElementById(id);
		if (el) {
			el.classList.toggle("health-ok", good === true);
			el.classList.toggle("health-bad", good === false);
		}
	}

	function renderHealth(d) {
		const ms = d.MethodStats || {};
		const tok = ms.Token || {};
		const rot = ms.Rotate || {};
		const routing = d.Routing || {};
		const rotate = d.Rotate || {};
		const tk = (d.ProxyHealth || {}).Tokens || {};

		// Token: same vocabulary as Rotate. "OK" read as "scraping by" — the state
		// this card is in almost all the time deserves to look like success.
		const tokenFull = Number(routing.TokenUsed || 0) >= Number(routing.TokenLimit || 0) && routing.TokenLimit;
		const noTokens = Number(tk.Count || 0) === 0;
		setStateWord(
			"health_token",
			noTokens ? "NO TOKEN" : tokenFull ? "AT BUDGET" : "WORKING",
			!noTokens && !tokenFull,
		);
		setText("token_count", String(tok.Requests || 0));
		setText("token_failed", String(tok.Failed || 0));
		setText("token_timeouts", String(tok.Timeouts || 0));
		setText("token_last_ok", tok.LastSuccessAt ? timeAgo(tok.LastSuccessAt) : "—");
		setText("token_last_req", tok.LastRequestTime ? timeAgo(tok.LastRequestTime) : "—");
		// The Token equivalent of Rotate's cooldown: when the safety budget frees up.
		const tokenReset = Number(routing.TokenResetIn || 0);
		setText("token_reset", tokenFull && tokenReset > 0 ? `${tokenReset}s` : "—");
		setText("token_loaded", String(tk.Count ?? 0));
		const terr = $("#token_error");
		if (terr) terr.textContent = tok.LastError ? ` • last error: ${tok.LastError}` : "";

		// Rotate: Disabled / Cooldown / Working.
		const rotResetIn = Number(routing.RotateResetIn || 0);
		let rotWord = "DISABLED";
		let rotGood = null;
		if (rotate.Configured && rotate.Enabled) {
			if (rotResetIn > 0) {
				rotWord = "COOLDOWN";
				rotGood = false;
			} else {
				rotWord = "WORKING";
				rotGood = true;
			}
		} else if (rotate.Configured) {
			rotWord = "OFF";
		}
		setStateWord("health_rotate", rotWord, rotGood);
		setText("rotate_count", String(rot.Requests || 0));
		setText("rotate_failed", String(rot.Failed || 0));
		setText("rotate_timeouts", String(rot.Timeouts || 0));
		setText("rotate_last_ok", rot.LastSuccessAt ? timeAgo(rot.LastSuccessAt) : "—");
		setText("rotate_last_req", rot.LastRequestTime ? timeAgo(rot.LastRequestTime) : "—");
		setText("rotate_reset", rotResetIn > 0 ? `${rotResetIn}s` : "—");
		setText("rotate_proxy", rotate.ProxyUrl || "(not configured)");
		const rerr = $("#rotate_error");
		if (rerr) rerr.textContent = rot.LastError ? ` • last error: ${rot.LastError}` : "";

		setText("health_tokens_count", String(tk.Count ?? 0));
		setText("health_tokens_expired", String(tk.ExpiredCount ?? 0));
		setText("health_tokens_validating", String(tk.BeingValidatedCount ?? 0));

		renderWorkerFleet(d);
	}

	// The fleet, not "whichever worker answered this poll". A single worker's
	// uptime jumps around because gunicorn recycles workers at max_requests, so
	// the headline number is the SERVICE's uptime and the per-worker detail lives
	// in its own table underneath.
	function renderWorkerFleet(d) {
		const fleet = d.WorkerFleet || {};
		const server = Number(d.ServerTime || 0);
		const serviceUptime = Number(fleet.ServiceUptime || 0);
		if (serviceUptime > 0) {
			setText("health_uptime", fmtDuration(serviceUptime));
			setText("health_started", fleet.ServiceStartedAt ? toTS(fleet.ServiceStartedAt) : "—");
		} else if (server && d.WorkerStartedAt) {
			// No registry yet (first boot, or the file isn't writable): fall back to
			// this worker rather than showing nothing.
			setText("health_uptime", fmtDuration(server - Number(d.WorkerStartedAt)));
			setText("health_started", toTS(Number(d.WorkerStartedAt)));
		}
		setText("health_host_uptime", fleet.HostUptime ? fmtDuration(fleet.HostUptime) : "—");
		const count = Number(fleet.Count || 0);
		const expected = Number(fleet.Expected || 0);
		const workerLabel = expected && count !== expected ? `${count} of ${expected}` : String(count || "—");
		setText("health_worker_count", workerLabel);
		setText("health_fleet_rss", fleet.TotalRSS ? fmtBytes(fleet.TotalRSS) : "—");
		const workerCount = $("#health_worker_count");
		if (workerCount) workerCount.classList.toggle("text-danger", Boolean(expected && count && count < expected));

		const tbody = $("#workersTable tbody");
		if (!tbody) return;
		setText("workerMaxRequests", fmtCount(fleet.MaxRequests || 2000));
		tbody.innerHTML = "";
		const rows = fleet.Workers || [];
		if (!rows.length) {
			tbody.appendChild(tr(["—", "—", "—", "—", "—", "—", "No workers have reported in yet"]));
			return;
		}
		for (const worker of rows) {
			const pid = document.createElement("span");
			pid.textContent = String(worker.Pid || "?");
			if (worker.IsThisWorker) {
				// Which worker served this page — the one whose numbers you'd see
				// without the registry.
				const tag = document.createElement("span");
				tag.className = "badge badge--muted";
				tag.textContent = "serving you";
				pid.appendChild(document.createTextNode(" "));
				pid.appendChild(tag);
			}
			// Zero proxy requests against a climbing total is the "nobody is using
			// it" case, not a broken one — dim it rather than letting it read as
			// a missing number.
			const proxied = document.createElement("span");
			proxied.textContent = fmtCount(worker.Proxied || 0);
			if (!Number(worker.Proxied || 0)) proxied.className = "text-muted";
			tbody.appendChild(
				tr([
					pid,
					fmtDuration(Number(worker.Uptime || 0)),
					fmtBytes(worker.RSS || 0),
					String(worker.Threads || "—"),
					fmtCount(worker.Requests || 0),
					proxied,
					worker.LastSeen ? tsNode(worker.LastSeen) : "—",
				]),
			);
		}
	}

	function renderPause(d) {
		const paused = Boolean(d?.Pause?.Paused);
		const since = Number(d?.Pause?.PausedSince || 0);
		const chip = $("#proxyStatusChip");
		const btn = $("#pauseToggle");
		const banner = $("#pauseBanner");
		if (chip) {
			chip.textContent = paused ? "Proxy: PAUSED" : "Proxy: Running";
			chip.classList.toggle("chip--danger", paused);
			chip.classList.toggle("chip--ok", !paused);
		}
		if (btn) {
			btn.textContent = paused ? "Resume Proxy" : "Pause Proxy";
			btn.classList.toggle("btn--filled", paused);
			btn.classList.toggle("btn--warning", !paused);
			btn.dataset.paused = String(paused);
		}
		if (banner) {
			banner.hidden = !paused;
			setText("pauseBannerDrops", String(d?.PauseDrops ?? 0));
			const reason = d?.Pause?.Reason || "";
			setText("pauseBannerMsg", reason ? `Message shown to users: "${reason}".` : "");
			setText("pauseBannerSince", paused && since ? `(since ${toTS(since)})` : "");
		}
		// Keep the saved message in the input (don't clobber while the admin types).
		const reasonInput = $("#pauseReason");
		if (reasonInput && document.activeElement !== reasonInput && d?.Pause) {
			reasonInput.value = d.Pause.Reason || "";
		}
	}

	function renderThrottleAll(d) {
		const ta = d?.ThrottleAll || {};
		const on = Boolean(ta.ThrottleAll);
		const since = Number(ta.ThrottleAllSince || 0);
		const limit = ta.Limit ?? 1;
		const period = ta.Period ?? 60;
		const btn = $("#throttleAllToggle");
		const banner = $("#throttleAllBanner");
		if (btn) {
			btn.textContent = on ? "Stop Throttle All" : "Throttle All";
			btn.classList.toggle("btn--warning", on);
			btn.classList.toggle("btn--tonal", !on);
			btn.dataset.on = String(on);
		}
		// Keep the Service Controls inputs/labels in sync (don't clobber while editing).
		setText("ta_limit_display", String(limit));
		setText("ta_period_display", String(period));
		const limitInput = $("#throttleLimit");
		const periodInput = $("#throttlePeriod");
		if (limitInput && document.activeElement !== limitInput) limitInput.value = String(limit);
		if (periodInput && document.activeElement !== periodInput) periodInput.value = String(period);
		if (banner) {
			banner.hidden = !on;
			setText("throttleBannerRate", `${limit}/${period}s`);
			setText("throttleBannerDrops", String(d?.ThrottleAllDrops ?? 0));
			const reason = ta.Reason || "";
			setText("throttleAllBannerMsg", reason ? `Message shown to users: "${reason}".` : "");
			setText("throttleAllBannerSince", on && since ? `(since ${toTS(since)})` : "");
		}
		const reasonInput = $("#throttleReason");
		if (reasonInput && document.activeElement !== reasonInput) reasonInput.value = ta.Reason || "";
	}

	function renderTrustedDevices(d) {
		setText("trustedCount", String(d?.TrustedDevices ?? 0));
		const here = $("#trustedThisDevice");
		if (here) {
			here.textContent = d?.TrustedThisDevice ? "trusted (skips 2FA)" : "not trusted";
			here.classList.toggle("text-danger", !d?.TrustedThisDevice);
		}
	}

	function renderVisitors(d) {
		const v = d.VisitorCounts || {};
		setText("kpi_human", String(v.Human ?? 0));
		setText("kpi_crawler", String(v.Crawler ?? 0));
	}

	let endpointEntries = []; // cached for filtering without refetch
	const expandedHosts = new Set(); // which root hosts are expanded (survives refreshes)
	const expandedTemplates = new Set(); // which templates are expanded to their concrete IDs
	const expandedConcretes = new Set(); // which concrete paths show their last headers
	const methodsText = methods =>
		Object.entries(methods || {})
			.map(([m, n]) => `${m}:${n}`)
			.join(", ") || "—";

	// A clickable cell with a chevron + indented label, for the endpoint tree.
	function endpointNameCell(chevronChar, label, { strong = false, depth = 0, sub = false } = {}) {
		const td = document.createElement("td");
		if (depth) td.style.paddingLeft = `${depth * 18 + 12}px`;
		if (chevronChar) {
			const chev = document.createElement("span");
			chev.className = "endpoint-host__chevron";
			chev.textContent = chevronChar;
			td.appendChild(chev);
		}
		const text = document.createElement(strong ? "strong" : "span");
		text.textContent = ` ${label} `;
		if (sub) text.className = "endpoint-sub-label";
		td.appendChild(text);
		return td;
	}

	// Top Endpoints as a 3-level tree: host -> ID-collapsed template -> concrete IDs.
	// template -> the drill-down payload (concrete paths, recent requests, IPs),
	// filled by the lazy fetch below.
	const endpointDetailCache = new Map();
	const expandedEndpointDetail = new Set(); // templates showing their recent requests

	function endpointConcretes(template) {
		return Object.entries(endpointDetailCache.get(template)?.Concrete || {});
	}

	async function fetchEndpointDetail(template) {
		if (endpointDetailCache.has(template)) return endpointDetailCache.get(template);
		try {
			const res = await api(`/admin/endpoints/concrete?template=${encodeURIComponent(template)}`);
			if (!res.ok) throw new Error(String(res.status));
			endpointDetailCache.set(template, await res.json());
		} catch {
			endpointDetailCache.set(template, { Concrete: {}, Recent: [], Last: {}, IPs: {} });
			showToast("Could not load detail for that endpoint");
		}
		return endpointDetailCache.get(template);
	}

	async function toggleEndpointTemplate(template) {
		if (expandedTemplates.has(template)) expandedTemplates.delete(template);
		else expandedTemplates.add(template);
		renderEndpoints({}); // Paint "Loading…" straight away.
		if (expandedTemplates.has(template)) await fetchEndpointDetail(template);
		renderEndpoints({});
	}

	// The "show me what this endpoint is actually being asked for" toggle. It hangs
	// off every endpoint row, not only ones whose path contains an ID — the busiest
	// endpoint here has no ID in its path, and it was the one the old drill-down
	// could say nothing about.
	async function toggleEndpointRequests(template) {
		if (expandedEndpointDetail.has(template)) expandedEndpointDetail.delete(template);
		else expandedEndpointDetail.add(template);
		renderEndpoints({});
		if (expandedEndpointDetail.has(template)) {
			endpointDetailCache.delete(template); // Always re-fetch: "recent" means recent.
			await fetchEndpointDetail(template);
			renderEndpoints({});
		}
	}

	// One recent request against an endpoint, rendered as a compact block.
	function recentRequestBlock(entry) {
		const rows = [
			["When", toTS(entry.Date)],
			["From", `${entry.IP || "—"}${entry.CallerId ? ` · place ${entry.CallerId}` : ""}`],
			["Method", entry.Method || "—"],
			["Query", entry.Query || "—"],
			["We answered", entry.Status ?? "—"],
			["Roblox answered", entry.UpstreamStatus === "" || entry.UpstreamStatus == null ? "—" : entry.UpstreamStatus],
			["Served by", entry.UpstreamMethod || "—"],
			["User-Agent", entry.UserAgent || "—"],
		];
		let headers = entry.Headers || "";
		try {
			headers = JSON.stringify(JSON.parse(headers), null, 2);
		} catch {}
		return (
			'<div class="recent-req">' +
			rows
				.map(([k, v]) => `<div class="recent-req__row"><span>${k}</span><span>${escapeHtml(String(v))}</span></div>`)
				.join("") +
			(entry.Body ? `<details><summary>Request body</summary><pre>${escapeHtml(entry.Body)}</pre></details>` : "") +
			(headers ? `<details><summary>Headers</summary><pre>${escapeHtml(headers)}</pre></details>` : "") +
			"</div>"
		);
	}

	function endpointRequestsRow(template) {
		const row = document.createElement("tr");
		row.dataset.sortSkip = "1";
		row.className = "endpoint-headers";
		const td = document.createElement("td");
		td.colSpan = 6;
		const payload = endpointDetailCache.get(template);
		if (!payload) {
			td.innerHTML = '<div class="text-muted endpoint-headers__meta">Loading recent requests…</div>';
		} else {
			const recent = payload.Recent || [];
			const ips = Object.entries(payload.IPs || {});
			td.innerHTML =
				`<div class="endpoint-headers__meta">Last ${recent.length} request(s) · ${fmtCount(
					payload.IPCount,
				)} distinct IP(s)</div>` +
				(ips.length
					? '<div class="endpoint-ips">' +
						ips
							.slice(0, 12)
							.map(([ip, n]) => `<span class="chip chip--sm mono">${escapeHtml(ip)} · ${fmtCount(n)}</span>`)
							.join(" ") +
						"</div>"
					: "") +
				(recent.length
					? recent.map(recentRequestBlock).join("")
					: '<div class="text-muted">Nothing recorded yet. Raise <code>endpoint_recent_requests</code> in Settings to keep more.</div>');
		}
		row.appendChild(td);
		return row;
	}

	// The endpoint tree sorts itself: whichever column header is active orders the
	// hosts, then the templates within each host, then the concrete IDs within
	// each template. The generic DOM sorter can't do this one — it would tear the
	// tree apart — so the active sort state is read here and applied per level.
	const ENDPOINT_SORTERS = {
		name: r => r.name.toLowerCase(),
		count: r => Number(r.count || 0),
		methods: r => methodsText(r.methods).toLowerCase(),
		ip: r => (r.ip || "").toLowerCase(),
		status: r => Number(r.status) || 0,
		last: r => Number(r.last || 0),
	};

	function sortEndpointLevel(rows) {
		const cfg = sortState("#endpointsTable") || { key: "count", dir: "desc" };
		const pick = ENDPOINT_SORTERS[cfg.key] || ENDPOINT_SORTERS.count;
		const dir = cfg.dir === "asc" ? 1 : -1;
		return rows.sort((a, b) => {
			const av = pick(a);
			const bv = pick(b);
			const ab = isBlankSort(av);
			const bb = isBlankSort(bv);
			if (ab !== bb) return ab ? 1 : -1;
			return compareSort(av, bv) * dir;
		});
	}

	// Trailing cells shared by every level of the tree.
	function endpointStatCells(row, info) {
		const cells = [String(info.Count || 0), methodsText(info.Methods)];
		for (const text of cells) {
			const td = document.createElement("td");
			td.textContent = text;
			row.appendChild(td);
		}
		const tdIp = document.createElement("td");
		tdIp.className = "mono";
		tdIp.textContent = info.LastIP || "—";
		if (info.LastCallerId) tdIp.title = `Roblox-Id (place): ${info.LastCallerId}`;
		row.appendChild(tdIp);
		const tdStatus = document.createElement("td");
		const status = info.LastStatus;
		if (status) {
			const badge = document.createElement("span");
			const s = String(status);
			badge.className = `badge badge--${s.startsWith("2") ? "ok" : s.startsWith("4") ? "warn" : "bad"}`;
			badge.textContent = s;
			tdStatus.appendChild(badge);
			tdStatus.dataset.sortValue = s;
		} else tdStatus.textContent = "—";
		row.appendChild(tdStatus);
		const tdLast = document.createElement("td");
		tdLast.appendChild(tsNode(info.LastRequestTime));
		row.appendChild(tdLast);
	}

	function inspectButton(template) {
		const btn = document.createElement("button");
		btn.type = "button";
		btn.className = "btn btn--ghost btn--xs";
		btn.textContent = expandedEndpointDetail.has(template) ? "Hide requests" : "Inspect";
		btn.title = "Show the most recent requests this endpoint received, with headers and bodies";
		btn.addEventListener("click", e => {
			e.stopPropagation();
			toggleEndpointRequests(template);
		});
		return btn;
	}

	function renderEndpoints(d) {
		if (d.Endpoints) endpointEntries = Object.entries(d.Endpoints);
		const tbody = $("#endpointsTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const q = ($("#endpointsFilter")?.value || "").trim().toLowerCase();
		const filtering = Boolean(q);

		// Group templates by host.
		const hosts = new Map();
		for (const [template, info] of endpointEntries) {
			// Concrete paths are fetched per template on expand (each carries a
			// captured header dump, far too heavy for the dashboard poll), so only
			// ones already loaded are available to match against.
			const concretes = endpointConcretes(template);
			if (q) {
				const hit = template.toLowerCase().includes(q) || concretes.some(([p]) => p.toLowerCase().includes(q));
				if (!hit) continue;
			}
			const host = template.split("/", 1)[0];
			let group = hosts.get(host);
			if (!group) {
				group = { count: 0, last: 0, methods: {}, templates: [], ip: "", status: "" };
				hosts.set(host, group);
			}
			group.count += Number(info.Count || 0);
			if (Number(info.LastRequestTime || 0) >= group.last) {
				group.last = Number(info.LastRequestTime || 0);
				group.ip = info.LastIP || group.ip;
				group.status = info.LastStatus || group.status;
			}
			for (const [m, n] of Object.entries(info.Methods || {})) {
				group.methods[m] = (group.methods[m] || 0) + Number(n || 0);
			}
			group.templates.push([template, info, concretes]);
		}

		const sortedHosts = sortEndpointLevel(
			[...hosts.entries()].map(([host, group]) => ({
				host,
				group,
				name: host,
				count: group.count,
				methods: group.methods,
				ip: group.ip,
				status: group.status,
				last: group.last,
			})),
		);
		if (sortedHosts.length === 0) {
			tbody.appendChild(
				tr([q ? "No endpoints match the filter" : "No endpoints recorded yet", "—", "—", "—", "—", "—"]),
			);
			return;
		}

		for (const { host, group } of sortedHosts) {
			const hostExpanded = expandedHosts.has(host) || filtering;
			const hostRow = document.createElement("tr");
			hostRow.className = "endpoint-host";
			hostRow.setAttribute("aria-expanded", String(hostExpanded));
			const tdHost = endpointNameCell(hostExpanded ? "▾" : "▸", host, { strong: true });
			tdHost.dataset.sortValue = host;
			const meta = document.createElement("span");
			meta.className = "endpoint-host__count";
			meta.textContent = ` (${group.templates.length} endpoint${group.templates.length === 1 ? "" : "s"})`;
			tdHost.appendChild(meta);
			hostRow.appendChild(tdHost);
			endpointStatCells(hostRow, {
				Count: group.count,
				Methods: group.methods,
				LastIP: group.ip,
				LastStatus: group.status,
				LastRequestTime: group.last,
			});
			hostRow.addEventListener("click", () => {
				expandedHosts.has(host) ? expandedHosts.delete(host) : expandedHosts.add(host);
				renderEndpoints({});
			});
			tbody.appendChild(hostRow);
			if (!hostExpanded) continue;

			const templates = sortEndpointLevel(
				group.templates.map(([template, info, concretes]) => ({
					template,
					info,
					concretes,
					name: template,
					count: info.Count,
					methods: info.Methods,
					ip: info.LastIP,
					status: info.LastStatus,
					last: info.LastRequestTime,
				})),
			);
			for (const { template, info, concretes } of templates) {
				const sub = template.slice(host.length) || "/";
				const idCount = Number(info.ConcreteCount || 0);
				const hasConcrete = idCount > 0;
				const tmplExpanded = expandedTemplates.has(template) && hasConcrete;
				const tmplRow = document.createElement("tr");
				tmplRow.className = "endpoint-template";
				tmplRow.title = template;
				const chevron = hasConcrete ? (tmplExpanded ? "▾" : "▸") : "";
				const tdName = endpointNameCell(chevron, sub, { depth: 1 });
				tdName.dataset.sortValue = template;
				if (hasConcrete) {
					const c = document.createElement("span");
					c.className = "endpoint-host__count";
					c.textContent = ` (${fmtCount(idCount)} id${idCount === 1 ? "" : "s"})`;
					tdName.appendChild(c);
				}
				// Every endpoint gets an Inspect affordance, whether or not its path
				// happens to contain an ID.
				tdName.appendChild(inspectButton(template));
				tmplRow.appendChild(tdName);
				endpointStatCells(tmplRow, info);
				if (hasConcrete) {
					tmplRow.style.cursor = "pointer";
					tmplRow.addEventListener("click", e => {
						if (e.target.closest("button")) return;
						toggleEndpointTemplate(template);
					});
				}
				tbody.appendChild(tmplRow);
				if (expandedEndpointDetail.has(template)) tbody.appendChild(endpointRequestsRow(template));
				if (!tmplExpanded) continue;
				if (!endpointDetailCache.has(template)) {
					const loading = document.createElement("tr");
					loading.dataset.sortSkip = "1";
					const td = document.createElement("td");
					td.colSpan = 6;
					td.innerHTML = '<div class="text-muted endpoint-headers__meta">Loading paths…</div>';
					loading.appendChild(td);
					tbody.appendChild(loading);
					continue;
				}

				const rows = sortEndpointLevel(
					concretes
						.filter(([p]) => !q || p.toLowerCase().includes(q) || template.toLowerCase().includes(q))
						.map(([path, cinfo]) => ({
							path,
							cinfo,
							name: path,
							count: cinfo.Count,
							methods: cinfo.Methods,
							ip: cinfo.LastIP,
							status: cinfo.LastStatus,
							last: cinfo.LastRequestTime,
						})),
				);
				for (const { path: concretePath, cinfo } of rows) {
					const csub = concretePath.slice(host.length) || "/";
					const hasHeaders = Boolean(cinfo.LastHeaders);
					const cExpanded = expandedConcretes.has(concretePath);
					const cRow = document.createElement("tr");
					cRow.className = "endpoint-concrete";
					cRow.title = concretePath;
					const tdC = endpointNameCell(hasHeaders ? (cExpanded ? "▾" : "▸") : "", csub, { depth: 2, sub: true });
					tdC.dataset.sortValue = concretePath;
					cRow.appendChild(tdC);
					endpointStatCells(cRow, cinfo);
					if (hasHeaders) {
						cRow.style.cursor = "pointer";
						cRow.addEventListener("click", () => {
							expandedConcretes.has(concretePath)
								? expandedConcretes.delete(concretePath)
								: expandedConcretes.add(concretePath);
							renderEndpoints({});
						});
					}
					tbody.appendChild(cRow);
					if (hasHeaders && cExpanded) {
						let headersText = cinfo.LastHeaders;
						try {
							headersText = JSON.stringify(JSON.parse(cinfo.LastHeaders), null, 2);
						} catch {}
						const detail = document.createElement("tr");
						detail.dataset.sortSkip = "1";
						detail.className = "endpoint-headers";
						const td = document.createElement("td");
						td.colSpan = 6;
						td.innerHTML =
							`<div class="endpoint-headers__meta">Last request from IP <strong>${escapeHtml(cinfo.LastIP || "—")}</strong>` +
							(cinfo.LastCallerId ? ` (place <strong>${escapeHtml(cinfo.LastCallerId)}</strong>)` : "") +
							" • last sent headers:</div>" +
							`<pre class="endpoint-headers__pre">${escapeHtml(headersText || "(none)")}</pre>` +
							(cinfo.LastBody
								? `<div class="endpoint-headers__meta">Last body:</div><pre class="endpoint-headers__pre">${escapeHtml(cinfo.LastBody)}</pre>`
								: "");
						detail.appendChild(td);
						tbody.appendChild(detail);
					}
				}
			}
		}
	}

	function renderStatusDetailed(d) {
		const tbody = $("#statusDetailedTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const entries = Object.entries(d.StatusCodesDetailed || {});
		entries.sort((a, b) => Number(a[0]) - Number(b[0]));
		const max = Math.max(1, ...entries.map(([, n]) => Number(n) || 0));
		for (const [code, count] of entries) {
			// A small inline bar makes the distribution scannable at a glance.
			const wrap = document.createElement("div");
			wrap.className = "minibar";
			const fill = document.createElement("div");
			const klass = code.startsWith("2") ? "ok" : code.startsWith("4") || code.startsWith("5") ? "bad" : "mid";
			fill.className = `minibar__fill minibar__fill--${klass}`;
			fill.style.width = `${Math.max(2, (Number(count) / max) * 100)}%`;
			wrap.appendChild(fill);
			const label = document.createElement("span");
			label.className = "minibar__label";
			label.textContent = String(count);
			wrap.appendChild(label);
			tbody.appendChild(tr([code, wrap]));
		}
	}

	function renderRetries(d) {
		const rc = d.RetryCounts || {};
		setText("retryTotal", `${rc.Total || 0} total`);

		const byStatus = $("#retryStatusTable tbody");
		if (byStatus) {
			byStatus.innerHTML = "";
			for (const [code, n] of Object.entries(rc.ByStatusCode || {})) {
				byStatus.appendChild(tr([code, String(n)]));
			}
		}
		const byReason = $("#retryReasonTable tbody");
		if (byReason) {
			byReason.innerHTML = "";
			for (const [reason, n] of Object.entries(rc.Reasons || {})) {
				byReason.appendChild(tr([reason, String(n)]));
			}
		}
		const reasons = d.ReasonCounts || {};
		setText("reason_custom", String(reasons.Custom || 0));
		setText("reason_roblox", String(reasons.Roblox || 0));
	}

	function renderExploitSummary(d) {
		const tbody = $("#exploitSummaryTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const entries = Object.entries(d.ExploitSummary || {});
		entries.sort((a, b) => (b[1].Count || 0) - (a[1].Count || 0));
		for (const [reason, info] of entries) {
			tbody.appendChild(tr([reason, String(info.Count || 0), tsNode(info.LastSeen)]));
		}
		if (entries.length === 0) {
			tbody.appendChild(tr(["Nothing recorded (or cleared)", "—", "—"]));
		}
	}

	function renderErrors(d) {
		const tbody = $("#errorsTable tbody");
		if (!tbody) return;
		if (d.Errors) renderErrors._last = d.Errors;
		const all = Object.entries(renderErrors._last || {});
		all.sort((a, b) => (b[1].Count || 0) - (a[1].Count || 0));
		setText("errorsTotal", `${all.length} distinct`);
		const q = ($("#errorsFilter")?.value || "").trim().toLowerCase();
		// Keep expanded detail rows expanded across refreshes.
		const open = new Set($$("#errorsTable tr.error-detail-open").map(r => r.dataset.sig));
		tbody.innerHTML = "";
		const shown = all.filter(([sig, info]) => !q || `${sig} ${info.LastDetail || ""}`.toLowerCase().includes(q));
		if (shown.length === 0) {
			tbody.appendChild(tr([q ? "No errors match the filter" : "No errors recorded 🎉", "—", "—", "—", "—"]));
			return;
		}
		for (const [sig, info] of shown) {
			// Whose fault it was. "Is this mine to fix?" is the first question asked
			// of an error log and the signature alone never answered it.
			const source = document.createElement("span");
			const kind = info.Source || "Roxy";
			source.className = `badge badge--${kind === "Roblox" ? "warn" : kind === "Internal" ? "muted" : "bad"}`;
			source.textContent = kind;
			source.dataset.sortValue = kind;
			const row = tr([sig, source, String(info.Count || 0), tsNode(info.FirstSeen), tsNode(info.LastSeen)]);
			row.className = "error-row";
			row.style.cursor = "pointer";
			row.dataset.sig = sig;
			const detail = document.createElement("tr");
			detail.dataset.sortSkip = "1";
			detail.className = "error-detail";
			detail.dataset.sig = sig;
			const td = document.createElement("td");
			td.colSpan = 5;
			const pre = document.createElement("pre");
			pre.className = "error-detail__pre";
			pre.textContent = info.LastDetail || "(no detail)";
			td.appendChild(pre);
			detail.appendChild(td);
			const isOpen = open.has(sig);
			detail.style.display = isOpen ? "" : "none";
			if (isOpen) row.classList.add("error-detail-open");
			row.addEventListener("click", () => {
				const showing = detail.style.display !== "none";
				detail.style.display = showing ? "none" : "";
				row.classList.toggle("error-detail-open", !showing);
			});
			tbody.appendChild(row);
			tbody.appendChild(detail);
		}
	}

	const expandedUa = new Set(); // which UA rows are expanded to show last headers
	// User-agent frequency table. Rows with a captured last request expand to show
	// the last headers + endpoint that UA sent (handy for the mysterious "(none)" UA).
	const uaDetailCache = new Map(); // uaKey -> the fetched last-request detail

	function renderUaTable(tbodySel, totalId, data, filterSel, keyPrefix = "") {
		const tbody = $(tbodySel);
		if (!tbody) return;
		const blocked = keyPrefix === "b:";
		const entries = Object.entries(data || {});
		entries.sort((a, b) => (b[1].Count || 0) - (a[1].Count || 0));
		setText(totalId, `${fmtCount(entries.length)} distinct`);
		const q = ($(filterSel)?.value || "").trim().toLowerCase();
		tbody.innerHTML = "";
		let shown = 0;
		for (const [key, info] of entries) {
			if (q && !key.toLowerCase().includes(q)) continue;
			shown++;
			const hasDetail = Boolean(info.HasDetail);
			const uaKey = keyPrefix + key;
			const expanded = expandedUa.has(uaKey);
			const tdName = document.createElement("td");
			if (hasDetail) {
				const chev = document.createElement("span");
				chev.className = "endpoint-host__chevron";
				chev.textContent = expanded ? "▾ " : "▸ ";
				tdName.appendChild(chev);
			}
			tdName.appendChild(document.createTextNode(key));
			const row = document.createElement("tr");
			row.appendChild(tdName);
			for (const cell of [fmtCount(info.Count), tsNode(info.LastSeen)]) {
				const td = document.createElement("td");
				if (cell instanceof Node) td.appendChild(cell);
				else td.textContent = cell;
				row.appendChild(td);
			}
			tbody.appendChild(row);
			if (!hasDetail) continue;

			row.style.cursor = "pointer";
			row.addEventListener("click", () => toggleUaDetail(blocked, key, uaKey));
			// The captured headers are a per-record blob, so they are fetched on
			// expand rather than shipped with every dashboard poll.
			if (expanded) tbody.appendChild(uaDetailRow(uaKey));
		}
		if (shown === 0) {
			tbody.appendChild(tr([q ? "No user-agents match the filter" : "No user-agents recorded yet", "—", "—"]));
		}
	}

	function uaDetailRow(uaKey) {
		const detail = document.createElement("tr");
		detail.dataset.sortSkip = "1";
		const td = document.createElement("td");
		td.colSpan = 3;
		const info = uaDetailCache.get(uaKey);
		if (!info) {
			td.innerHTML = '<div class="text-muted">Loading last request…</div>';
		} else {
			let headersText = info.LastHeaders;
			try {
				headersText = JSON.stringify(JSON.parse(info.LastHeaders), null, 2);
			} catch {}
			td.innerHTML =
				`<div class="endpoint-headers__meta">Last seen at <strong>${escapeHtml(info.LastPath || "—")}</strong> from IP <strong>${escapeHtml(info.LastIP || "—")}</strong> • last sent headers:</div>` +
				`<pre class="endpoint-headers__pre">${escapeHtml(headersText || "(none)")}</pre>`;
		}
		detail.appendChild(td);
		return detail;
	}

	async function toggleUaDetail(blocked, userAgent, uaKey) {
		if (expandedUa.has(uaKey)) {
			expandedUa.delete(uaKey);
			renderFingerprints({});
			return;
		}
		expandedUa.add(uaKey);
		renderFingerprints({});
		try {
			const res = await api(
				`/admin/fingerprints/user_agent?ua=${encodeURIComponent(userAgent)}&blocked=${blocked ? 1 : 0}`,
			);
			if (!res.ok) throw new Error(String(res.status));
			uaDetailCache.set(uaKey, await res.json());
		} catch {
			uaDetailCache.set(uaKey, { LastHeaders: "", LastPath: "", LastIP: "" });
			showToast("Could not load the last request for that user-agent");
		}
		renderFingerprints({});
	}

	const expandedFp = new Set(); // which header rows are expanded to show their values
	const fpValueCache = new Map(); // fpKey -> the fetched value breakdown

	// How many values to render inside an expanded header row. The server caps
	// how many it will send; this caps how many we will paint. Building a table
	// of thousands of rows in one innerHTML assignment locks up the tab, and
	// nobody reads past the first screenful anyway.
	const FP_VALUES_SHOWN = 50;

	// Header-name table. Values are fetched only when a row is expanded, so the
	// frequent dashboard poll never carries them.
	function renderHeaderNameTable(tbodySel, totalId, data, filterSel, blocked) {
		const tbody = $(tbodySel);
		if (!tbody) return;
		const entries = Object.entries(data || {});
		entries.sort((a, b) => (b[1].Count || 0) - (a[1].Count || 0));
		setText(totalId, `${fmtCount(entries.length)} distinct`);
		const q = ($(filterSel)?.value || "").trim().toLowerCase();
		tbody.innerHTML = "";
		let shown = 0;
		for (const [name, info] of entries) {
			if (q && !name.toLowerCase().includes(q)) continue;
			shown++;
			const ignored = Boolean(info.ValuesIgnored) || isIgnoredHeader(name);
			const valCount = Number(info.ValueCount || 0);
			const canExpand = !ignored && valCount > 0;
			const fpKey = (blocked ? "b:" : "l:") + name;
			const expanded = expandedFp.has(fpKey);

			const row = document.createElement("tr");
			row.className = "fp-row";

			const tdName = document.createElement("td");
			if (canExpand) tdName.style.cursor = "pointer";
			const chev = document.createElement("span");
			chev.className = "endpoint-host__chevron";
			chev.textContent = canExpand ? (expanded ? "▾" : "▸") : "";
			const nm = document.createElement("strong");
			nm.textContent = ` ${name} `;
			tdName.append(chev, nm);

			if (ignored) {
				// The header is recorded, its values deliberately are not.
				const badge = document.createElement("span");
				badge.className = "badge badge--muted";
				badge.textContent = "values not recorded";
				badge.title =
					"This header carries a different value on nearly every request, so the list of values " +
					"is unbounded and tells you nothing. Its request count is still tracked.";
				tdName.append(" ", badge);
			} else {
				const cnt = document.createElement("span");
				cnt.className = "endpoint-host__count";
				cnt.textContent = valCount ? `(${fmtCount(valCount)} value${valCount === 1 ? "" : "s"})` : "";
				tdName.append(cnt);
				// Unique-per-request is the signature of a header that will fill
				// the data file. Surface it before it becomes a problem.
				const ratio = Number(info.UniqueRatio || 0);
				if (ratio >= 0.9 && Number(info.Count || 0) >= 100) {
					const warn = document.createElement("span");
					warn.className = "badge badge--warn";
					warn.textContent = "high cardinality";
					warn.title = `${Math.round(ratio * 100)}% of requests carried a different value — consider "Ignore values".`;
					tdName.append(" ", warn);
				}
			}
			if (canExpand) {
				tdName.addEventListener("click", () => toggleHeaderValues(blocked, name, fpKey));
			}
			row.appendChild(tdName);

			const tdC = document.createElement("td");
			tdC.textContent = fmtCount(info.Count);
			row.appendChild(tdC);

			const tdL = document.createElement("td");
			tdL.appendChild(tsNode(info.LastSeen));
			row.appendChild(tdL);

			const tdAct = document.createElement("td");
			tdAct.className = "fp-actions";
			// Three distinct things an admin might mean by "clear", spelled out
			// instead of collapsed into one ambiguous button.
			if (!ignored) {
				tdAct.appendChild(
					fpButton("Ignore values", `Stop recording distinct values for "${name}" (keeps its count)`, () =>
						setHeaderIgnored(blocked, name, true),
					),
				);
				tdAct.appendChild(
					fpButton("Clear values", `Drop the recorded values for "${name}", keep the header`, () =>
						clearFingerprintHeader(blocked, name, true),
					),
				);
			} else {
				tdAct.appendChild(
					fpButton("Record values", `Start recording distinct values for "${name}" again`, () =>
						setHeaderIgnored(blocked, name, false),
					),
				);
			}
			tdAct.appendChild(
				fpButton("Remove", `Remove "${name}" from the table entirely`, () =>
					clearFingerprintHeader(blocked, name, false),
				),
			);
			row.appendChild(tdAct);
			tbody.appendChild(row);

			if (expanded) tbody.appendChild(headerValuesRow(fpKey, name));
		}
		if (shown === 0) {
			tbody.appendChild(tr([q ? "No header names match the filter" : "No header names recorded yet", "—", "—", ""]));
		}
	}

	function fpButton(label, title, onClick) {
		const btn = document.createElement("button");
		btn.className = "btn btn--outline btn--sm";
		btn.textContent = label;
		btn.title = title;
		btn.addEventListener("click", e => {
			e.stopPropagation();
			onClick();
		});
		return btn;
	}

	// The expanded value breakdown for one header, rendered from the cache the
	// lazy fetch fills in.
	function headerValuesRow(fpKey, name) {
		const detail = document.createElement("tr");
		detail.dataset.sortSkip = "1";
		detail.className = "fp-values";
		const td = document.createElement("td");
		td.colSpan = 4;
		const payload = fpValueCache.get(fpKey);
		if (!payload) {
			td.innerHTML = '<div class="text-muted">Loading values…</div>';
			detail.appendChild(td);
			return detail;
		}
		const entries = Object.entries(payload.Values || {}).slice(0, FP_VALUES_SHOWN);
		if (entries.length === 0) {
			td.innerHTML = '<div class="text-muted">No values recorded for this header.</div>';
			detail.appendChild(td);
			return detail;
		}
		let html = "";
		if (payload.Total > entries.length) {
			html +=
				`<div class="fp-values__meta">Showing the ${entries.length} most frequent of ` +
				`${fmtCount(payload.Total)} recorded values.</div>`;
		}
		html += '<table class="fp-values__table">';
		for (const [val, vinfo] of entries) {
			html +=
				`<tr><td class="fp-values__val">${escapeHtml(val)}</td>` +
				`<td>${fmtCount(vinfo.Count)}×</td>` +
				`<td>${escapeHtml(timeAgo(vinfo.LastSeen))}</td></tr>`;
		}
		html += "</table>";
		td.innerHTML = html;
		detail.appendChild(td);
		return detail;
	}

	async function toggleHeaderValues(blocked, name, fpKey) {
		if (expandedFp.has(fpKey)) {
			expandedFp.delete(fpKey);
			renderFingerprints({});
			return;
		}
		expandedFp.add(fpKey);
		renderFingerprints({}); // Paint the "Loading values…" placeholder immediately.
		try {
			const query = `name=${encodeURIComponent(name)}&blocked=${blocked ? 1 : 0}&limit=${FP_VALUES_SHOWN * 4}`;
			const res = await api(`/admin/fingerprints/values?${query}`);
			if (!res.ok) throw new Error(String(res.status));
			fpValueCache.set(fpKey, await res.json());
		} catch {
			fpValueCache.set(fpKey, { Values: {}, Total: 0 });
			showToast("Could not load values for that header");
		}
		renderFingerprints({});
	}

	function isIgnoredHeader(name) {
		return Object.prototype.hasOwnProperty.call(ignoredValueHeaders, String(name).toLowerCase());
	}

	async function setHeaderIgnored(blocked, name, ignore) {
		try {
			const res = await api("/admin/fingerprints/ignore", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name, ignore, blocked }),
			});
			const data = await res.json().catch(() => ({}));
			if (!res.ok) throw new Error(String(res.status));
			ignoredValueHeaders = data.IgnoredValueHeaders || ignoredValueHeaders;
			fpValueCache.delete((blocked ? "b:" : "l:") + name);
			showToast(data.Message || "Updated");
			await refreshAll(true);
		} catch {
			showToast("Could not change value recording for that header");
		}
	}

	async function clearFingerprintHeader(blocked, name, valuesOnly) {
		try {
			const res = await api("/admin/fingerprints/clear_header", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ blocked, name, values_only: Boolean(valuesOnly) }),
			});
			const data = await res.json().catch(() => ({}));
			if (!res.ok) throw new Error(String(res.status));
			const fpKey = (blocked ? "b:" : "l:") + name;
			fpValueCache.delete(fpKey);
			if (!valuesOnly) expandedFp.delete(fpKey);
			showToast(data.Message || `Cleared "${name}"`, 3200);
			await refreshAll(true);
		} catch {
			showToast("Failed to clear header");
		}
	}

	// The admin-managed list of headers whose values we deliberately don't record.
	let ignoredValueHeaders = {};

	function renderIgnoredHeaders(d) {
		if (d.IgnoredValueHeaders) ignoredValueHeaders = d.IgnoredValueHeaders;
		const tbody = $("#ignoredHeadersTable tbody");
		if (!tbody) return;
		const entries = Object.entries(ignoredValueHeaders).sort((a, b) => a[0].localeCompare(b[0]));
		setText("ignoredHeadersTotal", `${fmtCount(entries.length)} header${entries.length === 1 ? "" : "s"}`);
		tbody.innerHTML = "";
		if (entries.length === 0) {
			tbody.appendChild(tr(["Every header's values are being recorded.", "—", "—", ""]));
			return;
		}
		for (const [name, info] of entries) {
			const row = document.createElement("tr");
			const tdName = document.createElement("td");
			const strong = document.createElement("strong");
			strong.textContent = name;
			tdName.appendChild(strong);
			row.appendChild(tdName);

			const tdWhy = document.createElement("td");
			tdWhy.textContent = info.Auto ? "Detected automatically" : info.Note === "default" ? "Default" : "Added by you";
			row.appendChild(tdWhy);

			const tdNote = document.createElement("td");
			tdNote.className = "text-muted";
			tdNote.textContent = info.Note && info.Note !== "default" ? info.Note : "—";
			row.appendChild(tdNote);

			const tdAct = document.createElement("td");
			tdAct.appendChild(
				fpButton("Record again", `Start recording distinct values for "${name}"`, () =>
					setHeaderIgnored(false, name, false),
				),
			);
			row.appendChild(tdAct);
			tbody.appendChild(row);
		}
	}

	function renderFingerprints(d) {
		if (d.HeaderNames) renderFingerprints._hn = d.HeaderNames;
		if (d.UserAgents) renderFingerprints._ua = d.UserAgents;
		if (d.BlockedHeaderNames) renderFingerprints._bhn = d.BlockedHeaderNames;
		if (d.BlockedUserAgents) renderFingerprints._bua = d.BlockedUserAgents;
		renderHeaderNameTable("#headerNamesTable tbody", "headerNamesTotal", renderFingerprints._hn || {}, "#headerNamesFilter", false);
		renderUaTable("#userAgentsTable tbody", "userAgentsTotal", renderFingerprints._ua || {}, "#userAgentsFilter", "l:");
		renderHeaderNameTable("#blockedHeaderNamesTable tbody", "blockedHeaderNamesTotal", renderFingerprints._bhn || {}, "#blockedHeaderNamesFilter", true);
		renderUaTable("#blockedUserAgentsTable tbody", "blockedUserAgentsTotal", renderFingerprints._bua || {}, "#blockedUserAgentsFilter", "b:");
	}

	// -----------------------------
	// Live request feed
	// -----------------------------
	// Every proxied request, served or refused, newest first. The feed carries
	// metadata only; the actual request/response bytes are fetched per card from
	// the capture store when a card is opened — see capture.py for why they are
	// not carried in the poll payload.
	const OUTCOME_LABELS = {
		served: "Served",
		upstream_failed: "Upstream failed",
		throttled: "Throttled (per-IP)",
		throttle_all: "Throttled (global)",
		blocked_endpoint: "Blocked endpoint",
		endpoint_rule: "Endpoint rate rule",
		header_rule: "Request filter",
		auth_attempt: "Auth attempt rejected",
		probe: "Probe rejected",
		paused: "Paused",
		ignored_path: "Ignored path",
	};
	// Only "served" is genuinely good; everything else is either us refusing or
	// Roblox failing, and the feed says which at a glance.
	const outcomeClass = outcome => (outcome === "served" ? "ok" : outcome === "upstream_failed" ? "bad" : "warn");

	let liveItems = []; // cached for filtering without refetch
	const liveBodyCache = new Map(); // capture id -> fetched payload (or an error marker)
	const liveKey = item => item.Id || `${item.Date}|${item.IP}|${item.URL}`;

	function prettyJson(text) {
		if (!text) return "";
		try {
			return JSON.stringify(JSON.parse(text), null, 2);
		} catch {
			return text; // Not JSON (an HTML error page, a plain string) — show it as-is.
		}
	}

	function liveMatches(item, q, outcome) {
		if (outcome && (item.Outcome || "") !== outcome) return false;
		if (!q) return true;
		const hay = `${item.URL || ""} ${item.IP || ""} ${item.Method || ""} ${item.CallerId || ""} ${
			item.UserAgent || ""
		} ${item.StatusCode || ""} ${item.Outcome || ""} ${item.Query || ""} ${item.Body || ""}`;
		return hay.toLowerCase().includes(q);
	}

	function renderLiveFeed(d) {
		if (Array.isArray(d.LiveRequests)) liveItems = d.LiveRequests;
		const feed = $("#liveFeed");
		if (!feed) return;
		const q = ($("#liveFilter")?.value || "").trim().toLowerCase();
		const outcome = $("#liveOutcomeFilter")?.value || "";
		const items = liveItems.filter(it => liveMatches(it, q, outcome));
		const refused = items.filter(it => it.Outcome && it.Outcome !== "served").length;
		setText("liveCount", `${items.length} shown${refused ? ` • ${refused} refused` : ""}`);
		// Keep expanded cards expanded across refreshes.
		const openKeys = new Set(
			$$("#liveFeed details[open]")
				.map(el => el.dataset.key)
				.filter(Boolean),
		);
		feed.innerHTML = "";
		if (items.length === 0) {
			const empty = document.createElement("p");
			empty.className = "text-muted";
			empty.textContent = q || outcome ? "No requests match the filter." : "No requests recorded yet.";
			feed.appendChild(empty);
			return;
		}
		for (const item of items) feed.appendChild(liveCard(item, openKeys));
	}

	function liveCard(item, openKeys) {
		const card = document.createElement("details");
		card.className = "live-item";
		card.dataset.key = liveKey(item);
		const isOpen = openKeys.has(card.dataset.key);
		if (isOpen) card.open = true;
		const code = Number(item.StatusCode || 0);
		const codeClass = code >= 200 && code < 300 ? "ok" : code >= 500 ? "bad" : "warn";
		const upstream = item.UpstreamStatus;
		const oc = item.Outcome || "";

		const summary = document.createElement("summary");
		summary.className = "live-item__summary";
		summary.innerHTML =
			`<span class="badge badge--method">${escapeHtml(item.Method || "?")}</span>` +
			`<span class="badge badge--${codeClass}">${code || "?"}</span>` +
			// Roblox's own answer next to ours. When they differ — an upstream 404
			// relayed as a 500, a 200 we refused before sending — that difference is
			// the single most useful thing on the card.
			(upstream && String(upstream) !== String(code)
				? `<span class="badge badge--muted" title="What Roblox actually returned">↑${escapeHtml(
						String(upstream),
					)}</span>`
				: "") +
			(oc && oc !== "served"
				? `<span class="badge badge--${outcomeClass(oc)}">${escapeHtml(OUTCOME_LABELS[oc] || oc)}</span>`
				: "") +
			`<span class="live-item__url">${escapeHtml(item.URL || "")}</span>` +
			`<span class="live-item__meta">${escapeHtml(item.IP || "")}${
				item.CallerId ? ` • place ${escapeHtml(item.CallerId)}` : ""
			} • ${escapeHtml(timeAgo(item.Date))}</span>`;
		card.appendChild(summary);

		const body = document.createElement("div");
		body.className = "live-item__body";
		body.appendChild(liveMetaBlock(item));
		const bodies = document.createElement("div");
		bodies.className = "live-item__bodies";
		bodies.innerHTML = '<div class="text-muted">Open to load the request and response bodies…</div>';
		body.appendChild(bodies);
		card.appendChild(body);

		// Bodies are fetched on first open, not on render: a feed of 50 cards would
		// otherwise pull 50 payloads the admin never looks at.
		const load = () => loadLiveBodies(item, bodies);
		card.addEventListener("toggle", () => {
			if (card.open) load();
		});
		if (isOpen) load();
		return card;
	}

	function liveMetaBlock(item) {
		const wrap = document.createElement("div");
		const rows = [
			["Time", toTS(item.Date)],
			["Outcome", OUTCOME_LABELS[item.Outcome] || item.Outcome || "—"],
			["Refused because", item.Reason || "—"],
			["Answered by", item.Source === "Relay" ? "Roblox (relayed)" : item.Source || "—"],
			["Roblox status", item.UpstreamStatus === "" || item.UpstreamStatus == null ? "—" : item.UpstreamStatus],
			["Upstream method", item.UpstreamMethod || "—"],
			["Upstream error", item.UpstreamError || "—"],
			["Attempts", `${item.Attempts || 0}${item.Retries ? ` (+${item.Retries} retries)` : ""}`],
			["Took", item.Duration ? `${Number(item.Duration).toFixed(3)}s` : "—"],
			["Roblox-Id (place)", item.CallerId || "—"],
			["User-Agent", item.UserAgent || "—"],
			["Query", item.Query || "—"],
		];
		wrap.innerHTML = rows
			.map(([k, v]) => `<div class="live-item__row"><strong>${k}:</strong> ${escapeHtml(String(v))}</div>`)
			.join("");
		if (item.Bypass) {
			wrap.innerHTML += '<div class="live-item__row"><span class="badge badge--muted">Throttle-bypass IP</span></div>';
		}
		const headers = document.createElement("div");
		headers.className = "live-item__row";
		headers.innerHTML = `<strong>Headers:</strong><pre>${escapeHtml(
			JSON.stringify(item.Headers || {}, null, 2),
		)}</pre>`;
		wrap.appendChild(headers);
		return wrap;
	}

	async function loadLiveBodies(item, mount) {
		if (mount.dataset.loaded === "1") return;
		const id = item.CaptureId || "";
		if (!id) {
			mount.dataset.loaded = "1";
			mount.innerHTML =
				`<div class="live-item__row"><strong>Request body:</strong><pre>${escapeHtml(item.Body || "—")}</pre></div>` +
				'<div class="text-muted">Response capture was off for this request (Settings → capture_enabled).</div>';
			return;
		}
		if (!liveBodyCache.has(id)) {
			mount.innerHTML = '<div class="text-muted">Loading bodies…</div>';
			try {
				const res = await api(`/admin/live/detail?id=${encodeURIComponent(id)}`);
				liveBodyCache.set(id, res.ok ? await res.json() : { Expired: true });
			} catch {
				liveBodyCache.set(id, { Expired: true });
			}
		}
		mount.dataset.loaded = "1";
		const payload = liveBodyCache.get(id) || {};
		if (payload.Expired) {
			// Say what to change, not just that it is gone. The capture window is
			// short by design under load, and "expired" on its own reads as broken.
			mount.innerHTML =
				`<div class="live-item__row"><strong>Request body:</strong><pre>${escapeHtml(item.Body || "—")}</pre></div>` +
				'<div class="text-muted">The captured bodies aged out of the capture window (currently ' +
				`<strong>${escapeHtml(lastDiagnostics?.Capture?.WindowSeconds ? fmtDuration(lastDiagnostics.Capture.WindowSeconds) : "—")}` +
				"</strong>). Raise <code>capture_max_records</code> or <code>capture_max_bytes</code> in Settings to keep more.</div>";
			return;
		}
		const note = (text, truncated, length) =>
			truncated ? `<span class="text-muted"> — truncated from ${fmtCount(length)} chars</span>` : "";
		mount.innerHTML =
			`<div class="live-item__row"><strong>Request body:</strong>${note(
				payload.RequestBody,
				payload.RequestBodyTruncated,
				payload.RequestBodyLength,
			)}<pre>${escapeHtml(prettyJson(payload.RequestBody) || "—")}</pre></div>` +
			`<div class="live-item__row"><strong>Response headers:</strong><pre>${escapeHtml(
				JSON.stringify(payload.ResponseHeaders || {}, null, 2),
			)}</pre></div>` +
			`<div class="live-item__row"><strong>Response body:</strong>${note(
				payload.ResponseBody,
				payload.ResponseBodyTruncated,
				payload.ResponseBodyLength,
			)}<pre>${escapeHtml(prettyJson(payload.ResponseBody) || "—")}</pre></div>`;
	}

	function renderCaptureState(d) {
		const cap = d.Capture || {};
		const on = Boolean(cap.Enabled);
		const chip = $("#captureChip");
		if (chip) {
			chip.textContent = on
				? `Capturing • ${fmtCount(cap.Count)}/${fmtCount(cap.MaxRecords)} • ${fmtBytes(cap.Bytes)}`
				: "Capture off";
			chip.className = `chip ${on ? "chip--ok" : "chip--muted"}`;
			chip.title = on
				? `Bodies are kept for up to ${fmtDuration(cap.TTL)} or ${fmtBytes(cap.MaxBytes)}, whichever runs out first.`
				: "Enable capture_enabled in Settings to record request/response bodies.";
		}
		// How far back the capture window actually reaches. Under a flood it
		// collapses to seconds — worth seeing, because it explains why an older
		// card has no bodies rather than leaving it looking broken.
		setText("captureWindow", on ? (cap.WindowSeconds ? fmtDuration(cap.WindowSeconds) : "—") : "off");
	}

	// -----------------------------
	// Who is calling
	// -----------------------------
	// Two tables over the same traffic. Top Talkers is keyed on client IP —
	// precise, but one Roblox experience arrives from hundreds of game-server IPs
	// and scatters across it. Callers is keyed on the Roblox-Id header, which is
	// the place the request came from: self-reported, therefore evidence rather
	// than proof, but the only key that collapses one experience into one row —
	// and the only one worth writing a block rule against.
	const expandedActivity = new Set(); // "kind:key" rows showing their breakdown
	const activityCache = new Map();

	function rateCell(record) {
		// Requests in the last minute, with the 5- and 60-minute figures behind a
		// tooltip. The instantaneous rate is what an incident is judged on; the
		// lifetime Count is what it is judged against.
		const per1 = Number(record.Rate1 || 0);
		const span = document.createElement("span");
		span.textContent = per1 ? `${fmtCount(per1)}/min` : "—";
		if (per1 >= 60) span.className = "text-bad";
		else if (per1 >= 10) span.className = "text-warn";
		span.title = `Last minute: ${fmtCount(per1)} • last 5 min: ${fmtCount(record.Rate5)} • last hour: ${fmtCount(
			record.Rate60,
		)}`;
		span.dataset.sortValue = String(per1);
		return span;
	}

	function refusedCell(record) {
		const total = Number(record.Count || 0);
		const refused = Number(record.Refused || 0);
		const pct = total ? Math.round((refused / total) * 100) : 0;
		const span = document.createElement("span");
		span.textContent = refused ? `${fmtCount(refused)} (${pct}%)` : "0";
		if (pct >= 90 && refused) span.className = "text-bad";
		else if (pct >= 25) span.className = "text-warn";
		span.dataset.sortValue = String(refused);
		return span;
	}

	function activityActions(kind, key, record) {
		const wrap = document.createElement("div");
		wrap.className = "row-actions";
		if (kind === "caller") {
			// The two things worth doing with an identified caller: find out whose
			// experience it is, and stop it. Both one click from the row that
			// prompted the question.
			wrap.appendChild(
				fpButton("Identify", "Look up the experience and owner behind this place ID", () => runLookup(key)),
			);
			wrap.appendChild(
				fpButton("Block", "Add a request filter blocking this Roblox-Id header", () => blockCaller(key)),
			);
		} else {
			wrap.appendChild(fpButton("Bypass", "Add this IP to the throttle-bypass allowlist", () => addBypass(key)));
		}
		wrap.appendChild(
			fpButton("Filter feed", "Show this caller's requests in the live feed", () => filterLiveBy(key)),
		);
		return wrap;
	}

	function renderActivityTable(tableSel, totalId, data, kind, filterSel) {
		const tbody = $(`${tableSel} tbody`);
		if (!tbody) return;
		const entries = Object.entries(data || {});
		setText(totalId, `${fmtCount(entries.length)} ${kind === "caller" ? "places" : "IPs"}`);
		const q = ($(filterSel)?.value || "").trim().toLowerCase();
		tbody.innerHTML = "";
		const shown = entries.filter(([key, info]) => !q || `${key} ${info.TopEndpoint || ""}`.toLowerCase().includes(q));
		if (!shown.length) {
			tbody.appendChild(tr([q ? "No matches." : "No traffic recorded yet.", "", "", "", "", "", ""]));
			return;
		}
		for (const [key, info] of shown) {
			const rowKey = `${kind}:${key}`;
			const expanded = expandedActivity.has(rowKey);
			const name = document.createElement("span");
			name.className = "mono";
			name.textContent = key;
			const chev = document.createElement("span");
			chev.className = "chev";
			chev.textContent = expanded ? "▾" : "▸";
			const nameCell = document.createElement("span");
			nameCell.append(chev, name);
			nameCell.dataset.sortValue = key;

			const row = tr([
				nameCell,
				fmtCount(info.Count),
				rateCell(info),
				refusedCell(info),
				sortable(info.TopEndpoint || "—", info.TopEndpoint || ""),
				fmtCount(info.PeerCount),
				tsNode(info.LastSeen),
				activityActions(kind, key, info),
			]);
			row.style.cursor = "pointer";
			row.addEventListener("click", e => {
				if (e.target.closest("button")) return;
				if (expandedActivity.has(rowKey)) expandedActivity.delete(rowKey);
				else expandedActivity.add(rowKey);
				loadActivityDetail(kind, key);
			});
			tbody.appendChild(row);
			if (expanded) tbody.appendChild(activityDetailRow(kind, key));
		}
	}

	function activityDetailRow(kind, key) {
		const row = document.createElement("tr");
		row.dataset.sortSkip = "1";
		const td = document.createElement("td");
		td.colSpan = 8;
		const info = activityCache.get(`${kind}:${key}`);
		if (!info) {
			td.innerHTML = '<div class="text-muted">Loading…</div>';
		} else {
			const list = (title, map, mono) => {
				const items = Object.entries(map || {});
				if (!items.length) return "";
				return (
					`<div class="detail-block"><div class="detail-block__title">${title}</div><ul class="detail-list">` +
					items
						.map(
							([k, n]) =>
								`<li><span class="${mono ? "mono" : ""}">${escapeHtml(k)}</span><span>${fmtCount(n)}</span></li>`,
						)
						.join("") +
					"</ul></div>"
				);
			};
			td.innerHTML =
				'<div class="detail-grid">' +
				list("Endpoints", info.Endpoints, true) +
				list("Status codes", info.Statuses) +
				list("Outcomes", info.Outcomes) +
				list("Methods", info.Methods) +
				list(kind === "ip" ? "Places (Roblox-Id)" : "Source IPs", info.Peers, true) +
				"</div>" +
				`<div class="text-muted">Last user-agent: ${escapeHtml(info.UserAgent || "—")}</div>`;
		}
		row.appendChild(td);
		return row;
	}

	async function loadActivityDetail(kind, key) {
		const cacheKey = `${kind}:${key}`;
		if (!expandedActivity.has(cacheKey)) {
			if (lastDiagnostics) renderActivity(lastDiagnostics);
			return;
		}
		try {
			const res = await api(`/admin/activity/detail?kind=${kind}&key=${encodeURIComponent(key)}`);
			if (res.ok) activityCache.set(cacheKey, await res.json());
		} catch {
			/* leave it showing "Loading…" rather than blanking the row */
		}
		if (lastDiagnostics) renderActivity(lastDiagnostics);
	}

	function renderActivity(d) {
		if (d.IpActivity) renderActivity._ips = d.IpActivity;
		if (d.Callers) renderActivity._callers = d.Callers;
		renderActivityTable("#talkersTable", "talkersTotal", renderActivity._ips || {}, "ip", "#talkersFilter");
		renderActivityTable("#callersTable", "callersTotal", renderActivity._callers || {}, "caller", "#callersFilter");
		sortTable("#talkersTable");
		sortTable("#callersTable");
		renderThrottleWatch(d);
	}

	// While throttle-all is on, this is the "who is knocking, for what, how often"
	// panel — the same activity data narrowed to the callers being turned away, so
	// a global throttle can be judged and lifted rather than left on out of caution.
	function renderThrottleWatch(d) {
		const panel = $("#throttleWatch");
		if (!panel) return;
		const on = Boolean(d?.ThrottleAll?.ThrottleAll);
		panel.hidden = !on;
		if (!on) return;
		const tbody = $("#throttleWatchTable tbody");
		if (!tbody) return;
		const rows = Object.entries(renderActivity._ips || {})
			.filter(([, info]) => Number(info.Refused || 0) > 0)
			.sort((a, b) => Number(b[1].Refused || 0) - Number(a[1].Refused || 0))
			.slice(0, 25);
		setText("throttleWatchTotal", `${rows.length} IP(s) being refused`);
		setText("throttleWatchDrops", fmtCount(d.ThrottleAllDrops || 0));
		tbody.innerHTML = "";
		if (!rows.length) {
			tbody.appendChild(tr(["Nothing has been refused since throttle-all was enabled.", "", "", "", ""]));
			return;
		}
		for (const [ip, info] of rows) {
			const row = tr([
				sortable(ip, ip),
				fmtCount(info.Count),
				refusedCell(info),
				rateCell(info),
				sortable(info.TopEndpoint || "—", info.TopEndpoint || ""),
				tsNode(info.LastSeen),
			]);
			row.children[0].className = "mono";
			tbody.appendChild(row);
		}
		sortTable("#throttleWatchTable");
	}

	// -----------------------------
	// Why are we returning this?
	// -----------------------------
	const SOURCE_LABELS = {
		Roblox: "Roblox → us",
		Relay: "Roblox → caller (relayed)",
		Roxy: "Roxy (our own refusals)",
		Internal: "Our own probes",
	};
	const SOURCE_HINTS = {
		Roblox: "What Roblox actually answered our upstream calls with. 429s here mean WE are being rate-limited.",
		Relay: "Statuses we passed back to callers that came from Roblox.",
		Roxy: "Statuses we generated ourselves: throttles, blocks, filters, pause, our own errors.",
		Internal: "Statuses from Roxy's own calls (token validation, rotation probe) — not user traffic.",
	};

	function renderStatusSources(d) {
		const sources = d.StatusSources || {};
		const tbody = $("#statusSourceTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const rows = [];
		for (const [source, codes] of Object.entries(sources)) {
			for (const [code, count] of Object.entries(codes || {})) {
				rows.push({ source, code, count: Number(count || 0) });
			}
		}
		// The headline the whole split exists for: are the 429s ours or theirs?
		const total = (src, pred) =>
			rows.filter(r => r.source === src && pred(r.code)).reduce((acc, r) => acc + r.count, 0);
		const robloxLimited = total("Roblox", c => c === "429");
		const weLimited = total("Roxy", c => c === "429");
		setText("src_roblox_429", fmtCount(robloxLimited));
		setText("src_roxy_429", fmtCount(weLimited));
		setText("src_roblox_5xx", fmtCount(total("Roblox", c => c.startsWith("5"))));
		setText("src_roxy_5xx", fmtCount(total("Roxy", c => c.startsWith("5"))));
		const verdict = $("#statusSourceVerdict");
		if (verdict) {
			if (robloxLimited > 0) {
				verdict.textContent =
					`Roblox has rate-limited us ${fmtCount(robloxLimited)} time(s). This is the one to act on — ` +
					"reduce upstream volume or the account behind the token is at risk.";
				verdict.className = "callout callout--bad";
			} else if (weLimited > 0) {
				verdict.textContent =
					`All ${fmtCount(weLimited)} of the 429s are ours — Roxy turning callers away, not Roblox ` +
					"turning us away. Nothing to do upstream.";
				verdict.className = "callout callout--ok";
			} else {
				verdict.textContent = "No rate limiting recorded from either side.";
				verdict.className = "callout callout--muted";
			}
		}
		if (!rows.length) {
			tbody.appendChild(tr(["No status codes recorded yet.", "", "", ""]));
			return;
		}
		for (const row of rows) {
			const src = document.createElement("span");
			src.textContent = SOURCE_LABELS[row.source] || row.source;
			src.title = SOURCE_HINTS[row.source] || "";
			src.dataset.sortValue = row.source;
			const code = document.createElement("span");
			code.className = `badge badge--${
				row.code.startsWith("2") ? "ok" : row.code.startsWith("4") ? "warn" : "bad"
			}`;
			code.textContent = row.code;
			tbody.appendChild(tr([src, sortable(code, row.code), fmtCount(row.count)]));
		}
		sortTable("#statusSourceTable");
	}

	function renderRefusals(d) {
		const tbody = $("#refusalsTable tbody");
		if (!tbody) return;
		const entries = Object.entries(d.Refusals || {});
		setText("refusalsTotal", `${fmtCount(entries.length)} reason(s)`);
		tbody.innerHTML = "";
		if (!entries.length) {
			tbody.appendChild(tr(["Roxy has not refused anything yet.", "", "", "", "", ""]));
			return;
		}
		for (const [reason, info] of entries) {
			const ips = info.IPs ? Object.keys(info.IPs).length : 0;
			const row = tr([
				sortable(reason, reason),
				fmtCount(info.Count),
				sortable(String(info.Status || "—"), Number(info.Status) || 0),
				sortable(info.LastPath || "—", info.LastPath || ""),
				sortable(info.LastIP || "—", info.LastIP || ""),
				fmtCount(ips),
				tsNode(info.LastSeen),
			]);
			row.children[3].className = "mono";
			row.children[4].className = "mono";
			tbody.appendChild(row);
		}
		sortTable("#refusalsTable");
	}

	function renderInternalRequests(d) {
		const tbody = $("#internalTable tbody");
		if (!tbody) return;
		const stats = d.InternalRequests || {};
		const known = d.InternalEndpoints || [];
		tbody.innerHTML = "";
		const byPurpose = new Map(known.map(e => [e.Purpose, e]));
		for (const key of Object.keys(stats)) if (!byPurpose.has(key)) byPurpose.set(key, { Purpose: key, URL: "", What: "" });
		for (const [purpose, meta] of byPurpose) {
			const info = stats[purpose] || {};
			const count = Number(info.Count || 0);
			const failed = Number(info.Failed || 0);
			const health = document.createElement("span");
			if (!count) {
				health.className = "badge badge--muted";
				health.textContent = "Not called yet";
			} else if (failed && Number(info.LastErrorAt || 0) > Number(info.LastSuccessAt || 0)) {
				health.className = "badge badge--bad";
				health.textContent = "Failing";
			} else {
				health.className = "badge badge--ok";
				health.textContent = "OK";
			}
			const avg = count ? Number(info.TotalTime || 0) / count : 0;
			tbody.appendChild(
				tr([
					sortable(purpose, purpose),
					sortable(meta.URL || info.LastEndpoint || "—", meta.URL || ""),
					sortable(health, count ? (health.textContent === "OK" ? 2 : 1) : 0),
					fmtCount(count),
					fmtCount(failed),
					sortable(avg ? `${avg.toFixed(2)}s` : "—", avg),
					sortable(info.LastError || "—", info.LastError || ""),
					tsNode(info.LastSeen),
				]),
			);
			tbody.children[tbody.children.length - 1].children[1].className = "mono";
		}
		sortTable("#internalTable");
	}

	// -----------------------------
	// Identify a caller
	// -----------------------------
	// Turns a place ID from the Roblox-Id header into a named experience with a
	// named owner. Roblox's Open Cloud v2 could answer more, but only for
	// experiences the API key's owner controls — which excludes every stranger,
	// i.e. everyone you would ever want to look up. These public endpoints work
	// for anyone, and go out through our own proxy so they share its routing.
	async function runLookup(id, kind = "place") {
		const input = $("#lookupId");
		if (input) input.value = id;
		const out = $("#lookupResult");
		if (out) {
			out.hidden = false;
			out.innerHTML = '<div class="text-muted">Looking up…</div>';
		}
		document.getElementById("section-callers")?.scrollIntoView({ behavior: "smooth", block: "start" });
		try {
			const res = await api("/admin/lookup/place", {
				method: "POST",
				body: JSON.stringify({ id: String(id), kind }),
			});
			const data = await res.json().catch(() => ({}));
			if (!out) return;
			if (!res.ok) {
				out.innerHTML = `<div class="callout callout--bad">${escapeHtml(data.Message || "Lookup failed")}</div>`;
				return;
			}
			const created = data.Created ? new Date(data.Created).toLocaleString() : "—";
			// A place created hours ago with a handful of visits is not a game that
			// happens to use the proxy heavily; it is a burner made to point at it.
			const ageMs = data.Created ? Date.now() - new Date(data.Created).getTime() : 0;
			const suspicious = ageMs > 0 && ageMs < 7 * 86400 * 1000 && Number(data.Visits || 0) < 1000;
			out.innerHTML =
				`<div class="lookup"><div class="lookup__head"><strong>${escapeHtml(data.Name || "—")}</strong>` +
				`<span class="text-dim"> · universe ${escapeHtml(String(data.UniverseId || "—"))}</span></div>` +
				`<dl class="lookup__grid">` +
				[
					["Owner", `${data.CreatorName || "—"} (${data.CreatorType || "?"} ${data.CreatorId || "—"})`],
					["Place ID", data.RootPlaceId || data.PlaceId || "—"],
					["Created", created],
					["Visits", fmtCount(data.Visits)],
					["Playing now", fmtCount(data.Playing)],
					["Max players", fmtCount(data.MaxPlayers)],
					["Favourites", fmtCount(data.FavoritedCount)],
				]
					.map(([k, v]) => `<dt>${k}</dt><dd>${escapeHtml(String(v))}</dd>`)
					.join("") +
				"</dl>" +
				(data.Description
					? `<div class="lookup__desc">${escapeHtml(String(data.Description).slice(0, 400))}</div>`
					: "") +
				`<div class="lookup__links">` +
				(data.Url ? `<a href="${escapeHtml(data.Url)}" target="_blank" rel="noopener">Experience ↗</a>` : "") +
				(data.CreatorUrl
					? ` <a href="${escapeHtml(data.CreatorUrl)}" target="_blank" rel="noopener">Owner ↗</a>`
					: "") +
				"</div>" +
				(suspicious
					? '<div class="callout callout--warn">Recently created with very few visits — consistent with a ' +
						"throwaway place made to point traffic at this proxy rather than a real game using it.</div>"
					: "") +
				"</div>";
		} catch (err) {
			if (out) out.innerHTML = '<div class="callout callout--bad">Lookup failed.</div>';
		}
	}

	async function blockCaller(id) {
		if (!confirm(`Block every request carrying Roblox-Id "${id}"?`)) return;
		try {
			const res = await api("/admin/headers/rule", {
				method: "POST",
				body: JSON.stringify({
					header: "Roblox-Id",
					scope: "value",
					mode: "exact",
					needle: String(id),
					note: `Blocked from Callers on ${new Date().toLocaleDateString()}`,
				}),
			});
			const data = await res.json().catch(() => ({}));
			showToast(res.ok ? `Blocking Roblox-Id ${id}` : data.Message || "Could not add the filter");
			if (res.ok) refreshAll(true);
		} catch {
			showToast("Could not add the filter");
		}
	}

	async function addBypass(ip) {
		try {
			const res = await api("/admin/throttle/bypass", {
				method: "POST",
				body: JSON.stringify({ ip: String(ip), expires_in: 3600, note: "Added from Top Talkers" }),
			});
			const data = await res.json().catch(() => ({}));
			showToast(res.ok ? `${ip} bypasses throttling for 1h` : data.Message || "Could not add the bypass");
			if (res.ok) refreshAll(true);
		} catch {
			showToast("Could not add the bypass");
		}
	}

	function filterLiveBy(value) {
		const input = $("#liveFilter");
		if (input) {
			input.value = String(value);
			input.dispatchEvent(new Event("input"));
		}
		document.getElementById("section-live")?.scrollIntoView({ behavior: "smooth", block: "start" });
	}

	const SETTING_LABELS = {
		allowed_requests_per_minute: "Allowed requests per period",
		throttle_reset_duration: "Throttle reset duration (s)",
		stale_ip_duration: "Stale IP duration (s)",
		max_retries_per_request: "Max retries per request",
		two_fa_expiration: "2FA code lifetime (s)",
		challenge_expiration: "Login challenge lifetime (s)",
		token_expiration_cooldown: "Token re-check cooldown (s)",
		request_timeout: "Upstream request timeout (s)",
		email_cooldown: "Token-expired email cooldown (s)",
		error_email_cooldown: "Error email cooldown (s)",
		autosave_interval: "Autosave interval (s)",
		max_live_requests: "Live feed size",
		max_exploit_records: "Exploit records kept",
		max_login_records: "Login records kept",
		max_crawl_records: "Crawl records kept",
		max_throttle_records: "Throttle records kept",
		max_header_name_records: "Header names kept",
		max_header_value_records: "Values kept per header",
		max_user_agent_records: "User-agents kept",
		max_error_records: "Error signatures kept",
		auto_ignore_high_cardinality: "Auto-ignore unique-per-request headers (1 = on)",
		diagnostics_flush_interval: "Dashboard merge interval (s)",
		max_endpoint_records: "Endpoint records kept",
		token_budget_requests: "Token budget: max requests",
		token_budget_window: "Token budget: window (s)",
		global_throttle_limit: "Throttle-all: max requests / IP",
		global_throttle_period: "Throttle-all: window (s)",
		token_weight: "Method weight: Token",
		rotate_weight: "Method weight: Rotate",
		token_danger_zone: "Token danger zone (requests)",
		rotate_enabled: "IP rotation enabled (1/0)",
		rotate_cooldown: "Rotate cooldown after failures (s)",
		rotate_max_failures: "Rotate: failures before cooldown",
		tarpit_enabled: "Tarpit enabled (1/0)",
		tarpit_min_seconds: "Tarpit: hold at least (s)",
		tarpit_max_seconds: "Tarpit: hold at most (s)",
		tarpit_max_concurrent: "Tarpit: max held at once",
		tarpit_on_header_rule: "Tarpit: filter-blocked requests (1/0)",
		tarpit_on_probe: "Tarpit: non-Roblox URLs (1/0)",
		tarpit_on_throttle: "Tarpit: per-IP throttle (1/0)",
		tarpit_on_throttle_all: "Tarpit: throttle-all (1/0)",
		tarpit_on_endpoint_rule: "Tarpit: endpoint rate rules (1/0)",
		tarpit_on_blocked_endpoint: "Tarpit: blocked endpoints (1/0)",
		tarpit_on_auth_attempt: "Tarpit: ROBLOSECURITY attempts (1/0)",
	};

	// Group settings so the (long) list is navigable. Any key not listed falls
	// into "Other" so nothing is ever hidden.
	const SETTING_GROUPS = [
		["Routing & method mix", ["token_weight", "rotate_weight", "token_danger_zone"]],
		["IP rotation", ["rotate_enabled", "rotate_cooldown", "rotate_max_failures"]],
		["Token safety budget", ["token_budget_requests", "token_budget_window", "token_expiration_cooldown"]],
		["Throttling", ["allowed_requests_per_minute", "throttle_reset_duration", "stale_ip_duration", "global_throttle_limit", "global_throttle_period"]],
		[
			"Tarpit (slow refusals)",
			[
				"tarpit_enabled",
				"tarpit_min_seconds",
				"tarpit_max_seconds",
				"tarpit_max_concurrent",
				"tarpit_on_header_rule",
				"tarpit_on_probe",
				"tarpit_on_throttle",
				"tarpit_on_throttle_all",
				"tarpit_on_endpoint_rule",
				"tarpit_on_blocked_endpoint",
				"tarpit_on_auth_attempt",
			],
		],
		["Upstream & retries", ["request_timeout", "max_retries_per_request"]],
		["Email", ["email_cooldown", "error_email_cooldown"]],
		["Login & sessions", ["two_fa_expiration", "challenge_expiration"]],
		["Dashboard", ["diagnostics_flush_interval"]],
		[
			"Record caps & persistence",
			[
				"autosave_interval",
				"max_live_requests",
				"max_exploit_records",
				"max_login_records",
				"max_crawl_records",
				"max_throttle_records",
				"max_endpoint_records",
				"max_header_name_records",
				"max_header_value_records",
				"max_user_agent_records",
				"max_error_records",
				"auto_ignore_high_cardinality",
			],
		],
	];
	function groupedSettingKeys(settings) {
		const seen = new Set();
		const groups = [];
		for (const [label, keys] of SETTING_GROUPS) {
			const present = keys.filter(k => k in settings);
			present.forEach(k => seen.add(k));
			if (present.length) groups.push([label, present]);
		}
		const leftovers = Object.keys(settings).filter(k => !seen.has(k));
		if (leftovers.length) groups.push(["Other", leftovers]);
		return groups;
	}

	function renderSettings(d) {
		const tbody = $("#settingsTable tbody");
		if (!tbody) return;
		const settings = d.Settings || {};
		// Never clobber the table while the admin is mid-edit (auto-refresh would
		// otherwise wipe their typing every 5 seconds).
		const editing = tbody.contains(document.activeElement) || tbody.querySelector("input[data-dirty='1']");
		if (editing) {
			for (const input of $$("input[data-setting]", tbody)) {
				const info = settings[input.dataset.setting];
				if (!info) continue;
				const current = input.closest("tr")?.querySelector("[data-current]");
				if (current) current.textContent = String(info.value);
			}
			return;
		}
		tbody.innerHTML = "";
		for (const [groupLabel, keys] of groupedSettingKeys(settings)) {
			const headRow = document.createElement("tr");
			headRow.className = "settings-group";
			const headTd = document.createElement("td");
			headTd.colSpan = 5;
			headTd.innerHTML = `<strong>${escapeHtml(groupLabel)}</strong>`;
			headRow.appendChild(headTd);
			tbody.appendChild(headRow);

			for (const key of keys) {
				const info = settings[key];
				const row = document.createElement("tr");

				const tdName = document.createElement("td");
				tdName.textContent = SETTING_LABELS[key] || key;
				tdName.title = key;

				const tdCurrent = document.createElement("td");
				tdCurrent.textContent = String(info.value);
				tdCurrent.dataset.current = "1";

				const tdInput = document.createElement("td");
				const input = document.createElement("input");
				input.className = "input";
				input.type = "number";
				input.value = String(info.value);
				input.min = String(info.min);
				input.max = String(info.max);
				input.dataset.setting = key;
				input.addEventListener("input", () => {
					input.dataset.dirty = "1";
				});
				tdInput.appendChild(input);

				const tdRange = document.createElement("td");
				tdRange.textContent = `${info.min} – ${info.max}`;

				const tdUpdated = document.createElement("td");
				tdUpdated.appendChild(info.updated ? tsNode(info.updated) : document.createTextNode("—"));

				[tdName, tdCurrent, tdInput, tdRange, tdUpdated].forEach(td => row.appendChild(td));
				tbody.appendChild(row);
			}
		}
	}

	// The admin-authored reply a refused caller receives. Rendered dimmed when
	// unset so an empty column reads as "default message", not as missing data.
	function messageCell(info) {
		const text = String(info?.Message || "").trim();
		const span = document.createElement("span");
		if (!text) {
			span.className = "text-muted";
			span.textContent = "default";
			span.dataset.sortValue = "";
			span.title = "The caller receives the built-in message";
		} else {
			span.className = "rule-message";
			span.textContent = text;
			span.title = text;
			span.dataset.sortValue = text;
		}
		return span;
	}

	const typeBadge = info => {
		const badge = document.createElement("span");
		const isRegex = info.Type === "regex";
		badge.className = `badge ${isRegex ? "badge--method" : ""}`;
		badge.textContent = isRegex ? "Regex" : "Wildcard";
		return badge;
	};

	function renderThrottleBypass(d) {
		if ("YourIP" in d) {
			renderThrottleBypass._yourIp = d.YourIP || "";
			setText("yourIp", d.YourIP || "—");
		}
		if (d.ThrottleBypassIps) renderThrottleBypass._last = d.ThrottleBypassIps;
		const tbody = $("#bypassTable tbody");
		if (!tbody) return;
		const entries = Object.entries(renderThrottleBypass._last || {});
		entries.sort((a, b) => (b[1].Added || 0) - (a[1].Added || 0));
		setText("throttleBypassTotal", `${entries.length} IP${entries.length === 1 ? "" : "s"}`);
		tbody.innerHTML = "";
		if (entries.length === 0) {
			tbody.appendChild(tr(["—", "No bypass IPs", "—", "—", ""]));
			return;
		}
		for (const [ip, info] of entries) {
			const btn = document.createElement("button");
			btn.className = "btn btn--outline btn--sm";
			btn.textContent = "Remove";
			btn.addEventListener("click", () => removeThrottleBypass(ip));
			const expires = Number(info.Expires || 0);
			tbody.appendChild(tr([ip, info.Note || "—", tsNode(info.Added), expires > 0 ? tsNode(expires) : "never", btn]));
		}
	}

	async function removeThrottleBypass(ip) {
		try {
			const res = await api("/admin/throttle/bypass/remove", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ ip }),
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.Message || String(res.status));
			renderThrottleBypass({ ThrottleBypassIps: data.ThrottleBypassIps });
			showToast(`Removed bypass for ${ip}`);
		} catch {
			showToast("Failed to remove bypass");
		}
	}

	function renderEndpointBlocks(d) {
		const tbody = $("#blocksTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const entries = Object.entries(d.EndpointBlocks || {});
		if (entries.length === 0) {
			tbody.appendChild(tr(["—", "—", "No endpoints blocked", "—", "—", ""]));
			return;
		}
		for (const [pattern, info] of entries) {
			const btn = document.createElement("button");
			btn.className = "btn btn--outline btn--sm";
			btn.textContent = "Unblock";
			btn.addEventListener("click", () => unblockEndpoint(pattern));
			tbody.appendChild(
				tr([pattern, typeBadge(info), info.Note || "—", messageCell(info), tsNode(info.Added), btn]),
			);
		}
	}

	function renderEndpointRules(d) {
		const tbody = $("#rulesTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const entries = Object.entries(d.EndpointRules || {});
		if (entries.length === 0) {
			tbody.appendChild(tr(["—", "—", "—", "—", "—", "—", ""]));
			return;
		}
		for (const [pattern, info] of entries) {
			const btn = document.createElement("button");
			btn.className = "btn btn--outline btn--sm";
			btn.textContent = "Remove";
			btn.addEventListener("click", () => clearEndpointRule(pattern));
			tbody.appendChild(
				tr([
					pattern,
					typeBadge(info),
					String(info.Limit ?? "—"),
					String(info.Period ?? "—"),
					messageCell(info),
					tsNode(info.Added),
					btn,
				]),
			);
		}
	}

	function renderBlockedAttempts(d) {
		renderRejectedAttempts("#blockedAttemptsTable tbody", "blockedAttemptsTotal", d.BlockedEndpointAttempts || {});
	}

	function renderRateLimitedAttempts(d) {
		renderRejectedAttempts(
			"#rateLimitedAttemptsTable tbody",
			"rateLimitedAttemptsTotal",
			d.RateLimitedAttempts || {},
		);
	}

	function renderRejectedAttempts(tbodySel, totalId, data) {
		const tbody = $(tbodySel);
		if (!tbody) return;
		tbody.innerHTML = "";
		const entries = Object.entries(data);
		entries.sort((a, b) => (b[1].Count || 0) - (a[1].Count || 0));
		let total = 0;
		for (const [path, info] of entries) {
			total += Number(info.Count || 0);
			const methods = Object.entries(info.Methods || {})
				.map(([m, n]) => `${m}:${n}`)
				.join(", ");
			const uniqueIps = info.IPs ? Object.keys(info.IPs).length : 0;
			tbody.appendChild(
				tr([
					path,
					String(info.Count || 0),
					String(uniqueIps),
					methods || "—",
					info.Pattern || "—",
					info.LastIP || "—",
					tsNode(info.LastRequestTime),
				]),
			);
		}
		if (entries.length === 0) {
			tbody.appendChild(tr(["—", "0", "0", "—", "—", "—", "—"]));
		}
		setText(totalId, `${total} attempts`);
	}

	async function unblockEndpoint(pattern) {
		try {
			const res = await api("/admin/endpoints/unblock", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ pattern }),
			});
			const data = await res.json();
			renderEndpointBlocks({ EndpointBlocks: data.EndpointBlocks });
			showToast(`Unblocked ${pattern}`);
		} catch {
			showToast("Failed to unblock");
		}
	}

	async function clearEndpointRule(pattern) {
		try {
			const res = await api("/admin/endpoints/rule/clear", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ pattern }),
			});
			const data = await res.json();
			renderEndpointRules({ EndpointRules: data.EndpointRules });
			showToast(`Removed rule for ${pattern}`);
		} catch {
			showToast("Failed to remove rule");
		}
	}

	const HEADER_SCOPE_LABELS = { key: "Header name", value: "Header value", either: "Name or value" };
	const HEADER_MODE_LABELS = { contains: "Contains", exact: "Exact", regex: "Regex" };
	function renderHeaderRules(d) {
		const tbody = $("#headerRulesTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const entries = Object.entries(d.HeaderRules || {});
		if (entries.length === 0) {
			tbody.appendChild(tr(["—", "—", "—", "No header rules", "—", "—", "—", ""]));
			return;
		}
		for (const [id, info] of entries) {
			const btn = document.createElement("button");
			btn.className = "btn btn--outline btn--sm";
			btn.textContent = "Remove";
			btn.addEventListener("click", () => removeHeaderRule(id));
			const reply = messageCell(info);
			// An empty reply here is the SAFE state (the caller cannot tell they
			// were filtered), so it is labelled rather than left looking unset.
			if (!String(info.Message || "").trim()) {
				reply.textContent = "stealth 429";
				reply.title = "The caller sees an ordinary throttle response and cannot tell they were filtered";
			}
			tbody.appendChild(
				tr([
					info.Header || "(any)",
					HEADER_SCOPE_LABELS[info.Scope] || info.Scope || "—",
					HEADER_MODE_LABELS[info.Mode] || info.Mode || "Contains",
					info.Needle || "—",
					info.Note || "—",
					reply,
					tsNode(info.Added),
					btn,
				]),
			);
		}
	}

	// -----------------------------
	// Tarpit
	// -----------------------------
	const TARPIT_CATEGORY_LABELS = {
		header_rule: "Caught by a Request Filter",
		probe: "Not a Roblox URL",
		throttle: "Per-IP rate limit",
		throttle_all: "Global throttle-all",
		endpoint_rule: "Per-endpoint rate rule",
		blocked_endpoint: "Blocked endpoint",
		auth_attempt: "Sent a ROBLOSECURITY cookie",
	};

	// Durations here span "1.4s" to "3 days of wasted exploiter time", so pick a
	// unit rather than printing 259200s.
	function fmtSeconds(s) {
		s = Number(s || 0);
		if (!s) return "—";
		if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)}s`;
		if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
		return fmtDuration(s);
	}

	function renderTarpit(d) {
		if (d.TarpitStats) renderTarpit._stats = d.TarpitStats;
		if (d.TarpitIps) renderTarpit._ips = d.TarpitIps;
		if (d.TarpitRates) renderTarpit._rates = d.TarpitRates;
		const stats = renderTarpit._stats || {};
		const ips = renderTarpit._ips || {};
		const rates = renderTarpit._rates || [];
		const state = d.Tarpit || renderTarpit._state || {};
		if (d.Tarpit) renderTarpit._state = d.Tarpit;

		const enabled = Boolean(state.Enabled) && (state.Categories || []).length > 0;
		const chip = $("#tarpitStatusChip");
		if (chip) {
			chip.textContent = !state.Enabled
				? "Off"
				: (state.Categories || []).length === 0
					? "On, but nothing selected"
					: `Holding ${(state.Categories || []).length} kind(s)`;
			chip.classList.toggle("chip--ok", enabled);
			chip.classList.toggle("chip--danger", Boolean(state.Enabled) && !enabled);
		}

		// Don't fight the admin while they are typing into these controls.
		const toggle = $("#tarpitEnabled");
		if (toggle && document.activeElement !== toggle) toggle.checked = Boolean(state.Enabled);
		const settings = d.Settings || {};
		const setIfIdle = (id, value) => {
			const el = document.getElementById(id);
			if (el && document.activeElement !== el && el.dataset.dirty !== "1") el.value = String(value);
		};
		if (settings.tarpit_min_seconds) setIfIdle("tarpitMin", settings.tarpit_min_seconds.value);
		if (settings.tarpit_max_seconds) setIfIdle("tarpitMax", settings.tarpit_max_seconds.value);
		if (settings.tarpit_max_concurrent) setIfIdle("tarpitConcurrent", settings.tarpit_max_concurrent.value);
		for (const box of $$(".tarpit-cat__box")) {
			if (document.activeElement === box) continue;
			box.checked = (state.Categories || []).includes(box.dataset.category);
		}

		const held = Number(stats.Count || 0);
		const totalHeld = Number(stats.TotalHeld || 0);
		setText("tarpit_count", fmtCount(held));
		setText("tarpit_skipped", fmtCount(stats.Skipped || 0));
		setText("tarpit_active", String(state.ActiveHolds ?? 0));
		setText("tarpit_capacity", String(state.MaxConcurrent ?? 0));
		// The number the admin set vs. the number actually enforced, plus how much
		// of the fleet is currently sat on by held refusals. A clamp that is not
		// shown is a setting that silently lies about what it does.
		const capHint = $("#tarpitCapacityHint");
		if (capHint) {
			const slots = Number(state.FleetSlots || 0);
			const used = Number(state.CapacityUsedPct || 0);
			capHint.innerHTML =
				`A held request occupies one of the fleet's <strong>${slots || "—"}</strong> request slots for its ` +
				`whole hold, so <strong>Max concurrent</strong> is clamped to ${state.CapacityCeilingPct ?? 50}% of ` +
				"them — setting it higher is quietly ignored rather than starving real traffic. " +
				(state.Clamped
					? `<span class="text-warn">Clamped: you asked for ${state.ConfiguredConcurrent}, ` +
						`${state.MaxConcurrent} is enforced.</span> `
					: "") +
				`Currently holding <strong>${used}%</strong> of fleet capacity.`;
		}
		setText("tarpit_avg", held ? fmtSeconds(totalHeld / held) : "—");
		setText("tarpit_min", stats.Min ? fmtSeconds(stats.Min) : "—");
		setText("tarpit_max", stats.Max ? fmtSeconds(stats.Max) : "—");
		setText("tarpit_total", fmtSeconds(totalHeld));

		// A rising "skipped" means our own concurrency cap is the binding limit,
		// not the caller — worth shouting about, since it silently disables the
		// feature you think is running.
		const skipEl = $("#tarpit_skipped");
		if (skipEl) skipEl.classList.toggle("text-danger", Number(stats.Skipped || 0) > held && held > 0);

		const gaps = Number(stats.Gaps || 0);
		const lifetimeGap = gaps ? Number(stats.TotalGap || 0) / gaps : 0;
		setText("tarpit_gap", lifetimeGap ? fmtSeconds(lifetimeGap) : "—");
		const byWindow = Object.fromEntries(rates.map(r => [r.Minutes, r]));
		for (const minutes of [15, 60, 1440]) {
			const row = byWindow[minutes] || {};
			setText(`tarpit_gap_${minutes}`, row.Count ? fmtSeconds(row.AvgGap) : "—");
		}
		setText("tarpit_hour", fmtCount(byWindow[60]?.Count || 0));
		setText("tarpit_15", fmtCount(byWindow[15]?.Count || 0));
		setText("tarpit_24h", fmtCount(byWindow[1440]?.Count || 0));
		setText("tarpit_ip_count", fmtCount(Object.keys(ips).length));

		// The headline question: are they knocking less often than they used to?
		const recent = byWindow[60];
		const trend = $("#tarpit_trend");
		if (trend) {
			if (!recent || !recent.Count || !lifetimeGap) {
				trend.textContent = "Not enough data yet to compare.";
				trend.className = "text-dim";
			} else {
				const ratio = recent.AvgGap / lifetimeGap;
				const pct = Math.abs(Math.round((ratio - 1) * 100));
				if (ratio >= 1.15) {
					trend.textContent = `Backing off: ${pct}% longer between requests this hour than usual.`;
					trend.className = "health-ok";
				} else if (ratio <= 0.85) {
					trend.textContent = `Speeding up: ${pct}% shorter between requests this hour.`;
					trend.className = "health-bad";
				} else {
					trend.textContent = "Holding steady — same request rate as their lifetime average.";
					trend.className = "text-dim";
				}
			}
		}

		const catBody = $("#tarpitCategoryTable tbody");
		if (catBody) {
			catBody.innerHTML = "";
			const entries = Object.entries(stats.Categories || {});
			entries.sort((a, b) => (b[1].Count || 0) - (a[1].Count || 0));
			if (!entries.length) {
				catBody.appendChild(tr(["Nothing held yet", "0", "0", "—", "—", "—"]));
			}
			for (const [name, info] of entries) {
				const count = Number(info.Count || 0);
				catBody.appendChild(
					tr([
						TARPIT_CATEGORY_LABELS[name] || name,
						fmtCount(count),
						fmtCount(info.Skipped || 0),
						count ? fmtSeconds(Number(info.TotalHeld || 0) / count) : "—",
						fmtSeconds(info.TotalHeld || 0),
						info.LastRequestTime ? tsNode(info.LastRequestTime) : "—",
					]),
				);
			}
		}

		const ipBody = $("#tarpitIpsTable tbody");
		if (!ipBody) return;
		ipBody.innerHTML = "";
		const rows = Object.entries(ips).sort((a, b) => (b[1].Count || 0) - (a[1].Count || 0));
		if (!rows.length) {
			ipBody.appendChild(tr(["No callers held yet", "0", "0", "—", "—", "—", "—"]));
			return;
		}
		for (const [ip, info] of rows) {
			const ipGaps = Number(info.Gaps || 0);
			ipBody.appendChild(
				tr([
					ip,
					fmtCount(info.Count || 0),
					fmtCount(info.Skipped || 0),
					ipGaps ? fmtSeconds(Number(info.TotalGap || 0) / ipGaps) : "—",
					fmtSeconds(info.TotalHeld || 0),
					info.FirstSeen ? tsNode(info.FirstSeen) : "—",
					info.LastRequestTime ? tsNode(info.LastRequestTime) : "—",
				]),
			);
		}
	}

	function renderHeaderBlocked(d) {
		const tbody = $("#headerBlockedTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const entries = Object.entries(d.HeaderBlockedAttempts || {});
		entries.sort((a, b) => (b[1].Count || 0) - (a[1].Count || 0));
		let total = 0;
		for (const [, info] of entries) {
			total += Number(info.Count || 0);
			const scope = HEADER_SCOPE_LABELS[info.Scope] || info.Scope || "?";
			const verb = info.Mode === "exact" ? "is" : info.Mode === "regex" ? "matches" : "contains";
			const ruleDesc = `${scope} ${verb} "${info.Needle || ""}"`;
			const uniqueIps = info.IPs ? Object.keys(info.IPs).length : 0;
			const triggered = info.LastField === "key" ? "Header name" : info.LastField === "value" ? "Header value" : "—";
			tbody.appendChild(
				tr([
					ruleDesc,
					String(info.Count || 0),
					String(uniqueIps),
					info.LastHeader || "—",
					triggered,
					info.LastMatch || "—",
					info.LastIP || "—",
					info.LastPath || "—",
					tsNode(info.LastRequestTime),
				]),
			);
		}
		if (entries.length === 0) {
			tbody.appendChild(tr(["No header-blocked requests", "0", "0", "—", "—", "—", "—", "—", "—"]));
		}
		setText("headerBlockedTotal", `${total} blocked`);
	}

	async function removeHeaderRule(id) {
		try {
			const res = await api("/admin/headers/rule/clear", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ id }),
			});
			const data = await res.json();
			renderHeaderRules({ HeaderRules: data.HeaderRules });
			showToast("Header rule removed");
		} catch {
			showToast("Failed to remove header rule");
		}
	}

	// -----------------------------
	// Data plumbing
	// -----------------------------
	let lastFetchedAt = 0;
	let refreshInFlight = false;
	let lastDiagnostics = null; // Reused by exports so a download doesn't refetch everything.

	// `force` makes the server merge every worker's stats before answering. The
	// background poll skips it (the merge is the expensive part and a few seconds
	// of staleness is invisible); an explicit Refresh asks for it.
	async function fetchDiagnostics(force = false) {
		const res = await api(`/admin/diagnostics${force ? "?flush=1" : ""}`, { method: "GET" });
		if (!res.ok) throw new Error("Diagnostics fetch failed: " + res.status);
		lastFetchedAt = Date.now() / 1000;
		lastDiagnostics = await res.json();
		return lastDiagnostics;
	}

	// Exports work from the last refresh rather than pulling the whole payload
	// again; a click on "Export" should not cost another full server-side merge.
	async function diagnosticsForExport() {
		return lastDiagnostics || (await fetchDiagnostics());
	}

	// Tick the "Updated Xs ago" chip without refetching.
	setInterval(() => {
		if (lastFetchedAt) setText("lastUpdatedChip", `Updated: ${timeAgo(lastFetchedAt)}`);
	}, 1000);

	async function refreshAll(silent = false) {
		if (refreshInFlight) return; // Never let refreshes overlap and pile up.
		refreshInFlight = true;
		try {
			// A silent refresh is the background poll; a loud one is the admin
			// pressing Refresh, which should merge every worker's numbers first.
			const d = await fetchDiagnostics(!silent);
			renderOverview(d);
			renderPageVisits(d);
			renderVisitors(d);
			renderTraffic(d);
			renderRequests(d);
			renderProxyTimings(d);
			renderMethodTimings(d);
			renderRequestFailures(d);
			renderRotateIps(d);
			renderTokens(d);
			renderProbes(d);
			renderLogins(d);
			renderHealth(d);
			renderCrawls(d);
			renderThrottled(d);
			renderPause(d);
			renderThrottleAll(d);
			renderTrustedDevices(d);
			renderEndpoints(d);
			renderStatusDetailed(d);
			renderRetries(d);
			renderExploitSummary(d);
			renderErrors(d);
			renderFingerprints(d);
			renderLiveFeed(d);
			renderBudget(d);
			renderPersistence(d);
			renderSettings(d);
			renderEndpointBlocks(d);
			renderEndpointRules(d);
			renderThrottleBypass(d);
			renderTarpit(d);
			renderHeaderRules(d);
			renderTesterSamples();
			renderBlockedAttempts(d);
			renderRateLimitedAttempts(d);
			renderHeaderBlocked(d);
			renderIgnoredHeaders(d);
			renderStoreSizes(d);
			renderActivity(d);
			renderStatusSources(d);
			renderRefusals(d);
			renderInternalRequests(d);
			renderCaptureState(d);
			renderThreatLevel(d);
			// One pass at the end rather than inside each renderer: every table has
			// just been rebuilt from scratch, and the sort the admin chose has to
			// survive that or it is useless on live data.
			sortAllTables();
			setText("lastUpdatedChip", "Updated: just now");
			if (!silent) showToast("Dashboard updated");
		} catch (err) {
			console.error(err);
			if (!silent && sessionAlive) showToast("Failed to refresh diagnostics");
		} finally {
			refreshInFlight = false;
		}
	}

	// What is actually accumulating on disk. This is the number that would have
	// made the old unbounded-growth problem obvious months before it took the
	// server down, so it gets a permanent home on the dashboard.
	const STORE_LABELS = {
		header_names: "Header names",
		user_agents: "User-agents",
		endpoints: "Endpoint templates",
		errors: "Errors",
		request_failures: "Request failures",
		exploit_summary: "Probe reasons",
		blocked_endpoint_attempts: "Blocked attempts",
		rate_limited_attempts: "Rate-limited attempts",
		crawls: "Crawlers",
		throttled_ips: "Throttled IPs",
		live_requests: "Live feed",
		traffic_minutes: "Traffic buckets",
	};

	function renderStoreSizes(d) {
		const tbody = $("#storeSizesTable tbody");
		if (!tbody) return;
		const sizes = d.StoreSizes || {};
		tbody.innerHTML = "";
		const rows = Object.entries(STORE_LABELS)
			.map(([key, label]) => [label, Number(sizes[key] || 0)])
			.sort((a, b) => b[1] - a[1]);
		for (const [label, n] of rows) {
			const row = tr([label, fmtCount(n)]);
			row.children[1].className = "num";
			tbody.appendChild(row);
		}
	}

	// -----------------------------
	// CSV Export (simple, sectioned)
	// -----------------------------
	// Spreadsheets treat a leading = + - @ (or tab / CR) as the start of a
	// formula and will evaluate it on open. Much of what we export -- header
	// names, header values, user-agents -- is written by whoever sent the
	// request, so a cell is prefixed with an apostrophe to force it to text.
	function csvSafe(value) {
		const s = String(value ?? "");
		return /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
	}
	function toCSVRow(arr) {
		return arr.map(x => `"${csvSafe(x).replaceAll('"', '""')}"`).join(",");
	}
	function download(filename, text) {
		const a = document.createElement("a");
		a.href = URL.createObjectURL(new Blob([text], { type: "text/csv;charset=utf-8;" }));
		a.download = filename;
		a.click();
		setTimeout(() => URL.revokeObjectURL(a.href), 1000);
	}
	function exportCSV(d) {
		const lines = [];
		lines.push("# Roxy Diagnostics Export");
		lines.push(`# Timestamp,${new Date().toISOString()}`);

		lines.push("");
		lines.push("[PageVisits]");
		const pv = d.PageVisits || {};
		lines.push(toCSVRow(["home", pv.home ?? 0]));
		lines.push(toCSVRow(["admin", pv.admin ?? 0]));
		lines.push(toCSVRow(["robots", pv.robots ?? 0]));

		lines.push("");
		lines.push("[RequestCounts]");
		const rc = d.RequestCounts || {};
		["GET", "POST", "PATCH", "PUT", "DELETE"].forEach(m => {
			const row = rc[m] || { Successful: 0, Failed: 0 };
			lines.push(toCSVRow([m, row.Successful || 0, row.Failed || 0, (row.Successful || 0) + (row.Failed || 0)]));
		});

		lines.push("");
		lines.push("[StatusCodeCounts]");
		const sc = d.StatusCodeCounts || {};
		lines.push(toCSVRow(["2xx", sc["2xx"] || 0]));
		lines.push(toCSVRow(["4xx", sc["4xx"] || 0]));

		lines.push("");
		lines.push("[TrafficMinutes]");
		for (const [minute, info] of Object.entries(d.TrafficMinutes || {})) {
			lines.push(toCSVRow([minute, info.Successful || 0, info.Failed || 0]));
		}

		lines.push("");
		lines.push("[ProxyRequestCounts]");
		const pc = d.ProxyRequestCounts || {};
		["GET", "POST", "PATCH", "PUT", "DELETE"].forEach(m => {
			const r = pc[m] || {};
			lines.push(
				toCSVRow([
					m,
					r.Count || 0,
					r.TotalTime || 0,
					r.Min === Infinity ? 0 : r.Min || 0,
					r.Max || 0,
					r.LastRequestTime || 0,
				]),
			);
		});

		lines.push("");
		lines.push("[Crawls]");
		for (const [ip, info] of Object.entries(d.Crawls || {})) {
			lines.push(toCSVRow([ip, info.Count || 0, info.LastRequestTime || 0]));
		}

		lines.push("");
		lines.push("[Tokens]");
		(Array.isArray(d.Tokens) ? d.Tokens : []).forEach((t, i) => {
			lines.push(toCSVRow([i + 1, t.Masked || "…***", t.BeingValidated ? "Yes" : "No", t.Uses || 0]));
		});

		lines.push("");
		lines.push("[ExploitAttempts]");
		(Array.isArray(d.ExploitAttempts) ? d.ExploitAttempts : []).forEach(r => {
			lines.push(toCSVRow([r.Date || 0, r.IP || "", r.UserAgent || "", r.Reason || ""]));
		});

		lines.push("");
		lines.push("[LoginAttempts]");
		(Array.isArray(d.LoginAttempts) ? d.LoginAttempts : []).forEach(r => {
			lines.push(toCSVRow([r.Date || 0, r.IP || "", r.Successful ? "success" : "fail"]));
		});

		lines.push("");
		lines.push("[ThrottledIPs]");
		const ti = d.ThrottledIPs || d.throttled_ips || {};
		for (const [ip, info] of Object.entries(ti)) {
			lines.push(toCSVRow([ip, info.Count ?? 0, info.LastThrottleTime ?? 0]));
		}

		download(`roxy_diagnostics_${Date.now()}.csv`, lines.join("\n"));
	}

	// -----------------------------
	// Events / wiring
	// -----------------------------
	const navToggle = $("#navToggle");
	navToggle?.addEventListener("click", () => {
		const nav = $("#appNav");
		const expanded = nav?.classList.toggle("is-open");
		navToggle.setAttribute("aria-expanded", expanded ? "true" : "false");
	});

	// Scrollspy: highlight the nav link for the section in view.
	const navLinkBySection = new Map(
		$$(".nav__link")
			.map(a => [a.getAttribute("href")?.slice(1), a])
			.filter(([id]) => Boolean(id)),
	);
	const spy = new IntersectionObserver(
		entries => {
			for (const entry of entries) {
				if (!entry.isIntersecting) continue;
				const link = navLinkBySection.get(entry.target.id);
				if (!link) continue;
				$$(".nav__link").forEach(a => a.classList.remove("is-active"));
				link.classList.add("is-active");
				break;
			}
		},
		{ rootMargin: "-15% 0px -75% 0px" },
	);
	$$("main .section[id]").forEach(s => spy.observe(s));

	$("#refreshAll")?.addEventListener("click", () => refreshAll(false));
	$("#navRefresh")?.addEventListener("click", () => refreshAll(false));
	$("#errorsFilter")?.addEventListener("input", () => renderErrors({ Errors: renderErrors._last || {} }));
	$("#headerNamesFilter")?.addEventListener("input", () => renderFingerprints({}));
	$("#userAgentsFilter")?.addEventListener("input", () => renderFingerprints({}));
	$("#blockedHeaderNamesFilter")?.addEventListener("input", () => renderFingerprints({}));
	$("#blockedUserAgentsFilter")?.addEventListener("input", () => renderFingerprints({}));
	$("#exportAll")?.addEventListener("click", async () => {
		try {
			const d = await diagnosticsForExport();
			exportCSV(d);
			showToast("CSV exported");
		} catch {
			showToast("Export failed");
		}
	});

	$("#exportCrawls")?.addEventListener("click", async () => {
		try {
			const d = await diagnosticsForExport();
			const lines = ["IP,Count,LastRequestTime"];
			for (const [ip, info] of Object.entries(d.Crawls || {})) {
				lines.push(`${ip},${info.Count || 0},${info.LastRequestTime || 0}`);
			}
			download(`roxy_crawls_${Date.now()}.csv`, lines.join("\n"));
			showToast("Crawler data exported");
		} catch {
			showToast("Failed to export crawls");
		}
	});

	$("#exportThrottled")?.addEventListener("click", async () => {
		try {
			const d = await diagnosticsForExport();
			const ti = d.ThrottledIPs || d.throttled_ips || {};
			const lines = ["IP,Count,LastThrottleTime"];
			for (const [ip, info] of Object.entries(ti)) {
				lines.push(`${ip},${info.Count ?? 0},${info.LastThrottleTime ?? 0}`);
			}
			download(`roxy_throttled_${Date.now()}.csv`, lines.join("\n"));
			showToast("Throttled IPs exported");
		} catch {
			showToast("Export failed");
		}
	});

	// Tokens: fetch button just refreshes diagnostics and scrolls into view
	$("#fetchTokensBtn")?.addEventListener("click", async () => {
		await refreshAll(true);
		$("#tokensTable")?.scrollIntoView({ behavior: "smooth", block: "center" });
	});

	// Token submit: send JSON instead of default form post; then refresh
	$("#tokenForm")?.addEventListener("submit", async e => {
		e.preventDefault();
		const tokensRaw = $("#tokensInput")?.value || "";
		const tokens = tokensRaw
			.split(/\r?\n/)
			.map(s => s.trim())
			.filter(Boolean);
		try {
			const res = await api("/admin/tokens", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ tokens }),
			});
			if (!res.ok) throw new Error(String(res.status));
			const data = await res.json();
			// The token file is always written -- that file is how the other
			// workers learn about the change -- so the only thing worth
			// reporting is whether the write actually landed.
			let msg = `Replaced token set (n=${data.Count ?? tokens.length})`;
			msg += data.Persisted ? "; saved to the token file" : "; COULD NOT SAVE to the token file";
			showToast(msg, 3200);
			$("#tokensInput").value = "";
			await refreshAll(true);
		} catch (err) {
			console.error(err);
			showToast("Token submit failed");
		}
	});

	// Collapsible sections
	$$(".collapsible-toggle").forEach(btn => {
		btn.addEventListener("click", () => {
			const id = btn.dataset.target;
			const content = document.getElementById(id);
			if (!content) return;
			const isOpen = content.classList.toggle("is-open");
			btn.textContent = isOpen ? "Collapse" : "Expand";
			btn.setAttribute("aria-expanded", String(isOpen));
		});
	});

	// Pause / resume the proxy (sends the optional reason from Service Controls)
	$("#pauseToggle")?.addEventListener("click", async () => {
		const currentlyPaused = $("#pauseToggle")?.dataset.paused === "true";
		const body = { paused: !currentlyPaused };
		if (!currentlyPaused) body.reason = $("#pauseReason")?.value.trim() || "";
		try {
			const res = await api("/admin/proxy/toggle", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
			});
			if (!res.ok) throw new Error(String(res.status));
			const state = await res.json();
			renderPause({ Pause: state });
			showToast(state.Paused ? "Proxy paused" : "Proxy resumed");
			refreshAll(true);
		} catch (err) {
			console.error(err);
			showToast("Failed to change pause state");
		}
	});

	// Throttle-all toggle (sends limit/period/reason from Service Controls)
	$("#throttleAllToggle")?.addEventListener("click", async () => {
		const currentlyOn = $("#throttleAllToggle")?.dataset.on === "true";
		const body = { enabled: !currentlyOn };
		if (!currentlyOn) {
			body.reason = $("#throttleReason")?.value.trim() || "";
			const limit = Number($("#throttleLimit")?.value);
			const period = Number($("#throttlePeriod")?.value);
			if (limit >= 1) body.limit = limit;
			if (period >= 1) body.period = period;
		}
		try {
			const res = await api("/admin/proxy/throttle_all", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
			});
			if (!res.ok) throw new Error(String(res.status));
			const state = await res.json();
			renderThrottleAll({ ThrottleAll: state });
			showToast(state.ThrottleAll ? `Throttling all IPs to ${state.Limit}/${state.Period}s` : "Throttle-all disabled");
			refreshAll(true);
		} catch (err) {
			console.error(err);
			showToast("Failed to change throttle-all state");
		}
	});

	// Auto-refresh (paused while the tab is hidden; remembered across visits).
	// The interval is the admin's choice, and a tick is skipped whenever the
	// previous refresh is still in flight -- otherwise a slow response makes the
	// requests stack up and each one arrives to find another already queued.
	const AUTO_REFRESH_KEY = "roxy.autoRefreshSeconds";
	const AUTO_REFRESH_CHOICES = [0, 5, 15, 30, 60];
	let autoRefreshTimer = null;

	function autoRefreshSeconds() {
		const stored = Number(localStorage.getItem(AUTO_REFRESH_KEY));
		if (AUTO_REFRESH_CHOICES.includes(stored)) return stored;
		// Migrate the old on/off flag; default to a calm 15s rather than 5s.
		return localStorage.getItem("roxy.autoRefresh") === "1" ? 15 : 0;
	}

	function applyAutoRefresh(seconds) {
		clearInterval(autoRefreshTimer);
		autoRefreshTimer = null;
		localStorage.setItem(AUTO_REFRESH_KEY, String(seconds));
		if (!seconds) return;
		autoRefreshTimer = setInterval(() => {
			if (document.hidden || !sessionAlive || refreshInFlight) return;
			refreshAll(true);
		}, seconds * 1000);
	}

	const autoSelect = $("#autoRefreshInterval");
	if (autoSelect) {
		autoSelect.value = String(autoRefreshSeconds());
		applyAutoRefresh(autoRefreshSeconds());
		autoSelect.addEventListener("change", e => {
			const seconds = Number(e.target.value) || 0;
			applyAutoRefresh(seconds);
			showToast(seconds ? `Auto-refresh every ${seconds}s` : "Auto-refresh off");
		});
	}

	// Live feed manual refresh + filter
	$("#refreshLive")?.addEventListener("click", async e => {
		// An explicit refresh must actually go to the server, unlike the exports.
		await withBusy(e.currentTarget, "Refreshing…", async () => {
			try {
				renderLiveFeed(await fetchDiagnostics());
				showToast("Live feed updated");
			} catch {
				showToast("Failed to refresh live feed");
			}
		});
	});
	$("#liveFilter")?.addEventListener("input", () => renderLiveFeed({}));
	$("#endpointsFilter")?.addEventListener("input", () => renderEndpoints({}));

	// Settings: save changes
	$("#settingsForm")?.addEventListener("submit", async e => {
		e.preventDefault();
		const inputs = $$("#settingsTable input[data-setting]");
		const settings = {};
		inputs.forEach(i => {
			settings[i.dataset.setting] = Number(i.value);
		});
		try {
			const res = await api("/admin/settings", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ settings }),
			});
			if (!res.ok) throw new Error(String(res.status));
			const data = await res.json();
			const rejected = Object.entries(data.Results || {}).filter(([, msg]) => msg !== "Success");
			inputs.forEach(i => delete i.dataset.dirty);
			await refreshAll(true);
			if (rejected.length) {
				showToast(`Saved with ${rejected.length} rejected: ${rejected[0][1]}`, 3500);
			} else {
				showToast("Settings saved");
			}
		} catch (err) {
			console.error(err);
			showToast("Failed to save settings");
		}
	});
	$("#reloadSettings")?.addEventListener("click", () => refreshAll(false));

	// Per-section "Clear data" buttons. Each maps to a server-side clear target;
	// clears propagate to every worker and the data file (manual-only erasure).
	const CLEAR_BUTTONS = {
		"section-overview": { target: "visits", what: "page-visit and visitor counters" },
		"section-traffic": { target: "requests", what: "ALL request stats (counters, status codes, timings, retries, traffic chart)" },
		"section-requests": { target: "requests", what: "ALL request stats (counters, status codes, timings, retries, traffic chart)" },
		"section-status": { target: "requests", what: "ALL request stats (counters, status codes, timings, retries, traffic chart)" },
		"section-retries": { target: "requests", what: "ALL request stats (counters, status codes, timings, retries, traffic chart)" },
		"section-proxy": { target: "proxy_timings", what: "the proxy timing stats (independently of the request counters)" },
		"section-request-failures": { target: "request_failures", what: "the request-failure log" },
		"section-rotation": { target: "rotate_ips", what: "the recorded rotation exit IPs" },
		"section-endpoints": { target: "endpoints", what: "the endpoint popularity records" },
		"section-blocked-attempts": { target: "blocked_attempts", what: "blocked-endpoint attempt records" },
		"section-ratelimited-attempts": { target: "rate_limited_attempts", what: "rate-limited attempt records" },
		"section-header-blocked": { target: "header_blocked_attempts", what: "header-blocked attempt records" },
		"section-live": { target: "live", what: "the live request feed" },
		"section-probes": { target: "probes", what: "probe/exploit attempts and their summary" },
		"section-exploit-summary": { target: "probes", what: "probe/exploit attempts and their summary" },
		"section-logins": { target: "logins", what: "admin login records" },
		"section-crawls": { target: "crawls", what: "crawler activity records" },
		"section-throttled": { target: "throttled", what: "throttled-IP records" },
		"section-fingerprints": { target: "fingerprints", what: "the recorded header names and user-agents" },
		"section-blocked-fingerprints": { target: "blocked_fingerprints", what: "the blocked-request header names and user-agents" },
		"section-errors": { target: "errors", what: "the error log" },
		"section-refusals": { target: "refusals", what: "the refusal-reason records" },
		"section-callers": { target: "callers", what: "the per-place and per-IP caller activity" },
		"section-internal": { target: "internal_requests", what: "the internal-request stats" },
	};
	for (const [sectionId, info] of Object.entries(CLEAR_BUTTONS)) {
		const section = document.getElementById(sectionId);
		if (!section) continue;
		let actions = $(".section__actions", section);
		if (!actions) {
			actions = document.createElement("div");
			actions.className = "section__actions";
			$(".section__header", section)?.appendChild(actions);
		}
		const btn = document.createElement("button");
		btn.type = "button";
		btn.className = "btn btn--warning btn--sm";
		btn.textContent = "Clear data";
		btn.title = `Permanently clear ${info.what}`;
		btn.addEventListener("click", async () => {
			if (!confirm(`Permanently clear ${info.what}? This cannot be undone.`)) return;
			await withBusy(btn, "Clearing…", async () => {
				try {
					const res = await api("/admin/data/clear", {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({ target: info.target }),
					});
					if (!res.ok) throw new Error(String(res.status));
					showToast(await res.json().catch(() => "Cleared"));
					noteCleared(sectionId);
					await refreshAll(true);
				} catch {
					showToast("Failed to clear");
				}
			});
		});
		actions.appendChild(btn);
		renderClearedStamp(sectionId);
	}

	// A section that repopulates after a clear looks identical to one that was
	// never cleared, which is exactly the ambiguity that made the fingerprint
	// clear bug so hard to pin down. Remember when each section was last cleared
	// and say so next to the button.
	const CLEARED_KEY = "roxy.lastCleared";
	function loadCleared() {
		try {
			return JSON.parse(localStorage.getItem(CLEARED_KEY) || "{}");
		} catch {
			return {};
		}
	}
	function noteCleared(sectionId) {
		const all = loadCleared();
		all[sectionId] = Date.now() / 1000;
		localStorage.setItem(CLEARED_KEY, JSON.stringify(all));
		renderClearedStamp(sectionId);
	}
	function renderClearedStamp(sectionId) {
		const section = document.getElementById(sectionId);
		const when = loadCleared()[sectionId];
		if (!section || !when) return;
		const actions = $(".section__actions", section);
		if (!actions) return;
		let stamp = $(".section__cleared", actions);
		if (!stamp) {
			stamp = document.createElement("span");
			stamp.className = "section__cleared text-muted";
			actions.insertBefore(stamp, actions.firstChild);
		}
		stamp.textContent = `Cleared ${timeAgo(when)}`;
		stamp.title = `Last cleared at ${toTS(when)}`;
	}

	// Collapsible sections: click a section title to fold it; state is remembered.
	const COLLAPSE_KEY = "roxy.collapsedSections";
	let collapsedSections;
	try {
		collapsedSections = new Set(JSON.parse(localStorage.getItem(COLLAPSE_KEY) || "[]"));
	} catch {
		collapsedSections = new Set();
	}
	const saveCollapsed = () => localStorage.setItem(COLLAPSE_KEY, JSON.stringify([...collapsedSections]));
	$$("main .section[id]").forEach(section => {
		const title = $(".section__title", section);
		if (!title) return;
		const chevron = document.createElement("span");
		chevron.className = "section__chevron";
		chevron.textContent = "▾";
		title.prepend(chevron);
		title.classList.add("section__title--toggle");
		title.setAttribute("role", "button");
		title.setAttribute("tabindex", "0");
		const apply = collapsed => {
			section.classList.toggle("is-collapsed", collapsed);
			title.setAttribute("aria-expanded", String(!collapsed));
		};
		apply(collapsedSections.has(section.id));
		const toggle = () => {
			const collapsed = !section.classList.contains("is-collapsed");
			if (collapsed) collapsedSections.add(section.id);
			else collapsedSections.delete(section.id);
			saveCollapsed();
			apply(collapsed);
		};
		title.addEventListener("click", toggle);
		title.addEventListener("keydown", e => {
			if (e.key === "Enter" || e.key === " ") {
				e.preventDefault();
				toggle();
			}
		});
	});

	// Throttle bypass: add an allowlisted IP (optional expiry in minutes)
	$("#bypassForm")?.addEventListener("submit", async e => {
		e.preventDefault();
		const ip = $("#bypassIp")?.value.trim();
		const minutes = Number($("#bypassExpiry")?.value);
		const note = $("#bypassNote")?.value.trim() || "";
		if (!ip) return;
		const body = { ip, note };
		if (minutes >= 1) body.expires_in = Math.round(minutes * 60);
		try {
			const res = await api("/admin/throttle/bypass", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.Message || String(res.status));
			renderThrottleBypass({ ThrottleBypassIps: data.ThrottleBypassIps });
			$("#bypassIp").value = "";
			$("#bypassExpiry").value = "";
			$("#bypassNote").value = "";
			showToast(`Bypass added for ${ip}`);
		} catch (err) {
			showToast("Add bypass failed: " + err.message);
		}
	});
	$("#bypassMyIp")?.addEventListener("click", () => {
		const ipInput = $("#bypassIp");
		if (ipInput && renderThrottleBypass._yourIp) ipInput.value = renderThrottleBypass._yourIp;
	});

	// Endpoint controls: block
	$("#blockForm")?.addEventListener("submit", async e => {
		e.preventDefault();
		const pattern = $("#blockPattern")?.value.trim();
		const note = $("#blockNote")?.value.trim() || "";
		const type = $("#blockType")?.value || "glob";
		// Note is private (admin-only); message is returned verbatim to the caller.
		const message = $("#blockMessage")?.value.trim() || "";
		if (!pattern) return;
		try {
			const res = await api("/admin/endpoints/block", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ pattern, note, type, message }),
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.Message || String(res.status));
			renderEndpointBlocks({ EndpointBlocks: data.EndpointBlocks });
			$("#blockPattern").value = "";
			$("#blockNote").value = "";
			if ($("#blockMessage")) $("#blockMessage").value = "";
			showToast(`Blocked ${pattern}`);
		} catch (err) {
			showToast("Block failed: " + err.message);
		}
	});

	// Endpoint controls: set rate rule
	$("#ruleForm")?.addEventListener("submit", async e => {
		e.preventDefault();
		const pattern = $("#rulePattern")?.value.trim();
		const limit = Number($("#ruleLimit")?.value);
		const period = Number($("#rulePeriod")?.value) || 60;
		const type = $("#ruleType")?.value || "glob";
		const message = $("#ruleMessage")?.value.trim() || "";
		if (!pattern || !limit) return;
		try {
			const res = await api("/admin/endpoints/rule", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ pattern, limit, period, type, message }),
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.Message || String(res.status));
			renderEndpointRules({ EndpointRules: data.EndpointRules });
			$("#rulePattern").value = "";
			$("#ruleLimit").value = "";
			if ($("#ruleMessage")) $("#ruleMessage").value = "";
			showToast(`Rule set for ${pattern}`);
		} catch (err) {
			showToast("Rule failed: " + err.message);
		}
	});

	// -----------------------------
	// Request-filter tester
	// -----------------------------
	// The form above can only tell you a rule was accepted, not whether it does
	// anything. This runs the server's real matcher over sample headers so a rule
	// can be checked against actual captured traffic before it goes live.
	const EXAMPLE_HEADERS = [
		"User-Agent: Roblox/WinInet",
		"Xeno-Fingerprint: 4f3a91c0",
		"Accept: */*",
		"Content-Type: application/json",
	].join("\n");

	function headersToText(headers) {
		return Object.entries(headers || {})
			.map(([name, value]) => `${name}: ${value}`)
			.join("\n");
	}

	// The live feed already carries the (sanitized) headers of recent requests,
	// so the most useful samples are the ones that actually hit the proxy.
	function renderTesterSamples() {
		const select = $("#testerSample");
		if (!select || document.activeElement === select) return;
		const chosen = select.value;
		select.innerHTML = "";
		const placeholder = document.createElement("option");
		placeholder.value = "";
		placeholder.textContent = liveItems.length
			? "Load headers from a recent request…"
			: "No recent requests captured yet";
		select.appendChild(placeholder);
		liveItems.slice(0, 40).forEach((item, index) => {
			if (!item || !item.Headers) return;
			const option = document.createElement("option");
			option.value = String(index);
			const ua = (item.UserAgent || "no user-agent").slice(0, 40);
			option.textContent = `${timeAgo(item.Date)} — ${item.IP || "?"} — ${ua}`;
			select.appendChild(option);
		});
		if (chosen && select.querySelector(`option[value="${chosen}"]`)) select.value = chosen;
	}

	function draftFromTester() {
		const needle = $("#testerNeedle")?.value.trim() || "";
		if (!needle) return null;
		return {
			header: $("#testerHeader")?.value.trim() || "",
			scope: $("#testerScope")?.value || "either",
			mode: $("#testerMode")?.value || "contains",
			needle,
		};
	}

	function describeRule(info) {
		const scope = HEADER_SCOPE_LABELS[info.Scope] || info.Scope || "?";
		const verb = info.Mode === "exact" ? "is" : info.Mode === "regex" ? "matches" : "contains";
		const target = info.Header ? `"${info.Header}" value` : scope;
		return `${target} ${verb} "${info.Needle || ""}"`;
	}

	function renderTesterResult(result) {
		const panel = $("#testerVerdict");
		const headline = $("#testerHeadline");
		const detail = $("#testerDetail");
		const wrap = $("#testerRulesWrap");
		if (!panel || !headline || !detail) return;
		panel.hidden = false;
		panel.classList.toggle("tester-verdict--blocked", Boolean(result.Blocked));
		panel.classList.toggle("tester-verdict--allowed", !result.Blocked);
		detail.innerHTML = "";

		const draft = result.Draft;
		if (result.Blocked) {
			const by = result.BlockedBy || {};
			headline.textContent = "🚫 This request would be BLOCKED";
			const side = by.MatchedField === "key" ? "header name" : "header value";
			detail.appendChild(
				lineNode(
					`Caught by <strong>${escapeHtml(describeRule(by))}</strong> — the ${side} ` +
						`<code>${escapeHtml(by.MatchedText || "")}</code> on header ` +
						`<code>${escapeHtml(by.MatchedHeader || "")}</code>.`,
				),
			);
		} else {
			headline.textContent = "✅ This request would be allowed through";
			detail.appendChild(
				lineNode(
					`None of your ${result.Rules.length} saved filter(s) match these ${result.HeaderCount} header(s).`,
				),
			);
		}

		if (draft) {
			if (!draft.Valid) {
				const why = escapeHtml(draft.Error || "");
				detail.appendChild(lineNode(`<strong>Draft rule is invalid:</strong> ${why}`));
			} else if (draft.Matched) {
				const side = draft.MatchedField === "key" ? "header name" : "header value";
				detail.appendChild(
					lineNode(
						`<strong>Your draft rule WOULD catch this</strong> — matched the ${side} ` +
							`<code>${escapeHtml(draft.MatchedText || "")}</code> on header ` +
							`<code>${escapeHtml(draft.MatchedHeader || "")}</code>.` +
							(draft.AlreadyBlocked
								? " A saved rule already blocks this request, so adding it would change nothing here."
								: ""),
					),
				);
			} else {
				detail.appendChild(
					lineNode(
						"<strong>Your draft rule would NOT catch this.</strong> Check the header name, or try " +
							"“Contains” instead of “Exact”.",
					),
				);
			}
		}

		if (!wrap) return;
		const tbody = $("#testerRulesTable tbody");
		wrap.hidden = !result.Rules.length;
		if (!tbody) return;
		tbody.innerHTML = "";
		for (const rule of result.Rules) {
			const badge = document.createElement("span");
			const tone = rule.Matched ? (rule.IsFirstMatch ? "badge--bad" : "badge--warn") : "badge--muted";
			badge.className = `badge ${tone}`;
			// Only the first match is credited with the block — the proxy stops there.
			badge.textContent = rule.IsFirstMatch ? "blocks it" : rule.Matched ? "also matches" : "no match";
			tbody.appendChild(
				tr([
					badge,
					describeRule(rule),
					rule.MatchedHeader || "—",
					rule.MatchedText || "—",
				]),
			);
		}
	}

	// Every interpolation into this must be escaped by the caller: the sample
	// headers being described are attacker-authored by definition — that is the
	// whole point of pasting them in here.
	function lineNode(html) {
		const div = document.createElement("div");
		div.innerHTML = html;
		return div;
	}

	async function runFilterTest() {
		const headers = $("#testerHeaders")?.value || "";
		if (!headers.trim()) {
			showToast("Paste some headers to test against");
			return;
		}
		try {
			const res = await api("/admin/headers/test", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ headers, draft: draftFromTester() }),
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.Message || String(res.status));
			renderTesterResult(data);
		} catch (err) {
			showToast("Test failed: " + err.message);
		}
	}

	$("#testerRun")?.addEventListener("click", e => withBusy(e.currentTarget, "Testing…", runFilterTest));
	$("#testerExample")?.addEventListener("click", () => {
		const box = $("#testerHeaders");
		if (box) box.value = EXAMPLE_HEADERS;
	});
	$("#testerSample")?.addEventListener("change", e => {
		const item = liveItems[Number(e.target.value)];
		const box = $("#testerHeaders");
		if (!item || !box) return;
		box.value = headersToText(item.Headers);
		showToast(`Loaded headers from ${item.IP || "a recent request"}`);
	});
	// Carry whatever is in the add-rule form into the tester, so "would this work?"
	// is one click away from "I am about to add this".
	$("#testerCopyFromForm")?.addEventListener("click", () => {
		const copy = (from, to) => {
			const src = $(from);
			const dst = $(to);
			if (src && dst) dst.value = src.value;
		};
		copy("#headerRuleHeader", "#testerHeader");
		copy("#headerRuleScope", "#testerScope");
		copy("#headerRuleMode", "#testerMode");
		copy("#headerRuleNeedle", "#testerNeedle");
		showToast("Copied the rule above into the tester");
	});
	// Enter in the draft-text box runs the test rather than doing nothing.
	$("#testerNeedle")?.addEventListener("keydown", e => {
		if (e.key === "Enter") {
			e.preventDefault();
			runFilterTest();
		}
	});

	// -----------------------------
	// Tarpit controls
	// -----------------------------
	async function saveTarpitSettings(settings, message) {
		try {
			const res = await api("/admin/settings", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ settings }),
			});
			const data = await res.json();
			if (!res.ok) throw new Error(String(res.status));
			const failures = Object.entries(data.Results || {}).filter(([, msg]) => msg !== "Success");
			if (failures.length) throw new Error(failures.map(([key, msg]) => `${key}: ${msg}`).join(", "));
			showToast(message);
			refreshAll(true);
		} catch (err) {
			showToast("Could not save: " + err.message);
			refreshAll(true); // Put the controls back to what the server actually has.
		}
	}

	$("#tarpitEnabled")?.addEventListener("change", e => {
		saveTarpitSettings({ tarpit_enabled: e.target.checked ? 1 : 0 }, e.target.checked ? "Tarpit on" : "Tarpit off");
	});

	$$(".tarpit-cat__box").forEach(box => {
		box.addEventListener("change", () => {
			saveTarpitSettings(
				{ [`tarpit_on_${box.dataset.category}`]: box.checked ? 1 : 0 },
				box.checked ? "Now holding these" : "No longer holding these",
			);
		});
	});

	$("#tarpitForm")?.addEventListener("submit", e => {
		e.preventDefault();
		const min = Number($("#tarpitMin")?.value);
		const max = Number($("#tarpitMax")?.value);
		const concurrent = Number($("#tarpitConcurrent")?.value);
		if (min > max) {
			showToast("The minimum hold cannot be longer than the maximum");
			return;
		}
		saveTarpitSettings(
			{ tarpit_min_seconds: min, tarpit_max_seconds: max, tarpit_max_concurrent: concurrent },
			"Tarpit settings saved",
		);
	});

	$("#clearTarpitBtn")?.addEventListener("click", e =>
		withBusy(e.currentTarget, "Clearing…", async () => {
			try {
				const res = await api("/admin/data/clear", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ target: "tarpit" }),
				});
				if (!res.ok) throw new Error(String(res.status));
				renderTarpit._stats = {};
				renderTarpit._ips = {};
				renderTarpit._rates = [];
				showToast("Tarpit stats cleared");
				refreshAll(true);
			} catch (err) {
				showToast("Could not clear: " + err.message);
			}
		}),
	);

	$("#timingSplitToggle")?.addEventListener("change", () => {
		renderProxyTimings({});
		renderMethodTimings({});
	});

	// Header rules: add
	$("#headerRuleForm")?.addEventListener("submit", async e => {
		e.preventDefault();
		const header = $("#headerRuleHeader")?.value.trim() || "";
		const scope = $("#headerRuleScope")?.value || "either";
		const mode = $("#headerRuleMode")?.value || "contains";
		const needle = $("#headerRuleNeedle")?.value.trim();
		const note = $("#headerRuleNote")?.value.trim() || "";
		// Optional and consequential: a message tells the blocked caller they were
		// filtered rather than merely rate-limited. See the warning in the form.
		const message = $("#headerRuleMessage")?.value.trim() || "";
		if (!needle) return;
		try {
			const res = await api("/admin/headers/rule", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ header, scope, mode, needle, note, message }),
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.Message || String(res.status));
			renderHeaderRules({ HeaderRules: data.HeaderRules });
			$("#headerRuleHeader").value = "";
			$("#headerRuleNeedle").value = "";
			$("#headerRuleNote").value = "";
			if ($("#headerRuleMessage")) $("#headerRuleMessage").value = "";
			showToast("Header rule added");
		} catch (err) {
			showToast("Header rule failed: " + err.message);
		}
	});

	// Header-blocked attempts export
	$("#exportHeaderBlocked")?.addEventListener("click", async () => {
		try {
			const d = await diagnosticsForExport();
			const lines = [
				"Rule,Scope,Mode,Needle,Blocked,UniqueIPs,LastHeader,TriggeredBy,MatchedText,LastIP,LastPath,LastRequestTime",
			];
			for (const [id, info] of Object.entries(d.HeaderBlockedAttempts || {})) {
				const uniqueIps = info.IPs ? Object.keys(info.IPs).length : 0;
				lines.push(
					toCSVRow([
						id,
						info.Scope || "",
						info.Mode || "",
						info.Needle || "",
						info.Count || 0,
						uniqueIps,
						info.LastHeader || "",
						info.LastField || "",
						info.LastMatch || "",
						info.LastIP || "",
						info.LastPath || "",
						info.LastRequestTime || 0,
					]),
				);
			}
			download(`roxy_header_blocked_${Date.now()}.csv`, lines.join("\n"));
			showToast("Header-blocked attempts exported");
		} catch {
			showToast("Export failed");
		}
	});

	// Endpoints export (template rows + their concrete IDs)
	$("#exportEndpoints")?.addEventListener("click", async () => {
		try {
			const d = await diagnosticsForExport();
			const lines = ["Level,Endpoint,Count,Methods,LastRequestTime"];
			const methodsOf = m =>
				Object.entries(m || {})
					.map(([k, n]) => `${k}:${n}`)
					.join(" ");
			for (const [template, info] of Object.entries(d.Endpoints || {})) {
				lines.push(toCSVRow(["template", template, info.Count || 0, methodsOf(info.Methods), info.LastRequestTime || 0]));
				for (const [concrete, cinfo] of Object.entries(info.Concrete || {})) {
					lines.push(
						toCSVRow(["concrete", concrete, cinfo.Count || 0, methodsOf(cinfo.Methods), cinfo.LastRequestTime || 0]),
					);
				}
			}
			download(`roxy_endpoints_${Date.now()}.csv`, lines.join("\n"));
			showToast("Endpoints exported");
		} catch {
			showToast("Export failed");
		}
	});

	// Blocked endpoint attempts export
	$("#exportBlockedAttempts")?.addEventListener("click", async () => {
		try {
			const d = await diagnosticsForExport();
			const lines = ["Endpoint,Attempts,UniqueIPs,Methods,Pattern,LastIP,LastRequestTime"];
			for (const [path, info] of Object.entries(d.BlockedEndpointAttempts || {})) {
				const methods = Object.entries(info.Methods || {})
					.map(([m, n]) => `${m}:${n}`)
					.join(" ");
				const uniqueIps = info.IPs ? Object.keys(info.IPs).length : 0;
				lines.push(
					toCSVRow([
						path,
						info.Count || 0,
						uniqueIps,
						methods,
						info.Pattern || "",
						info.LastIP || "",
						info.LastRequestTime || 0,
					]),
				);
			}
			download(`roxy_blocked_attempts_${Date.now()}.csv`, lines.join("\n"));
			showToast("Blocked attempts exported");
		} catch {
			showToast("Export failed");
		}
	});

	// Rate-limited endpoint attempts export
	$("#exportRateLimitedAttempts")?.addEventListener("click", async () => {
		try {
			const d = await diagnosticsForExport();
			const lines = ["Endpoint,Attempts,UniqueIPs,Methods,Pattern,LastIP,LastRequestTime"];
			for (const [path, info] of Object.entries(d.RateLimitedAttempts || {})) {
				const methods = Object.entries(info.Methods || {})
					.map(([m, n]) => `${m}:${n}`)
					.join(" ");
				const uniqueIps = info.IPs ? Object.keys(info.IPs).length : 0;
				lines.push(
					toCSVRow([
						path,
						info.Count || 0,
						uniqueIps,
						methods,
						info.Pattern || "",
						info.LastIP || "",
						info.LastRequestTime || 0,
					]),
				);
			}
			download(`roxy_rate_limited_attempts_${Date.now()}.csv`, lines.join("\n"));
			showToast("Rate-limited attempts exported");
		} catch {
			showToast("Export failed");
		}
	});

	// Exploit summary export
	$("#exportExploitSummary")?.addEventListener("click", async () => {
		try {
			const d = await diagnosticsForExport();
			const lines = ["Reason,Count,LastSeen"];
			for (const [reason, info] of Object.entries(d.ExploitSummary || {})) {
				lines.push(toCSVRow([reason, info.Count || 0, info.LastSeen || 0]));
			}
			download(`roxy_exploit_summary_${Date.now()}.csv`, lines.join("\n"));
			showToast("Exploit summary exported");
		} catch {
			showToast("Export failed");
		}
	});

	// Probes export
	$("#exportProbes")?.addEventListener("click", async () => {
		try {
			const d = await diagnosticsForExport();
			const lines = ["Date,IP,UserAgent,Reason"];
			(Array.isArray(d.ExploitAttempts) ? d.ExploitAttempts : []).forEach(r => {
				lines.push(toCSVRow([r.Date || 0, r.IP || "", r.UserAgent || "", r.Reason || ""]));
			});
			download(`roxy_probes_${Date.now()}.csv`, lines.join("\n"));
			showToast("Probes exported");
		} catch {
			showToast("Export failed");
		}
	});

	// Logins export
	$("#exportLogins")?.addEventListener("click", async () => {
		try {
			const d = await diagnosticsForExport();
			const lines = ["Date,IP,Successful"];
			(Array.isArray(d.LoginAttempts) ? d.LoginAttempts : []).forEach(r => {
				lines.push(toCSVRow([r.Date || 0, r.IP || "", r.Successful ? "success" : "fail"]));
			});
			download(`roxy_logins_${Date.now()}.csv`, lines.join("\n"));
			showToast("Logins exported");
		} catch {
			showToast("Export failed");
		}
	});

	// Tools: download diagnostics JSON
	$("#downloadJsonBtn")?.addEventListener("click", async () => {
		try {
			const d = await diagnosticsForExport();
			const a = document.createElement("a");
			a.href = URL.createObjectURL(new Blob([JSON.stringify(d, null, 2)], { type: "application/json" }));
			a.download = `roxy_diagnostics_${Date.now()}.json`;
			a.click();
			setTimeout(() => URL.revokeObjectURL(a.href), 1000);
			showToast("Diagnostics downloaded");
		} catch {
			showToast("Download failed");
		}
	});

	// Tools: force revalidate tokens (synchronous; reports which are still active)
	$("#forceRevalidateBtn")?.addEventListener("click", async e => {
		await withBusy(e.currentTarget, "Revalidating…", async () => {
			try {
				const res = await api("/admin/tokens/force_revalidate", { method: "POST" });
				if (!res.ok) throw new Error(String(res.status));
				const data = await res.json();
				const total = Number(data.Total || 0);
				if (!total) {
					showToast("No tokens loaded to revalidate", 3200);
				} else {
					const dead = (data.Tokens || []).filter(t => t.Active === false).map(t => t.Masked);
					let msg = `${data.Active}/${total} token(s) active`;
					if (dead.length) msg += ` — expired: ${dead.join(", ")}`;
					showToast(msg, 4200);
				}
				await refreshAll(true);
			} catch {
				showToast("Revalidation failed");
			}
		});
	});

	// Tools: health check — server up + each token live + rotation exit IP
	$("#healthCheckBtn")?.addEventListener("click", async e => {
		// This one really can take tens of seconds (it talks to Roblox), so the
		// button has to visibly hold rather than just fire a toast and look idle.
		await withBusy(e.currentTarget, "Checking…", async () => {
			try {
				const res = await api("/admin/health_check", { method: "POST" });
				if (!res.ok) throw new Error(String(res.status));
				const d = await res.json();
				const parts = [`Server ${d.Status}${d.Paused ? " (PAUSED)" : ""}`];
				parts.push(`Tokens: ${d.TokensActive}/${d.TokensTotal} active`);
				const rot = d.Rotation || {};
				if (!rot.Configured) parts.push("Rotation: not configured");
				else if (rot.ExitIP) parts.push(`Rotation OK — exit IP ${rot.ExitIP}`);
				else parts.push(`Rotation FAILED — ${rot.Error || "no IP"}`);
				showToast(parts.join(" • "), 6000);
				await refreshAll(true);
			} catch {
				showToast("Health check FAILED — the server did not respond", 3200);
			}
		});
	});

	// Rotation: verify exit IP through the proxy (rotation only; no token spend)
	$("#verifyRotationBtn")?.addEventListener("click", async e => {
		await withBusy(e.currentTarget, "Checking…", async () => {
			try {
				const res = await api("/admin/rotation/verify", { method: "POST" });
				if (!res.ok) throw new Error(String(res.status));
				const d = await res.json();
				if (!d.Configured) showToast("Rotation is not configured", 3500);
				else if (d.ExitIP) showToast(`Rotation working — exit IP ${d.ExitIP}`, 4500);
				else showToast(`Rotation FAILED — ${d.Error || "no IP returned"}`, 5000);
				await refreshAll(true);
			} catch {
				showToast("Rotation check failed");
			}
		});
	});

	// Tools: clear all data
	$("#clearAllBtn")?.addEventListener("click", async () => {
		if (!confirm("Permanently clear ALL diagnostics data (every section)? Settings, tokens, rules and trusted devices are kept. This cannot be undone.")) {
			return;
		}
		try {
			const res = await api("/admin/data/clear", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ target: "all" }),
			});
			if (!res.ok) throw new Error(String(res.status));
			showToast("All diagnostics data cleared");
			await refreshAll(true);
		} catch {
			showToast("Failed to clear all data");
		}
	});

	// Service Controls: revoke trusted devices
	$("#revokeTrustedBtn")?.addEventListener("click", async () => {
		if (!confirm("Revoke ALL trusted devices? Every device (including this one) will need full 2FA next login.")) {
			return;
		}
		try {
			const res = await api("/admin/trusted_devices/revoke", { method: "POST" });
			if (!res.ok) throw new Error(String(res.status));
			const data = await res.json();
			showToast(`Revoked ${data.Revoked ?? 0} trusted device(s)`);
			await refreshAll(true);
		} catch {
			showToast("Failed to revoke trusted devices");
		}
	});

	// Errors export
	$("#exportErrors")?.addEventListener("click", async () => {
		try {
			const d = await diagnosticsForExport();
			const lines = ["Error,Count,FirstSeen,LastSeen,LastDetail"];
			for (const [sig, info] of Object.entries(d.Errors || {})) {
				lines.push(toCSVRow([sig, info.Count || 0, info.FirstSeen || 0, info.LastSeen || 0, info.LastDetail || ""]));
			}
			download(`roxy_errors_${Date.now()}.csv`, lines.join("\n"));
			showToast("Errors exported");
		} catch {
			showToast("Export failed");
		}
	});

	// Fingerprints export (header names + their values + user-agents)
	// Values live behind the per-header endpoint now, so the export pulls them one
	// header at a time rather than expecting them in the poll payload.
	async function exportFingerprints(headerStore, uaStore, blocked, filename) {
		const lines = ["Type,Header,Value,Count,LastSeen"];
		for (const [name, info] of Object.entries(headerStore || {})) {
			lines.push(toCSVRow(["header", name, "", info.Count || 0, info.LastSeen || 0]));
			if (info.ValuesIgnored || !info.ValueCount) continue;
			try {
				const query = `name=${encodeURIComponent(name)}&blocked=${blocked ? 1 : 0}&limit=1000`;
				const res = await api(`/admin/fingerprints/values?${query}`);
				if (!res.ok) continue;
				const payload = await res.json();
				for (const [val, vinfo] of Object.entries(payload.Values || {})) {
					lines.push(toCSVRow(["header-value", name, val, vinfo.Count || 0, vinfo.LastSeen || 0]));
				}
			} catch {
				lines.push(toCSVRow(["header-value", name, "(could not be loaded)", 0, 0]));
			}
		}
		for (const [ua, info] of Object.entries(uaStore || {})) {
			lines.push(toCSVRow(["user-agent", "", ua, info.Count || 0, info.LastSeen || 0]));
		}
		download(filename, lines.join("\n"));
	}
	$("#exportFingerprints")?.addEventListener("click", async e => {
		await withBusy(e.currentTarget, "Exporting…", async () => {
			try {
				const d = await diagnosticsForExport();
				await exportFingerprints(d.HeaderNames, d.UserAgents, false, `roxy_fingerprints_${Date.now()}.csv`);
				showToast("Fingerprints exported");
			} catch {
				showToast("Export failed");
			}
		});
	});
	$("#exportBlockedFingerprints")?.addEventListener("click", async e => {
		await withBusy(e.currentTarget, "Exporting…", async () => {
			try {
				const d = await diagnosticsForExport();
				await exportFingerprints(
					d.BlockedHeaderNames,
					d.BlockedUserAgents,
					true,
					`roxy_blocked_fingerprints_${Date.now()}.csv`,
				);
				showToast("Blocked fingerprints exported");
			} catch {
				showToast("Export failed");
			}
		});
	});

	// -----------------------------
	// Threat level
	// -----------------------------
	// One line at the top that answers "is something wrong right now?" without
	// reading nine tables. It is deliberately conservative: it reports what the
	// numbers say and names the section that explains it, rather than trying to
	// classify an attack.
	function renderThreatLevel(d) {
		const banner = $("#threatBanner");
		if (!banner) return;
		const ips = d.IpActivity || {};
		const callers = d.Callers || {};
		const busiest = arr => arr.reduce((best, cur) => (cur[1].Rate1 > (best?.[1]?.Rate1 ?? -1) ? cur : best), null);
		const topIp = busiest(Object.entries(ips));
		const topCaller = busiest(Object.entries(callers));
		const robloxLimited = Number((d.StatusSources?.Roblox || {})["429"] || 0);
		const notes = [];
		let level = "ok";

		if (robloxLimited > 0) {
			level = "bad";
			notes.push(`Roblox has rate-limited us ${fmtCount(robloxLimited)} time(s) — reduce upstream volume.`);
		}
		const rate = Number(topCaller?.[1]?.Rate1 || 0);
		if (rate >= 120) {
			level = "bad";
			notes.push(`Place ${topCaller[0]} is sending ${fmtCount(rate)} req/min.`);
		} else if (rate >= 30) {
			if (level !== "bad") level = "warn";
			notes.push(`Place ${topCaller[0]} is sending ${fmtCount(rate)} req/min.`);
		}
		const ipRate = Number(topIp?.[1]?.Rate1 || 0);
		if (ipRate >= 120 && !notes.length) {
			level = "warn";
			notes.push(`${topIp[0]} is sending ${fmtCount(ipRate)} req/min.`);
		}
		if (d?.Pause?.Paused) {
			level = "warn";
			notes.push("The proxy is paused.");
		}
		if (d?.ThrottleAll?.ThrottleAll) {
			if (level === "ok") level = "warn";
			notes.push("Throttle-all is on.");
		}
		const tokens = Number((d.ProxyHealth?.Tokens || {}).Count || 0);
		if (!tokens) {
			level = "bad";
			notes.push("No auth tokens are loaded.");
		}
		banner.hidden = level === "ok" && !notes.length;
		banner.className = `threat-banner threat-banner--${level}`;
		const label = level === "bad" ? "Needs attention" : level === "warn" ? "Worth a look" : "All clear";
		banner.innerHTML =
			`<strong>${label}</strong> ${escapeHtml(notes.join(" "))}` +
			(level !== "ok" ? ' <a href="#section-callers">Investigate →</a>' : "");
	}

	// -----------------------------
	// Sortable table registration
	// -----------------------------
	// Registered once at boot. Tables that render as a plain list of rows use the
	// generic DOM sorter; the endpoint tree redraws itself instead, because
	// reordering its rows in place would separate hosts from their children.
	const SORTABLE_TABLES = [
		"#talkersTable",
		"#callersTable",
		"#throttleWatchTable",
		"#refusalsTable",
		"#statusSourceTable",
		"#internalTable",
		"#blocksTable",
		"#rulesTable",
		"#bypassTable",
		"#headerRulesTable",
		"#blockedAttemptsTable",
		"#rateLimitedAttemptsTable",
		"#headerBlockedTable",
		"#tokensTable",
		"#statusDetailedTable",
		"#retryStatusTable",
		"#retryReasonTable",
		"#requestFailuresTable",
		"#crawlsTable",
		"#throttledTable",
		"#probeTable",
		"#exploitSummaryTable",
		"#headerNamesTable",
		"#userAgentsTable",
		"#blockedHeaderNamesTable",
		"#blockedUserAgentsTable",
		"#ignoredHeadersTable",
		"#errorsTable",
		"#loginsTable",
		"#workersTable",
		"#rotateIpsTable",
		"#storeSizesTable",
		"#tarpitCategoryTable",
		"#tarpitIpsTable",
	];

	function initAllSortables() {
		for (const sel of SORTABLE_TABLES) initSortable(sel);
		// The endpoint tree sorts per level, so a header click re-runs its renderer
		// rather than shuffling rows.
		initSortable("#endpointsTable", () => renderEndpoints({}));
	}

	// -----------------------------
	// New controls
	// -----------------------------
	$("#resetWorkerCounts")?.addEventListener("click", async e => {
		if (!confirm("Zero the request counters for every worker?")) return;
		await withBusy(e.currentTarget, "Resetting…", async () => {
			try {
				const res = await api("/admin/workers/reset", { method: "POST" });
				showToast(res.ok ? "Worker request counts reset" : "Reset failed");
				refreshAll(true);
			} catch {
				showToast("Reset failed");
			}
		});
	});

	$("#clearCaptures")?.addEventListener("click", async e => {
		await withBusy(e.currentTarget, "Clearing…", async () => {
			try {
				const res = await api("/admin/live/clear", { method: "POST" });
				liveBodyCache.clear();
				showToast(res.ok ? "Live feed and captured bodies cleared" : "Clear failed");
				refreshAll(true);
			} catch {
				showToast("Clear failed");
			}
		});
	});

	$("#lookupForm")?.addEventListener("submit", e => {
		e.preventDefault();
		const id = $("#lookupId")?.value.trim();
		if (!id) return;
		runLookup(id, $("#lookupKind")?.value || "place");
	});

	for (const sel of ["#talkersFilter", "#callersFilter", "#liveOutcomeFilter"]) {
		$(sel)?.addEventListener("input", () => {
			if (!lastDiagnostics) return;
			if (sel === "#liveOutcomeFilter") renderLiveFeed({});
			else renderActivity({});
		});
		$(sel)?.addEventListener("change", () => {
			if (!lastDiagnostics) return;
			if (sel === "#liveOutcomeFilter") renderLiveFeed({});
			else renderActivity({});
		});
	}

	// -----------------------------
	// Keyboard: jump to a section
	// -----------------------------
	// Thirty-odd sections is more than a sidebar scan is good for during an
	// incident. "/" focuses the section jump box; Escape leaves it.
	const jump = $("#sectionJump");
	if (jump) {
		document.addEventListener("keydown", e => {
			if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "")) {
				e.preventDefault();
				jump.focus();
				jump.select();
			}
			if (e.key === "Escape" && document.activeElement === jump) jump.blur();
		});
		const jumpTo = () => {
			const q = jump.value.trim().toLowerCase();
			if (!q) return;
			const link = $$("#appNav .nav__link").find(a => a.textContent.toLowerCase().includes(q));
			if (link) {
				document.querySelector(link.getAttribute("href"))?.scrollIntoView({ behavior: "smooth", block: "start" });
				jump.blur();
			} else showToast("No section matches that");
		};
		jump.addEventListener("keydown", e => {
			if (e.key === "Enter") {
				e.preventDefault();
				jumpTo();
			}
		});
	}

	// Initial load
	function boot() {
		initAllSortables();
		refreshAll(true);
	}
	document.addEventListener("DOMContentLoaded", boot);
	if (document.readyState !== "loading") boot();
})();
