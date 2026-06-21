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
	// A timestamp cell: relative time as text, exact time on hover.
	function tsNode(ts) {
		const span = document.createElement("span");
		span.textContent = timeAgo(ts);
		if (typeof ts === "number" && isFinite(ts) && ts > 0) span.title = toTS(ts);
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

	// Build a <tr> with cells
	function tr(cells = []) {
		const tr = document.createElement("tr");
		cells.forEach(c => {
			const td = document.createElement("td");
			if (c instanceof Node) td.appendChild(c);
			else td.textContent = c;
			tr.appendChild(td);
		});
		return tr;
	}

	function escapeHtml(s) {
		return String(s)
			.replaceAll("&", "&amp;")
			.replaceAll("<", "&lt;")
			.replaceAll(">", "&gt;")
			.replaceAll('"', "&quot;");
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
		const broken = !p.Writable || (p.LastErrorAt && p.LastErrorAt > (p.LastWriteOK || 0));
		setText("persist_status", broken ? "PROBLEM" : "OK");
		$("#persist_status")?.classList.toggle("text-danger", Boolean(broken));
		setText("persist_last", p.LastWriteOK ? timeAgo(p.LastWriteOK) : "never");
		setText("persist_file", p.DataFile || "—");
		const err = $("#persist_error");
		if (err) err.textContent = broken && p.LastError ? ` • ${p.LastError}` : "";
	}

	function renderProxyTimings(d) {
		const pc = d.ProxyRequestCounts || {};
		const methods = ["GET", "POST", "PATCH", "PUT", "DELETE"];
		for (const m of methods) {
			const row = pc[m] || { TotalTime: 0, Count: 0, Min: 0, Max: 0, LastRequestTime: 0 };
			const pref = `pt_${m.toLowerCase()}`;
			setText(`${pref}_c`, String(row.Count || 0));
			setText(`${pref}_tot`, fmtNum(row.Count ? row.TotalTime / row.Count : 0, 3));
			const minVal = row.Min === Infinity ? 0 : row.Min || 0;
			setText(`${pref}_min`, fmtNum(minVal, 3));
			setText(`${pref}_max`, fmtNum(row.Max || 0, 3));
			setText(`${pref}_last`, row.LastRequestTime ? timeAgo(row.LastRequestTime) : "—");
		}
	}

	function renderTokens(d) {
		const tbody = $("#tokensTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const list = Array.isArray(d.Tokens) ? d.Tokens : [];
		if (list.length === 0) {
			tbody.appendChild(tr(["—", "No tokens loaded", "—", "—"]));
			return;
		}
		list.forEach((t, i) => {
			const masked = t?.Masked ?? "…***";
			const being = Boolean(t?.BeingValidated);
			const uses = Number(t?.Uses || 0);
			tbody.appendChild(tr([String(i + 1), masked, being ? "Yes" : "No", String(uses)]));
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

	function renderHealth(d) {
		const h = d.ProxyHealth || {};
		const da = h.DirectAPI || {};
		const rp = h.RoProxy || {};
		const tk = h.Tokens || {};

		setText("health_direct", da.IsInCooldown ? "COOLDOWN" : "OK");
		setText("direct_last", da.LastRequestTime ? timeAgo(da.LastRequestTime) : "—");
		setText("direct_cooldown", String(Boolean(da.IsInCooldown)));
		setText("direct_count", String(da.Count || 0));

		setText("health_roproxy", rp.IsInCooldown ? "COOLDOWN" : "OK");
		setText("roproxy_last", rp.LastRequestTime ? timeAgo(rp.LastRequestTime) : "—");
		setText("roproxy_cooldown", String(Boolean(rp.IsInCooldown)));
		setText("roproxy_count", String(rp.Count || 0));

		setText("health_tokens_count", String(tk.Count ?? 0));
		setText("health_tokens_expired", String(tk.ExpiredCount ?? 0));
		setText("health_tokens_validating", String(tk.BeingValidatedCount ?? 0));

		const started = Number(d.WorkerStartedAt || 0);
		const server = Number(d.ServerTime || 0);
		if (started && server) {
			setText("health_uptime", fmtDuration(server - started));
			setText("health_started", toTS(started));
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
			setText("pauseBannerSince", paused && since ? `(since ${toTS(since)})` : "");
		}
	}

	function renderVisitors(d) {
		const v = d.VisitorCounts || {};
		setText("kpi_human", String(v.Human ?? 0));
		setText("kpi_crawler", String(v.Crawler ?? 0));
	}

	let endpointEntries = []; // cached for filtering without refetch
	const expandedHosts = new Set(); // which root hosts are expanded (survives refreshes)
	const methodsText = methods =>
		Object.entries(methods || {})
			.map(([m, n]) => `${m}:${n}`)
			.join(", ") || "—";

	// Endpoints grouped by root service (games.roblox.com, avatar.roblox.com...).
	// Clicking a host row expands into the individual endpoints under it.
	function renderEndpoints(d) {
		if (d.Endpoints) {
			endpointEntries = Object.entries(d.Endpoints);
			endpointEntries.sort((a, b) => (b[1].Count || 0) - (a[1].Count || 0));
		}
		const tbody = $("#endpointsTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const q = ($("#endpointsFilter")?.value || "").trim().toLowerCase();

		const hosts = new Map();
		for (const [path, info] of endpointEntries) {
			if (q && !path.toLowerCase().includes(q)) continue;
			const host = path.split("/", 1)[0];
			let group = hosts.get(host);
			if (!group) {
				group = { count: 0, last: 0, methods: {}, children: [] };
				hosts.set(host, group);
			}
			group.count += Number(info.Count || 0);
			group.last = Math.max(group.last, Number(info.LastRequestTime || 0));
			for (const [m, n] of Object.entries(info.Methods || {})) {
				group.methods[m] = (group.methods[m] || 0) + Number(n || 0);
			}
			group.children.push([path, info]);
		}

		const sortedHosts = [...hosts.entries()].sort((a, b) => b[1].count - a[1].count);
		if (sortedHosts.length === 0) {
			tbody.appendChild(tr([q ? "No endpoints match the filter" : "No endpoints recorded yet", "—", "—", "—"]));
			return;
		}
		for (const [host, group] of sortedHosts) {
			const expanded = expandedHosts.has(host) || Boolean(q); // filtering implies expanded
			const hostRow = document.createElement("tr");
			hostRow.className = "endpoint-host";
			hostRow.setAttribute("aria-expanded", String(expanded));

			const tdHost = document.createElement("td");
			const chevron = document.createElement("span");
			chevron.className = "endpoint-host__chevron";
			chevron.textContent = expanded ? "▾" : "▸";
			const name = document.createElement("strong");
			name.textContent = ` ${host} `;
			const meta = document.createElement("span");
			meta.className = "endpoint-host__count";
			meta.textContent = `(${group.children.length} endpoint${group.children.length === 1 ? "" : "s"})`;
			tdHost.append(chevron, name, meta);
			hostRow.appendChild(tdHost);
			[String(group.count), methodsText(group.methods)].forEach(text => {
				const td = document.createElement("td");
				td.textContent = text;
				hostRow.appendChild(td);
			});
			const tdLast = document.createElement("td");
			tdLast.appendChild(tsNode(group.last));
			hostRow.appendChild(tdLast);

			hostRow.addEventListener("click", () => {
				if (expandedHosts.has(host)) expandedHosts.delete(host);
				else expandedHosts.add(host);
				renderEndpoints({});
			});
			tbody.appendChild(hostRow);

			if (!expanded) continue;
			for (const [path, info] of group.children) {
				const sub = path.slice(host.length) || "/";
				const row = tr([`└ ${sub}`, String(info.Count || 0), methodsText(info.Methods), tsNode(info.LastRequestTime)]);
				row.className = "endpoint-child";
				row.title = path;
				tbody.appendChild(row);
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

	let liveItems = []; // cached for filtering without refetch
	const liveKey = item => `${item.Date}|${item.IP}|${item.URL}`;
	function renderLiveFeed(d) {
		if (Array.isArray(d.LiveRequests)) liveItems = d.LiveRequests;
		const feed = $("#liveFeed");
		if (!feed) return;
		const q = ($("#liveFilter")?.value || "").trim().toLowerCase();
		const items = liveItems.filter(
			it => !q || `${it.URL || ""} ${it.IP || ""} ${it.Method || ""}`.toLowerCase().includes(q),
		);
		setText("liveCount", `${items.length} shown`);
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
			empty.textContent = q ? "No requests match the filter." : "No requests recorded yet.";
			feed.appendChild(empty);
			return;
		}
		for (const item of items) {
			const card = document.createElement("details");
			card.className = "live-item";
			card.dataset.key = liveKey(item);
			if (openKeys.has(card.dataset.key)) card.open = true;
			const code = Number(item.StatusCode || 0);
			const codeClass = code >= 200 && code < 300 ? "ok" : "bad";

			const summary = document.createElement("summary");
			summary.className = "live-item__summary";
			summary.innerHTML =
				`<span class="badge badge--method">${escapeHtml(item.Method || "?")}</span>` +
				`<span class="badge badge--${codeClass}">${code || "?"}</span>` +
				`<span class="live-item__url">${escapeHtml(item.URL || "")}</span>` +
				`<span class="live-item__meta">${escapeHtml(item.IP || "")} • ${escapeHtml(timeAgo(item.Date))}</span>`;
			card.appendChild(summary);

			const body = document.createElement("div");
			body.className = "live-item__body";
			const ua = escapeHtml(item.UserAgent || "—");
			const headers = escapeHtml(JSON.stringify(item.Headers || {}, null, 2));
			const reqBody = escapeHtml(item.Body || "");
			body.innerHTML =
				`<div class="live-item__row"><strong>Time:</strong> ${escapeHtml(toTS(item.Date))}</div>` +
				`<div class="live-item__row"><strong>User-Agent:</strong> ${ua}</div>` +
				`<div class="live-item__row"><strong>Headers:</strong><pre>${headers}</pre></div>` +
				(reqBody ? `<div class="live-item__row"><strong>Body:</strong><pre>${reqBody}</pre></div>` : "");
			card.appendChild(body);
			feed.appendChild(card);
		}
	}

	const SETTING_LABELS = {
		allowed_requests_per_minute: "Allowed requests per period",
		throttle_reset_duration: "Throttle reset duration (s)",
		stale_ip_duration: "Stale IP duration (s)",
		direct_api_cooldown: "Direct API cooldown (s)",
		roproxy_cooldown: "RoProxy cooldown (s)",
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
		max_endpoint_records: "Endpoint records kept",
		token_budget_requests: "Token budget: max requests",
		token_budget_window: "Token budget: window (s)",
	};

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
		for (const [key, info] of Object.entries(settings)) {
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

	function renderEndpointBlocks(d) {
		const tbody = $("#blocksTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const entries = Object.entries(d.EndpointBlocks || {});
		if (entries.length === 0) {
			tbody.appendChild(tr(["—", "No endpoints blocked", "—", ""]));
			return;
		}
		for (const [pattern, info] of entries) {
			const btn = document.createElement("button");
			btn.className = "btn btn--outline btn--sm";
			btn.textContent = "Unblock";
			btn.addEventListener("click", () => unblockEndpoint(pattern));
			tbody.appendChild(tr([pattern, info.Note || "—", tsNode(info.Added), btn]));
		}
	}

	function renderEndpointRules(d) {
		const tbody = $("#rulesTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const entries = Object.entries(d.EndpointRules || {});
		if (entries.length === 0) {
			tbody.appendChild(tr(["—", "—", "—", "—", ""]));
			return;
		}
		for (const [pattern, info] of entries) {
			const btn = document.createElement("button");
			btn.className = "btn btn--outline btn--sm";
			btn.textContent = "Remove";
			btn.addEventListener("click", () => clearEndpointRule(pattern));
			tbody.appendChild(
				tr([pattern, String(info.Limit ?? "—"), String(info.Period ?? "—"), tsNode(info.Added), btn]),
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
	function renderHeaderRules(d) {
		const tbody = $("#headerRulesTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const entries = Object.entries(d.HeaderRules || {});
		if (entries.length === 0) {
			tbody.appendChild(tr(["—", "—", "No header rules", "—", "—", ""]));
			return;
		}
		for (const [id, info] of entries) {
			const btn = document.createElement("button");
			btn.className = "btn btn--outline btn--sm";
			btn.textContent = "Remove";
			btn.addEventListener("click", () => removeHeaderRule(id));
			tbody.appendChild(
				tr([
					HEADER_SCOPE_LABELS[info.Scope] || info.Scope || "—",
					info.Mode === "exact" ? "Exact" : "Contains",
					info.Needle || "—",
					info.Note || "—",
					tsNode(info.Added),
					btn,
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
			const ruleDesc = `${scope} ${info.Mode === "exact" ? "is" : "contains"} "${info.Needle || ""}"`;
			const uniqueIps = info.IPs ? Object.keys(info.IPs).length : 0;
			tbody.appendChild(
				tr([
					ruleDesc,
					String(info.Count || 0),
					String(uniqueIps),
					info.LastHeader || "—",
					info.LastIP || "—",
					info.LastPath || "—",
					tsNode(info.LastRequestTime),
				]),
			);
		}
		if (entries.length === 0) {
			tbody.appendChild(tr(["No header-blocked requests", "0", "0", "—", "—", "—", "—"]));
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
	async function fetchDiagnostics() {
		const res = await api("/admin/diagnostics", { method: "GET" });
		if (!res.ok) throw new Error("Diagnostics fetch failed: " + res.status);
		lastFetchedAt = Date.now() / 1000;
		return await res.json();
	}

	// Tick the "Updated Xs ago" chip without refetching.
	setInterval(() => {
		if (lastFetchedAt) setText("lastUpdatedChip", `Updated: ${timeAgo(lastFetchedAt)}`);
	}, 1000);

	async function refreshAll(silent = false) {
		try {
			const d = await fetchDiagnostics();
			renderOverview(d);
			renderPageVisits(d);
			renderVisitors(d);
			renderTraffic(d);
			renderRequests(d);
			renderProxyTimings(d);
			renderTokens(d);
			renderProbes(d);
			renderLogins(d);
			renderHealth(d);
			renderCrawls(d);
			renderThrottled(d);
			renderPause(d);
			renderEndpoints(d);
			renderStatusDetailed(d);
			renderRetries(d);
			renderExploitSummary(d);
			renderLiveFeed(d);
			renderBudget(d);
			renderPersistence(d);
			renderSettings(d);
			renderEndpointBlocks(d);
			renderEndpointRules(d);
			renderHeaderRules(d);
			renderBlockedAttempts(d);
			renderRateLimitedAttempts(d);
			renderHeaderBlocked(d);
			setText("lastUpdatedChip", "Updated: just now");
			if (!silent) showToast("Dashboard updated");
		} catch (err) {
			console.error(err);
			if (!silent && sessionAlive) showToast("Failed to refresh diagnostics");
		}
	}

	// -----------------------------
	// CSV Export (simple, sectioned)
	// -----------------------------
	function toCSVRow(arr) {
		return arr.map(x => `"${String(x).replaceAll('"', '""')}"`).join(",");
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
	$("#exportAll")?.addEventListener("click", async () => {
		try {
			const d = await fetchDiagnostics();
			exportCSV(d);
			showToast("CSV exported");
		} catch {
			showToast("Export failed");
		}
	});

	$("#exportCrawls")?.addEventListener("click", async () => {
		try {
			const d = await fetchDiagnostics();
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
			const d = await fetchDiagnostics();
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
		const persist = $("#persistTokens")?.checked || false;
		const tokens = tokensRaw
			.split(/\r?\n/)
			.map(s => s.trim())
			.filter(Boolean);
		try {
			const res = await api("/admin/tokens", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ tokens, persist }),
			});
			if (!res.ok) throw new Error(String(res.status));
			const data = await res.json();
			let msg = `Replaced token set (n=${data.Count ?? tokens.length})`;
			if (persist) msg += data.Persisted ? "; written to token file" : "; FILE WRITE FAILED";
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

	// Pause / resume the proxy
	$("#pauseToggle")?.addEventListener("click", async () => {
		const currentlyPaused = $("#pauseToggle")?.dataset.paused === "true";
		try {
			const res = await api("/admin/proxy/toggle", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ paused: !currentlyPaused }),
			});
			if (!res.ok) throw new Error(String(res.status));
			const state = await res.json();
			renderPause({ Pause: state });
			showToast(state.Paused ? "Proxy paused" : "Proxy resumed");
		} catch (err) {
			console.error(err);
			showToast("Failed to change pause state");
		}
	});

	// Auto-refresh (paused while the tab is hidden; remembered across visits)
	const AUTO_REFRESH_KEY = "roxy.autoRefresh";
	let autoRefreshTimer = null;
	function startAutoRefresh() {
		if (autoRefreshTimer) return;
		autoRefreshTimer = setInterval(() => {
			if (!document.hidden && sessionAlive) refreshAll(true);
		}, 5000);
	}
	function stopAutoRefresh() {
		clearInterval(autoRefreshTimer);
		autoRefreshTimer = null;
	}
	const autoToggle = $("#autoRefreshToggle");
	if (autoToggle) {
		autoToggle.checked = localStorage.getItem(AUTO_REFRESH_KEY) === "1";
		if (autoToggle.checked) startAutoRefresh();
		autoToggle.addEventListener("change", e => {
			localStorage.setItem(AUTO_REFRESH_KEY, e.target.checked ? "1" : "0");
			if (e.target.checked) {
				startAutoRefresh();
				showToast("Auto-refresh on");
			} else {
				stopAutoRefresh();
				showToast("Auto-refresh off");
			}
		});
	}

	// Live feed manual refresh + filter
	$("#refreshLive")?.addEventListener("click", async () => {
		try {
			const d = await fetchDiagnostics();
			renderLiveFeed(d);
			showToast("Live feed updated");
		} catch {
			showToast("Failed to refresh live feed");
		}
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
		"section-proxy": { target: "requests", what: "ALL request stats (counters, status codes, timings, retries, traffic chart)" },
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
			try {
				const res = await api("/admin/data/clear", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ target: info.target }),
				});
				if (!res.ok) throw new Error(String(res.status));
				showToast(await res.json().catch(() => "Cleared"));
				await refreshAll(true);
			} catch {
				showToast("Failed to clear");
			}
		});
		actions.appendChild(btn);
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

	// Endpoint controls: block
	$("#blockForm")?.addEventListener("submit", async e => {
		e.preventDefault();
		const pattern = $("#blockPattern")?.value.trim();
		const note = $("#blockNote")?.value.trim() || "";
		if (!pattern) return;
		try {
			const res = await api("/admin/endpoints/block", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ pattern, note }),
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.Message || String(res.status));
			renderEndpointBlocks({ EndpointBlocks: data.EndpointBlocks });
			$("#blockPattern").value = "";
			$("#blockNote").value = "";
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
		if (!pattern || !limit) return;
		try {
			const res = await api("/admin/endpoints/rule", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ pattern, limit, period }),
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.Message || String(res.status));
			renderEndpointRules({ EndpointRules: data.EndpointRules });
			$("#rulePattern").value = "";
			$("#ruleLimit").value = "";
			showToast(`Rule set for ${pattern}`);
		} catch (err) {
			showToast("Rule failed: " + err.message);
		}
	});

	// Header rules: add
	$("#headerRuleForm")?.addEventListener("submit", async e => {
		e.preventDefault();
		const scope = $("#headerRuleScope")?.value || "either";
		const mode = $("#headerRuleMode")?.value || "contains";
		const needle = $("#headerRuleNeedle")?.value.trim();
		const note = $("#headerRuleNote")?.value.trim() || "";
		if (!needle) return;
		try {
			const res = await api("/admin/headers/rule", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ scope, mode, needle, note }),
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.Message || String(res.status));
			renderHeaderRules({ HeaderRules: data.HeaderRules });
			$("#headerRuleNeedle").value = "";
			$("#headerRuleNote").value = "";
			showToast("Header rule added");
		} catch (err) {
			showToast("Header rule failed: " + err.message);
		}
	});

	// Header-blocked attempts export
	$("#exportHeaderBlocked")?.addEventListener("click", async () => {
		try {
			const d = await fetchDiagnostics();
			const lines = ["Rule,Scope,Mode,Needle,Blocked,UniqueIPs,LastHeader,LastIP,LastPath,LastRequestTime"];
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

	// Endpoints export
	$("#exportEndpoints")?.addEventListener("click", async () => {
		try {
			const d = await fetchDiagnostics();
			const lines = ["Endpoint,Count,Methods,LastRequestTime"];
			for (const [path, info] of Object.entries(d.Endpoints || {})) {
				const methods = Object.entries(info.Methods || {})
					.map(([m, n]) => `${m}:${n}`)
					.join(" ");
				lines.push(toCSVRow([path, info.Count || 0, methods, info.LastRequestTime || 0]));
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
			const d = await fetchDiagnostics();
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
			const d = await fetchDiagnostics();
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
			const d = await fetchDiagnostics();
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
			const d = await fetchDiagnostics();
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
			const d = await fetchDiagnostics();
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
			const d = await fetchDiagnostics();
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

	// Tools: force revalidate tokens
	$("#forceRevalidateBtn")?.addEventListener("click", async () => {
		try {
			const res = await api("/admin/tokens/force_revalidate", { method: "POST" });
			if (!res.ok) throw new Error(String(res.status));
			showToast("Token revalidation queued");
			setTimeout(() => refreshAll(true), 1500);
		} catch {
			showToast("Revalidation failed");
		}
	});

	// Tools: health check
	$("#healthCheckBtn")?.addEventListener("click", async () => {
		try {
			const res = await fetch("/health", { headers: { Accept: "application/json" } });
			const data = await res.json();
			showToast(`Health: ${data.Status}${data.Paused ? " (paused)" : ""}`);
		} catch {
			showToast("Health check failed");
		}
	});

	// Initial load
	document.addEventListener("DOMContentLoaded", () => refreshAll(true));
	if (document.readyState !== "loading") refreshAll(true);
})();
