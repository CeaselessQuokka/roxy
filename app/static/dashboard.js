/* Roxy Admin Dashboard — wiring for diagnostics-backed UI
   - Consumes GET /admin/diagnostics -> get_diagnostics() shape provided
   - Updates KPI cards, tables, health, tokens, attempts
   - Handles: Refresh, Export CSV, Submit Tokens, Fetch Tokens button
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
	function fmtNum(x, digits = 0) {
		if (x === Infinity || x === -Infinity || Number.isNaN(x)) return "—";
		if (typeof x !== "number") return "0";
		return digits ? x.toFixed(digits) : String(Math.trunc(x));
	}
	function sum(...ns) {
		return ns.reduce((a, b) => a + (Number(b) || 0), 0);
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

	function renderRequests(d) {
		const rc = d.RequestCounts || {};
		const methods = ["GET", "POST", "PATCH", "PUT", "DELETE"];
		let totalS = 0,
			totalF = 0;
		for (const m of methods) {
			const row = rc[m] || { Successful: 0, Failed: 0 };
			const s = Number(row.Successful || 0);
			const f = Number(row.Failed || 0);
			setText(`mc_${m.toLowerCase()}_s`, String(s));
			setText(`mc_${m.toLowerCase()}_f`, String(f));
			setText(`mc_${m.toLowerCase()}_t`, String(s + f));
			totalS += s;
			totalF += f;
		}
		setText("mc_total_s", String(totalS));
		setText("mc_total_f", String(totalF));
		setText("mc_total_t", String(totalS + totalF));

		const sc = d.StatusCodeCounts || {};
		setText("count_2xx", String(sc["2xx"] || 0));
		setText("count_4xx", String(sc["4xx"] || 0));
	}

	function renderProxyTimings(d) {
		const pc = d.ProxyRequestCounts || {};
		const methods = ["GET", "POST", "PATCH", "PUT", "DELETE"];
		for (const m of methods) {
			const row = pc[m] || { TotalTime: 0, Count: 0, Min: 0, Max: 0, LastRequestTime: 0 };
			const pref = `pt_${m.toLowerCase()}`;
			setText(`${pref}_c`, String(row.Count || 0));
			setText(`${pref}_tot`, fmtNum(row.Count ? row.TotalTime / row.Count : 0, 3));
			// Min could be Infinity when no data; normalize
			const minVal = row.Min === Infinity ? 0 : row.Min || 0;
			setText(`${pref}_min`, fmtNum(minVal, 3));
			setText(`${pref}_max`, fmtNum(row.Max || 0, 3));
			setText(`${pref}_last`, toTS(row.LastRequestTime || 0));
		}
	}

	function renderTokens(d) {
		const tbody = $("#tokensTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const list = Array.isArray(d.Tokens) ? d.Tokens : [];
		list.forEach((t, i) => {
			const idx = i + 1;
			const masked = t?.Masked ?? "…***";
			const being = Boolean(t?.BeingValidated);
			tbody.appendChild(tr([String(idx), masked, being ? "Yes" : "No"]));
		});
	}

	function renderProbes(d) {
		const tbody = $("#probeTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const items = Array.isArray(d.ExploitAttempts) ? d.ExploitAttempts : [];
		items.forEach(row => {
			tbody.appendChild(tr([toTS(row?.Date), row?.IP || "—", row?.UserAgent || "—", row?.Reason || "—"]));
		});
	}

	function renderLogins(d) {
		const tbody = $("#loginsTable tbody");
		if (!tbody) return;
		tbody.innerHTML = "";
		const items = Array.isArray(d.LoginAttempts) ? d.LoginAttempts : [];
		items.forEach(row => {
			tbody.appendChild(tr([toTS(row?.Date), row?.IP || "—", row?.Successful ? "success" : "fail"]));
		});
	}

	function renderHealth(d) {
		const h = d.ProxyHealth || {};
		const da = h.DirectAPI || {};
		const rp = h.RoProxy || {};
		const tk = h.Tokens || {};
		setText("health_direct", da.IsInCooldown ? "COOLDOWN" : "OK");
		setText("direct_last", toTS(da.LastRequestTime || 0));
		setText("direct_cooldown", String(Boolean(da.IsInCooldown)));

		setText("health_roproxy", rp.IsInCooldown ? "COOLDOWN" : "OK");
		setText("roproxy_last", toTS(rp.LastRequestTime || 0));
		setText("roproxy_cooldown", String(Boolean(rp.IsInCooldown)));

		setText("health_tokens_count", String(tk.Count ?? 0));
		setText("health_tokens_expired", String(tk.ExpiredCount ?? 0));
		setText("health_tokens_validating", String(tk.BeingValidatedCount ?? 0));
	}

	// -----------------------------
	// Data plumbing
	// -----------------------------
	async function fetchDiagnostics() {
		const res = await fetch("/admin/diagnostics", { method: "GET", headers: { Accept: "application/json" } });
		if (!res.ok) throw new Error("Diagnostics fetch failed: " + res.status);
		return await res.json();
	}

	async function refreshAll() {
		try {
			const d = await fetchDiagnostics();
			renderOverview(d);
			renderRequests(d);
			renderProxyTimings(d);
			renderTokens(d);
			renderProbes(d);
			renderLogins(d);
			renderHealth(d);
			showToast("Dashboard updated");
		} catch (err) {
			console.error(err);
			showToast("Failed to refresh diagnostics");
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

		// Requests
		lines.push("");
		lines.push("[RequestCounts]");
		const rc = d.RequestCounts || {};
		[["GET"], ["POST"], ["PATCH"], ["PUT"], ["DELETE"]].forEach(([m]) => {
			const row = rc[m] || { Successful: 0, Failed: 0 };
			lines.push(toCSVRow([m, row.Successful || 0, row.Failed || 0, (row.Successful || 0) + (row.Failed || 0)]));
		});

		// Status codes
		lines.push("");
		lines.push("[StatusCodeCounts]");
		const sc = d.StatusCodeCounts || {};
		lines.push(toCSVRow(["2xx", sc["2xx"] || 0]));
		lines.push(toCSVRow(["4xx", sc["4xx"] || 0]));

		// Proxy timings
		lines.push("");
		lines.push("[ProxyRequestCounts]");
		const pc = d.ProxyRequestCounts || {};
		[["GET"], ["POST"], ["PATCH"], ["PUT"], ["DELETE"]].forEach(([m]) => {
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

		// Tokens (masked only)
		lines.push("");
		lines.push("[Tokens]");
		(Array.isArray(d.Tokens) ? d.Tokens : []).forEach((t, i) => {
			lines.push(toCSVRow([i + 1, t.Masked || "…***", t.BeingValidated ? "Yes" : "No"]));
		});

		// Exploit attempts
		lines.push("");
		lines.push("[ExploitAttempts]");
		(Array.isArray(d.ExploitAttempts) ? d.ExploitAttempts : []).forEach(r => {
			lines.push(toCSVRow([r.Date || 0, r.IP || "", r.UserAgent || "", r.Reason || ""]));
		});

		// Login attempts
		lines.push("");
		lines.push("[LoginAttempts]");
		(Array.isArray(d.LoginAttempts) ? d.LoginAttempts : []).forEach(r => {
			lines.push(toCSVRow([r.Date || 0, r.IP || "", r.Successful ? "success" : "fail"]));
		});

		download(`roxy_diagnostics_${Date.now()}.csv`, lines.join("\n"));
	}

	// -----------------------------
	// Events / wiring
	// -----------------------------
	const navToggle = $("#navToggle");
	navToggle?.addEventListener("click", () => {
		const nav = $("#appNav");
		const expanded = nav?.classList.toggle("is-open");
		if (navToggle) navToggle.setAttribute("aria-expanded", expanded ? "true" : "false");
	});

	$("#refreshAll")?.addEventListener("click", refreshAll);
	$("#exportAll")?.addEventListener("click", async () => {
		try {
			const d = await fetchDiagnostics();
			exportCSV(d);
			showToast("CSV exported");
		} catch {
			showToast("Export failed");
		}
	});

	// Tokens: fetch button just refreshes diagnostics and scrolls into view
	$("#fetchTokensBtn")?.addEventListener("click", async () => {
		await refreshAll();
		$("#tokensTable")?.scrollIntoView({ behavior: "smooth", block: "center" });
	});

	// Token submit: send JSON instead of default form post; then refresh
	$("#tokenForm")?.addEventListener("submit", async e => {
		e.preventDefault();
		const tokensRaw = $("#tokensInput")?.value || "";
		// const persist = $("#persistTokens")?.checked || false;
		const tokens = tokensRaw
			.split(/\r?\n/)
			.map(s => s.trim())
			.filter(Boolean);
		try {
			const res = await fetch("/admin/tokens", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ tokens }),
			});
			if (!res.ok) throw new Error(String(res.status));
			showToast(`Replaced token set (n=${tokens.length})`);
			$("#tokensInput").value = "";
			await refreshAll();
		} catch (err) {
			console.error(err);
			showToast("Token submit failed");
		}
	});

	// Initial load
	document.addEventListener("DOMContentLoaded", refreshAll);
})();
