"use strict";

const SEV_ORDER = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

const els = {
  scanBtn: document.getElementById("scanBtn"),
  heroScan: document.getElementById("heroScan"),
  pasteBtn: document.getElementById("pasteBtn"),
  results: document.getElementById("results"),
  hero: document.getElementById("hero"),
  stats: document.getElementById("stats"),
  controls: document.getElementById("controls"),
  overlay: document.getElementById("overlay"),
  overlayMsg: document.getElementById("overlayMsg"),
  sevFilter: document.getElementById("sevFilter"),
  search: document.getElementById("search"),
  modal: document.getElementById("modal"),
  scanText: document.getElementById("scanText"),
  modalRun: document.getElementById("modalRun"),
  modalCancel: document.getElementById("modalCancel"),
};

let state = { networks: [], minSev: "ALL", query: "" };

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function signalBars(pct) {
  const lvl = pct == null ? 0 : Math.max(1, Math.round(pct / 25));
  let html = '<span class="signal" title="' + (pct == null ? "unknown" : pct + "%") + '">';
  for (let i = 1; i <= 4; i++) html += `<i class="${i <= lvl ? "on" : ""}"></i>`;
  return html + "</span>";
}

function showOverlay(msg) {
  els.overlayMsg.textContent = msg;
  els.overlay.hidden = false;
}
function hideOverlay() { els.overlay.hidden = true; }

function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4200);
}

function renderStats(summary) {
  els.stats.hidden = false;
  document.getElementById("s-total").textContent = summary.total;
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]) {
    document.getElementById("s-" + sev).textContent = summary.by_severity[sev] || 0;
  }
}

function bands(net) {
  const b = new Set();
  (net.access_points || []).forEach((ap) => ap.band && b.add(ap.band));
  return [...b].sort();
}

function cardHtml(net) {
  const sev = net.worst_severity;
  const findings = [...net.findings].sort(
    (a, b) => SEV_ORDER[b.severity] - SEV_ORDER[a.severity]
  );
  const fHtml = findings.map((f) => `
    <li class="finding">
      <span class="dot" data-sev="${f.severity}"></span>
      <span><span class="f-title">${escapeHtml(f.title)}</span> —
      <span class="f-detail">${escapeHtml(f.detail)}</span></span>
    </li>`).join("");

  const bnd = bands(net);
  const titleCls = net.is_hidden ? "net-title hidden-ssid" : "net-title";

  return `
  <article class="net-card" data-sev="${sev}">
    <div class="net-head">
      <h3 class="${titleCls}">${escapeHtml(net.display_ssid)}</h3>
      <span class="badge" data-sev="${sev}">${sev}</span>
    </div>
    <div class="net-meta">
      ${signalBars(net.best_signal)}
      <span>${net.best_signal == null ? "—" : net.best_signal + "%"}</span>
      <span><b>${escapeHtml(net.authentication || "?")}</b> / ${escapeHtml(net.encryption || "?")}</span>
      ${bnd.length ? `<span>${bnd.join(", ")}</span>` : ""}
      <span>${(net.access_points || []).length} radio(s)</span>
    </div>
    <ul class="findings">${fHtml}</ul>
  </article>`;
}

function applyFilters() {
  const min = state.minSev === "ALL" ? -1 : SEV_ORDER[state.minSev];
  const q = state.query.trim().toLowerCase();
  return state.networks.filter((n) => {
    if (SEV_ORDER[n.worst_severity] < min) return false;
    if (q && !n.display_ssid.toLowerCase().includes(q)) return false;
    return true;
  });
}

function render() {
  const list = applyFilters().sort((a, b) => {
    const d = SEV_ORDER[b.worst_severity] - SEV_ORDER[a.worst_severity];
    return d !== 0 ? d : (b.best_signal || 0) - (a.best_signal || 0);
  });
  if (!state.networks.length) {
    els.results.innerHTML = `<div class="hero"><p>No networks found in range.</p></div>`;
    return;
  }
  if (!list.length) {
    els.results.innerHTML = `<div class="hero"><p>No networks match the current filter.</p></div>`;
    return;
  }
  els.results.innerHTML = list.map(cardHtml).join("");
}

async function runScan() {
  showOverlay("Scanning for nearby networks…");
  try {
    const res = await fetch("/api/scan");
    const data = await res.json();
    handleResult(data);
  } catch (e) {
    toast("Scan request failed: " + e.message);
  } finally {
    hideOverlay();
  }
}

async function runScanFile(text) {
  showOverlay("Auditing scan data…");
  try {
    const res = await fetch("/api/scan-file", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    handleResult(await res.json());
  } catch (e) {
    toast("Audit failed: " + e.message);
  } finally {
    hideOverlay();
  }
}

function handleResult(data) {
  if (!data.ok) {
    toast(data.error || "Scan failed");
    return;
  }
  state.networks = data.networks;
  els.hero.hidden = true;
  els.controls.hidden = false;
  renderStats(data.summary);
  render();
}

// ---- events ----
els.scanBtn.addEventListener("click", runScan);
els.heroScan.addEventListener("click", runScan);

els.pasteBtn.addEventListener("click", () => { els.modal.hidden = false; els.scanText.focus(); });
els.modalCancel.addEventListener("click", () => { els.modal.hidden = true; });
els.modal.addEventListener("click", (e) => { if (e.target === els.modal) els.modal.hidden = true; });
els.modalRun.addEventListener("click", () => {
  const text = els.scanText.value;
  els.modal.hidden = true;
  if (text.trim()) runScanFile(text);
});

els.sevFilter.addEventListener("click", (e) => {
  const btn = e.target.closest(".chip");
  if (!btn) return;
  els.sevFilter.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
  btn.classList.add("active");
  state.minSev = btn.dataset.min;
  render();
});

els.search.addEventListener("input", (e) => { state.query = e.target.value; render(); });
