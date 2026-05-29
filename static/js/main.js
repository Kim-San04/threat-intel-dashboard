/* ------------------------------------------------------------------ */
/*  CTI Dashboard – main.js                                             */
/* ------------------------------------------------------------------ */

let map = null;
let mapMarker = null;
let vtChart = null;
let abChart = null;
let currentData = null;

// ------------------------------------------------------------------ //
//  Init
// ------------------------------------------------------------------ //
document.addEventListener("DOMContentLoaded", () => {
  initMap();
  setupSearch();
  showEmpty();
});

function initMap() {
  map = L.map("map", { zoomControl: false }).setView([20, 0], 2);
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: "&copy; CartoDB",
    maxZoom: 18,
  }).addTo(map);
  L.control.zoom({ position: "bottomright" }).addTo(map);
}

function setupSearch() {
  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc-input");
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const ioc = input.value.trim();
    if (ioc) runAnalysis(ioc);
  });
}

// ------------------------------------------------------------------ //
//  API call
// ------------------------------------------------------------------ //
async function runAnalysis(ioc) {
  setLoading(true);
  hideError();

  try {
    const resp = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ioc }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || "Server error");
    currentData = data;
    renderAll(data);
    refreshHistorySidebar();
  } catch (err) {
    showError(err.message);
  } finally {
    setLoading(false);
  }
}

// ------------------------------------------------------------------ //
//  Render
// ------------------------------------------------------------------ //
function renderAll(d) {
  document.getElementById("results-section").style.display = "flex";
  document.getElementById("empty-state").style.display = "none";

  renderRiskHero(d);
  renderVTCard(d.virustotal);
  renderAbuseCard(d.abuseipdb);
  renderShodanCard(d.shodan);
  renderCharts(d);
  renderMap(d);
  renderMeta(d);
}

/* Risk hero */
function renderRiskHero(d) {
  const score = d.risk_score;
  const label = d.risk_label;
  const color = riskColor(label);

  // Ring
  const ring = document.getElementById("score-ring-fg");
  const circumference = 2 * Math.PI * 54;
  ring.style.strokeDasharray = circumference;
  ring.style.strokeDashoffset = circumference - (score / 100) * circumference;
  ring.style.stroke = color;

  document.getElementById("score-number").textContent = score;
  const lbl = document.getElementById("score-label");
  lbl.textContent = label.toUpperCase();
  lbl.style.color = color;

  // Info rows
  document.getElementById("hero-ioc").textContent = d.ioc;
  document.getElementById("hero-ts").textContent = new Date(d.timestamp).toLocaleString();

  // Sub-scores bars
  const vtScore  = vtSubScore(d.virustotal);
  const abScore  = abuseSubScore(d.abuseipdb);
  const shScore  = shodanSubScore(d.shodan);
  setBar("bar-vt", vtScore);
  setBar("bar-ab", abScore);
  setBar("bar-sh", shScore);
}

function setBar(id, value) {
  const el = document.getElementById(id);
  if (el) {
    el.style.width = value + "%";
    el.style.background = barColor(value);
  }
}

function vtSubScore(vt) {
  if (!vt || vt.error) return 0;
  const ratio = vt.malicious / (vt.total_engines || 1);
  return Math.round(ratio * 100);
}
function abuseSubScore(ab) {
  return (!ab || ab.error) ? 0 : (ab.abuse_confidence_score || 0);
}
function shodanSubScore(sh) {
  if (!sh || sh.error) return 0;
  return Math.min((sh.vulns || []).length * 20 + (sh.ports || []).length, 100);
}

/* VirusTotal card */
function renderVTCard(vt) {
  const el = document.getElementById("vt-card-body");
  if (!vt || vt.error) {
    el.innerHTML = errHtml(vt?.error || "No data");
    return;
  }
  const ratio = `${vt.malicious} / ${vt.total_engines}`;
  el.innerHTML = `
    <div class="kv-list">
      ${kv("Detection", `<span style="color:${vt.malicious > 0 ? 'var(--risk-high)' : 'var(--risk-low)'};font-weight:700">${ratio}</span>`)}
      ${kv("IOC Type", vt.ioc_type || "—")}
      ${kv("Reputation", vt.reputation ?? "—")}
      ${kv("Country", vt.country || "—")}
      ${kv("AS Owner", vt.as_owner || "—")}
    </div>
    ${vt.categories && Object.keys(vt.categories).length ? `
      <div class="tag-list" style="margin-top:12px">
        ${Object.values(vt.categories).map(c => `<span class="tag">${c}</span>`).join("")}
      </div>` : ""}
  `;
}

/* AbuseIPDB card */
function renderAbuseCard(ab) {
  const el = document.getElementById("ab-card-body");
  if (!ab || ab.error || !ab.ip) {
    el.innerHTML = `<p class="empty-state" style="padding:12px 0;font-size:.8rem">Only available for IP addresses.</p>`;
    return;
  }
  const conf = ab.abuse_confidence_score || 0;
  el.innerHTML = `
    <div class="kv-list">
      ${kv("Confidence", `<span style="color:${barColor(conf)};font-weight:700">${conf}%</span>`)}
      ${kv("Total Reports", ab.total_reports)}
      ${kv("Distinct Users", ab.num_distinct_users)}
      ${kv("ISP", ab.isp || "—")}
      ${kv("Country", ab.country_code || "—")}
      ${kv("Usage Type", ab.usage_type || "—")}
      ${kv("Whitelisted", ab.is_whitelisted ? "Yes" : "No")}
      ${kv("Last Report", ab.last_reported_at ? new Date(ab.last_reported_at).toLocaleDateString() : "—")}
    </div>
  `;
}

/* Shodan card */
function renderShodanCard(sh) {
  const el = document.getElementById("sh-card-body");
  if (!sh || !sh.ip) {
    el.innerHTML = `<p class="empty-state" style="padding:12px 0;font-size:.8rem">Only available for IP addresses.</p>`;
    return;
  }
  if (sh.error) {
    el.innerHTML = errHtml(`Shodan indisponible : ${sh.error}`);
    return;
  }
  const vulnHtml = (sh.vulns || []).length
    ? `<div class="tag-list">${sh.vulns.map(v => `<span class="vuln-chip">${v}</span>`).join("")}</div>`
    : "";
  const portHtml = (sh.ports || []).length
    ? `<div class="ports-grid">${sh.ports.map(p => `<span class="port-chip">${p}</span>`).join("")}</div>`
    : "";
  el.innerHTML = `
    <div class="kv-list">
      ${kv("Org", sh.org || "—")}
      ${kv("ISP", sh.isp || "—")}
      ${kv("OS", sh.os || "—")}
      ${kv("Country", sh.country_name || "—")}
      ${kv("City", sh.city || "—")}
      ${kv("Hostnames", (sh.hostnames || []).join(", ") || "—")}
      ${kv("Open Ports", (sh.ports || []).length)}
      ${kv("CVEs", (sh.vulns || []).length)}
    </div>
    ${portHtml}
    ${vulnHtml}
  `;
}

/* Charts */
function renderCharts(d) {
  const vt = d.virustotal || {};
  const sh = d.shodan || {};

  // VT doughnut
  const vtStats = vt.last_analysis_stats || {};
  const vtCtx = document.getElementById("vt-chart").getContext("2d");
  if (vtChart) vtChart.destroy();
  vtChart = new Chart(vtCtx, {
    type: "doughnut",
    data: {
      labels: Object.keys(vtStats),
      datasets: [{
        data: Object.values(vtStats),
        backgroundColor: ["#f85149","#3fb950","#d29922","#58a6ff","#8b949e","#bc8cff"],
        borderWidth: 0,
      }],
    },
    options: {
      plugins: {
        legend: { labels: { color: "#8b949e", boxWidth: 12, font: { size: 11 } } },
      },
      maintainAspectRatio: false,
      cutout: "65%",
    },
  });

  // Shodan services bar
  const services = (sh.services || []).slice(0, 8);
  const abCtx = document.getElementById("sh-chart").getContext("2d");
  if (abChart) abChart.destroy();
  abChart = new Chart(abCtx, {
    type: "bar",
    data: {
      labels: services.map(s => s.port),
      datasets: [{
        label: "Port",
        data: services.map(() => 1),
        backgroundColor: "#bc8cff88",
        borderColor: "#bc8cff",
        borderWidth: 1,
      }],
    },
    options: {
      indexAxis: "y",
      plugins: { legend: { display: false } },
      scales: {
        x: { display: false },
        y: { ticks: { color: "#8b949e", font: { size: 11 } }, grid: { color: "#30363d" } },
      },
      maintainAspectRatio: false,
    },
  });
}

/* Map */
function renderMap(d) {
  const sh  = d.shodan || {};
  const geo = d.geo    || {};

  const lat = sh.latitude  ?? geo.lat;
  const lng = sh.longitude ?? geo.lon;
  if (lat == null || lng == null) return;

  const city    = sh.city         || geo.city    || "";
  const country = sh.country_name || geo.country || "";
  const label   = d.risk_label    || "low";

  map.setView([lat, lng], 6);
  if (mapMarker) mapMarker.remove();

  const color = riskColor(label);
  const icon = L.divIcon({
    className: "",
    html: `<div style="width:14px;height:14px;border-radius:50%;background:${color};
                       box-shadow:0 0 10px ${color};border:2px solid #fff"></div>`,
    iconSize: [14, 14],
    iconAnchor: [7, 7],
  });
  mapMarker = L.marker([lat, lng], { icon })
    .bindPopup(`<b>${d.ioc}</b><br>${city} ${country}`)
    .addTo(map)
    .openPopup();
}

function renderMeta(d) {
  const el = document.getElementById("result-meta");
  el.textContent = `${d.ioc}  ·  ${new Date(d.timestamp).toLocaleString()}`;
}

// ------------------------------------------------------------------ //
//  History sidebar (reload from server)
// ------------------------------------------------------------------ //
async function refreshHistorySidebar() {
  const resp = await fetch("/");
  if (!resp.ok) return;
  const txt = await resp.text();
  const parser = new DOMParser();
  const doc = parser.parseFromString(txt, "text/html");
  const newList = doc.getElementById("history-list");
  const curList = document.getElementById("history-list");
  if (newList && curList) curList.innerHTML = newList.innerHTML;
}

async function clearHistory() {
  await fetch("/history/clear", { method: "POST" });
  const list = document.getElementById("history-list");
  if (list) list.innerHTML = "";
}

// ------------------------------------------------------------------ //
//  PDF export
// ------------------------------------------------------------------ //
async function exportPDF() {
  if (!currentData) return;
  const resp = await fetch("/export-pdf", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data: currentData }),
  });
  if (!resp.ok) { alert("PDF export failed"); return; }
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `cti_report_${currentData.ioc}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}

// ------------------------------------------------------------------ //
//  Helpers
// ------------------------------------------------------------------ //
function kv(k, v) {
  return `<div class="kv"><span class="k">${k}</span><span class="v">${v}</span></div>`;
}
function errHtml(msg) {
  return `<p style="color:var(--text-muted);font-size:.82rem">${msg}</p>`;
}
function riskColor(label) {
  return { low: "#3fb950", medium: "#d29922", high: "#f85149", critical: "#ff0040" }[label] || "#8b949e";
}
function barColor(val) {
  if (val >= 75) return "#f85149";
  if (val >= 50) return "#d29922";
  if (val >= 25) return "#58a6ff";
  return "#3fb950";
}
function showEmpty() {
  document.getElementById("empty-state").style.display = "block";
  document.getElementById("results-section").style.display = "none";
}
function setLoading(on) {
  const btn = document.getElementById("analyze-btn");
  const sp  = document.getElementById("spinner");
  btn.disabled = on;
  sp.style.display = on ? "block" : "none";
}
function showError(msg) {
  const el = document.getElementById("error-banner");
  el.textContent = msg;
  el.classList.add("visible");
}
function hideError() {
  document.getElementById("error-banner").classList.remove("visible");
}
