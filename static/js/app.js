/* Supernova Dashboard — shared logic for all themes */

const API = "/api";

/* ── Tab switching ── */
function showTab(name, btn) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("page-" + name).classList.add("active");
  if (btn) btn.classList.add("active");
}

/* ── Hardware bar (SOC theme) ── */
function updateHardwareBar() {
  const cpu = document.getElementById("hw-cpu");
  const ram = document.getElementById("hw-ram");
  const uptime = document.getElementById("hw-uptime");
  if (!cpu && !ram && !uptime) return; // not on SOC theme
  cpu.textContent = Math.floor(Math.random() * 10 + 38) + "C";
  ram.textContent = Math.floor(Math.random() * 100 + 180) + "MB";
  const now = Math.floor(Date.now() / 1000);
  const h = Math.floor(now / 3600) % 24, m = Math.floor(now / 60) % 60, s = now % 60;
  uptime.textContent = String(h).padStart(2,"0") + ":" + String(m).padStart(2,"0") + ":" + String(s).padStart(2,"0");
}

/* ── Sidebar status (SOC theme) ── */
function updateSidebar() {
  const sbApp = document.getElementById("sb-app");
  if (!sbApp) return;
  const ldapEl = document.getElementById("badge-ldap");
  const npuEl = document.getElementById("badge-npu");
  const statusEl = document.getElementById("badge-status");
  const authEl = document.getElementById("sb-auth");
  document.getElementById("sb-ldap").textContent = ldapEl ? ldapEl.textContent.toLowerCase() : "mock";
  document.getElementById("sb-ldap-dot").className = "dot " + (ldapEl && ldapEl.classList.contains("badge-active") ? "green" : "amber");
  if (authEl) authEl.textContent = statusEl && statusEl.textContent === "COMPLETE" ? "unlocked" : "locked";
  const rEl = document.getElementById("m-risk");
  if (rEl) document.getElementById("sb-risk").textContent = rEl.textContent;
  document.getElementById("sb-findings").textContent = (document.getElementById("m-findings") || {textContent:"0"}).textContent;
}

/* ── Status ── */
async function fetchStatus() {
  try {
    const r = await fetch(API + "/status");
    const s = await r.json();
    const ldap = document.getElementById("badge-ldap");
    if (ldap) {
      ldap.textContent = s.ldap_mode === "mock" ? "Mock" : "Live";
      ldap.className = "badge " + (s.ldap_mode === "mock" ? "badge-warn" : "badge-active");
    }
    const npu = document.getElementById("badge-npu");
    if (npu) {
      npu.textContent = s.npu_enabled ? "NPU On" : "NPU Off";
      npu.className = "badge " + (s.npu_enabled ? "badge-active" : "badge-neutral");
    }
  } catch (e) {
    const ldap = document.getElementById("badge-ldap");
    if (ldap) { ldap.textContent = "Offline"; ldap.className = "badge badge-error"; }
  }
}

/* ── Assessment ── */
let auditRunning = false;

function term(line, cls) {
  const t = document.getElementById("terminal");
  const div = document.createElement("div");
  div.textContent = line;
  if (cls) div.className = cls;
  t.appendChild(div);
  t.scrollTop = t.scrollHeight;
}

function setProgress(categories, current) {
  const el = document.getElementById("audit-progress");
  el.innerHTML = "";
  categories.forEach(c => {
    const row = document.createElement("div");
    row.className = "prog-row" + (c.state === "done" ? " done" : c.state === "active" ? " active" : "");
    row.innerHTML = `<div class="prog-dot"></div><span class="prog-name">${c.name}</span><span class="prog-status">${c.state === "done" ? "Complete" : c.state === "active" ? "Running..." : ""}</span>`;
    el.appendChild(row);
  });
}

function addFinding(f) {
  const list = document.getElementById("finding-list");
  const empty = list.querySelector(".empty");
  if (empty) empty.remove();
  const row = document.createElement("div");
  row.className = "finding-row";
  const sev = f.severity === "critical" ? "critical" : f.severity === "high" ? "high" : f.severity === "medium" ? "medium" : "low";
  row.innerHTML = `<span class="sev-badge ${sev}">${f.severity.toUpperCase()}</span><span class="finding-name">${f.title}</span>`;
  list.appendChild(row);
}

function updateMetrics(crit, high, med, total, risk) {
  document.getElementById("m-findings").textContent = total;
  const mr = document.getElementById("m-risk");
  mr.textContent = risk || "—";
  mr.className = "metric-val" + (risk === "CRITICAL" ? " crit" : risk === "HIGH" ? " high" : "");
  document.getElementById("b-crit").textContent = crit;
  document.getElementById("b-high").textContent = high;
}

async function startAssessment() {
  if (auditRunning) return;
  auditRunning = true;
  document.getElementById("run-btn").disabled = true;
  document.getElementById("reset-btn").disabled = true;
  const badge = document.getElementById("badge-status");
  badge.textContent = "Running";
  badge.className = "badge badge-warn";

  const terminal = document.getElementById("terminal");
  terminal.innerHTML = "";
  term("[ Project Supernova v2.0 ]", "t-gray");
  term("");

  const names = [
    "Account Policy", "Kerberos Configuration", "Privileged Groups",
    "ACL Integrity", "GPO Hygiene", "Protocol Hardening",
    "Certificate Services", "Trust Configuration", "Endpoint Security"
  ];

  let catState = names.map(n => ({ name: n, state: "" }));
  setProgress(catState, "");

  for (let i = 0; i < names.length; i++) {
    catState[i].state = "active";
    setProgress(catState);
    term(`[${names[i]}]`, "t-cyan");
    await sleep(200);
    catState[i].state = "done";
    setProgress(catState);
  }
  term("");

  try {
    const r = await fetch(API + "/assessment/start", { method: "POST" });
    const data = await r.json();
    if (data.error) {
      term("[Error] " + data.error, "t-red");
    } else {
      term(`[Done] ${data.total_findings} findings — Overall risk: ${data.summary.overall_risk}`, "t-green");
      const fr = await fetch(API + "/assessment/findings");
      const fd = await fr.json();
      let crit = 0, high = 0, med = 0;
      fd.findings.forEach(f => {
        addFinding(f);
        if (f.severity === "critical") crit++;
        else if (f.severity === "high") high++;
        else if (f.severity === "medium") med++;
      });
      updateMetrics(crit, high, med, fd.count, data.summary.overall_risk);
    }
  } catch (e) {
    term("[Error] " + e.message, "t-red");
  }

  badge.textContent = "Complete";
  badge.className = "badge badge-active";
  document.getElementById("reset-btn").disabled = false;
  auditRunning = false;
}

function resetAssessment() {
  document.getElementById("terminal").innerHTML = '<span class="t-gray">Press "Run Assessment" to begin.</span>';
  document.getElementById("finding-list").innerHTML = '<div class="empty">No findings yet.</div>';
  document.getElementById("badge-status").textContent = "Ready";
  document.getElementById("badge-status").className = "badge badge-neutral";
  document.getElementById("run-btn").disabled = false;
  updateMetrics(0, 0, 0, 0, "—");
  setProgress([], "");
  document.getElementById("report-content").innerHTML = '<div class="empty">Run an assessment to view the report.</div>';
}

/* ── Guard ── */
async function refreshGuard() {
  try {
    const r = await fetch(API + "/guard/status");
    const s = await r.json();
    document.getElementById("g-events").textContent = s.events_analysed || 0;
    document.getElementById("g-alerts").textContent = s.alerts_triggered || 0;
    document.getElementById("g-uptime").textContent = formatUptime(s.uptime_seconds || 0);
    const th = document.getElementById("threat-level");
    const level = s.threat_level || "low";
    th.textContent = "Threat: " + level.charAt(0).toUpperCase() + level.slice(1);
    th.className = "threat-badge threat-" + level;

    if (s.recent_alerts && s.recent_alerts.length) {
      const feed = document.getElementById("alert-feed");
      feed.innerHTML = "";
      s.recent_alerts.slice(-10).forEach(a => {
        const item = document.createElement("div");
        const sev = a.severity === "critical" ? "critical" : a.severity === "high" ? "high" : "";
        item.className = "alert-item" + (sev ? " " + sev : "");
        item.innerHTML = `<span class="sev-badge ${sev || 'info'}">${a.severity.toUpperCase()}</span>
          <div style="flex:1"><div class="alert-title">${a.title}</div><div class="alert-detail">${a.change_type}</div></div>
          <span class="alert-time">${new Date(a.timestamp).toLocaleTimeString()}</span>`;
        feed.appendChild(item);
      });
    }
  } catch (e) {}
}

/* ── Report ── */
async function loadReport() {
  try {
    const r = await fetch(API + "/assessment/findings");
    const fd = await r.json();
    if (!fd.count) {
      document.getElementById("report-content").innerHTML = '<div class="empty">No findings. Run an assessment first.</div>';
      return;
    }
    let html = `<div class="report-header"><div class="report-title">AD Security Assessment Report</div><div class="report-meta">Total Findings: ${fd.count}</div></div>`;
    fd.findings.forEach(f => {
      const sev = f.severity === "critical" ? "critical" : f.severity === "high" ? "high" : f.severity === "medium" ? "medium" : "low";
      html += `<div class="report-finding">
        <div class="rf-header">
          <span class="sev-badge ${sev}">${f.severity.toUpperCase()}</span>
          <span class="rf-title">${f.title}</span>
        </div>
        <div class="rf-desc">${f.description}</div>
        ${f.remediation_ps ? `<div class="rem-cmd">${f.remediation_ps}</div>` : ""}
      </div>`;
    });
    document.getElementById("report-content").innerHTML = html;
  } catch (e) {
    document.getElementById("report-content").innerHTML = '<div class="empty">Failed to load report.</div>';
  }
}

/* ── Utils ── */
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function formatUptime(s) { const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60); return h + "h " + m + "m"; }

/* ── Init ── */
fetchStatus();
updateHardwareBar();
showTab("assessment", document.querySelector(".tab-btn"));
setInterval(refreshGuard, 5000);
setInterval(updateHardwareBar, 10000);
setInterval(updateSidebar, 3000);

/* ── Guard Simulation ── */
function simulateAlert() {
  const scenarios = [
    { sev: "critical", title: "New member added to Domain Admins: sqlservice", change: "group_membership_added" },
    { sev: "critical", title: "DCSync right granted to: helpdesk", change: "replication_rights_added" },
    { sev: "critical", title: "Unconstrained delegation enabled on: WS02", change: "delegation_enabled" },
    { sev: "high", title: "New SPN registered: HTTP/WS01 for luqman.zafree", change: "spn_registered" },
    { sev: "high", title: "AdminSDHolder ACL modified: WriteProperty for Domain Users", change: "adminsdholder_modified" },
    { sev: "critical", title: "GPO link changed on Domain Controllers OU", change: "gpo_link_modified" },
    { sev: "high", title: "Password policy weakened: min length changed to 6", change: "password_policy_modified" },
  ];
  const s = scenarios[Math.floor(Math.random() * scenarios.length)];
  const feed = document.getElementById("alert-feed");
  if (!feed) return;
  const empty = feed.querySelector(".empty");
  if (empty) empty.remove();
  const item = document.createElement("div");
  item.className = "alert-item " + (s.sev === "critical" ? "critical" : "high");
  const now = new Date();
  item.innerHTML = '<span class="sev-badge ' + s.sev + '">' + s.sev.toUpperCase() + '</span><div style="flex:1"><div class="alert-title">' + s.title + '</div><div class="alert-detail">' + s.change + '</div></div><span class="alert-time">' + now.toLocaleTimeString() + '</span>';
  feed.insertBefore(item, feed.firstChild);
  const aEl = document.getElementById("g-alerts");
  if (aEl) aEl.textContent = parseInt(aEl.textContent || 0) + 1;
  const th = document.getElementById("threat-level");
  if (th && s.sev === "critical") { let t = th.className.replace(/threat-\w+/g,''); th.textContent = "THREAT_HIGH"; th.className = (t + " threat-high").trim(); }
}

/* ── Theme Switcher ── */
function switchTheme(theme) {
  const themes = { light: "/", blue: "/blue", soc: "/soc", "soc-light": "/soc-light" };
  const url = themes[theme];
  if (url) window.location.href = url;
}

/* ── Charts (Analytics tab) ── */
let severityChart = null, categoryChart = null;

async function renderCharts() {
  try {
    const r = await fetch(API + "/assessment/findings");
    const fd = await r.json();
    if (!fd.count) return;

    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const catCounts = {};
    fd.findings.forEach(f => {
      sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
      catCounts[f.category] = (catCounts[f.category] || 0) + 1;
    });

    const ctx1 = document.getElementById("chart-severity");
    if (ctx1) {
      if (severityChart) severityChart.destroy();
      severityChart = new Chart(ctx1, {
        type: "doughnut",
        data: {
          labels: ["Critical", "High", "Medium", "Low", "Info"],
          datasets: [{
            data: [sevCounts.critical, sevCounts.high, sevCounts.medium, sevCounts.low, sevCounts.info],
            backgroundColor: ["#D1533A", "#E8962E", "#4386EB", "#484F58", "#1C2128"],
            borderColor: "#131720",
            borderWidth: 2
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { position: "bottom", labels: { color: "#8B949E", font: { family: "'JetBrains Mono', monospace", size: 10 }, padding: 12 } } }
        }
      });
    }

    const ctx2 = document.getElementById("chart-category");
    if (ctx2) {
      if (categoryChart) categoryChart.destroy();
      const cats = Object.keys(catCounts);
      categoryChart = new Chart(ctx2, {
        type: "bar",
        data: {
          labels: cats,
          datasets: [{
            label: "findings",
            data: cats.map(c => catCounts[c]),
            backgroundColor: "#4386EB",
            borderColor: "#131720",
            borderWidth: 1,
            borderRadius: 0
          }]
        },
        options: {
          indexAxis: "y",
          responsive: true, maintainAspectRatio: false,
          scales: {
            x: { grid: { color: "#1C2128" }, ticks: { color: "#484F58", font: { family: "'JetBrains Mono', monospace", size: 10 } } },
            y: { grid: { display: false }, ticks: { color: "#8B949E", font: { family: "'JetBrains Mono', monospace", size: 10 } } }
          },
          plugins: { legend: { display: false } }
        }
      });
    }
  } catch (e) {}
}
