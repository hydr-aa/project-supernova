/* Supernova Dashboard — Main Application Logic */

const API = "http://" + window.location.host + "/api";

/* ── Tab switching ── */
function showTab(name, btn) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("page-" + name).classList.add("active");
  if (btn) btn.classList.add("active");
}

/* ── Status ── */
async function fetchStatus() {
  try {
    const r = await fetch(API + "/status");
    const s = await r.json();
    document.getElementById("badge-ldap").textContent = s.ldap_mode === "mock" ? "MOCK" : "LIVE";
    document.getElementById("badge-ldap").className = "status-badge " + (s.ldap_mode === "mock" ? "warn" : "ok");
    document.getElementById("badge-npu").textContent = s.npu_enabled ? "NPU ON" : "NPU OFF";
    document.getElementById("badge-npu").className = "status-badge " + (s.npu_enabled ? "ok" : "warn");
    document.getElementById("meta-version").textContent = s.version;
  } catch (e) {
    document.getElementById("badge-ldap").textContent = "OFFLINE";
    document.getElementById("badge-ldap").className = "status-badge err";
  }
}

/* ── Assessment ── */
let auditRunning = false;

function term(line, cls) {
  const t = document.getElementById("terminal");
  t.innerHTML += `<div class="${cls || ''}">${line}</div>`;
  t.scrollTop = t.scrollHeight;
}

function setProgress(categories, current) {
  const el = document.getElementById("audit-progress");
  el.innerHTML = "";
  for (const cat of categories) {
    const status = cat.state === "done" ? " done" : cat.state === "active" ? " active" : "";
    el.innerHTML += `<div class="prog-row${status}">
      <div class="prog-dot"></div>
      <span class="prog-name">${cat.name}</span>
      <span class="prog-status">${cat.state === "done" ? "done" : cat.state === "active" ? "running..." : ""}</span>
    </div>`;
  }
}

function addFinding(f) {
  const list = document.getElementById("finding-list");
  const empty = list.querySelector(".empty");
  if (empty) empty.remove();
  list.innerHTML += `<div class="finding-row">
    <span class="sev-badge ${f.severity}">${f.severity.toUpperCase()}</span>
    <span class="finding-name">${f.title}</span>
  </div>`;
}

function updateMetrics(crit, high, med, total, risk) {
  document.getElementById("m-findings").textContent = total;
  document.getElementById("m-risk").textContent = risk || "—";
  document.getElementById("m-risk").className = "metric-val " + (risk === "CRITICAL" ? "red" : risk === "HIGH" ? "amber" : "green");
  document.getElementById("b-crit").textContent = crit;
  document.getElementById("b-high").textContent = high;
  document.getElementById("b-med").textContent = med;
}

async function startAssessment() {
  if (auditRunning) return;
  auditRunning = true;
  document.getElementById("run-btn").disabled = true;
  document.getElementById("reset-btn").disabled = true;
  document.getElementById("badge-status").textContent = "RUNNING";
  document.getElementById("badge-status").className = "status-badge warn";

  term("[ Project Supernova v2.0 ]", "t-gray");
  term("");

  const categories = [
    "Account Policy", "Kerberos Configuration", "Privileged Group Membership",
    "ACL Integrity", "GPO Hygiene", "Protocol Hardening",
    "Certificate Services", "Trust Configuration", "Endpoint Security",
  ];

  let catState = categories.map(name => ({ name, state: "" }));
  setProgress(catState, "");
  updateMetrics(0, 0, 0, 0, "—");

  for (let i = 0; i < categories.length; i++) {
    catState[i].state = "active";
    setProgress(catState, "");
    term(`[CATEGORY] ${categories[i]}`, "t-cyan");
    await sleep(300);
    catState[i].state = "done";
  }
  setProgress(catState, "");
  term("");

  try {
    term("[INFO] Starting assessment via API...", "t-yellow");
    const r = await fetch(API + "/assessment/start", { method: "POST" });
    const data = await r.json();

    if (data.error) {
      term("[ERROR] " + data.error, "t-red");
    } else {
      term(`[DONE] Assessment complete — ${data.total_findings} findings`, "t-green");
      term("");

      // Load full findings
      const fr = await fetch(API + "/assessment/findings");
      const fd = await fr.json();

      let crit = 0, high = 0, med = 0;
      for (const f of fd.findings) {
        addFinding(f);
        if (f.severity === "critical") crit++;
        else if (f.severity === "high") high++;
        else if (f.severity === "medium") med++;
      }
      updateMetrics(crit, high, med, fd.count, crit > 0 ? "CRITICAL" : high > 0 ? "HIGH" : "MEDIUM");
    }
  } catch (e) {
    term("[ERROR] API request failed: " + e.message, "t-red");
  }

  document.getElementById("badge-status").textContent = "COMPLETE";
  document.getElementById("badge-status").className = "status-badge ok";
  document.getElementById("reset-btn").disabled = false;
  auditRunning = false;
}

function resetAssessment() {
  document.getElementById("terminal").innerHTML = '<span class="t-gray">Press "Run Assessment" to begin.</span>';
  document.getElementById("finding-list").innerHTML = '<div class="empty">No findings yet.</div>';
  document.getElementById("badge-status").textContent = "READY";
  document.getElementById("badge-status").className = "status-badge ok";
  document.getElementById("run-btn").disabled = false;
  updateMetrics(0, 0, 0, 0, "—");
  setProgress([], "");
  document.getElementById("report-content").innerHTML = '<div class="empty">Run an assessment to generate a report.</div>';
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
    th.textContent = "THREAT: " + (s.threat_level || "low").toUpperCase();
    th.className = "threat-badge threat-" + (s.threat_level || "low");

    if (s.recent_alerts && s.recent_alerts.length > 0) {
      const feed = document.getElementById("alert-feed");
      feed.innerHTML = "";
      for (const a of s.recent_alerts.slice(-10)) {
        feed.innerHTML += `<div class="alert-item ${a.severity}">
          <span class="sev-badge ${a.severity}">${a.severity.toUpperCase()}</span>
          <div>
            <div class="alert-title">${a.title}</div>
            <div class="alert-detail">${a.change_type}</div>
          </div>
          <span class="alert-time">${new Date(a.timestamp).toLocaleTimeString()}</span>
        </div>`;
      }
    }
  } catch (e) {}
}

/* ── Report ── */
async function loadReport() {
  try {
    const r = await fetch(API + "/assessment/findings");
    const fd = await r.json();
    if (fd.count === 0) {
      document.getElementById("report-content").innerHTML = '<div class="empty">No findings. Run an assessment first.</div>';
      return;
    }
    let html = `<div class="report-header">
      <div class="report-title">Active Directory Security Assessment Report</div>
      <div class="report-meta">Total Findings: <span>${fd.count}</span></div>
    </div>`;
    for (const f of fd.findings) {
      html += `<div class="finding-row" style="margin-bottom:6px;padding:12px;">
        <span class="sev-badge ${f.severity}">${f.severity.toUpperCase()}</span>
        <div style="flex:1">
          <div style="font-weight:600;color:#ddd;margin-bottom:4px;">${f.title}</div>
          <div style="font-size:11px;color:#888;">${f.description.slice(0, 200)}...</div>
          ${f.remediation_ps ? `<div style="background:#080808;border:1px solid #1e1e1e;border-radius:5px;padding:8px;margin-top:8px;font-family:Consolas,monospace;font-size:10px;color:#85B7EB;">${f.remediation_ps}</div>` : ""}
        </div>
      </div>`;
    }
    document.getElementById("report-content").innerHTML = html;
  } catch (e) {
    document.getElementById("report-content").innerHTML = '<div class="empty">Failed to load report.</div>';
  }
}

/* ── Utils ── */
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function formatUptime(s) { const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60); return `${h}h ${m}m`; }

/* ── Init ── */
fetchStatus();
showTab("assessment", document.querySelector(".tab-btn"));
setInterval(refreshGuard, 5000);
