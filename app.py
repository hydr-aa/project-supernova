"""Project Supernova — Flask application entry point.

Start the server:
    python app.py                         # dev mode, uses .env
    SUPERNOVA_AUTHORIZED=1 python app.py   # dev mode, authorised

API documentation: docs/API.md
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, jsonify, request, render_template, send_file
from flask_cors import CORS

from modules.utils.config import load_config
from modules.utils.logger import get_logger
from modules.utils.network import verify_network_scope
from modules.utils.safety import request_authorization
from modules.ldap_client import LDAPClient


app = Flask(__name__)
CORS(app)

# ── Bootstrap ────────────────────────────────────────────────

cfg = load_config("config.yaml")
log = get_logger(cfg)

# Use mock LDAP if no DC is reachable (development mode)
MOCK = True
ldap_client = LDAPClient(cfg, mock=MOCK, logger=log)

authorised = False
assessment_active = False
assessment_findings = []
last_report_html = ""
last_report_json = ""

# Guard instance (lazy init)
guard_poller = None


@app.before_request
def check_scope():
    if request.path == "/api/status" or request.path == "/":
        return
    if not MOCK and not verify_network_scope(cfg, log):
        return jsonify({"error": "Network scope not verified"}), 403


# ── Dashboard ────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/blue")
def dashboard_blue():
    return render_template("dashboard-blue.html")


@app.route("/soc-light")
def dashboard_soc_light():
    return render_template("dashboard-soc-light.html")


@app.route("/soc")
def dashboard_soc():
    return render_template("dashboard-soc.html")


# ── API: Status ──────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    guard_status = guard_poller.status if guard_poller else {}
    return jsonify({
        "version": cfg["supernova"]["version"],
        "mode": cfg["supernova"]["mode"],
        "ldap_mode": "mock" if MOCK else "live",
        "ldap_connected": ldap_client.connected,
        "authorised": authorised,
        "assessment_active": assessment_active,
        "npu_enabled": cfg.get("npu", {}).get("enabled", False),
        "guard": guard_status,
    })


# ── API: Assessment ──────────────────────────────────────────

@app.route("/api/assessment/start", methods=["POST"])
def api_assessment_start():
    global authorised, assessment_active, assessment_findings
    global last_report_html, last_report_json

    if not authorised:
        if not request_authorization(cfg, log):
            return jsonify({"error": "Authorisation required"}), 403
        authorised = True

    if assessment_active:
        return jsonify({"error": "Assessment already in progress"}), 409

    assessment_active = True
    assessment_findings = []
    log.info("assessment_started")

    try:
        if not ldap_client.connected:
            ldap_client.connect()

        from modules.auditors.account_policy import AccountPolicyAuditor
        from modules.auditors.kerberos import KerberosAuditor
        from modules.auditors.privileges import PrivilegesAuditor
        from modules.auditors.acl import ACLAuditor
        from modules.auditors.gpo import GPOAuditor
        from modules.auditors.protocols import ProtocolsAuditor
        from modules.auditors.adcs import ADCSAuditor
        from modules.auditors.trusts import TrustsAuditor
        from modules.auditors.endpoints import EndpointsAuditor
        from modules.smb_client import SMBClient
        from modules.scoring.risk_engine import RiskEngine
        from modules.reporting import html_report, json_report
        from modules.reporting.remediation import get_remediation

        smb_client = SMBClient(cfg, mock=MOCK, logger=log)
        engine = RiskEngine()

        auditors = [
            AccountPolicyAuditor(ldap_client),
            KerberosAuditor(ldap_client),
            PrivilegesAuditor(ldap_client),
            ACLAuditor(ldap_client),
            GPOAuditor(ldap_client, smb_client=smb_client),
            ProtocolsAuditor(ldap_client),
            ADCSAuditor(ldap_client),
            TrustsAuditor(ldap_client),
            EndpointsAuditor(ldap_client),
        ]

        for auditor in auditors:
            findings = auditor.run()
            for f in findings:
                if not f.remediation_ps:
                    f.remediation_ps = get_remediation(f.id)
            assessment_findings.extend(findings)
            log.info("auditor_complete", extra_data={
                "category": auditor.category,
                "findings": len(findings),
            })

        engine.score_all(assessment_findings)

        last_report_html = html_report.generate(assessment_findings, cfg)
        last_report_json = json_report.generate(assessment_findings, cfg)

    except Exception as e:
        log.error(f"assessment_failed: {e}")
        assessment_active = False
        return jsonify({"error": str(e)}), 500

    assessment_active = False
    summary = engine.summary(assessment_findings)
    log.info("assessment_complete", extra_data=summary)

    return jsonify({
        "status": "complete",
        "total_findings": len(assessment_findings),
        "summary": summary,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category,
                "mitre_technique": f.mitre_technique,
                "exploitability": f.exploitability,
                "impact": f.impact,
            }
            for f in assessment_findings
        ],
    })


@app.route("/api/assessment/findings")
def api_assessment_findings():
    severity = request.args.get("severity")
    results = assessment_findings
    if severity:
        results = [f for f in results if f.severity.value == severity]
    return jsonify({
        "count": len(results),
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category,
                "description": f.description,
                "mitre_technique": f.mitre_technique,
                "remediation_ps": f.remediation_ps,
                "evidence": f.evidence,
                "affected_objects": f.affected_objects,
                "exploitability": f.exploitability,
                "impact": f.impact,
            }
            for f in results
        ],
    })


@app.route("/api/assessment/progress")
def api_assessment_progress():
    return jsonify({
        "active": assessment_active,
        "total_categories": 9,
        "findings_so_far": len(assessment_findings),
    })


# ── API: Reports ─────────────────────────────────────────────

@app.route("/api/report/latest")
def api_report_latest():
    from modules.scoring.risk_engine import RiskEngine
    engine = RiskEngine()
    summary = engine.summary(assessment_findings) if assessment_findings else {}
    return jsonify({
        "available": len(assessment_findings) > 0,
        "total_findings": len(assessment_findings),
        "summary": summary,
        "html_path": last_report_html,
        "json_path": last_report_json,
    })


@app.route("/api/report/download")
def api_report_download():
    fmt = request.args.get("format", "html")
    path = last_report_html if fmt == "html" else last_report_json
    if not path or not Path(path).exists():
        return jsonify({"error": "No report available. Run an assessment first."}), 404
    return send_file(
        Path(path).absolute(),
        as_attachment=True,
        download_name=Path(path).name,
    )


# ── API: Guard ───────────────────────────────────────────────

@app.route("/api/guard/status")
def api_guard_status():
    status = guard_poller.status if guard_poller else {
        "running": False,
        "threat_level": "low",
        "events_analysed": 0,
        "alerts_triggered": 0,
        "uptime_seconds": 0,
        "recent_alerts": [],
    }
    return jsonify(status)


@app.route("/api/guard/start", methods=["POST"])
def api_guard_start():
    global guard_poller
    if guard_poller is None:
        from modules.guard.poller import GuardPoller
        guard_poller = GuardPoller(ldap_client, cfg, logger=log)
    if not guard_poller.status["running"]:
        guard_poller.start()
    return jsonify(guard_poller.status)


@app.route("/api/guard/stop", methods=["POST"])
def api_guard_stop():
    global guard_poller
    if guard_poller and guard_poller.status["running"]:
        guard_poller.stop()
    return jsonify(guard_poller.status if guard_poller else {"running": False})


# ── Main ─────────────────────────────────────────────────────

if __name__ == "__main__":
    port = 5000
    print(f"\n  Project Supernova v{cfg['supernova']['version']}")
    print(f"  LDAP mode: {'mock (dev)' if MOCK else 'live'}")
    print(f"  Dashboard: http://{cfg['network']['supernova_ip']}:{port}")
    print(f"  API:       http://{cfg['network']['supernova_ip']}:{port}/api/status\n")
    app.run(host="0.0.0.0", port=port, debug=True)
