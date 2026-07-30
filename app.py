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

from flask import Flask, jsonify, request
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
MOCK = True  # Will switch to False when DC is available
ldap_client = LDAPClient(cfg, mock=MOCK, logger=log)

authorised = False
assessment_active = False
assessment_findings = []


@app.before_request
def check_scope():
    """Block API if network scope is not verified."""
    if request.path == "/api/status":
        return  # Always allow health check
    if not MOCK and not verify_network_scope(cfg, log):
        return jsonify({"error": "Network scope not verified"}), 403


# ── API Routes ───────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    return jsonify({
        "version": cfg["supernova"]["version"],
        "mode": cfg["supernova"]["mode"],
        "ldap_mode": "mock" if MOCK else "live",
        "ldap_connected": ldap_client.connected,
        "authorised": authorised,
        "assessment_active": assessment_active,
        "npu_enabled": cfg.get("npu", {}).get("enabled", False),
    })


@app.route("/api/assessment/start", methods=["POST"])
def api_assessment_start():
    global authorised, assessment_active, assessment_findings

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

        # Import and run all auditors
        from modules.auditors.account_policy import AccountPolicyAuditor
        from modules.auditors.kerberos import KerberosAuditor
        from modules.auditors.privileges import PrivilegesAuditor

        auditors = [
            AccountPolicyAuditor(ldap_client),
            KerberosAuditor(ldap_client),
            PrivilegesAuditor(ldap_client),
        ]

        for auditor in auditors:
            findings = auditor.run()
            assessment_findings.extend(findings)
            log.info("auditor_complete", extra_data={
                "category": auditor.category,
                "findings": len(findings),
            })

    except Exception as e:
        log.error(f"assessment_failed: {e}")
        assessment_active = False
        return jsonify({"error": str(e)}), 500

    assessment_active = False
    log.info("assessment_complete", extra_data={"total_findings": len(assessment_findings)})

    return jsonify({
        "status": "complete",
        "total_findings": len(assessment_findings),
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category,
                "mitre_technique": f.mitre_technique,
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
            }
            for f in results
        ],
    })


@app.route("/api/guard/status")
def api_guard_status():
    return jsonify({
        "guard_active": False,
        "threat_level": "low",
        "events_analysed": 0,
        "alerts_triggered": 0,
    })


# ── Main ─────────────────────────────────────────────────────

if __name__ == "__main__":
    port = 5000
    print(f"\n  Project Supernova v{cfg['supernova']['version']}")
    print(f"  LDAP mode: {'mock (dev)' if MOCK else 'live'}")
    print(f"  Dashboard: http://{cfg['network']['supernova_ip']}:{port}")
    print(f"  API:       http://{cfg['network']['supernova_ip']}:{port}/api/status\n")
    app.run(host="0.0.0.0", port=port, debug=True)
