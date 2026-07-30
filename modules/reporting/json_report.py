"""JSON report generator — produces machine-parseable assessment reports."""

import json
from datetime import datetime, timezone
from pathlib import Path


def generate(findings, config, output_dir="./reports") -> str:
    """Generate a JSON report and return the file path."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    scan_id = f"SN-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    filename = output_path / f"assessment_{scan_id}.json"

    report = {
        "scan_metadata": {
            "tool": "Project Supernova",
            "version": config.get("supernova", {}).get("version", "2.0.0"),
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_domain": config.get("ldap", {}).get("domain", ""),
            "target_dc": config.get("ldap", {}).get("server", ""),
            "checks_executed": len({f.category for f in findings}),
            "findings_total": len(findings),
        },
        "findings": [],
    }

    for f in findings:
        report["findings"].append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "category": f.category,
            "description": f.description,
            "evidence": f.evidence,
            "mitre_technique": f.mitre_technique,
            "remediation_ps": f.remediation_ps,
            "affected_objects": f.affected_objects,
            "risk_score": {
                "exploitability": f.exploitability,
                "impact": f.impact,
                "calculated_severity": f.severity.value,
            },
        })

    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    return str(filename)
