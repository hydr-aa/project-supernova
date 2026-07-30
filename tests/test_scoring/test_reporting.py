"""Tests for the reporting and remediation modules."""

from modules.reporting import remediation
from modules.reporting import html_report, json_report
from modules.auditors.auditor_base import Finding, Severity


class TestRemediation:
    def test_known_finding(self):
        cmd = remediation.get_remediation("AUDIT-ACC-001")
        assert "MinPasswordLength" in cmd

    def test_unknown_finding(self):
        cmd = remediation.get_remediation("UNKNOWN-ID")
        assert "No automated remediation" in cmd

    def test_extra_override(self):
        cmd = remediation.get_remediation("AUDIT-ACC-001", extra="Custom remediation")
        assert cmd == "Custom remediation"


class TestReportGeneration:
    def test_html_report_generates(self, config):
        f = Finding(
            id="AUDIT-ACC-001", title="Weak password",
            description="Password is weak", severity=Severity.HIGH,
            category="Account Policy", evidence=["min=7"],
            mitre_technique="T1110.003",
            remediation_ps="Set-ADDefaultDomainPasswordPolicy",
        )
        path = html_report.generate([f], config)
        assert path.endswith(".html")
        import os
        assert os.path.exists(path)
        with open(path) as fh:
            content = fh.read()
            assert "Weak password" in content
            assert "Set-ADDefaultDomainPasswordPolicy" in content

    def test_json_report_generates(self, config):
        f = Finding(
            id="AUDIT-ACC-002", title="No complexity",
            description="Complexity disabled", severity=Severity.HIGH,
            category="Account Policy",
        )
        path = json_report.generate([f], config)
        assert path.endswith(".json")
        import os, json
        assert os.path.exists(path)
        with open(path) as fh:
            data = json.load(fh)
            assert data["scan_metadata"]["tool"] == "Project Supernova"
            assert len(data["findings"]) == 1
            assert data["findings"][0]["id"] == "AUDIT-ACC-002"
