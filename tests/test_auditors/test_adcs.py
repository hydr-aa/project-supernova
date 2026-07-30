"""Tests for the ADCS auditor."""

from modules.auditors.adcs import ADCSAuditor
from modules.auditors.auditor_base import Severity


class TestADCSAuditor:
    def test_returns_findings(self, mock_ldap):
        auditor = ADCSAuditor(mock_ldap)
        findings = auditor.run()
        assert len(findings) > 0

    def test_reports_not_installed(self, mock_ldap):
        auditor = ADCSAuditor(mock_ldap)
        findings = auditor.run()
        not_installed = [f for f in findings if f.id == "AUDIT-ADCS-000"]
        assert len(not_installed) == 1
        assert not_installed[0].severity == Severity.INFO

    def test_category_is_set(self, mock_ldap):
        auditor = ADCSAuditor(mock_ldap)
        findings = auditor.run()
        for f in findings:
            assert f.category == "Certificate Services"
