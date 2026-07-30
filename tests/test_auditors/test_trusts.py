"""Tests for the Trusts auditor."""

from modules.auditors.trusts import TrustsAuditor
from modules.auditors.auditor_base import Severity


class TestTrustsAuditor:
    def test_returns_findings(self, mock_ldap):
        auditor = TrustsAuditor(mock_ldap)
        findings = auditor.run()
        assert len(findings) > 0

    def test_reports_no_trusts(self, mock_ldap):
        auditor = TrustsAuditor(mock_ldap)
        findings = auditor.run()
        no_trusts = [f for f in findings if f.id == "AUDIT-TST-000"]
        assert len(no_trusts) == 1
        assert no_trusts[0].severity == Severity.INFO

    def test_category_is_set(self, mock_ldap):
        auditor = TrustsAuditor(mock_ldap)
        findings = auditor.run()
        for f in findings:
            assert f.category == "Trust Configuration"
