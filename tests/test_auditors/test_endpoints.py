"""Tests for the Endpoints auditor."""

from modules.auditors.endpoints import EndpointsAuditor
from modules.auditors.auditor_base import Severity


class TestEndpointsAuditor:
    def test_returns_findings(self, mock_ldap):
        auditor = EndpointsAuditor(mock_ldap)
        findings = auditor.run()
        assert len(findings) > 0

    def test_detects_laps_not_deployed(self, mock_ldap):
        auditor = EndpointsAuditor(mock_ldap)
        findings = auditor.run()
        laps = [f for f in findings if f.id == "AUDIT-EPT-001"]
        assert len(laps) == 1
        assert laps[0].severity == Severity.HIGH

    def test_detects_protected_users(self, mock_ldap):
        auditor = EndpointsAuditor(mock_ldap)
        findings = auditor.run()
        protected = [f for f in findings if f.id == "AUDIT-EPT-002"]
        assert len(protected) == 1

    def test_category_is_set(self, mock_ldap):
        auditor = EndpointsAuditor(mock_ldap)
        findings = auditor.run()
        for f in findings:
            assert f.category == "Endpoint Security"
