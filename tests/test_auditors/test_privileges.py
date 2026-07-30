"""Tests for the Privileged Groups auditor."""

from modules.auditors.privileges import PrivilegesAuditor
from modules.auditors.auditor_base import Severity


class TestPrivilegesAuditor:
    def test_returns_findings(self, mock_ldap):
        auditor = PrivilegesAuditor(mock_ldap)
        findings = auditor.run()
        assert isinstance(findings, list)

    def test_category_is_set(self, mock_ldap):
        auditor = PrivilegesAuditor(mock_ldap)
        findings = auditor.run()
        for f in findings:
            assert f.category == "Privileged Group Membership"
