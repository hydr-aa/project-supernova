"""Tests for the ACL auditor."""

from modules.auditors.acl import ACLAuditor
from modules.auditors.auditor_base import Severity


class TestACLAuditor:
    def test_returns_findings(self, mock_ldap):
        auditor = ACLAuditor(mock_ldap)
        findings = auditor.run()
        assert len(findings) > 0

    def test_detects_genericall_on_domain_admins(self, mock_ldap):
        auditor = ACLAuditor(mock_ldap)
        findings = auditor.run()
        genericall = [f for f in findings if f.id == "AUDIT-ACL-001"]
        assert len(genericall) == 1
        assert genericall[0].severity == Severity.CRITICAL

    def test_detects_adminsdholder(self, mock_ldap):
        auditor = ACLAuditor(mock_ldap)
        findings = auditor.run()
        holder = [f for f in findings if f.id == "AUDIT-ACL-005"]
        assert len(holder) == 1

    def test_category_is_set(self, mock_ldap):
        auditor = ACLAuditor(mock_ldap)
        findings = auditor.run()
        for f in findings:
            assert f.category == "ACL Integrity"
