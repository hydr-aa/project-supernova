"""Tests for the Kerberos auditor."""

from modules.auditors.kerberos import KerberosAuditor


class TestKerberosAuditor:
    def test_returns_findings(self, mock_ldap):
        auditor = KerberosAuditor(mock_ldap)
        findings = auditor.run()
        assert isinstance(findings, list)

    def test_detects_roastable_accounts(self, mock_ldap):
        auditor = KerberosAuditor(mock_ldap)
        findings = auditor.run()

        roastable = [
            f for f in findings if f.id == "AUDIT-KRB-004"
        ]
        assert len(roastable) >= 1  # svc_backup has SPN in mock data

    def test_category_is_set(self, mock_ldap):
        auditor = KerberosAuditor(mock_ldap)
        findings = auditor.run()
        for f in findings:
            assert f.category == "Kerberos Configuration"
