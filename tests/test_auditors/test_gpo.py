"""Tests for the GPO auditor."""

from modules.auditors.gpo import GPOAuditor
from modules.auditors.auditor_base import Severity


class TestGPOAuditor:
    def test_returns_findings(self, mock_ldap, config):
        from modules.smb_client import SMBClient
        smb = SMBClient(config, mock=True)
        auditor = GPOAuditor(mock_ldap, smb_client=smb)
        findings = auditor.run()
        assert len(findings) > 0

    def test_detects_cpassword(self, mock_ldap, config):
        from modules.smb_client import SMBClient
        smb = SMBClient(config, mock=True)
        auditor = GPOAuditor(mock_ldap, smb_client=smb)
        findings = auditor.run()
        cpassword = [f for f in findings if f.id == "AUDIT-GPO-001"]
        assert len(cpassword) == 1
        assert cpassword[0].severity == Severity.CRITICAL

    def test_category_is_set(self, mock_ldap, config):
        from modules.smb_client import SMBClient
        smb = SMBClient(config, mock=True)
        auditor = GPOAuditor(mock_ldap, smb_client=smb)
        findings = auditor.run()
        for f in findings:
            assert f.category == "GPO Hygiene"
