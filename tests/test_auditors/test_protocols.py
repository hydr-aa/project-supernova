"""Tests for the Protocols auditor."""

from modules.auditors.protocols import ProtocolsAuditor
from modules.auditors.auditor_base import Severity


class TestProtocolsAuditor:
    def test_returns_findings(self, mock_ldap):
        auditor = ProtocolsAuditor(mock_ldap)
        findings = auditor.run()
        assert len(findings) > 0

    def test_detects_ldap_signing(self, mock_ldap):
        auditor = ProtocolsAuditor(mock_ldap)
        findings = auditor.run()
        ldap_sign = [f for f in findings if f.id == "AUDIT-PRT-001"]
        assert len(ldap_sign) == 1
        assert ldap_sign[0].severity == Severity.HIGH

    def test_detects_llmnr(self, mock_ldap):
        auditor = ProtocolsAuditor(mock_ldap)
        findings = auditor.run()
        llmnr = [f for f in findings if f.id == "AUDIT-PRT-004"]
        assert len(llmnr) == 1

    def test_detects_print_spooler(self, mock_ldap):
        auditor = ProtocolsAuditor(mock_ldap)
        findings = auditor.run()
        spooler = [f for f in findings if f.id == "AUDIT-PRT-007"]
        assert len(spooler) == 1

    def test_category_is_set(self, mock_ldap):
        auditor = ProtocolsAuditor(mock_ldap)
        findings = auditor.run()
        for f in findings:
            assert f.category == "Protocol Hardening"
