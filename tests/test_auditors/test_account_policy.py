"""Tests for the Account Policy auditor."""

from modules.auditors.account_policy import AccountPolicyAuditor
from modules.auditors.auditor_base import Severity


class TestAccountPolicyAuditor:
    def test_returns_findings(self, mock_ldap):
        auditor = AccountPolicyAuditor(mock_ldap)
        findings = auditor.run()
        assert len(findings) > 0

    def test_password_length_finding(self, mock_ldap):
        auditor = AccountPolicyAuditor(mock_ldap)
        findings = auditor.run()

        min_len = [
            f for f in findings if f.id == "AUDIT-ACC-001"
        ]
        assert len(min_len) == 1
        assert min_len[0].severity == Severity.HIGH

    def test_complexity_finding(self, mock_ldap):
        auditor = AccountPolicyAuditor(mock_ldap)
        findings = auditor.run()

        complexity = [
            f for f in findings if f.id == "AUDIT-ACC-002"
        ]
        assert len(complexity) == 1

    def test_lockout_finding(self, mock_ldap):
        auditor = AccountPolicyAuditor(mock_ldap)
        findings = auditor.run()

        lockout = [
            f for f in findings if f.id == "AUDIT-ACC-006"
        ]
        assert len(lockout) == 1

    def test_category_is_set(self, mock_ldap):
        auditor = AccountPolicyAuditor(mock_ldap)
        findings = auditor.run()
        for f in findings:
            assert f.category == "Account Policy"
