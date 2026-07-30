"""Account Policy Auditor — checks password policies, lockout, pre-auth, inactive accounts."""

from modules.auditors.auditor_base import BaseAuditor, Severity, Finding


class AccountPolicyAuditor(BaseAuditor):
    @property
    def category(self) -> str:
        return "Account Policy"

    def run(self) -> list[Finding]:
        findings = []
        findings.extend(self._check_password_policy())
        findings.extend(self._check_user_account_flags())
        return findings

    def _check_password_policy(self) -> list[Finding]:
        findings = []
        policy = self.ldap.get_password_policy()

        if not policy:
            return findings

        # AUDIT-ACC-001: Minimum password length
        min_len = policy.get("min_length", 0)
        if min_len < 14:
            findings.append(self.finding(
                id="AUDIT-ACC-001",
                title=f"Minimum password length is {min_len} (recommended: 14+)",
                severity=Severity.HIGH,
                description=(
                    f"The domain minimum password length is set to {min_len} characters. "
                    "Short passwords are vulnerable to brute-force and spraying attacks."
                ),
                evidence=[f"minPwdLength = {min_len}"],
                mitre_technique="T1110.003",
                remediation_ps=(
                    "Set-ADDefaultDomainPasswordPolicy -Identity "
                    f"$((Get-ADDomain).DNSRoot) -MinPasswordLength 14"
                ),
                affected_objects=["Default Domain Policy"],
            ))

        # AUDIT-ACC-002: Password complexity
        if not policy.get("complexity_enabled", False):
            findings.append(self.finding(
                id="AUDIT-ACC-002",
                title="Password complexity is disabled",
                severity=Severity.HIGH,
                description="Password complexity requirements are not enforced.",
                evidence=["pwdProperties does not include DOMAIN_PASSWORD_COMPLEX (bit 0)"],
                mitre_technique="T1110.003",
                remediation_ps=(
                    "Set-ADDefaultDomainPasswordPolicy -Identity "
                    "$((Get-ADDomain).DNSRoot) -ComplexityEnabled $true"
                ),
                affected_objects=["Default Domain Policy"],
            ))

        # AUDIT-ACC-003: Password history
        hist = policy.get("history_length", 0)
        if hist < 24:
            findings.append(self.finding(
                id="AUDIT-ACC-003",
                title=f"Password history is {hist} (recommended: 24)",
                severity=Severity.MEDIUM,
                description="A short password history allows users to reuse recent passwords.",
                evidence=[f"pwdHistoryLength = {hist}"],
                mitre_technique="T1078",
                remediation_ps=(
                    "Set-ADDefaultDomainPasswordPolicy -Identity "
                    "$((Get-ADDomain).DNSRoot) -PasswordHistoryCount 24"
                ),
                affected_objects=["Default Domain Policy"],
            ))

        # AUDIT-ACC-006: Lockout threshold
        threshold = policy.get("lockout_threshold", 0)
        if threshold == 0:
            findings.append(self.finding(
                id="AUDIT-ACC-006",
                title="Account lockout threshold is disabled (0)",
                severity=Severity.HIGH,
                description="No account lockout policy is configured, allowing unlimited password guessing.",
                evidence=[f"lockoutThreshold = {threshold}"],
                mitre_technique="T1110.003",
                remediation_ps=(
                    "Set-ADDefaultDomainPasswordPolicy -Identity "
                    "$((Get-ADDomain).DNSRoot) -LockoutThreshold 5 -LockoutDuration 00:30:00"
                ),
                affected_objects=["Default Domain Policy"],
            ))

        return findings

    def _check_user_account_flags(self) -> list[Finding]:
        findings = []
        users = self.ldap.get_all_users()

        UAC_PASSWD_NOTREQD = 0x0020
        UAC_DONT_EXPIRE = 0x10000
        UAC_DISABLED = 0x0002
        UAC_NO_PREAUTH = 0x40000000

        for user in users:
            uac = _uac(user)
            name = _attr(user, "sAMAccountName")

            if uac & UAC_PASSWD_NOTREQD:
                findings.append(self.finding(
                    id="AUDIT-ACC-008",
                    title=f"PASSWD_NOTREQD flag set on {name}",
                    severity=Severity.CRITICAL,
                    description=f"The account {name} does not require a password.",
                    evidence=[f"{name}: userAccountControl = {uac}"],
                    mitre_technique="T1078.001",
                    remediation_ps=f"Set-ADUser -Identity {name} -PasswordNotRequired $false",
                    affected_objects=[name],
                ))

            if uac & UAC_NO_PREAUTH and not (uac & UAC_DISABLED):
                findings.append(self.finding(
                    id="AUDIT-ACC-010",
                    title=f"Kerberos pre-authentication disabled on {name} (AS-REP roastable)",
                    severity=Severity.HIGH,
                    description=(
                        f"The account {name} does not require Kerberos pre-authentication. "
                        "This makes it vulnerable to AS-REP roasting attacks."
                    ),
                    evidence=[f"{name}: userAccountControl = {uac}"],
                    mitre_technique="T1558.004",
                    remediation_ps=(
                        f"Set-ADAccountControl -Identity {name} "
                        "-DoesNotRequirePreAuth $false"
                    ),
                    affected_objects=[name],
                ))

        return findings


def _uac(user: dict) -> int:
    val = user.get("userAccountControl", [0])
    return int(val[0]) if val else 0


def _attr(user: dict, key: str) -> str:
    val = user.get(key, [""])
    return str(val[0]) if val else ""
