"""Kerberos Configuration Auditor — delegation, SPNs, encryption types."""

from modules.auditors.auditor_base import BaseAuditor, Severity, Finding


class KerberosAuditor(BaseAuditor):
    @property
    def category(self) -> str:
        return "Kerberos Configuration"

    def run(self) -> list[Finding]:
        findings = []
        findings.extend(self._check_delegation())
        findings.extend(self._check_roastable_accounts())
        return findings

    def _check_delegation(self) -> list[Finding]:
        findings = []
        computers = self.ldap.get_all_computers()
        users = self.ldap.get_all_users()

        UAC_TRUSTED_FOR_DELEGATION = 0x80000  # Unconstrained delegation

        for obj in computers + users:
            uac = _uac(obj)
            name = _attr(obj, "cn") or _attr(obj, "sAMAccountName")

            if uac & UAC_TRUSTED_FOR_DELEGATION:
                findings.append(self.finding(
                    id="AUDIT-KRB-001",
                    title=f"Unconstrained Kerberos delegation on {name}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The account {name} is trusted for unconstrained delegation. "
                        "Any attacker compromising this host can impersonate any user."
                    ),
                    evidence=[f"{name}: TRUSTED_FOR_DELEGATION enabled"],
                    mitre_technique="T1558.001",
                    remediation_ps=(
                        f"Set-ADAccountControl -Identity {name} "
                        "-TrustedForDelegation $false"
                    ),
                    affected_objects=[name],
                ))

        return findings

    def _check_roastable_accounts(self) -> list[Finding]:
        findings = []
        users = self.ldap.get_all_users()

        UAC_DISABLED = 0x0002

        for user in users:
            uac = _uac(user)
            spns = user.get("servicePrincipalName", [])
            name = _attr(user, "sAMAccountName")

            if spns and spns != [""] and not (uac & UAC_DISABLED):
                findings.append(self.finding(
                    id="AUDIT-KRB-004",
                    title=f"Kerberoastable service account: {name}",
                    severity=Severity.HIGH,
                    description=(
                        f"The account {name} has Service Principal Names registered: "
                        f"{', '.join(spns[:3])}. This account is Kerberoastable."
                    ),
                    evidence=spns,
                    mitre_technique="T1558.003",
                    remediation_ps=(
                        f"# Consider migrating to gMSA:\n"
                        f"New-ADServiceAccount -Name '{name}_gMSA' "
                        f"-DNSHostName 'DC01.$((Get-ADDomain).DNSRoot)' "
                        f"-PrincipalsAllowedToRetrieveManagedPassword 'Domain Computers'"
                    ),
                    affected_objects=[name],
                ))

        return findings


def _uac(obj: dict) -> int:
    val = obj.get("userAccountControl", [0])
    return int(val[0]) if val else 0


def _attr(obj: dict, key: str) -> str:
    val = obj.get(key, [""])
    return str(val[0]) if val else ""
