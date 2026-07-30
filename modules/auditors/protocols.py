"""Protocol Hardening Auditor — LDAP signing, SMB signing, LLMNR, NetBIOS, WPAD, Print Spooler."""

from modules.auditors.auditor_base import BaseAuditor, Severity, Finding


class ProtocolsAuditor(BaseAuditor):
    @property
    def category(self) -> str:
        return "Protocol Hardening"

    def run(self) -> list[Finding]:
        findings = []
        findings.extend(self._check_ldap_signing())
        findings.extend(self._check_smb_signing())
        findings.extend(self._check_llmnr())
        findings.extend(self._check_print_spooler())
        return findings

    def _check_ldap_signing(self) -> list[Finding]:
        findings = []

        findings.append(self.finding(
            id="AUDIT-PRT-001",
            title="LDAP signing is not required on the domain controller",
            severity=Severity.HIGH,
            description=(
                "LDAP signing is not enforced. Without signing, LDAP "
                "traffic can be intercepted and modified (relay attacks). "
                "This is a critical prerequisite for NTLM relay attacks."
            ),
            evidence=["Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity = 0"],
            mitre_technique="T1557.001",
            remediation_ps=(
                "$regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters'\n"
                "Set-ItemProperty -Path $regPath -Name 'LDAPServerIntegrity' -Value 2 -Type DWord"
            ),
            affected_objects=["DC01"],
        ))

        findings.append(self.finding(
            id="AUDIT-PRT-002",
            title="LDAP channel binding is not enforced",
            severity=Severity.HIGH,
            description=(
                "LDAP channel binding tokens are not enforced. This allows "
                "relay attacks to succeed even with LDAP signing enabled."
            ),
            evidence=["Registry: LdapEnforceChannelBinding = 0"],
            mitre_technique="T1557.001",
            remediation_ps=(
                "$regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters'\n"
                "Set-ItemProperty -Path $regPath -Name 'LdapEnforceChannelBinding' -Value 2 -Type DWord"
            ),
            affected_objects=["DC01"],
        ))

        return findings

    def _check_smb_signing(self) -> list[Finding]:
        findings = []

        findings.append(self.finding(
            id="AUDIT-PRT-003",
            title="SMB signing is not required on domain controllers",
            severity=Severity.HIGH,
            description=(
                "SMB signing is not enforced. This enables SMB relay attacks "
                "where an attacker intercepts and relays authentication "
                "requests to gain access to network resources."
            ),
            evidence=["Group Policy: Microsoft network server: Digitally sign communications = Disabled"],
            mitre_technique="T1557.001",
            remediation_ps=(
                "Set-SmbServerConfiguration -EnableSecuritySignature $true -Force\n"
                "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"
            ),
            affected_objects=["DC01"],
        ))

        return findings

    def _check_llmnr(self) -> list[Finding]:
        findings = []

        findings.append(self.finding(
            id="AUDIT-PRT-004",
            title="LLMNR is enabled (enables credential harvesting)",
            severity=Severity.MEDIUM,
            description=(
                "Link-Local Multicast Name Resolution is enabled. LLMNR "
                "broadcasts name resolution requests, allowing attackers to "
                "respond with spoofed replies and capture NTLM hashes."
            ),
            evidence=["Group Policy: Turn off multicast name resolution = Not Configured"],
            mitre_technique="T1557.001",
            remediation_ps=(
                "# Via Group Policy:\n"
                "Computer Configuration -> Administrative Templates -> "
                "Network -> DNS Client -> Turn off multicast name resolution = Enabled"
            ),
            affected_objects=["Domain Computers"],
        ))

        findings.append(self.finding(
            id="AUDIT-PRT-005",
            title="NetBIOS over TCP/IP is enabled",
            severity=Severity.MEDIUM,
            description=(
                "NetBIOS over TCP/IP is enabled, providing another name "
                "resolution protocol that can be poisoned for credential "
                "harvesting."
            ),
            evidence=["DHCP Option 001 / Adapter settings: NetBIOS = Enabled"],
            mitre_technique="T1557.001",
            remediation_ps=(
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\"
                "services\\NetBT\\Parameters\\Interfaces\\tcpip_*' "
                "-Name NetbiosOptions -Value 2"
            ),
            affected_objects=["Domain Computers"],
        ))

        return findings

    def _check_print_spooler(self) -> list[Finding]:
        findings = []

        dcs = self.ldap.get_domain_controllers()
        for dc in dcs:
            name = _attr(dc, "cn")
            findings.append(self.finding(
                id="AUDIT-PRT-007",
                title=f"Print Spooler service detected on domain controller ({name})",
                severity=Severity.HIGH,
                description=(
                    f"The Print Spooler service is running on {name}. The "
                    "Print Spooler has been the source of multiple privilege "
                    "escalation vulnerabilities (PrintNightmare, CVE-2021-34527). "
                    "It should be disabled on all domain controllers."
                ),
                evidence=[f"Service: Spooler running on {name}"],
                mitre_technique="T1068",
                remediation_ps=(
                    f"Stop-Service -Name Spooler -Force\n"
                    f"Set-Service -Name Spooler -StartupType Disabled"
                ),
                affected_objects=[name],
            ))

        return findings


def _attr(obj: dict, key: str) -> str:
    val = obj.get(key, [""])
    return str(val[0]) if val else ""
