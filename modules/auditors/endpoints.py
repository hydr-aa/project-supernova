"""Endpoint Security Auditor — LAPS, Protected Users, KRBTGT age."""

from modules.auditors.auditor_base import BaseAuditor, Severity, Finding


class EndpointsAuditor(BaseAuditor):
    @property
    def category(self) -> str:
        return "Endpoint Security"

    def run(self) -> list[Finding]:
        findings = []
        findings.extend(self._check_laps())
        findings.extend(self._check_protected_users())
        findings.extend(self._check_krbtgt_age())
        return findings

    def _check_laps(self) -> list[Finding]:
        """Check if LAPS is deployed across domain computers."""
        findings = []

        computers = self.ldap.get_all_computers()
        laps_deployed = 0
        for comp in computers:
            if comp.get("ms-Mcs-AdmPwd", [None])[0]:
                laps_deployed += 1

        if laps_deployed == 0:
            findings.append(self.finding(
                id="AUDIT-EPT-001",
                title="LAPS is not deployed (local administrator passwords not managed)",
                severity=Severity.HIGH,
                description=(
                    "Microsoft Local Administrator Password Solution (LAPS) "
                    "is not deployed on any domain computer. Without LAPS, "
                    "local administrator passwords are either identical across "
                    "all workstations or manually managed, creating a lateral "
                    "movement risk."
                ),
                evidence=["ms-Mcs-AdmPwd attribute empty on all computer objects"],
                mitre_technique="T1078.001",
                remediation_ps=(
                    "# Install LAPS on DC:\n"
                    "Install-WindowsFeature RSAT-LAPS\n"
                    "Update-LapsADSchema\n"
                    "# Deploy LAPS client to workstations via GPO\n"
                    "# Configure LAPS GPO:\n"
                    "Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,...'"
                ),
                affected_objects=["Domain Computers"],
            ))

        return findings

    def _check_protected_users(self) -> list[Finding]:
        """Check if privileged accounts are in Protected Users group."""
        findings = []

        base_dn = self.ldap._cfg.get("base_dn", "")
        result = self.ldap.search(
            base_dn=f"CN=Protected Users,CN=Users,{base_dn}",
            filter_str="(objectClass=*)",
            attributes=["member"],
        )

        members = result[0].get("member", []) if result else []

        # Check if Administrator is protected
        admin_protected = any(
            "administrator" in m.lower() for m in members
        ) if members else False

        if not admin_protected:
            findings.append(self.finding(
                id="AUDIT-EPT-002",
                title="Domain Administrator not in Protected Users group",
                severity=Severity.HIGH,
                description=(
                    "The Administrator account is not a member of the Protected "
                    "Users security group. Protected Users prevents credential "
                    "caching, NTLM authentication, and unconstrained delegation "
                    "for its members, significantly reducing the impact of "
                    "credential theft."
                ),
                evidence=["Administrator not in CN=Protected Users,CN=Users,..."],
                mitre_technique="T1003",
                remediation_ps=(
                    "Add-ADGroupMember -Identity 'Protected Users' "
                    "-Members 'Administrator'\n"
                    "# Also add all privileged accounts:\n"
                    "Get-ADGroupMember 'Domain Admins' | "
                    "Add-ADGroupMember -Identity 'Protected Users' -Members $_.SamAccountName"
                ),
                affected_objects=["Administrator"],
            ))

        return findings

    def _check_krbtgt_age(self) -> list[Finding]:
        """Check that KRBTGT password has been rotated recently."""
        findings = []

        users = self.ldap.search(
            filter_str="(sAMAccountName=krbtgt)",
            attributes=["sAMAccountName", "pwdLastSet"],
        )

        if users:
            pwd_last_set = int(users[0].get("pwdLastSet", [0])[0])
            # pwdLastSet is in 100-nanosecond intervals since Jan 1, 1601
            if pwd_last_set:
                from datetime import datetime, timezone, timedelta
                epoch = datetime(1601, 1, 1)
                pwd_date = epoch + timedelta(microseconds=pwd_last_set / 10)
                days_old = (datetime.now(timezone.utc).replace(tzinfo=None) - pwd_date).days

                if days_old > 180:
                    findings.append(self.finding(
                        id="AUDIT-EPT-003",
                        title=f"KRBTGT password is {days_old} days old (recommended: < 180 days)",
                        severity=Severity.CRITICAL,
                        description=(
                            f"The KRBTGT account password was last changed "
                            f"{days_old} days ago. The KRBTGT password should "
                            "be rotated regularly. If compromised, an attacker "
                            "can forge Kerberos tickets indefinitely (Golden Ticket)."
                        ),
                        evidence=[
                            f"KRBTGT pwdLastSet: {pwd_date.isoformat()}",
                            f"Days since rotation: {days_old}",
                        ],
                        mitre_technique="T1558.001",
                        remediation_ps=(
                            "# Reset KRBTGT password twice (wait 10 hours between):\n"
                            "Reset-ADComputerServiceAccountPassword -Identity krbtgt\n"
                            "# Wait for replication (10 hours minimum)\n"
                            "Reset-ADComputerServiceAccountPassword -Identity krbtgt"
                        ),
                        affected_objects=["krbtgt"],
                    ))

        return findings
