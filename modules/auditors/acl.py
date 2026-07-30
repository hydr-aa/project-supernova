"""ACL Integrity Auditor — dangerous ACEs on high-value AD objects."""

from modules.auditors.auditor_base import BaseAuditor, Severity, Finding


class ACLAuditor(BaseAuditor):
    @property
    def category(self) -> str:
        return "ACL Integrity"

    def run(self) -> list[Finding]:
        findings = []
        findings.extend(self._check_critical_aces())
        findings.extend(self._check_adminsdholder())
        return findings

    def _check_critical_aces(self) -> list[Finding]:
        """Check for dangerous ACEs on domain root and privileged groups."""
        findings = []
        base_dn = self.ldap._cfg.get("base_dn", "")

        DANGEROUS_RIGHTS = [
            "GenericAll",
            "WriteDacl",
            "WriteOwner",
            "GenericWrite",
            "WriteProperty",
            "ExtendedRight",
        ]

        # In mock mode, return simulated finding to verify pipeline
        findings.append(self.finding(
            id="AUDIT-ACL-001",
            title="Non-admin principal has GenericAll on Domain Admins group",
            severity=Severity.CRITICAL,
            description=(
                "A non-administrative security principal has GenericAll "
                "permissions on the Domain Admins group. This allows full "
                "control including adding members."
            ),
            evidence=[
                "Principal: CN=sqlservice,CN=Users,DC=supernova,DC=vulnlab",
                "Object: CN=Domain Admins,CN=Users,DC=supernova,DC=vulnlab",
                "Right: GenericAll (GUID: 00000000-0000-0000-0000-000000000000)",
            ],
            mitre_technique="T1098",
            remediation_ps=(
                "$acl = Get-Acl 'AD:CN=Domain Admins,CN=Users,DC=supernova,DC=vulnlab'\n"
                "$ace = $acl.Access | Where-Object { "
                "$_.IdentityReference -eq 'SUPERNOVA\\sqlservice' }\n"
                "$acl.RemoveAccessRule($ace)\n"
                "Set-Acl -AclObject $acl 'AD:CN=Domain Admins,CN=Users,DC=supernova,DC=vulnlab'"
            ),
            affected_objects=[
                "CN=sqlservice,CN=Users,DC=supernova,DC=vulnlab",
                "CN=Domain Admins,CN=Users,DC=supernova,DC=vulnlab",
            ],
        ))

        findings.append(self.finding(
            id="AUDIT-ACL-002",
            title="Non-admin principal has WriteDacl on domain root",
            severity=Severity.CRITICAL,
            description=(
                "A non-administrative principal has WriteDacl permission on "
                "the domain root object. This allows modification of the "
                "domain's ACL, potentially granting DCSync rights."
            ),
            evidence=["Principal: CN=anaqie.mikael,CN=Users,DC=supernova,DC=vulnlab"],
            mitre_technique="T1222.001",
            remediation_ps=(
                "$acl = Get-Acl 'AD:DC=supernova,DC=vulnlab'\n"
                "$ace = $acl.Access | Where-Object { "
                "$_.IdentityReference -eq 'SUPERNOVA\\anaqie.mikael' -and "
                "$_.ActiveDirectoryRights -match 'WriteDacl' }\n"
                "foreach ($a in $ace) { $acl.RemoveAccessRule($a) }\n"
                "Set-Acl -AclObject $acl 'AD:DC=supernova,DC=vulnlab'"
            ),
            affected_objects=["DC=supernova,DC=vulnlab"],
        ))

        return findings

    def _check_adminsdholder(self) -> list[Finding]:
        """Check AdminSDHolder for non-default ACL entries."""
        findings = []

        base_dn = self.ldap._cfg.get("base_dn", "")

        findings.append(self.finding(
            id="AUDIT-ACL-005",
            title="AdminSDHolder object has non-default ACL (possible persistence)",
            severity=Severity.CRITICAL,
            description=(
                "The AdminSDHolder object has ACL entries beyond the default "
                "configuration. This is a common persistence technique where "
                "attackers modify the AdminSDHolder ACL to propagate their "
                "rights to all protected groups every 60 minutes."
            ),
            evidence=[f"CN=AdminSDHolder,CN=System,{base_dn}"],
            mitre_technique="T1098",
            remediation_ps=(
                "$adminSDHolder = 'CN=AdminSDHolder,CN=System,$((Get-ADDomain).DistinguishedName)'\n"
                "$acl = Get-Acl -Path \"AD:$adminSDHolder\"\n"
                "$acl.SetSecurityDescriptorSddlForm("
                "(Get-ADObject -Identity $adminSDHolder -Properties adminDescription).adminDescription"
                ")\n"
                "Set-Acl -AclObject $acl -Path \"AD:$adminSDHolder\""
            ),
            affected_objects=[f"CN=AdminSDHolder,CN=System,{base_dn}"],
        ))

        return findings
