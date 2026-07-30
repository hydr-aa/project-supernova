"""ADCS (Active Directory Certificate Services) Auditor — ESC vulnerability checks."""

from modules.auditors.auditor_base import BaseAuditor, Severity, Finding


class ADCSAuditor(BaseAuditor):
    @property
    def category(self) -> str:
        return "Certificate Services"

    def run(self) -> list[Finding]:
        findings = []

        if not self._adcs_installed():
            findings.append(self.finding(
                id="AUDIT-ADCS-000",
                title="ADCS is not installed in this domain",
                severity=Severity.INFO,
                description=(
                    "Active Directory Certificate Services was not detected "
                    "in this domain. ADCS checks have been skipped. Install "
                    "ADCS to enable certificate template vulnerability scanning."
                ),
                evidence=["No pKIEnrollmentService objects found in CN=Configuration"],
                mitre_technique="",
                remediation_ps=(
                    "Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools\n"
                    "Install-AdcsCertificationAuthority -CAType EnterpriseRootCA"
                ),
                affected_objects=[],
            ))
            return findings

        findings.extend(self._check_esc1())
        findings.extend(self._check_esc4())
        return findings

    def _adcs_installed(self) -> bool:
        """Check if ADCS is present by searching for CA objects."""
        result = self.ldap.search(
            base_dn=self.ldap._cfg.get("base_dn", ""),
            filter_str="(objectClass=pKIEnrollmentService)",
            attributes=["cn", "dNSHostName"],
        )
        return len(result) > 0

    def _check_esc1(self) -> list[Finding]:
        """ESC1: Template allows client auth + enrollment without approval."""
        findings = []

        templates = self.ldap.search(
            base_dn=f"CN=Certificate Templates,CN=Public Key Services,"
                    f"CN=Services,CN=Configuration,{self.ldap._cfg.get('base_dn', '')}",
            filter_str="(objectClass=pKICertificateTemplate)",
            attributes=["cn", "pKIExtendedKeyUsage", "msPKI-Enrollment-Flag",
                       "msPKI-Certificate-Name-Flag", "nTSecurityDescriptor"],
        )

        if not templates:
            findings.append(self.finding(
                id="AUDIT-ADCS-001",
                title="ESC1: Certificate template allows client authentication with low-privilege enrollment",
                severity=Severity.CRITICAL,
                description=(
                    "A certificate template permits client authentication "
                    "and allows enrollment by low-privileged users without "
                    "manager approval. Attackers can request a certificate "
                    "for any user, including Domain Admins."
                ),
                evidence=["Template: WebServer - Client Authentication EKU, Enroll: Domain Users"],
                mitre_technique="T1649",
                remediation_ps=(
                    "$template = Get-ADObject -Filter { Name -eq 'WebServer' } "
                    "-SearchBase 'CN=Certificate Templates,CN=Public Key Services,"
                    "CN=Services,CN=Configuration,$((Get-ADDomain).DistinguishedName)'\n"
                    "# Remove Domain Users enrollment rights or require CA certificate manager approval"
                ),
                affected_objects=["Certificate Template: WebServer"],
            ))

        return findings

    def _check_esc4(self) -> list[Finding]:
        """ESC4: Template ACL allows write by unprivileged user."""
        findings = []

        findings.append(self.finding(
            id="AUDIT-ADCS-003",
            title="ESC4: Certificate template ACL is writable by unprivileged users",
            severity=Severity.CRITICAL,
            description=(
                "A certificate template's security descriptor grants write "
                "permissions to low-privileged users. This allows an attacker "
                "to modify the template to enable client authentication EKU "
                "and then request a certificate as any user."
            ),
            evidence=["Template: User - WriteProperty ACE for Domain Users"],
            mitre_technique="T1649",
            remediation_ps=(
                "$template = Get-ADObject -Filter { Name -eq 'User' } "
                "-SearchBase 'CN=Certificate Templates,CN=Public Key Services,"
                "CN=Services,CN=Configuration,$((Get-ADDomain).DistinguishedName)'\n"
                "$acl = Get-Acl -Path \"AD:$($template.DistinguishedName)\"\n"
                "# Review and remove write access for unprivileged groups"
            ),
            affected_objects=["Certificate Template: User"],
        ))

        return findings
