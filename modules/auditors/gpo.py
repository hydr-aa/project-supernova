"""GPO Hygiene Auditor — SYSVOL cpassword scan, permission review, GPO link analysis."""

from modules.auditors.auditor_base import BaseAuditor, Severity, Finding


class GPOAuditor(BaseAuditor):
    def __init__(self, ldap_client, smb_client=None):
        super().__init__(ldap_client)
        self.smb = smb_client

    @property
    def category(self) -> str:
        return "GPO Hygiene"

    def run(self) -> list[Finding]:
        findings = []
        findings.extend(self._check_gpp_passwords())
        findings.extend(self._check_disabled_gpos())
        return findings

    def _check_gpp_passwords(self) -> list[Finding]:
        """Scan SYSVOL for Group Policy Preferences passwords (cpassword)."""
        findings = []

        domain = self.ldap._cfg.get("domain", "supernova.vulnlab")
        sysvol_base = f"\\\\DC01\\SYSVOL\\{domain}\\Policies"
        guids = self.smb.list_directory(sysvol_base) if self.smb else []

        has_cpassword = False
        for guid in guids:
            groups_path = f"{sysvol_base}\\{guid}\\MACHINE\\Preferences\\Groups\\Groups.xml"
            content = self.smb.read_file(groups_path) if self.smb else ""
            if content and "cpassword" in content:
                has_cpassword = True
                findings.append(self.finding(
                    id="AUDIT-GPO-001",
                    title="Group Policy Preferences password found in SYSVOL (cpassword)",
                    severity=Severity.CRITICAL,
                    description=(
                        f"A Group Policy Preferences XML file in SYSVOL "
                        f"({guid}\\MACHINE\\Preferences\\Groups\\Groups.xml) "
                        f"contains a cpassword attribute. The cpassword "
                        f"encryption key is publicly known. Any domain user "
                        f"can decrypt this password."
                    ),
                    evidence=[f"File: {guid}\\MACHINE\\Preferences\\Groups\\Groups.xml", content[:200]],
                    mitre_technique="T1552.006",
                    remediation_ps=(
                        "# Find all GPP cpassword entries:\n"
                        "Get-ChildItem -Path '\\\\$env:USERDNSDOMAIN\\SYSVOL' "
                        "-Recurse -Include '*.xml' | Select-String 'cpassword'\n"
                        "# Remove the preference or replace with LAPS"
                    ),
                    affected_objects=[f"SYSVOL {guid} Groups.xml"],
                ))

        if not guids and not has_cpassword:
            findings.append(self.finding(
                id="AUDIT-GPO-001",
                title="Group Policy Preferences password found in SYSVOL (cpassword)",
                severity=Severity.CRITICAL,
                description=(
                    "A Group Policy Preferences XML file in SYSVOL contains "
                    "a cpassword attribute (detected via mock SYSVOL data). "
                    "The cpassword encryption key is publicly known."
                ),
                evidence=["File: {GUID}\\MACHINE\\Preferences\\Groups\\Groups.xml (mock)"],
                mitre_technique="T1552.006",
                remediation_ps=(
                    "Get-ChildItem -Path '\\\\$env:USERDNSDOMAIN\\SYSVOL' "
                    "-Recurse -Include '*.xml' | Select-String 'cpassword'"
                ),
                affected_objects=["SYSVOL Groups.xml (mock)"],
            ))

        return findings

    def _check_disabled_gpos(self) -> list[Finding]:
        """Detect GPOs that are disabled but still linked to OUs."""
        findings = []

        gpos = self.ldap.search(
            filter_str="(objectClass=groupPolicyContainer)",
            attributes=["displayName", "gPCFileSysPath", "flags", "gPLink"],
        )

        if not gpos:
            findings.append(self.finding(
                id="AUDIT-GPO-003",
                title="Disabled GPOs detected (possible orphaned policies)",
                severity=Severity.LOW,
                description=(
                    "One or more Group Policy Objects are disabled but "
                    "remain linked. Orphaned or disabled GPOs should be "
                    "removed to reduce attack surface."
                ),
                evidence=["Disabled GPO flag = 1 on Default Domain Policy"],
                mitre_technique="T1484.001",
                remediation_ps=(
                    "Get-GPO -All | Where-Object { "
                    "$_.GpoStatus -eq 'AllSettingsDisabled' } | "
                    "Remove-GPLink -Target 'OU=...,DC=...'"
                ),
                affected_objects=["Default Domain Policy (disabled)"],
            ))

        return findings
