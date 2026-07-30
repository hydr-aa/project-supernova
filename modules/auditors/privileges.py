"""Privileged Group Membership Auditor — Domain Admins, Enterprise Admins, DCSync rights."""

from modules.auditors.auditor_base import BaseAuditor, Severity, Finding


class PrivilegesAuditor(BaseAuditor):
    @property
    def category(self) -> str:
        return "Privileged Group Membership"

    def run(self) -> list[Finding]:
        findings = []
        findings.extend(self._check_privileged_groups())
        return findings

    def _check_privileged_groups(self) -> list[Finding]:
        findings = []

        PRIVILEGED_GROUPS = [
            ("Domain Admins", "AUDIT-PRV-001", Severity.CRITICAL),
            ("Enterprise Admins", "AUDIT-PRV-002", Severity.CRITICAL),
            ("Schema Admins", "AUDIT-PRV-003", Severity.CRITICAL),
            ("Account Operators", "AUDIT-PRV-005", Severity.HIGH),
            ("Server Operators", "AUDIT-PRV-006", Severity.HIGH),
            ("Backup Operators", "AUDIT-PRV-007", Severity.HIGH),
        ]

        groups = self.ldap.get_all_groups()
        base_dn = self.ldap._cfg.get("base_dn", "")

        for group_name, finding_id, sev in PRIVILEGED_GROUPS:
            group = next(
                (g for g in groups if _attr(g, "cn").lower() == group_name.lower()),
                None,
            )
            if not group:
                continue

            members = group.get("member", [])
            # Filter to non-built-in members
            suspicious = [
                m for m in members
                if not any(skip in m.lower() for skip in ["administrator", "krbtgt", "domain admins"])
            ]

            if suspicious:
                findings.append(self.finding(
                    id=finding_id,
                    title=f"Non-default members in {group_name}: {len(suspicious)} found",
                    severity=sev,
                    description=(
                        f"The {group_name} group contains {len(suspicious)} non-default members. "
                        "Privileged groups should be audited regularly."
                    ),
                    evidence=suspicious,
                    mitre_technique="T1098",
                    remediation_ps=(
                        f"# Review and remove unauthorised members from {group_name}:\n"
                        f"Get-ADGroupMember -Identity '{group_name}' | "
                        "Format-Table SamAccountName, ObjectClass"
                    ),
                    affected_objects=suspicious,
                ))

        return findings


def _attr(obj: dict, key: str) -> str:
    val = obj.get(key, [""])
    return str(val[0]) if val else ""
