"""Trust Configuration Auditor — trust direction, SID filtering, TGT delegation."""

from modules.auditors.auditor_base import BaseAuditor, Severity, Finding


class TrustsAuditor(BaseAuditor):
    @property
    def category(self) -> str:
        return "Trust Configuration"

    def run(self) -> list[Finding]:
        findings = []

        trusts = self.ldap.search(
            filter_str="(objectClass=trustedDomain)",
            attributes=["cn", "trustAttributes", "trustDirection",
                       "trustType", "flatName"],
        )

        if not trusts:
            findings.append(self.finding(
                id="AUDIT-TST-000",
                title="No domain trusts detected",
                severity=Severity.INFO,
                description="This domain does not have any forest or external trusts configured.",
                evidence=[],
                mitre_technique="",
                remediation_ps="",
                affected_objects=[],
            ))
            return findings

        for trust in trusts:
            name = _attr(trust, "cn")
            attrs = _uac(trust.get("trustAttributes"))
            direction = _uac(trust.get("trustDirection"))

            # AUDIT-TST-001: TGT delegation across trust
            TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x00000004
            TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x00000010
            TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x00000040
            TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x00000008

            findings.append(self.finding(
                id="AUDIT-TST-001",
                title=f"Trust with {name}: TGT delegation may be enabled",
                severity=Severity.CRITICAL,
                description=(
                    f"The trust relationship with {name} may allow TGT delegation. "
                    "Attackers can forge inter-forest TGTs if a trust allows "
                    "delegation and the trust account is compromised."
                ),
                evidence=[
                    f"Trust: {name}",
                    f"trustAttributes: {attrs}",
                    f"trustDirection: {direction}",
                ],
                mitre_technique="T1558.001",
                remediation_ps=(
                    "# Review trust attributes:\n"
                    f"Get-ADTrust -Identity '{name}' | "
                    "Format-List Name, TrustAttributes, TrustDirection\n"
                    "# Enable SID filtering and disable TGT delegation if not needed:\n"
                    f"Set-ADTrust -Identity '{name}' -EnableTGTDelegation $false"
                ),
                affected_objects=[name],
            ))

        return findings


def _attr(obj: dict, key: str) -> str:
    val = obj.get(key, [""])
    return str(val[0]) if val else ""


def _uac(val) -> int:
    if isinstance(val, (list, tuple)):
        return int(val[0]) if val else 0
    return int(val) if val is not None else 0
