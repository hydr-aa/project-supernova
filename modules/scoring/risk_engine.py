"""Risk scoring engine — assigns severity based on exploitability and impact.

Scoring matrix:
    Exploitability: TRIVIAL(4) EASY(3) MODERATE(2) HARD(1)
    Impact:         DOMAIN_ADMIN(4) PRIV_ESC(3) CRED_THEFT(2) RECON(1)
    Severity = max(Exploitability, Impact) -> mapped to CVSS-aligned grade
"""

from enum import Enum
from modules.auditors.auditor_base import Finding, Severity


class Exploitability(Enum):
    TRIVIAL = 4   # No creds needed (LLMNR, GPP)
    EASY = 3      # Low-priv user (Kerberoasting, AS-REP)
    MODERATE = 2  # Requires specific conditions (constrained delegation)
    HARD = 1      # Requires admin already (trust exploitation)


class Impact(Enum):
    DOMAIN_ADMIN = 4   # Full domain compromise (DCSync, unconstrained)
    PRIVILEGE_ESC = 3  # Local admin to DA path (ACL abuse)
    CREDENTIAL_THEFT = 2  # Credential exposure (GPP, AS-REP)
    RECON = 1          # Information disclosure only


class RiskEngine:
    SEVERITY_MATRIX = {
        (4, 4): Severity.CRITICAL,
        (4, 3): Severity.CRITICAL,
        (4, 2): Severity.HIGH,
        (4, 1): Severity.MEDIUM,
        (3, 4): Severity.CRITICAL,
        (3, 3): Severity.HIGH,
        (3, 2): Severity.HIGH,
        (3, 1): Severity.MEDIUM,
        (2, 4): Severity.HIGH,
        (2, 3): Severity.MEDIUM,
        (2, 2): Severity.MEDIUM,
        (2, 1): Severity.LOW,
        (1, 4): Severity.MEDIUM,
        (1, 3): Severity.LOW,
        (1, 2): Severity.LOW,
        (1, 1): Severity.INFO,
    }

    DEFAULT_MAPPING = {
        "AUDIT-ACC-001": (Exploitability.EASY, Impact.CREDENTIAL_THEFT),
        "AUDIT-ACC-002": (Exploitability.EASY, Impact.CREDENTIAL_THEFT),
        "AUDIT-ACC-003": (Exploitability.MODERATE, Impact.CREDENTIAL_THEFT),
        "AUDIT-ACC-006": (Exploitability.EASY, Impact.CREDENTIAL_THEFT),
        "AUDIT-ACC-008": (Exploitability.TRIVIAL, Impact.PRIVILEGE_ESC),
        "AUDIT-ACC-010": (Exploitability.EASY, Impact.CREDENTIAL_THEFT),
        "AUDIT-KRB-001": (Exploitability.MODERATE, Impact.DOMAIN_ADMIN),
        "AUDIT-KRB-004": (Exploitability.EASY, Impact.PRIVILEGE_ESC),
        "AUDIT-PRV-001": (Exploitability.MODERATE, Impact.DOMAIN_ADMIN),
        "AUDIT-PRV-002": (Exploitability.MODERATE, Impact.DOMAIN_ADMIN),
        "AUDIT-PRV-003": (Exploitability.MODERATE, Impact.DOMAIN_ADMIN),
        "AUDIT-PRV-005": (Exploitability.MODERATE, Impact.PRIVILEGE_ESC),
        "AUDIT-PRV-006": (Exploitability.MODERATE, Impact.PRIVILEGE_ESC),
        "AUDIT-PRV-007": (Exploitability.EASY, Impact.PRIVILEGE_ESC),
        "AUDIT-ACL-001": (Exploitability.MODERATE, Impact.DOMAIN_ADMIN),
        "AUDIT-ACL-002": (Exploitability.MODERATE, Impact.DOMAIN_ADMIN),
        "AUDIT-ACL-005": (Exploitability.MODERATE, Impact.DOMAIN_ADMIN),
        "AUDIT-GPO-001": (Exploitability.TRIVIAL, Impact.PRIVILEGE_ESC),
        "AUDIT-GPO-003": (Exploitability.HARD, Impact.RECON),
        "AUDIT-PRT-001": (Exploitability.EASY, Impact.PRIVILEGE_ESC),
        "AUDIT-PRT-002": (Exploitability.EASY, Impact.PRIVILEGE_ESC),
        "AUDIT-PRT-003": (Exploitability.EASY, Impact.PRIVILEGE_ESC),
        "AUDIT-PRT-004": (Exploitability.TRIVIAL, Impact.CREDENTIAL_THEFT),
        "AUDIT-PRT-005": (Exploitability.TRIVIAL, Impact.CREDENTIAL_THEFT),
        "AUDIT-PRT-007": (Exploitability.EASY, Impact.PRIVILEGE_ESC),
        "AUDIT-ADCS-001": (Exploitability.EASY, Impact.DOMAIN_ADMIN),
        "AUDIT-ADCS-003": (Exploitability.MODERATE, Impact.DOMAIN_ADMIN),
        "AUDIT-TST-001": (Exploitability.HARD, Impact.DOMAIN_ADMIN),
        "AUDIT-EPT-001": (Exploitability.MODERATE, Impact.PRIVILEGE_ESC),
        "AUDIT-EPT-002": (Exploitability.MODERATE, Impact.CREDENTIAL_THEFT),
        "AUDIT-EPT-003": (Exploitability.HARD, Impact.DOMAIN_ADMIN),
    }

    def score(self, finding: Finding) -> Finding:
        """Score a single finding, updating its exploitability, impact, and severity."""
        exp, imp = self.DEFAULT_MAPPING.get(
            finding.id,
            (Exploitability.MODERATE, Impact.RECON),
        )
        finding.exploitability = exp.value
        finding.impact = imp.value
        finding.severity = self.SEVERITY_MATRIX.get((exp.value, imp.value), Severity.MEDIUM)
        return finding

    def score_all(self, findings: list[Finding]) -> list[Finding]:
        """Score all findings in-place and return sorted by severity."""
        for f in findings:
            self.score(f)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        findings.sort(key=lambda f: severity_order.get(f.severity, 99))
        return findings

    def summary(self, findings: list[Finding]) -> dict:
        """Return counts per severity and an overall risk level."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            key = f.severity.value
            counts[key] = counts.get(key, 0) + 1

        if counts["critical"] > 0:
            overall = "CRITICAL"
        elif counts["high"] > 2:
            overall = "HIGH"
        elif counts["high"] > 0 or counts["medium"] > 3:
            overall = "MEDIUM"
        elif counts["medium"] > 0:
            overall = "LOW"
        else:
            overall = "INFO"

        return {"counts": counts, "overall_risk": overall, "total": len(findings)}
