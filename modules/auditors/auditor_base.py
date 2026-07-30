"""Base auditor — every audit module inherits from this.

Usage:
    class AccountPolicyAuditor(BaseAuditor):
        @property
        def category(self):
            return "Account Policy"

        def run(self):
            findings = []
            pwd_policy = self.ldap.get_password_policy()
            if pwd_policy.get("min_length", 0) < 14:
                findings.append(self.finding(
                    id="AUDIT-ACC-001",
                    title="Minimum password length below 14 characters",
                    severity=self.severity("AUDIT-ACC-001", default=Severity.HIGH),
                    description=f"Current minimum password length is {pwd_policy['min_length']}.",
                    evidence=[str(pwd_policy)],
                    mitre_technique="T1110.003",
                    remediation_ps=(
                        "Set-ADDefaultDomainPasswordPolicy -Identity supernova.vulnlab "
                        "-MinPasswordLength 14"
                    ),
                    affected_objects=["Default Domain Policy"],
                ))
            return findings
"""

from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    category: str
    evidence: list[str] = field(default_factory=list)
    mitre_technique: str = ""
    remediation_ps: str = ""
    affected_objects: list[str] = field(default_factory=list)
    exploitability: int = 0
    impact: int = 0


class BaseAuditor(ABC):
    def __init__(self, ldap_client):
        self.ldap = ldap_client

    @property
    @abstractmethod
    def category(self) -> str:
        """Human-readable category name for reports."""

    @abstractmethod
    def run(self) -> list[Finding]:
        """Execute all checks in this category. Returns list of Findings."""

    def finding(self, **kwargs) -> Finding:
        """Create a Finding with defaults populated."""
        kwargs.setdefault("category", self.category)
        return Finding(**kwargs)

    @staticmethod
    def severity(finding_id: str, default: Severity = Severity.MEDIUM) -> Severity:
        """
        Lookup severity for a finding ID. Override this per auditor to
        customise default severities. Falls back to 'default' parameter.
        """
        return default
