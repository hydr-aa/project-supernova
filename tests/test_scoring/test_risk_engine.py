"""Tests for the risk scoring engine and MITRE mapping."""

from modules.scoring.risk_engine import RiskEngine, Exploitability, Impact
from modules.scoring import mitre_mapping
from modules.auditors.auditor_base import Finding, Severity


class TestRiskEngine:
    def setup_method(self):
        self.engine = RiskEngine()

    def test_critical_scoring(self):
        f = Finding(id="AUDIT-ACC-008", title="Test", description="",
                    severity=Severity.MEDIUM, category="Test")
        self.engine.score(f)
        assert f.exploitability == Exploitability.TRIVIAL.value
        assert f.impact == Impact.PRIVILEGE_ESC.value
        assert f.severity == Severity.CRITICAL

    def test_info_scoring(self):
        f = Finding(id="AUDIT-GPO-003", title="Test", description="",
                    severity=Severity.MEDIUM, category="Test")
        self.engine.score(f)
        assert f.exploitability == Exploitability.HARD.value
        assert f.impact == Impact.RECON.value
        assert f.severity == Severity.INFO

    def test_unknown_id_gets_default(self):
        f = Finding(id="UNKNOWN-ID", title="Test", description="",
                    severity=Severity.CRITICAL, category="Test")
        self.engine.score(f)
        # Default is MODERATE(2) + RECON(1) -> LOW
        assert f.exploitability == Exploitability.MODERATE.value
        assert f.impact == Impact.RECON.value
        assert f.severity == Severity.LOW

    def test_score_all_sorts_by_severity(self):
        f_high = Finding(id="AUDIT-ACL-001", title="High", description="",
                        severity=Severity.MEDIUM, category="Test")
        f_info = Finding(id="AUDIT-GPO-003", title="Info", description="",
                        severity=Severity.MEDIUM, category="Test")
        findings = [f_info, f_high]
        self.engine.score_all(findings)
        # AUDIT-ACL-001 = HIGH, AUDIT-GPO-003 = INFO
        assert findings[0].severity == Severity.HIGH
        assert findings[-1].severity == Severity.INFO

    def test_summary_counts(self):
        f1 = Finding(id="AUDIT-ACL-001", title="C", description="",
                     severity=Severity.MEDIUM, category="Test")
        f2 = Finding(id="AUDIT-GPO-003", title="I", description="",
                     severity=Severity.MEDIUM, category="Test")
        self.engine.score_all([f1, f2])
        summary = self.engine.summary([f1, f2])
        assert summary["total"] == 2
        assert summary["overall_risk"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


class TestMITREMapping:
    def test_known_technique(self):
        data = mitre_mapping.lookup("T1558.003")
        assert data["name"] == "Kerberoasting"
        assert "Credential Access" in data["tactic"]

    def test_unknown_technique(self):
        data = mitre_mapping.lookup("T9999.999")
        assert data["name"] == "Unknown"

    def test_all_techniques_returns_dict(self):
        all_t = mitre_mapping.all_techniques()
        assert isinstance(all_t, dict)
        assert "T1557.001" in all_t
