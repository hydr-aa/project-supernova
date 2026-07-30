"""Tests for the Guard change detector and alert manager."""

from modules.guard.change_detector import ChangeDetector, Alert
from modules.guard.alert_manager import AlertManager
from modules.auditors.auditor_base import Severity


class TestChangeDetector:
    def test_take_baseline(self, mock_ldap):
        cd = ChangeDetector(mock_ldap)
        cd.take_baseline()
        assert "domain_admins" in cd.baseline
        assert "dcsync_rights" in cd.baseline
        assert "unconstrained_delegation" in cd.baseline

    def test_poll_no_changes(self, mock_ldap):
        cd = ChangeDetector(mock_ldap)
        cd.take_baseline()
        alerts = cd.poll()
        assert len(alerts) == 0


class TestAlertManager:
    def test_deduplicate(self):
        cfg = {"guard": {}}
        am = AlertManager(cfg)
        a1 = Alert(Severity.HIGH, "Test alert", "test_type")
        a2 = Alert(Severity.HIGH, "Test alert", "test_type")
        result = am.process([a1, a2])
        assert len(result) == 1

    def test_get_recent(self):
        cfg = {"guard": {}}
        am = AlertManager(cfg)
        a = Alert(Severity.CRITICAL, "Critical issue", "test")
        am.process([a])
        recent = am.get_recent()
        assert len(recent) == 1
        assert recent[0]["severity"] == "critical"


class TestAlertSerialization:
    def test_to_dict(self):
        a = Alert(Severity.CRITICAL, "Test", "test_type", details={"user": "admin"})
        d = a.to_dict()
        assert d["severity"] == "critical"
        assert d["title"] == "Test"
        assert d["details"]["user"] == "admin"
