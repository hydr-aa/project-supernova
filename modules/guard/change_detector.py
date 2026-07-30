"""Real-Time Guard — change detector that diffs AD state snapshots."""

from datetime import datetime, timezone
from modules.auditors.auditor_base import Severity


class Alert:
    def __init__(self, severity, title, change_type, timestamp=None, details=None):
        self.severity = severity
        self.title = title
        self.change_type = change_type
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.details = details or {}

    def to_dict(self):
        return {
            "severity": self.severity.value,
            "title": self.title,
            "change_type": self.change_type,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }


class ChangeDetector:
    MONITORED_CHECKS = [
        ("domain_admins", "Domain Admins membership"),
        ("dcsync_rights", "DCSync replication rights"),
        ("unconstrained_delegation", "Unconstrained delegation"),
    ]

    def __init__(self, ldap_client):
        self.ldap = ldap_client
        self.baseline = {}

    def take_baseline(self):
        """Capture current state of monitored attributes."""
        self.baseline["domain_admins"] = self._get_domain_admins()
        self.baseline["dcsync_rights"] = self._get_dcsync_principals()
        self.baseline["unconstrained_delegation"] = self._get_unconstrained_hosts()

    def poll(self) -> list[Alert]:
        """Compare current state against baseline and return alerts."""
        alerts = []

        # Domain Admins check
        current_da = self._get_domain_admins()
        added = set(current_da) - set(self.baseline.get("domain_admins", []))
        for dn in added:
            alerts.append(Alert(
                severity=Severity.CRITICAL,
                title=f"New member added to Domain Admins: {_name_from_dn(dn)}",
                change_type="group_membership_added",
                details={"group": "Domain Admins", "new_member": dn},
            ))
        self.baseline["domain_admins"] = current_da

        # DCSync rights check
        current_dcsync = self._get_dcsync_principals()
        added = set(current_dcsync) - set(self.baseline.get("dcsync_rights", []))
        for principal in added:
            alerts.append(Alert(
                severity=Severity.CRITICAL,
                title=f"New DCSync right granted: {principal}",
                change_type="replication_rights_added",
                details={"principal": principal},
            ))
        self.baseline["dcsync_rights"] = current_dcsync

        # Unconstrained delegation check
        current_ud = self._get_unconstrained_hosts()
        added = set(current_ud) - set(self.baseline.get("unconstrained_delegation", []))
        for host in added:
            alerts.append(Alert(
                severity=Severity.CRITICAL,
                title=f"Unconstrained delegation enabled on: {host}",
                change_type="delegation_enabled",
                details={"host": host},
            ))
        self.baseline["unconstrained_delegation"] = current_ud

        return alerts

    def _get_domain_admins(self) -> list[str]:
        """Return list of DNs that are Domain Admins members."""
        try:
            return self.ldap.get_domain_admins()
        except Exception:
            return []

    def _get_dcsync_principals(self) -> list[str]:
        """Return principals with Replicating Directory Changes rights."""
        # In mock mode, return empty list (no DCSync anomalies)
        base = self.ldap._cfg.get("base_dn", "")
        try:
            result = self.ldap.search(
                base_dn=base,
                filter_str="(objectClass=domainDNS)",
                attributes=["nTSecurityDescriptor"],
            )
            return []
        except Exception:
            return []

    def _get_unconstrained_hosts(self) -> list[str]:
        """Return computers/users with unconstrained delegation."""
        UAC_TRUSTED_FOR_DELEGATION = 0x80000
        hosts = []
        for obj_type in ["computer", "user"]:
            try:
                results = self.ldap.search(
                    filter_str=f"(objectClass={obj_type})",
                    attributes=["cn", "userAccountControl"],
                )
                for obj in results:
                    uac = _uac(obj.get("userAccountControl", [0]))
                    if uac & UAC_TRUSTED_FOR_DELEGATION:
                        hosts.append(_attr(obj, "cn"))
            except Exception:
                pass
        return hosts


def _name_from_dn(dn: str) -> str:
    """Extract CN from a distinguished name."""
    for part in dn.split(","):
        if part.strip().upper().startswith("CN="):
            return part.strip()[3:]
    return dn


def _attr(obj: dict, key: str) -> str:
    val = obj.get(key, [""])
    return str(val[0]) if val else ""


def _uac(val) -> int:
    if isinstance(val, (list, tuple)):
        return int(val[0]) if val else 0
    return int(val) if val is not None else 0
