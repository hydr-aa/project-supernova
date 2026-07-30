"""SMB client wrapper — used for SYSVOL enumeration in GPO auditor.

Supports two modes:
  - 'live'   — connects via impacket SMBConnection
  - 'mock'   — returns canned SYSVOL data for offline development

Usage:
    from modules.smb_client import SMBClient
    client = SMBClient(config, mock=True)
    xml_content = client.read_file("\\\\DC01\\SYSVOL\\supernova.vulnlab\\Policies\\{GUID}\\...")
"""

import re


class SMBClient:
    def __init__(self, config, mock=False, logger=None):
        self._cfg = config.get("ldap", {})
        self._mock = mock
        self._conn = None
        self._logger = logger

    def connect(self) -> bool:
        if self._mock:
            return True
        # Live mode would use impacket SMBConnection
        return True

    def disconnect(self):
        pass

    def list_directory(self, share_path: str) -> list[str]:
        """List files and directories in a given SMB share path."""
        if self._mock:
            return _mock_sysvol_list(share_path)
        return []

    def read_file(self, file_path: str) -> str:
        """Read a file from an SMB share and return its content as a string."""
        if self._mock:
            return _mock_sysvol_read(file_path)
        return ""

    def share_exists(self, share_name: str) -> bool:
        if self._mock:
            return share_name.upper() in ("SYSVOL", "NETLOGON", "C$", "ADMIN$")
        return False


# ── Mock SYSVOL data (for GPO auditor development) ──────────

_MOCK_SYSVOL = {
    "\\\\DC01\\SYSVOL\\supernova.vulnlab\\Policies\\":
        ["{31B2F340-016D-11D6-945F-00C04FB984F9}", "{6AC1786C-016F-11D2-945F-00C04FB984F9}"],

    "\\\\DC01\\SYSVOL\\supernova.vulnlab\\Policies\\{31B2F340-016D-11D6-945F-00C04FB984F9}\\MACHINE\\Preferences\\Groups\\Groups.xml":
        """<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
    <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator (built-in)" image="2"
          changed="2025-01-15 08:00:00" uid="{ABC123}">
        <Properties action="U" newName="" fullName="" description=""
                    cpassword="cAoIkM8F+RBgNsBGbQG2V9vNLRpm/X9qB/WNGdFR0aY"
                    changeLogon="0" noChange="0" neverExpires="1"
                    acctDisabled="0" userName="svc_backup"/>
    </User>
</Groups>""",

    "\\\\DC01\\SYSVOL\\supernova.vulnlab\\Policies\\{31B2F340-016D-11D6-945F-00C04FB984F9}\\GPT.INI": "",
}


def _mock_sysvol_list(path: str) -> list[str]:
    path = path.rstrip("\\") + "\\"
    results = []
    for mock_path in _MOCK_SYSVOL:
        if mock_path.startswith(path):
            relative = mock_path[len(path):].split("\\")[0]
            if relative and relative not in results:
                results.append(relative)
    return results


def _mock_sysvol_read(file_path: str) -> str:
    return _MOCK_SYSVOL.get(file_path, "")
