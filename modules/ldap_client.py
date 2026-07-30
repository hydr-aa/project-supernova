"""LDAP client wrapper — single connection manager used by all auditors.

Supports two modes:
  - 'live'   — connects to a real domain controller via ldap3
  - 'mock'   — returns canned data for offline development and unit tests

Usage:
    from modules.ldap_client import LDAPClient
    client = LDAPClient(config, mock=(not dc_available))
    client.connect()
    users = client.search("CN=Users,DC=supernova,DC=vulnlab", "(objectClass=user)")
    client.disconnect()
"""

import ssl

from modules.utils.logger import get_logger


class LDAPClient:
    def __init__(self, config, mock=False, logger=None):
        self._cfg = config.get("ldap", {})
        self._mock = mock
        self._conn = None
        self._logger = logger or get_logger(config)
        self._server_pool = None

    # ── Connection ────────────────────────────────────────────

    def connect(self) -> bool:
        if self._mock:
            self._logger.info("ldap_connect", extra_data={"mode": "mock"})
            return True

        server = self._cfg.get("server")
        port = self._cfg.get("port", 389)
        use_ssl_flag = self._cfg.get("use_ssl", False)

        from ldap3 import Server, Connection

        tls_config = None
        if use_ssl_flag:
            tls_config = ssl.create_default_context()
            tls_config.check_hostname = False
            tls_config.verify_mode = ssl.CERT_NONE

        self._server_pool = Server(
            server, port=port, use_ssl=use_ssl_flag, tls=tls_config, get_info=None
        )

        username = self._cfg.get("username", "")
        password = self._cfg.get("password", "")
        domain = self._cfg.get("domain", "")

        if domain and "\\" not in username and "@" not in username:
            bind_user = f"{domain}\\{username}"
        else:
            bind_user = username

        self._conn = Connection(
            self._server_pool,
            user=bind_user,
            password=password,
            authentication="NTLM" if domain else "SIMPLE",
            auto_bind=True,
        )

        self._logger.info("ldap_connected", extra_data={
            "server": server, "port": port, "ssl": use_ssl_flag
        })
        return True

    def disconnect(self):
        if self._conn:
            self._conn.unbind()
            self._logger.info("ldap_disconnected")

    @property
    def connected(self) -> bool:
        if self._mock:
            return True
        return self._conn is not None and self._conn.bound

    # ── Search ────────────────────────────────────────────────

    def search(self, base_dn="", filter_str="", attributes=None, scope="SUBTREE"):
        """Run an LDAP search and return a list of dicts."""
        if self._mock:
            return self._mock_search(filter_str)

        from ldap3 import SUBTREE, LEVEL, BASE

        scope_map = {"SUBTREE": SUBTREE, "ONELEVEL": LEVEL, "BASE": BASE}
        ldap_scope = scope_map.get(scope.upper(), SUBTREE)
        base = base_dn or self._cfg.get("base_dn", "")

        page_size = self._cfg.get("page_size", 1000)
        attributes = attributes or ["*"]

        self._conn.search(
            search_base=base,
            search_filter=filter_str,
            search_scope=ldap_scope,
            attributes=attributes,
            paged_size=page_size,
        )

        results = []
        for entry in self._conn.entries:
            results.append({attr.key: attr.values for attr in entry})
        return results

    # ── High-level queries ────────────────────────────────────

    def get_domain_controllers(self):
        return self.search(
            filter_str="(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            attributes=["cn", "dNSHostName", "operatingSystem"],
        )

    def get_all_users(self):
        return self.search(
            filter_str="(objectClass=user)",
            attributes=[
                "sAMAccountName", "userPrincipalName", "displayName",
                "userAccountControl", "pwdLastSet", "lastLogon",
                "memberOf", "servicePrincipalName", "description",
            ],
        )

    def get_all_groups(self):
        return self.search(
            filter_str="(objectClass=group)",
            attributes=["cn", "sAMAccountName", "member", "groupType", "description"],
        )

    def get_all_computers(self):
        return self.search(
            filter_str="(objectClass=computer)",
            attributes=["cn", "dNSHostName", "operatingSystem", "userAccountControl"],
        )

    def get_password_policy(self):
        base = self._cfg.get("base_dn", "")
        attrs = [
            "minPwdLength", "pwdHistoryLength", "maxPwdAge",
            "minPwdAge", "lockoutThreshold", "lockoutDuration",
            "lockoutObservationWindow", "pwdProperties",
        ]
        result = self.search(base_dn=base, filter_str="(objectClass=domainDNS)", attributes=attrs)
        if result:
            entry = result[0]
            return {
                "min_length": _int_or(entry.get("minPwdLength"), 0),
                "history_length": _int_or(entry.get("pwdHistoryLength"), 0),
                "max_age_days": -(_int_or(entry.get("maxPwdAge"), 0)) // -864000000000 if _int_or(entry.get("maxPwdAge"), 0) else 0,
                "min_age_days": _int_or(entry.get("minPwdAge"), 0) // 864000000000 if _int_or(entry.get("minPwdAge"), 0) else 0,
                "lockout_threshold": _int_or(entry.get("lockoutThreshold"), 0),
                "lockout_duration_min": _int_or(entry.get("lockoutDuration"), 0) // -600000000 if _int_or(entry.get("lockoutDuration"), 0) else 0,
                "complexity_enabled": bool(_int_or(entry.get("pwdProperties"), 0) & 1),
            }
        return {}

    def get_domain_admins(self):
        """Return list of DNs that are members of Domain Admins."""
        base = self._cfg.get("base_dn", "")
        result = self.search(
            base_dn=f"CN=Domain Admins,CN=Users,{base}",
            filter_str="(objectClass=*)",
            attributes=["member"],
        )
        if result:
            return result[0].get("member", [])
        return []

    # ── Mock data (for offline development) ───────────────────

    def _mock_search(self, filter_str):
        """Return canned data matching common filter patterns."""
        data = []

        if "user" in filter_str.lower():
            data = [
                {"sAMAccountName": ["Administrator"], "userAccountControl": [512], "pwdLastSet": [133600000000000000]},
                {"sAMAccountName": ["Guest"], "userAccountControl": [514]},
                {"sAMAccountName": ["svc_supernova"], "userAccountControl": [512], "servicePrincipalName": []},
                {"sAMAccountName": ["svc_backup"], "userAccountControl": [512], "servicePrincipalName": ["MSSQLSvc/WS01:1433"]},
                {"sAMAccountName": ["anaqie.mikael"], "userAccountControl": [512]},
                {"sAMAccountName": ["sitee.hajarr"], "userAccountControl": [512]},
            ]

        elif "group" in filter_str.lower():
            data = [
                {"cn": ["Domain Admins"], "sAMAccountName": ["Domain Admins"], "member": ["CN=Administrator,CN=Users,DC=supernova,DC=vulnlab"]},
                {"cn": ["Enterprise Admins"], "sAMAccountName": ["Enterprise Admins"], "member": ["CN=Administrator,CN=Users,DC=supernova,DC=vulnlab"]},
                {"cn": ["Domain Users"], "sAMAccountName": ["Domain Users"], "member": []},
            ]

        elif "computer" in filter_str.lower():
            data = [
                {"cn": ["DC01"], "dNSHostName": ["DC01.supernova.vulnlab"], "operatingSystem": ["Windows Server 2022"], "userAccountControl": [532480]},
                {"cn": ["WS01"], "dNSHostName": ["WS01.supernova.vulnlab"], "operatingSystem": ["Windows 10 Pro"], "userAccountControl": [4096]},
                {"cn": ["WS02"], "dNSHostName": ["WS02.supernova.vulnlab"], "operatingSystem": ["Windows 10 Pro"], "userAccountControl": [4096]},
            ]

        elif "domaindns" in filter_str.lower():
            data = [{
                "minPwdLength": [7], "pwdHistoryLength": [0], "maxPwdAge": [-36288000000000],
                "minPwdAge": [0], "lockoutThreshold": [0], "lockoutDuration": [-18000000000],
                "lockoutObservationWindow": [-18000000000], "pwdProperties": [0],
            }]

        return data


def _int_or(value, default=0):
    """Safely extract the first integer from an LDAP attribute value list."""
    if isinstance(value, (list, tuple)):
        return int(value[0]) if value else default
    if value is not None:
        return int(value)
    return default
