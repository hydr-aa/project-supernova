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
        if self._mock:
            return [{"cn": ["DC01"], "dNSHostName": ["DC01.supernova.vulnlab"], "operatingSystem": ["Windows Server 2022"]}]
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
        """Return canned data matching common filter patterns.
        Seeded with deliberate misconfigurations matching setup-dc.ps1."""
        data = []

        if "user" in filter_str.lower():
            data = [
                {"sAMAccountName": ["Administrator"], "userAccountControl": [512], "pwdLastSet": [133600000000000000], "description": ["Built-in account"], "memberOf": ["CN=Domain Admins,CN=Users,DC=supernova,DC=vulnlab"]},
                {"sAMAccountName": ["Guest"], "userAccountControl": [514], "description": ["Built-in guest account"]},
                {"sAMAccountName": ["krbtgt"], "userAccountControl": [514], "pwdLastSet": [130000000000000000], "description": ["KDC Service Account"]},
                {"sAMAccountName": ["anaqie.mikael"], "userAccountControl": [512], "displayName": ["Anaqie Mikael"], "description": ["Hardware & Infrastructure"], "memberOf": ["CN=Domain Users,CN=Users,DC=supernova,DC=vulnlab"]},
                {"sAMAccountName": ["sitee.hajarr"], "userAccountControl": [512], "displayName": ["Sitee Hajarr"], "description": ["Security Research"], "memberOf": ["CN=Domain Users,CN=Users,DC=supernova,DC=vulnlab"]},
                {"sAMAccountName": ["luqman.zafree"], "userAccountControl": [512], "displayName": ["Luqman Zafree"], "description": ["PM / Lead Dev"], "memberOf": ["CN=Domain Users,CN=Users,DC=supernova,DC=vulnlab"]},
                {"sAMAccountName": ["sqlservice"], "userAccountControl": [66048], "displayName": ["SQL Service"], "description": ["HAS DCSYNC RIGHTS + IN DOMAIN ADMINS"], "memberOf": ["CN=Domain Users,CN=Users,DC=supernova,DC=vulnlab", "CN=Domain Admins,CN=Users,DC=supernova,DC=vulnlab"]},
                {"sAMAccountName": ["svc_backup"], "userAccountControl": [512], "displayName": ["Backup Service"], "description": ["KERBEROASTABLE (SPN)"], "servicePrincipalName": ["MSSQLSvc/WS01:1433"], "memberOf": ["CN=Domain Users,CN=Users,DC=supernova,DC=vulnlab"]},
                {"sAMAccountName": ["asrep_user"], "userAccountControl": [4194816], "displayName": ["AS-REP Test"], "description": ["PRE-AUTHENTICATION DISABLED"], "memberOf": ["CN=Domain Users,CN=Users,DC=supernova,DC=vulnlab"]},
                {"sAMAccountName": ["svc_supernova"], "userAccountControl": [512], "displayName": ["Supernova Service"], "description": ["Read-only service account"], "memberOf": ["CN=Domain Users,CN=Users,DC=supernova,DC=vulnlab"]},
                {"sAMAccountName": ["helpdesk"], "userAccountControl": [512], "displayName": ["IT Helpdesk"], "description": ["IN ACCOUNT OPERATORS"], "memberOf": ["CN=Account Operators,CN=Builtin,DC=supernova,DC=vulnlab"]},
                {"sAMAccountName": ["backup_admin"], "userAccountControl": [512], "displayName": ["Backup Admin"], "description": ["IN BACKUP OPERATORS"], "memberOf": ["CN=Backup Operators,CN=Builtin,DC=supernova,DC=vulnlab"]},
            ]

        elif "group" in filter_str.lower():
            data = [
                {"cn": ["Domain Admins"], "sAMAccountName": ["Domain Admins"], "member": ["CN=Administrator,CN=Users,DC=supernova,DC=vulnlab", "CN=sqlservice,OU=ServiceAccounts,OU=GMI,DC=supernova,DC=vulnlab"], "groupType": [-2147483646], "description": ["sqlservice IS AN UNAUTHORISED MEMBER"]},
                {"cn": ["Enterprise Admins"], "sAMAccountName": ["Enterprise Admins"], "member": ["CN=Administrator,CN=Users,DC=supernova,DC=vulnlab"], "groupType": [-2147483646]},
                {"cn": ["Schema Admins"], "sAMAccountName": ["Schema Admins"], "member": ["CN=Administrator,CN=Users,DC=supernova,DC=vulnlab"], "groupType": [-2147483646]},
                {"cn": ["Account Operators"], "sAMAccountName": ["Account Operators"], "member": ["CN=helpdesk,OU=Users,OU=GMI,DC=supernova,DC=vulnlab"], "groupType": [-2147483646]},
                {"cn": ["Server Operators"], "sAMAccountName": ["Server Operators"], "member": [], "groupType": [-2147483646]},
                {"cn": ["Backup Operators"], "sAMAccountName": ["Backup Operators"], "member": ["CN=backup_admin,OU=Users,OU=GMI,DC=supernova,DC=vulnlab"], "groupType": [-2147483646], "description": ["backup_admin HAS DANGEROUS PRIVILEGE"]},
                {"cn": ["Protected Users"], "sAMAccountName": ["Protected Users"], "member": [], "groupType": [-2147483646], "description": ["EMPTY — NO PRIVILEGED ACCOUNTS PROTECTED"]},
                {"cn": ["Domain Users"], "sAMAccountName": ["Domain Users"], "member": [], "groupType": [-2147483646]},
            ]

        elif "computer" in filter_str.lower():
            data = [
                {"cn": ["DC01"], "dNSHostName": ["DC01.supernova.vulnlab"], "operatingSystem": ["Windows Server 2022"], "userAccountControl": [532480]},
                {"cn": ["WS01"], "dNSHostName": ["WS01.supernova.vulnlab"], "operatingSystem": ["Windows 10 Pro"], "userAccountControl": [4096], "description": ["UNCONSTRAINED DELEGATION"]},
                {"cn": ["WS02"], "dNSHostName": ["WS02.supernova.vulnlab"], "operatingSystem": ["Windows 10 Pro"], "userAccountControl": [4096]},
            ]

        elif "domaindns" in filter_str.lower():
            data = [{
                "minPwdLength": [7], "pwdHistoryLength": [0], "maxPwdAge": [-36288000000000],
                "minPwdAge": [0], "lockoutThreshold": [0], "lockoutDuration": [-18000000000],
                "lockoutObservationWindow": [-18000000000], "pwdProperties": [0],
            }]

        elif "pkienrollment" in filter_str.lower() or "pkicertificate" in filter_str.lower():
            data = []

        elif "trusteddomain" in filter_str.lower():
            data = []

        elif "grouppolicy" in filter_str.lower():
            data = [
                {"displayName": ["Default Domain Policy"], "flags": [1], "description": ["FLAGGED AS DISABLED"]},
            ]

        return data


def _int_or(value, default=0):
    """Safely extract the first integer from an LDAP attribute value list."""
    if isinstance(value, (list, tuple)):
        return int(value[0]) if value else default
    if value is not None:
        return int(value)
    return default
