"""MITRE ATT&CK technique mapping for audit findings."""


MITRE_TECHNIQUES = {
    "T1110.003": {
        "name": "Password Spraying",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1078.001": {
        "name": "Valid Accounts: Default Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/001/",
    },
    "T1558.001": {
        "name": "Golden Ticket",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1558/001/",
    },
    "T1558.003": {
        "name": "Kerberoasting",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1558/003/",
    },
    "T1558.004": {
        "name": "AS-REP Roasting",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1558/004/",
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1098/",
    },
    "T1222.001": {
        "name": "File and Directory Permissions Modification: Windows File and Directory Permissions Modification",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1222/001/",
    },
    "T1552.006": {
        "name": "Unsecured Credentials: Group Policy Preferences",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1552/006/",
    },
    "T1484.001": {
        "name": "Domain Policy Modification: Group Policy Modification",
        "tactic": "Defense Evasion, Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1484/001/",
    },
    "T1557.001": {
        "name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
        "tactic": "Credential Access, Collection",
        "url": "https://attack.mitre.org/techniques/T1557/001/",
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
    "T1649": {
        "name": "Steal or Forge Authentication Certificates",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1649/",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1003/001/",
    },
    "T1003.006": {
        "name": "OS Credential Dumping: DCSync",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1003/006/",
    },
}


def lookup(technique_id: str) -> dict:
    """Return MITRE ATT&CK information for a technique ID, or a default."""
    return MITRE_TECHNIQUES.get(
        technique_id,
        {
            "name": "Unknown",
            "tactic": "Unknown",
            "url": "https://attack.mitre.org/",
        },
    )


def all_techniques() -> dict:
    """Return the full MITRE mapping dictionary."""
    return MITRE_TECHNIQUES.copy()
