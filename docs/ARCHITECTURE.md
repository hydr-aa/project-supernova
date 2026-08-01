# Supernova Architecture

## System Overview

Supernova is a dual-mode Active Directory security appliance running on Raspberry Pi 5.

```
┌──────────────────────────────────────────────────────┐
│                  Raspberry Pi 5                       │
│                                                       │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────┐  │
│  │  Flask    │  │  Guard   │  │  Hailo-8 NPU       │  │
│  │  API      │  │  Poller  │  │  (optional)        │  │
│  │  (routes) │  │  (APSched)│  │  anomaly scoring  │  │
│  └─────┬─────┘  └────┬─────┘  └────────┬───────────┘  │
│        │             │                │               │
│  ┌─────▼─────────────▼────────────────▼───────────┐   │
│  │              Orchestration Engine               │   │
│  │                                                  │   │
│  │  ┌────────┐ ┌──────────┐ ┌──────────────────┐   │   │
│  │  │ 9      │ │ Scoring  │ │ Reporting        │   │   │
│  │  │Auditors│ │ Engine   │ │ (HTML/JSON)      │   │   │
│  │  └───┬────┘ └──────────┘ └──────────────────┘   │   │
│  └──────┼──────────────────────────────────────────┘   │
│         │                                               │
│  ┌──────▼──────────────────────────────┐               │
│  │  LDAP Client  │  SMB Client          │               │
│  │  (ldap3)      │  (impacket)          │               │
│  └──────┬────────┴──────────────────────┘               │
└─────────┼───────────────────────────────────────────────┘
          │ LDAP(389) / SMB(445)
          ▼
┌─────────────────────────┐
│   Domain Controller      │
│   Windows Server 2022    │
│   supernova.vulnlab      │
└─────────────────────────┘
```

## Data Flow

### Assessment Mode

```
1. User clicks "Run Assessment" on dashboard
2. POST /api/assessment/start
3. Flask calls request_authorization() → safety gate
4. Orchestration engine iterates 9 auditors
5. Each auditor runs LDAP/SMB queries against DC
6. Findings collected into list
7. Risk engine scores every finding (exploitability x impact)
8. Reporting module generates HTML + JSON reports
9. Response returned to dashboard with summary
```

### Guard Mode

```
1. User clicks Guard start or auto-starts
2. GuardPoller takes a baseline snapshot of critical AD state
3. APScheduler fires poll() every 60s (configurable)
4. ChangeDetector diffs current state against baseline
5. Any difference → Alert object created
6. AlertManager deduplicates and dispatches to Discord webhook
7. Dashboard polls /api/guard/status every 5s
8. Updated baseline becomes new reference
```

## Module Dependencies

```
app.py
 ├── modules/utils/config.py       — YAML config loader
 ├── modules/utils/logger.py       — JSON-line structured logging
 ├── modules/utils/network.py      — IP scope verification
 ├── modules/utils/safety.py       — Authorization gate
 ├── modules/ldap_client.py        — LDAP connection (live + mock)
 ├── modules/smb_client.py         — SMB client (live + mock)
 ├── modules/auditors/             — 9 audit modules
 │   ├── auditor_base.py           — BaseAuditor ABC, Finding, Severity
 │   ├── account_policy.py
 │   ├── kerberos.py
 │   ├── privileges.py
 │   ├── acl.py
 │   ├── gpo.py
 │   ├── protocols.py
 │   ├── adcs.py
 │   ├── trusts.py
 │   └── endpoints.py
 ├── modules/scoring/
 │   ├── risk_engine.py            — Exploitability x Impact matrix
 │   └── mitre_mapping.py          — MITRE ATT&CK technique database
 ├── modules/reporting/
 │   ├── html_report.py            — Self-contained HTML generator
 │   ├── json_report.py            — Machine-parseable JSON generator
 │   └── remediation.py            — PowerShell command database
 ├── modules/guard/
 │   ├── poller.py                 — APScheduler-based polling loop
 │   ├── change_detector.py        — Snapshot diff engine
 │   └── alert_manager.py          — Dedup, rate-limit, Discord dispatch
 └── modules/npu/
     └── hailo_stub.py             — No-op fallback when Hailo-8 absent
```

## Audit Engine Design

Every auditor inherits from `BaseAuditor`:

```python
class BaseAuditor(ABC):
    def __init__(self, ldap_client): ...

    @property
    @abstractmethod
    def category(self) -> str:
        """e.g. 'Account Policy'"""

    @abstractmethod
    def run(self) -> list[Finding]:
        """Execute all checks, return findings."""
```

Each `Finding` is a dataclass:

```python
@dataclass
class Finding:
    id: str                # e.g. "AUDIT-ACC-001"
    title: str             # Human-readable
    description: str       # What was found
    severity: Severity     # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str          # Assigned by auditor
    evidence: list[str]    # Raw LDAP/SMB data proving the finding
    mitre_technique: str   # e.g. "T1110.003"
    remediation_ps: str    # Copy-paste PowerShell command
    affected_objects: list[str]
    exploitability: int    # 1-4, set by risk engine
    impact: int            # 1-4, set by risk engine
```

## Scoring Matrix

```
                          IMPACT
                  DA(4)  PrivEsc(3)  Cred(2)  Recon(1)
EXPLOITABILITY  ┌────────┬──────────┬────────┬────────┐
  TRIVIAL (4)   │ CRIT   │ CRIT     │ HIGH   │ MED    │
  EASY (3)      │ CRIT   │ HIGH     │ HIGH   │ MED    │
  MODERATE (2)  │ HIGH   │ MED      │ MED    │ LOW    │
  HARD (1)      │ MED    │ LOW      │ LOW    │ INFO   │
                └────────┴──────────┴────────┴────────┘
```

## Safety Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Network      │────▶│ Authorization│────▶│ Read-Only    │
│ Scope Check  │     │ Gate         │     │ Guarantee    │
│ (allowlist)  │     │ (manual/env) │     │ (no LDAP mod)│
└──────────────┘     └──────────────┘     └──────────────┘
```

1. **Network verification** — Device IP must match authorized CIDR ranges. Wrong network = blocked.
2. **Authorization gate** — Operator must confirm via dashboard or `SUPERNOVA_AUTHORIZED=1` env var.
3. **Read-only guarantee** — Only `ldap3` search operations. No add/modify/delete/modifyDN. No `impacket` exploitation modules loaded.

---

## Deployment

### On Raspberry Pi 5

```bash
# 1. Clone repo
git clone https://github.com/hydr-aa/project-supernova.git /opt/supernova
cd /opt/supernova

# 2. Virtual environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
# Edit .env with LDAP credentials
# Edit config.yaml for your domain

# 4. Start
python app.py
# Dashboard: http://<pi-ip>:5000
```
