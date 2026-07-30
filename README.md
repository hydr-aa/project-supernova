# Project Supernova

**AI-Driven Active Directory Security Auditing & Real-Time Threat Detection**

Built on Raspberry Pi 5 with Hailo-8 AI acceleration (26 TOPS). Final Year Project — CBS/08/24B — German-Malaysian Institute.

---

## What It Does

Supernova is a self-contained, read-only Active Directory security appliance in two modes:

| Mode | Description |
|---|---|
| **Assessment** | Runs 35+ misconfiguration checks across 9 categories and generates HTML/JSON reports with PowerShell remediation |
| **Real-Time Guard** | Continuously monitors critical AD state (Domain Admins, DCSync rights, delegation) and fires Discord alerts on change |

**Key principle:** Read-only. Always. No credential dumping, no exploitation, no modification.

---

## Architecture

```
supernova/
├── app.py                         # Flask entry point, API routes
├── config.yaml                    # All configuration (no hardcoded values)
├── requirements.txt
├── .env                           # Secrets (gitignored)
│
├── modules/
│   ├── ldap_client.py             # LDAP wrapper (live + mock mode)
│   ├── smb_client.py              # SMB wrapper for SYSVOL reads
│   │
│   ├── auditors/                  # 9 audit categories, 35+ checks
│   │   ├── account_policy.py      # Password policy, pre-auth, lockout
│   │   ├── kerberos.py            # Delegation, SPNs, roastable accounts
│   │   ├── privileges.py          # DA/EA/SA membership, operator groups
│   │   ├── acl.py                 # Dangerous ACEs, AdminSDHolder
│   │   ├── gpo.py                 # SYSVOL cpassword, disabled GPOs
│   │   ├── protocols.py           # LDAP/SMB signing, LLMNR, Print Spooler
│   │   ├── adcs.py                # ESC1, ESC4 certificate template checks
│   │   ├── trusts.py              # TGT delegation, SID filtering
│   │   └── endpoints.py           # LAPS, Protected Users, KRBTGT age
│   │
│   ├── guard/                     # Real-Time Guard
│   │   ├── poller.py              # Periodic baseline + diff loop
│   │   ├── change_detector.py     # Snapshot comparison engine
│   │   └── alert_manager.py       # Dedup, rate limit, Discord dispatch
│   │
│   ├── scoring/                   # Risk Engine
│   │   ├── risk_engine.py         # Exploitability x Impact matrix
│   │   └── mitre_mapping.py       # MITRE ATT&CK technique database
│   │
│   ├── reporting/                 # Report Generators
│   │   ├── html_report.py         # Self-contained dark-themed HTML
│   │   ├── json_report.py         # Machine-parseable JSON
│   │   └── remediation.py         # PowerShell command database
│   │
│   ├── npu/                       # Hailo-8 (optional)
│   │   └── hailo_stub.py          # No-op fallback when NPU absent
│   │
│   └── utils/                     # Cross-cutting
│       ├── config.py              # YAML loader with env:VAR resolution
│       ├── logger.py              # JSON-line structured logging
│       ├── network.py             # IP scope verification
│       └── safety.py              # Authorization gate
│
├── templates/
│   └── dashboard.html             # Single-page web UI
│
├── static/
│   ├── css/dashboard.css
│   └── js/app.js
│
├── reports/                       # Generated reports
├── logs/                          # Audit trail
│
└── tests/
    ├── test_auditors/             # 27 auditor unit tests
    ├── test_guard/                # 5 guard unit tests
    └── test_scoring/              # 18 scoring + reporting tests
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- pip

### Setup

```bash
# Clone
git clone https://github.com/hydr-aa/project-supernova.git
cd project-supernova

# Create virtual environment
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt

# Configure secrets
cp .env.example .env
# Edit .env with your LDAP credentials (mock mode works without this)

# Run tests
python -m pytest tests/ -v

# Start dashboard
python app.py
```

Open `http://localhost:5000` to access the dashboard.

### Mock Mode (Development)

The system runs in **mock mode** by default when no domain controller is reachable. All 9 auditors produce simulated findings using canned LDAP data. Tests pass entirely offline. To switch to live mode, change `MOCK = False` in `app.py` and configure `config.yaml` with your DC details.

---

## API Endpoints

| Method | Route | Description |
|---|---|---|
| GET | `/` | Dashboard SPA |
| GET | `/api/status` | System health, LDAP mode, NPU status |
| POST | `/api/assessment/start` | Run full 9-category audit |
| GET | `/api/assessment/findings` | Get findings (filter by severity) |
| GET | `/api/assessment/progress` | Real-time audit progress |
| GET | `/api/report/latest` | Metadata of last report |
| GET | `/api/report/download?format=html\|json` | Download report file |
| GET | `/api/guard/status` | Guard metrics + recent alerts |
| POST | `/api/guard/start` | Activate continuous monitoring |
| POST | `/api/guard/stop` | Deactivate monitoring |

---

## Audit Categories & Checks

| Category | Checks | Key Findings |
|---|---|---|
| Account Policy | 5 | Password length, complexity, history, lockout, pre-auth |
| Kerberos Configuration | 2 | Unconstrained delegation, roastable SPNs |
| Privileged Groups | 6 | Domain Admins, Enterprise Admins, Schema Admins, Operators |
| ACL Integrity | 3 | GenericAll, WriteDacl, AdminSDHolder anomalies |
| GPO Hygiene | 2 | cpassword in SYSVOL, disabled-linked GPOs |
| Protocol Hardening | 5 | LDAP signing, SMB signing, LLMNR, NetBIOS, Print Spooler |
| Certificate Services | 2 | ESC1, ESC4 (graceful fallback if not installed) |
| Trust Configuration | 1 | TGT delegation, SID filtering |
| Endpoint Security | 3 | LAPS, Protected Users, KRBTGT rotation |

---

## Testing

```bash
# All tests
python -m pytest tests/ -v

# Specific module
python -m pytest tests/test_auditors/ -v
python -m pytest tests/test_scoring/ -v
python -m pytest tests/test_guard/ -v
```

**50 unit tests, all passing.**

---

## Hardware (Planned)

| Component | Specification |
|---|---|
| SBC | Raspberry Pi 5 (8GB RAM) |
| Storage | 256GB NVMe M.2 SSD (PCIe Gen 3) |
| AI Accelerator | Hailo-8 M.2 2242, 26 TOPS |
| Enclosure | Pironman 5-MAX (dual M.2, OLED, active cooling) |
| Network | TP-Link ES208G 8-Port Managed Switch |
| OS | Raspberry Pi OS Lite (64-bit, Bookworm) |

---

## Team

| Role | Name |
|---|---|
| Project Manager / Lead Developer | Muhammad Luqman Zafree Bin Mohd Fazlee |
| Security Researcher | Sitee Hajarr |
| Hardware & Infrastructure | Anaqie Mikael |
| Supervisor | Mohamad Aiman Hanif Bin Apandi |

---

## Technologies

Python · Flask · ldap3 · Impacket · YAML · APScheduler · Hailo-8 NPU · MITRE ATT&CK · Discord Webhooks · HTML/CSS/JS · Chart.js · Raspberry Pi OS (Linux ARM64) · Windows Server 2022 · Active Directory

---

## License

Academic project — German-Malaysian Institute, Final Year Project 2026.
