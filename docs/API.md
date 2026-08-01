# Supernova API Reference

Base URL: `http://<pi-ip>:5000/api`

---

## Status

### `GET /api/status`

Returns system health, LDAP mode, NPU status, and guard state.

```json
{
  "version": "2.0.0",
  "mode": "assessment",
  "ldap_mode": "mock",
  "ldap_connected": true,
  "authorised": false,
  "assessment_active": false,
  "npu_enabled": false,
  "guard": { "running": false, "threat_level": "low" }
}
```

---

## Assessment

### `POST /api/assessment/start`

Runs all 9 auditors against the domain controller. Requires authorization.

**Response (200):**
```json
{
  "status": "complete",
  "total_findings": 20,
  "summary": {
    "counts": { "critical": 4, "high": 10, "medium": 4, "low": 1, "info": 1 },
    "overall_risk": "CRITICAL",
    "total": 20
  },
  "findings": [
    {
      "id": "AUDIT-ACC-001",
      "title": "Minimum password length is 7 (recommended: 14+)",
      "severity": "high",
      "category": "Account Policy",
      "mitre_technique": "T1110.003",
      "exploitability": 3,
      "impact": 2
    }
  ]
}
```

**Errors:**
| Code | Meaning |
|---|---|
| 403 | Authorization required. Set `SUPERNOVA_AUTHORIZED=1` env var |
| 409 | Assessment already in progress |
| 500 | Internal error (e.g. LDAP bind failure) |

### `GET /api/assessment/findings`

Returns all findings from the most recent assessment.

**Query Parameters:**
| Parameter | Type | Description |
|---|---|---|
| `severity` | string | Filter by `critical`, `high`, `medium`, `low`, or `info` |

**Response:**
```json
{
  "count": 4,
  "findings": [
    {
      "id": "AUDIT-GPO-001",
      "title": "Group Policy Preferences password found in SYSVOL",
      "severity": "critical",
      "category": "GPO Hygiene",
      "description": "A Group Policy Preferences XML file in SYSVOL contains...",
      "mitre_technique": "T1552.006",
      "remediation_ps": "Get-ChildItem -Path '\\\\$env:USERDNSDOMAIN\\SYSVOL'...",
      "evidence": ["File: {GUID}\\MACHINE\\Preferences\\Groups\\Groups.xml"],
      "affected_objects": ["SYSVOL Groups.xml"],
      "exploitability": 4,
      "impact": 3
    }
  ]
}
```

### `GET /api/assessment/progress`

Returns real-time assessment progress (polled during long scans).

```json
{
  "active": true,
  "total_categories": 9,
  "findings_so_far": 12
}
```

---

## Reports

### `GET /api/report/latest`

Returns metadata about the most recent assessment report.

```json
{
  "available": true,
  "total_findings": 20,
  "summary": { "overall_risk": "CRITICAL", "counts": {...} },
  "html_path": "./reports/assessment_SN-20260801-143022.html",
  "json_path": "./reports/assessment_SN-20260801-143022.json"
}
```

### `GET /api/report/download`

Downloads the report file.

**Query Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `format` | string | `html` | `html` or `json` |

**Response:** File download (Content-Disposition: attachment)

---

## Real-Time Guard

### `GET /api/guard/status`

Returns current guard polling state and recent alerts.

```json
{
  "running": false,
  "threat_level": "low",
  "events_analysed": 142,
  "alerts_triggered": 0,
  "uptime_seconds": 3600,
  "recent_alerts": []
}
```

### `POST /api/guard/start`

Starts the guard polling loop. Takes a baseline snapshot, then polls at the configured interval.

```json
{
  "running": true,
  "threat_level": "low",
  "events_analysed": 0,
  "alerts_triggered": 0,
  "uptime_seconds": 0,
  "recent_alerts": []
}
```

### `POST /api/guard/stop`

Stops the guard polling loop.

```json
{
  "running": false,
  "threat_level": "low"
}
```

---

## Dashboard Routes

| Route | Description |
|---|---|
| `GET /` | Vercel-inspired light theme dashboard |
| `GET /blue` | Data-dense blue dashboard (Fira Code/Fira Sans) |
| `GET /soc` | Hardware appliance SOC dashboard (JetBrains Mono) |
