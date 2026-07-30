"""HTML report generator — produces self-contained assessment reports."""

from datetime import datetime
from pathlib import Path
from modules.scoring.mitre_mapping import lookup as mitre_lookup


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Supernova Assessment Report — {domain}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0a0a0a; color: #e0e0e0; padding: 2rem; }}
  h1 {{ font-size: 22px; letter-spacing: 2px; margin-bottom: 6px; }}
  h1 span {{ color: #E24B4A; }}
  .meta {{ font-size: 12px; color: #666; margin-bottom: 2rem; line-height: 1.8; }}
  .meta span {{ color: #85B7EB; }}
  .risk-box {{ display: flex; gap: 16px; margin-bottom: 2rem; }}
  .risk-badge {{ padding: 16px 24px; border-radius: 10px; text-align: center; min-width: 100px; }}
  .risk-badge.crit {{ background: #3d1010; border: 1px solid #5a1a1a; }}
  .risk-badge.high {{ background: #3d2a00; border: 1px solid #5a4000; }}
  .risk-badge.med  {{ background: #0d2040; border: 1px solid #1a3060; }}
  .risk-badge.low  {{ background: #0f2a0f; border: 1px solid #1a4a1a; }}
  .risk-badge.info {{ background: #1a1a1a; border: 1px solid #2a2a2a; }}
  .risk-label {{ font-size: 10px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }}
  .risk-crit .risk-label {{ color: #F09595; }}
  .risk-high .risk-label {{ color: #FAC775; }}
  .risk-med .risk-label  {{ color: #85B7EB; }}
  .risk-low .risk-label  {{ color: #5DCAA5; }}
  .risk-info .risk-label {{ color: #888; }}
  .risk-val {{ font-size: 36px; font-weight: bold; }}
  .risk-crit .risk-val {{ color: #E24B4A; }}
  .risk-high .risk-val {{ color: #EF9F27; }}
  .risk-med .risk-val  {{ color: #378ADD; }}
  .risk-low .risk-val  {{ color: #5DCAA5; }}
  .risk-info .risk-val {{ color: #666; }}
  .finding {{ background: #141414; border: 1px solid #1e1e1e; border-radius: 10px; margin-bottom: 16px; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 12px; padding: 12px 16px; background: #111; }}
  .finding-id {{ font-size: 10px; color: #555; min-width: 90px; }}
  .finding-title {{ font-size: 14px; flex: 1; color: #ddd; font-weight: 600; }}
  .sev-tag {{ padding: 4px 12px; border-radius: 12px; font-size: 10px; font-weight: bold; letter-spacing: 1px; }}
  .sev-tag.crit {{ background: #5a1a1a; color: #F09595; }}
  .sev-tag.high {{ background: #5a4000; color: #FAC775; }}
  .sev-tag.med  {{ background: #1a3060; color: #85B7EB; }}
  .sev-tag.low  {{ background: #1a4a1a; color: #5DCAA5; }}
  .sev-tag.info {{ background: #2a2a2a; color: #888; }}
  .finding-body {{ padding: 14px 16px; background: #0d0d0d; }}
  .finding-desc {{ font-size: 12px; color: #999; line-height: 1.7; margin-bottom: 12px; }}
  .section-title {{ font-size: 10px; color: #5DCAA5; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; font-weight: bold; }}
  .rem-cmd {{ background: #080808; border: 1px solid #1e1e1e; border-radius: 6px; padding: 10px 14px; font-family: Consolas, monospace; font-size: 11px; color: #85B7EB; white-space: pre-wrap; line-height: 1.6; margin-bottom: 8px; }}
  .mitre-tag {{ display: inline-block; background: #1a1a3d; color: #AFA9EC; border: 1px solid #2a2a5a; border-radius: 8px; padding: 3px 10px; font-size: 10px; margin-right: 6px; }}
  .footer {{ margin-top: 3rem; text-align: center; color: #3a3a3a; font-size: 11px; line-height: 1.8; }}
</style>
</head>
<body>
<h1>PROJECT <span>SUPERNOVA</span></h1>
<div class="meta">
  Scan ID: <span>{scan_id}</span> &nbsp;|&nbsp;
  Domain: <span>{domain}</span> &nbsp;|&nbsp;
  Domain Controller: <span>{dc}</span><br>
  Generated: <span>{timestamp}</span> &nbsp;|&nbsp;
  Total Findings: <span>{total_findings}</span> &nbsp;|&nbsp;
  Checks Executed: <span>{checks_executed}</span>
</div>

<div class="risk-box">
  <div class="risk-badge crit">
    <div class="risk-label">Critical</div>
    <div class="risk-val">{critical}</div>
  </div>
  <div class="risk-badge high">
    <div class="risk-label">High</div>
    <div class="risk-val">{high}</div>
  </div>
  <div class="risk-badge med">
    <div class="risk-label">Medium</div>
    <div class="risk-val">{medium}</div>
  </div>
  <div class="risk-badge low">
    <div class="risk-label">Low</div>
    <div class="risk-val">{low}</div>
  </div>
  <div class="risk-badge info">
    <div class="risk-label">Info</div>
    <div class="risk-val">{info}</div>
  </div>
</div>

<h2 style="color:#ccc; margin-bottom: 14px; font-size: 16px;">Detailed Findings</h2>
{findings_html}

<div class="footer">
  Project Supernova v{version} &nbsp;|&nbsp; German-Malaysian Institute &nbsp;|&nbsp; CBS/08/24B<br>
  <span style="color:#3a3a3a;">This report contains sensitive security findings. Handle in accordance with organisational data classification policies.</span>
</div>
</body>
</html>"""


def _render_finding(f) -> str:
    """Render a single finding as HTML."""
    mitre_data = mitre_lookup(f.mitre_technique) if f.mitre_technique else {}
    mitre_tag = ""
    if mitre_data and mitre_data.get("name") != "Unknown":
        mitre_tag = (
            f'<span class="mitre-tag">{f.mitre_technique}: {mitre_data["name"]}</span>'
        )

    evidence_html = ""
    if f.evidence:
        items = "".join(f"<li>{e}</li>" for e in f.evidence[:5])
        evidence_html = f'<div class="section-title">Evidence</div><ul style="color:#777;font-size:11px;margin-bottom:10px;">{items}</ul>'

    remediation_html = ""
    if f.remediation_ps:
        remediation_html = (
            f'<div class="section-title">Remediation (PowerShell)</div>'
            f'<div class="rem-cmd">{f.remediation_ps}</div>'
        )

    return f"""
<div class="finding">
  <div class="finding-header">
    <span class="finding-id">{f.id}</span>
    <span class="sev-tag {f.severity.value}">{f.severity.value.upper()}</span>
    <span class="finding-title">{f.title}</span>
    {mitre_tag}
  </div>
  <div class="finding-body">
    <div class="finding-desc">{f.description}</div>
    {evidence_html}
    {remediation_html}
  </div>
</div>"""


def generate(findings, config, output_dir="./reports") -> str:
    """Generate an HTML report and return the file path."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    scan_id = f"SN-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    filename = output_path / f"assessment_{scan_id}.html"

    # Severity counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    findings_html = "\n".join(_render_finding(f) for f in findings)

    html = HTML_TEMPLATE.format(
        domain=config.get("ldap", {}).get("domain", "unknown"),
        dc=config.get("ldap", {}).get("server", "unknown"),
        scan_id=scan_id,
        timestamp=datetime.now().strftime("%d %B %Y, %H:%M:%S MYT"),
        total_findings=len(findings),
        checks_executed=len({f.category for f in findings}),
        version=config.get("supernova", {}).get("version", "2.0.0"),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        findings_html=findings_html,
    )

    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(html)

    return str(filename)
