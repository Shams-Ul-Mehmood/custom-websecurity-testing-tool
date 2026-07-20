"""
report.py
Builds the final scan report (JSON and HTML) from the findings
collected by each module.
"""

import json
import os
from datetime import datetime

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 12, "LOW": 5, "INFO": 0}

SEVERITY_BADGE_COLOR = {
    "CRITICAL": "#7d12c9",
    "HIGH": "#d9363e",
    "MEDIUM": "#e2a63b",
    "LOW": "#2f9e44",
    "INFO": "#495057",
}


class Report:
    def __init__(self, target, modules_run):
        self.target = target
        self.modules_run = modules_run
        self.scan_date = datetime.now().isoformat(timespec="seconds")
        self.findings = []  # list of dicts

    def add_findings(self, module_name, findings):
        for f in findings:
            f.setdefault("module", module_name)
            self.findings.append(f)

    def _risk_rating(self):
        if not self.findings:
            return "INFORMATIONAL", 0
        score = sum(SEVERITY_WEIGHT.get(f.get("severity", "INFO").upper(), 0)
                    for f in self.findings)
        score = min(score, 100)
        if score >= 70:
            rating = "CRITICAL"
        elif score >= 45:
            rating = "HIGH"
        elif score >= 20:
            rating = "MEDIUM"
        elif score > 0:
            rating = "LOW"
        else:
            rating = "INFORMATIONAL"
        return rating, score

    def to_dict(self):
        rating, score = self._risk_rating()
        sorted_findings = sorted(
            self.findings,
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO").upper(), 5)
        )
        return {
            "target": self.target,
            "scan_date": self.scan_date,
            "modules_executed": self.modules_run,
            "total_findings": len(self.findings),
            "overall_risk_rating": rating,
            "risk_score": score,
            "findings": sorted_findings,
        }

    def save_json(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
        return path

    def save_html(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = self.to_dict()

        rows = ""
        if not data["findings"]:
            rows = "<tr><td colspan='5' class='none'>No issues detected.</td></tr>"
        else:
            for f in data["findings"]:
                sev = f.get("severity", "INFO").upper()
                color = SEVERITY_BADGE_COLOR.get(sev, "#495057")
                rows += f"""
                <tr>
                    <td><span class="badge" style="background:{color}">{sev}</span></td>
                    <td>{_esc(f.get('title',''))}</td>
                    <td>{_esc(f.get('module',''))}</td>
                    <td class="mono">{_esc(f.get('evidence',''))}</td>
                    <td>{_esc(f.get('recommendation',''))}</td>
                </tr>"""

        rating_color = SEVERITY_BADGE_COLOR.get(data["overall_risk_rating"], "#495057")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Web Security Report - {_esc(self.target)}</title>
<style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#0f1117; color:#e6e6e6; margin:0; padding:0; }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 30px; }}
    h1 {{ font-size: 24px; margin-bottom: 4px; }}
    .subtitle {{ color:#9aa0a6; margin-bottom: 24px; }}
    .summary-grid {{ display:grid; grid-template-columns: repeat(4, 1fr); gap:14px; margin-bottom:30px; }}
    .card {{ background:#171a23; border:1px solid #262b38; border-radius:10px; padding:16px; }}
    .card h3 {{ margin:0 0 6px 0; font-size:13px; color:#9aa0a6; text-transform:uppercase; letter-spacing:.05em; }}
    .card .value {{ font-size:22px; font-weight:700; }}
    table {{ width:100%; border-collapse: collapse; background:#171a23; border-radius:10px; overflow:hidden; }}
    th, td {{ padding:12px 14px; text-align:left; border-bottom:1px solid #262b38; font-size:14px; vertical-align:top; }}
    th {{ background:#1e2230; color:#9aa0a6; text-transform:uppercase; font-size:12px; letter-spacing:.04em; }}
    tr:last-child td {{ border-bottom:none; }}
    .badge {{ color:white; padding:3px 10px; border-radius:20px; font-size:11px; font-weight:700; }}
    .mono {{ font-family: Consolas, monospace; font-size:12px; color:#c8ccd4; max-width:280px; word-break:break-word; }}
    .none {{ text-align:center; color:#9aa0a6; padding:24px; }}
    footer {{ margin-top:24px; color:#666; font-size:12px; text-align:center; }}
</style>
</head>
<body>
<div class="container">
    <h1>Web Security Testing Report</h1>
    <div class="subtitle">Target: {_esc(self.target)} &nbsp;|&nbsp; Scan Date: {_esc(self.scan_date)}</div>

    <div class="summary-grid">
        <div class="card"><h3>Modules Executed</h3><div class="value">{_esc(', '.join(data['modules_executed']))}</div></div>
        <div class="card"><h3>Total Findings</h3><div class="value">{data['total_findings']}</div></div>
        <div class="card"><h3>Risk Score</h3><div class="value">{data['risk_score']}/100</div></div>
        <div class="card"><h3>Overall Risk Rating</h3><div class="value" style="color:{rating_color}">{data['overall_risk_rating']}</div></div>
    </div>

    <table>
        <thead>
            <tr><th>Severity</th><th>Finding</th><th>Module</th><th>Evidence</th><th>Remediation</th></tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>

    <footer>Generated by Custom Web Security Testing Framework &mdash; for authorized security testing only.</footer>
</div>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return path


def _esc(text):
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))
