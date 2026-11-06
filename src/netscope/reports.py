"""Report export helpers for NetScope."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

__all__ = ["export_json_report", "export_html_report"]


def export_json_report(report: dict[str, Any]) -> str:
    """Serialize a diagnostic report to a JSON string."""
    return json.dumps(report, indent=2, sort_keys=True)


def export_html_report(report: dict[str, Any], destination: str | Path) -> str:
    """Write a simple HTML summary of the report to a file and return the path."""
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)

    capture_name = report.get("capture_name", "Unknown capture")
    packet_count = report.get("packet_count", 0)
    findings = report.get("findings", [])

    findings_html = "".join(
        f"<li><strong>{finding.get('type', 'finding')}</strong>: {finding.get('message', '')}</li>"
        for finding in findings
    )
    if not findings_html:
        findings_html = "<li>No findings.</li>"

    html = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>{capture_name}</title>
</head>
<body>
  <h1>NetScope Diagnostic Report</h1>
  <h2>{capture_name}</h2>
  <p><strong>Packets analyzed:</strong> {packet_count}</p>
  <h3>Findings</h3>
  <ul>
    {findings_html}
  </ul>
</body>
</html>
"""

    destination_path.write_text(html, encoding="utf-8")
    return str(destination_path)
