import json
from pathlib import Path

from netscope.reports import export_json_report, export_html_report


def test_export_json_report_creates_expected_data():
    report = {
        "capture_name": "sample",
        "packet_count": 2,
        "findings": [{"type": "tcp_reset", "message": "reset observed"}],
    }

    output = export_json_report(report)

    loaded = json.loads(output)
    assert loaded["capture_name"] == "sample"
    assert loaded["packet_count"] == 2
    assert loaded["findings"][0]["type"] == "tcp_reset"


def test_export_html_report_contains_summary_and_findings(tmp_path):
    report = {
        "capture_name": "sample",
        "packet_count": 3,
        "findings": [{"type": "unanswered_syn", "message": "No SYN-ACK"}],
    }

    destination = tmp_path / "report.html"
    result_path = export_html_report(report, str(destination))

    assert result_path == str(destination)
    html = destination.read_text(encoding="utf-8")
    assert "sample" in html
    assert "unanswered_syn" in html
    assert "No SYN-ACK" in html
