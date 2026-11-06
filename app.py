from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import streamlit as st

from netscope.diagnostics import analyze_packets
from netscope.flows import group_packets_by_flow
from netscope.parser import parse_capture
from netscope.reports import export_html_report, export_json_report


st.set_page_config(page_title="NetScope", layout="wide")
st.title("NetScope Packet Analyzer")

uploaded_file = st.file_uploader("Upload a .pcap or .pcapng file", type=["pcap", "pcapng"])

if uploaded_file is not None:
    temp_path = Path("temp_capture")
    temp_path.mkdir(exist_ok=True)
    capture_path = temp_path / uploaded_file.name
    capture_path.write_bytes(uploaded_file.read())

    packets = parse_capture(str(capture_path))
    flows = group_packets_by_flow(packets)
    findings = analyze_packets(packets)

    st.subheader("Summary")
    col1, col2, col3 = st.columns(3)
    col1.metric("Packets", len(packets))
    col2.metric("Flows", len(flows))
    col3.metric("Findings", len(findings))

    st.subheader("Findings")
    if findings:
        st.json(findings)
    else:
        st.info("No TCP issues detected in this capture.")

    st.subheader("Flow overview")
    if flows:
        st.json(flows)
    else:
        st.info("No flow data available.")

    report = {
        "capture_name": uploaded_file.name,
        "packet_count": len(packets),
        "flow_count": len(flows),
        "findings": findings,
    }

    st.subheader("Exports")
    json_output = export_json_report(report)
    html_output_path = export_html_report(report, temp_path / "report.html")

    st.download_button("Download JSON", json_output, file_name="netscope_report.json")
    st.download_button("Download HTML", Path(html_output_path).read_text(encoding="utf-8"), file_name="netscope_report.html")
