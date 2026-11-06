# NetScope

NetScope is a lightweight packet analyzer built with Python and Streamlit. It currently supports:

- uploading a .pcap or .pcapng capture
- parsing packet metadata such as IPs, ports, protocol, flags, and timestamps
- grouping packets into bidirectional flows
- detecting basic TCP issues like unanswered SYNs and reset packets
- exporting a JSON or HTML report

This project is a simple MVP for learning and portfolio use.

## Run locally

1. Open PowerShell in the project root.
2. Activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

3. Start the app:

```powershell
streamlit run app.py
```

4. Open the local Streamlit URL in your browser.

## Project structure

```text
.
├── app.py
├── README.md
├── .gitignore
├── src/
│   └── netscope/
│       ├── parser.py
│       ├── flows.py
│       ├── diagnostics.py
│       ├── reports.py
│       └── __init__.py
├── tests/
│   ├── test_parser.py
│   ├── test_flows.py
│   ├── test_diagnostics.py
│   └── test_reports.py
└── .venv/
```

## Current status

This is an early-stage MVP. It focuses on basic packet parsing and diagnostics rather than full enterprise packet inspection.

## Notes

- The app is intended for authorized packet captures only.
- For live packet capture, always make sure you have permission to inspect the traffic.
