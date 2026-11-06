# NetScope — Network Packet Analyzer & Diagnostic Tool

**Duration:** 4 intensive days, approximately **28–36 focused hours** (7–9 hours/day).  
**Level:** Intermediate Python; beginner-to-intermediate networking.  
**Goal:** Build a reproducible portfolio application that analyzes authorized packet captures, highlights network problems, and exports defensible diagnostic reports.

## Scope and success criteria

### Must-have MVP
- [ ] Import `.pcap` and `.pcapng` captures (test supported formats; Scapy support may vary by file).
- [ ] Extract timestamps, IP versions, source/destination addresses, transport protocol, ports, TCP flags, and packet lengths.
- [ ] Aggregate packet counts, byte counts, and protocol breakdowns.
- [ ] Group TCP packets into bidirectional connections and show handshake evidence.
- [ ] Flag TCP RSTs, unanswered SYNs, and **suspected** retransmissions with explicit confidence/limitations.
- [ ] Display findings in a Streamlit dashboard.
- [ ] Export JSON and HTML diagnostic reports.
- [ ] Include automated tests and sanitized sample captures.
- [ ] Publish README, screenshots, architecture, and known limitations.

### Stretch goals (only after MVP)
- [ ] Optional live capture of traffic on interfaces you own or are authorized to monitor.
- [ ] DNS request/response timing and timeout heuristics.
- [ ] IPv6 extension-header edge cases and ICMPv6 analysis.
- [ ] Compare two captures from the same test scenario.

## Core glossary

| Term | Definition | Why it matters |
|---|---|---|
| Packet | Unit of data carried over a network. | Basic item analyzed. |
| Frame | Link-layer transmission unit, such as Ethernet. | Encapsulates network-layer packets. |
| Packet capture | Recording observed network traffic. | Supplies analyzer input. |
| PCAP | Common packet capture file format. | Portable test input. |
| PCAPNG | Newer packet capture format supporting richer metadata. | Common Wireshark export. |
| Wireshark | Graphical network protocol analyzer. | Ground truth for manual inspection. |
| Scapy | Python packet manipulation and parsing library. | Reads packets and extracts fields. |
| TCP | Reliable, ordered byte-stream transport protocol. | Handshakes, resets, retransmissions. |
| UDP | Connectionless transport protocol without built-in delivery guarantee. | DNS and other traffic. |
| IP | Protocol for addressing and routing network packets. | Source and destination addresses. |
| IPv4 | IP with 32-bit addresses. | Standard network traffic. |
| IPv6 | IP with 128-bit addresses. | Modern network traffic. |
| ICMP | Network control and diagnostic messaging protocol. | Errors and ping diagnostics. |
| ICMPv6 | IPv6 control protocol, including neighbor discovery. | IPv6 diagnostics. |
| DNS | System mapping names to resource records such as IP addresses. | Troubleshooting name resolution. |
| Ethernet | Common wired link-layer technology. | Typical frame encapsulation. |
| Network interface | Hardware or virtual interface carrying traffic. | Live capture source. |
| NIC | Network interface controller. | Physical/virtual network device. |
| Port | Transport-layer number distinguishing services/endpoints. | Group conversations. |
| Socket | Application endpoint for network communication. | Context for TCP/UDP. |
| Flow | Related packets identified by endpoints and protocol. | Connection summaries. |
| 5-tuple | Source IP, destination IP, source port, destination port, protocol. | Basic flow key. |
| Bidirectional flow | Traffic in both directions between endpoint pairs. | Handshake reconstruction. |
| SYN | TCP flag used to start connection establishment. | Handshake stage 1. |
| SYN-ACK | TCP response acknowledging a SYN while sending its own SYN. | Handshake stage 2. |
| ACK | TCP flag indicating acknowledgment number is valid. | Handshake stage 3 and data acknowledgment. |
| RST | TCP flag indicating connection reset/rejection. | Error/closure clue. |
| FIN | TCP flag signaling no more data from sender. | Normal shutdown clue. |
| Sequence number | TCP byte-stream position used to order data. | Retransmission heuristics. |
| Acknowledgment number | TCP number indicating next byte expected. | Delivery evidence. |
| Retransmission | Sending TCP data/control information again. | May indicate loss, delay, reordering, or artifacts. |
| Packet loss | Packets not arriving at destination. | Potential underlying issue. |
| RTT | Round-trip time for a request and its response. | Latency measurement. |
| Latency | Communication delay. | Performance metric. |
| Jitter | Variation in packet delay. | Performance context. |
| Throughput | Amount of data transferred per time. | Performance context. |
| Timeout | Expected event did not occur within a chosen period. | Failure heuristic. |
| BPF | Berkeley Packet Filter syntax for selecting packets. | Narrow authorized captures. |
| PCAP filter | Display/capture filtering rule; Wireshark display filters differ from BPF capture filters. | Avoid confusing filter languages. |
| False positive | Alert raised when no actual issue exists. | Accuracy testing. |
| False negative | Actual issue that the tool misses. | Coverage testing. |
| Heuristic | Practical rule that estimates a condition. | Retransmission/timeout classification. |
| Pytest | Python testing framework. | Repeatable validation. |
| Streamlit | Python web-app framework. | Interactive dashboard. |
| Pandas | Python tabular data library. | Aggregation and tables. |
| JSON | Structured text format for machine-readable data. | Report export. |
| HTML | Markup format for browser-readable documents. | Report export. |
| CLI | Command-line interface. | Repeatable analysis. |
| Virtual environment | Isolated Python dependency installation. | Reproducible setup. |
| Git | Version-control system. | Track project history. |
| GitHub | Hosted Git repository service. | Portfolio publication. |
| Npcap | Windows packet capture driver. | Optional Windows live capture. |
| Root/admin privileges | Elevated operating-system permissions. | Often required for live capture, not offline PCAP analysis. |

## Architecture

```text
Authorized PCAP / PCAPNG input
             |
             v
       Scapy parser
             |
             v
    Normalized packet records
             |
      +------+-------+
      |              |
      v              v
Protocol/flow     TCP diagnostics
statistics        (handshake, RST,
                  suspected retransmit)
      |              |
      +------+-------+
             v
       Findings + evidence
             |
      +------+-------+
      |              |
      v              v
 Streamlit UI      JSON / HTML
                  report export
```

## Suggested repository structure

```text
netscope/
├── app.py                 # Streamlit dashboard
├── netscope/
│   ├── __init__.py
│   ├── parser.py          # PCAP -> normalized records
│   ├── flows.py           # Bidirectional TCP flow grouping
│   ├── diagnostics.py     # Heuristics and evidence
│   ├── metrics.py         # Aggregated stats
│   ├── reports.py         # JSON / HTML output
│   └── cli.py             # Optional CLI entrypoint
├── tests/
│   ├── test_parser.py
│   ├── test_flows.py
│   ├── test_diagnostics.py
│   └── fixtures/          # Synthetic sanitized captures
├── examples/              # Sanitized reports/screenshots
├── requirements.txt
├── README.md
└── .gitignore
```

## Day 1 — Foundations, setup, packet parsing (7–9 hours)

**Hour 1–2: Learn and observe.** Study the OSI/TCP-IP layers, IP addresses, ports, TCP three-way handshake, UDP, ICMP, DNS, and TCP flags. Install Python, Git, Wireshark, and a code editor. On Windows, Npcap is needed for many live capture workflows; offline parsing is the safer starting point.

**Hour 3: Initialize project.** Create Git repository and virtual environment, install `scapy`, `pandas`, `streamlit`, `pytest`, and optionally `jinja2`. Commit a clean scaffold.

**Hour 4–6: Build parser.** Read a sample capture with Scapy, detect IPv4/IPv6, extract source/destination IP, protocol, ports, timestamp, TCP flags, TCP sequence/acknowledgment numbers, payload length, and packet length. Handle missing fields and malformed/unsupported packets gracefully.

**Hour 7–9: Verify.** Use Wireshark to manually compare at least 20 packets to your parser. Create automated tests for IPv4, IPv6, TCP, UDP, ICMP, and empty input.

**Deliverable:** A parser that reliably converts an authorized capture to structured packet records.

## Day 2 — Flow tracking and diagnostics (7–9 hours)

**Hour 1–2: Build flow grouping.** Identify TCP conversations using normalized bidirectional endpoints; account for connection reuse and flow expiration where possible.

**Hour 3–4: Track handshakes.** Recognize SYN -> SYN-ACK -> ACK where all stages are visible. Flag SYNs with no observed SYN-ACK after a configurable window as **unanswered in this capture**, not proven server failures. Distinguish capture-started-midstream traffic.

**Hour 5: Detect resets.** Record RST packets, direction, time, endpoints, and whether a reset occurred during establishment or an established session.

**Hour 6–8: Suspected retransmissions.** For each direction of a TCP flow, compare sequence-number intervals and payload lengths. Flag repeated/overlapping byte ranges, with exceptions for out-of-order packets and capture duplication. Label findings *suspected*; avoid equating retransmission with packet loss.

**Hour 9: Validate.** Generate controlled traffic on localhost or your own lab server, then inspect matching captures in Wireshark. Test normal connection, refused connection, and a repeated-segment fixture.

**Deliverable:** A diagnostics engine returning findings with timestamps, packet references, and confidence notes.

## Day 3 — Dashboard and report exports (7–9 hours)

**Hour 1–3: Streamlit interface.** Add file upload, packet/byte counts, protocol breakdown, top endpoints, sortable flow table, and filters for IP/protocol/port.

**Hour 4–5: Findings view.** Show unanswered SYNs, resets, and suspected retransmissions. Each finding should include an explanation, packet index/time, and limitations.

**Hour 6–7: Reporting.** Export JSON and HTML with capture metadata, aggregate metrics, findings, and disclaimers. Sanitize displayed text and avoid embedding raw untrusted payload content into HTML.

**Hour 8–9: Robustness.** Handle empty captures, IPv6-only captures, malformed files, and large captures. Add file-size limits and clear errors.

**Deliverable:** An interactive dashboard and downloadable diagnostic reports.

## Day 4 — Testing, validation, and portfolio polish (7–9 hours)

**Hour 1–3: Automated tests.** Cover TCP handshake, unanswered SYN, RST, retransmission candidates, no false retransmit for ordinary new sequence ranges, IPv4/IPv6, and malformed input. Use synthetic fixtures so tests are deterministic.

**Hour 4–5: Manual cross-check.** Compare your output to Wireshark on multiple authorized sample captures. Record where the tools disagree and why. Include expected vs observed outcomes.

**Hour 6: Performance check.** Measure processing time and memory on small/medium files. Document limits instead of claiming enterprise scalability.

**Hour 7–8: README and screenshots.** Explain setup, sample commands, architecture, protocol coverage, testing results, limitations, and safe usage. Add screenshots with private IPs and payloads removed or anonymized.

**Hour 9: Final demo.** Re-run tests, produce a sample report, tag a release, and write 2–3 truthful resume/portfolio bullets.

**Deliverable:** A complete GitHub-ready MVP with reproducible evidence.

## Setup commands (Windows PowerShell)

```powershell
mkdir netscope
cd netscope
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install scapy pandas streamlit pytest jinja2
pip freeze > requirements.txt
git init
```

If PowerShell blocks activation, use `.venv\Scripts\python.exe` directly rather than changing system-wide execution policy.

Launch the dashboard when `app.py` exists:

```powershell
streamlit run app.py
```

## Minimum test matrix

| Scenario | Expected behavior |
|---|---|
| Normal TCP handshake | Recognize SYN, SYN-ACK, ACK when captured |
| Connection refused | Show observed RST and its context |
| SYN without response | Label unanswered SYN in capture, not definitive outage |
| Repeated TCP byte range | Flag suspected retransmission with evidence |
| Ordinary sequential TCP data | No retransmission alert |
| UDP-only file | Protocol metrics work; no fabricated TCP findings |
| IPv6 TCP flow | IPv6 endpoints parsed and grouped |
| Empty capture | Graceful empty state |
| Corrupt/unsupported input | Clear error without application crash |
| Large capture | Size limit or bounded processing behavior documented |

## Security and ethical boundaries

Only capture traffic on devices/networks you own or have explicit permission to monitor. Packet captures can contain credentials, cookies, IP addresses, and personal data. Do not upload raw workplace/client captures to GitHub, a public Streamlit deployment, or third-party services. Use synthetic or sanitized fixtures, exclude capture files from Git by default, and restrict live capture to authorized interfaces. The app should not automatically inspect other people's networks.

## Completion criteria

The project is done when you can upload a sample capture, see correct protocol statistics, inspect at least three evidence-backed diagnostic categories, export reports, run a passing automated test suite, and reproduce the demo from README instructions.

## Interview explanation

> I built NetScope, a Python-based network packet analysis tool using Scapy and Wireshark. It parses IPv4/IPv6 traffic, reconstructs TCP flow evidence, flags resets, unanswered connection attempts, and suspected retransmissions, and exports diagnostic reports through a Streamlit dashboard. I validated findings against Wireshark and automated the core behavior with Pytest. I explicitly distinguish what a capture proves from possible network causes.

## Realistic timing

- **28–36 hours:** Portfolio-ready MVP if Python is familiar and the scope stays tight.
- **40–55 hours:** More realistic if TCP sequence/acknowledgment logic and Wireshark are new.
- **Additional days:** Reliable high-volume capture, comprehensive TCP state tracking, advanced IPv6 handling, polished deployment, and production-grade diagnostics.

**Priority if behind:** Parser -> flow tracking -> RST/unanswered SYN -> basic suspected retransmission heuristic -> dashboard -> reports -> tests/docs. Drop live capture and advanced features before cutting validation.
