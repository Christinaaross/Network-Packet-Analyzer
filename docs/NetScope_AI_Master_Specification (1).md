# NetScope AI — Master Project Specification

**Status:** Target architecture and implementation roadmap (not yet implemented)  
**Purpose:** A local-first, open-source network diagnostics platform that combines deterministic packet analysis, machine-learning anomaly detection, and evidence-grounded AI explanations.  
**Primary learner/developer:** Project owner; Claude acts as mentor and reviewer, not autonomous implementer.

## 1. Product vision and acceptance criteria

Users can import authorized PCAP/PCAPNG captures, inspect network flows and protocol statistics, diagnose common TCP connectivity problems, run optional ML anomaly detection, and request optional LLM-generated explanations grounded in structured evidence. Live capture is opt-in and restricted to authorized interfaces. The product must remain useful when both ML and LLM features are disabled.

**Definition of first public release (v1.0):**
- Local Streamlit interface and documented CLI/API-like Python service boundaries.
- Offline PCAP ingestion, optional live capture, IPv4/IPv6, TCP/UDP/ICMP/ICMPv6/DNS recognition; explicit unsupported cases.
- Flow aggregation; TCP SYN/SYN-ACK/ACK, RST, FIN, suspected retransmissions, timeouts with capture-completeness caveats.
- Transparent rule-based findings, timestamps, packet/flow evidence, confidence/limitations; JSON and HTML reports.
- Scikit-learn Isolation Forest model trained on engineered flow/window features; reproducible training, saved model and feature schema, validation and threshold calibration; alert labels clearly marked as anomalies, not attacks.
- Optional Ollama-backed local diagnostic explanation; optional user-supplied cloud LLM configuration only after explicit opt-in, redaction and preview; no raw payloads sent by default.
- Tests, synthetic/sanitized example captures, GitHub Actions CI, docs, contributor and security policies, license.
- Installable via Python on Windows/Linux/macOS where dependencies support it. **Native desktop installer is not in v1.0**; architecture must allow a future UI replacement without rewriting analysis logic.

**Out of scope for v1.0:** full IDS/IPS, blocking traffic, automatic remediation, guaranteed root-cause determination, deep packet inspection of encrypted payloads, carrier-grade DOCSIS/5G certification, distributed multi-user SaaS, real-time high-volume capture guarantees, native Electron/Tauri shell, hosted inference service.

## 2. Technology choices and reasons

| Layer | Choice | Reason / boundary |
|---|---|---|
| Language | Python 3.11+ | Strong network/ML ecosystem; pin and test supported versions |
| PCAP parsing | Scapy | Inspect packets and fields; keep library behind adapter |
| Live capture | Scapy with OS capture dependencies | Opt-in; Windows generally requires Npcap; permissions differ by OS |
| Protocol verification | Wireshark | Manual packet-level ground truth and learning tool |
| Data modeling | Python dataclasses or Pydantic | Typed, stable contracts across modules |
| Tables/features | Pandas, NumPy | Feature preparation and aggregation |
| Anomaly model | scikit-learn IsolationForest | Practical unsupervised baseline; no attack labels required |
| Dashboard | Streamlit | Fast local UI; must not contain core parsing logic |
| Reports | JSON + HTML templates | Machine-readable and human-readable outputs |
| Local LLM | Ollama (optional) | Local inference, no per-request API fee; model download/resource/license caveats |
| Cloud LLM | Optional provider adapter | User-owned key, consent, redaction, explicit data-transfer notice |
| Testing | Pytest, fixtures, GitHub Actions | Regression tests and repeatable validation |
| Packaging | pyproject.toml, virtual environment, optional CLI entry point | Open-source installation and dependency management |
| License | Apache-2.0 proposed | Permissive license with explicit patent terms; confirm dependency and model licenses |

## 3. Architecture — establish these interfaces before implementation

```text
Authorized PCAP/PCAPNG or opt-in live capture
            |
      capture/ingest adapters
            |
    normalized packet records
            |
       flow aggregation
            |
     shared feature schema
            |
      +-----+------+------------------+
      |            |                  |
 rule engine   ML inference     evidence builder
      |            |                  |
      +------------+------------------+
                   |
         structured findings
                   |
          reporting service
                   |
       optional LLM explainer
                   |
          CLI / Streamlit UI
```

**Critical separation:** Core parsing, feature engineering, rule detection, ML scoring, evidence construction, report generation, and LLM integration must be callable without Streamlit. LLM output must never overwrite packet facts or ML scores. Dependency direction is inward: UI -> services -> domain models/adapters. Avoid circular imports.

### Stable data contracts (define early, version deliberately)

- `PacketRecord`: timestamp, source/destination IP, source/destination port if applicable, protocol, packet length, TCP flags, sequence/ack numbers where available, capture source reference; payload omitted by default.
- `FlowKey`: IP version, protocol, endpoint A/B and ports, canonicalization rules, direction metadata.
- `FlowStats`: start/end, packet/byte counts by direction, durations, rates, TCP flag counts, sequence observations, missing-data flags.
- `FeatureVector`: versioned numeric feature names, values, time-window scope, missing-value policy.
- `Finding`: stable ID, type, severity, observation, evidence packet/flow IDs, possible causes, uncertainty, detector/version.
- `AnomalyResult`: model version, feature schema version, raw `decision_function` score, calibrated threshold, flagged/not flagged; optional UI score only with explicit documented transformation.
- `DiagnosticSummary`: sanitized structured findings, metadata, caveats, permitted context for LLM.
- `Report`: schema version, capture provenance, analysis configuration, findings, model metadata, explanations, export timestamp.

Never treat raw Isolation Forest scores as probabilities or 0–1 confidence. Threshold selection must be documented and evaluated.

## 4. Detection logic and scientific validity

**Rules:** Parse TCP handshakes and resets; detect incomplete attempts only when a bounded observation window supports the claim. Retransmission detection should consider direction, flow, sequence ranges, payload length, timestamps and SYN/FIN handling; classify as *suspected* and validate with Wireshark. Account for asymmetric/incomplete captures, offloading, out-of-order packets, duplicate captures and NAT. DNS/ICMP observations are supporting evidence, not guaranteed root causes.

**ML:** Start with per-flow and per-time-window features (packet count, bytes, duration, average packet size, directional ratio, SYN/RST counts, connection-attempt rate, interarrival summaries). Prevent train/test leakage by separating captures/sessions/time windows, not randomly splitting nearly identical packets. Fit preprocessing only on training data. Use normal-traffic baseline where feasible and held-out controlled anomalies; evaluate false-positive rate, detection rate on known scenarios, alert stability, and drift. Avoid claims of attack detection without suitable labeled evaluation.

**LLM:** Provide only validated, redacted structured summaries by default. Explicitly separate **observed evidence**, **possible explanations**, **recommended verification steps**, and **unknowns**. LLM must not invent packet IDs, assert proven root cause, or autonomously execute network commands. Treat packet contents, DNS names, filenames and user annotations as untrusted prompt-injection inputs. Show generated text as advisory. Provide a no-LLM mode and deterministic fallback summary.

## 5. Privacy, security and open-source readiness

- Capture only networks/interfaces the user is authorized to inspect. No stealth capture or automatic network scanning.
- Default to offline PCAP analysis; live capture requires explicit action and OS permissions.
- Never commit real credentials, private packet payloads, API keys, client addresses, internal hostnames, or proprietary captures.
- Include synthetic fixtures and sanitized examples; sanitize both packet metadata and payload where relevant.
- Use `.gitignore`, `.env.example`, secret scanning and dependency checks; no hardcoded tokens.
- Local-first by default. Cloud LLM disabled until the user explicitly enables it, reviews redacted content and acknowledges transmission.
- Bound upload/file size, parsing time and memory use; handle malformed/truncated captures safely; no arbitrary shell execution from captures or LLM text.
- Disclose that network data may be sensitive even when payloads are encrypted (IP addresses, DNS names, timestamps, endpoints).
- Provide `LICENSE`, `README.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (optional), `SECURITY.md`, example issue templates, architecture and data/privacy documentation.
- Check license compatibility for dependencies and separately downloaded LLM models.

## 6. Repository layout (planned)

```text
netscope-ai/
  pyproject.toml
  README.md
  LICENSE
  CONTRIBUTING.md
  SECURITY.md
  .env.example
  .gitignore
  src/netscope/
    domain/              # typed records and stable schemas
    ingest/              # PCAP and live capture adapters
    protocols/           # packet normalization and TCP logic
    flows/               # bidirectional aggregation
    features/            # shared deterministic feature extraction
    rules/               # transparent diagnostics
    ml/                  # training, evaluation, model registry, inference
    llm/                 # prompts, redaction, local/cloud adapters
    reports/             # JSON/HTML rendering
    services/            # orchestrates analysis pipeline
    cli.py               # optional headless interface
  dashboard/app.py       # Streamlit presentation only
  tests/unit/
  tests/integration/
  tests/fixtures/        # synthetic or verified sanitized captures
  scripts/               # developer utilities; no hidden side effects
  docs/                  # concepts, architecture, privacy, examples
  models/README.md      # model storage policy, no large binaries by default
  .github/workflows/ci.yml
```

## 7. Roadmap and time budget

### Phase 0 — Architecture and setup (0.5–1 day)
Agree on scope, domain records, module contracts, environment, repo structure, sample fixtures and testing strategy. Avoid premature abstraction; write only interfaces needed for planned features.

### Phase 1 — Four-day packet analyzer MVP (28–36 focused hours)
**Day 1:** TCP/IP, IPv4/IPv6, Wireshark basics; import PCAP, normalize packets, parse protocol fields, unit tests.  
**Day 2:** Bidirectional flows, TCP handshake/reset observations, suspected retransmissions, incomplete-capture caveats, deterministic test fixtures.  
**Day 3:** Rule findings, JSON/HTML reports, initial Streamlit dashboard, bounded error handling.  
**Day 4:** Integration tests, Wireshark comparison, packaging basics, documentation and GitHub demo.  
**Exit gate:** Reproducible PCAP import, traceable rule-based findings, tests passing, no ML or LLM required.

### Phase 2 — ML anomaly detection (3–5 intensive days)
- Implement shared flow/window feature extractor and versioned schema.
- Build training/validation pipeline and save model with metadata.
- Evaluate on held-out captures and controlled anomaly scenarios; document false positives and limitations.
- Integrate anomaly alerts and model/threshold details into existing reporting and dashboard.
**Exit gate:** Reproducible model, defensible evaluation, optional ML toggle, no false certainty.

### Phase 3 — AI diagnostic explanations (2–3 intensive days)
- Build redacted `DiagnosticSummary` and deterministic fallback.
- Add local Ollama adapter and structured evidence-grounded prompt; test with model absent.
- Add opt-in cloud provider adapter only if desired, with explicit preview/consent.
- Evaluate explanations against evidence for hallucinations, privacy leakage and prompt injection.
**Exit gate:** Evidence-grounded, clearly advisory explanations; safe no-LLM operation.

### Phase 4 — Open-source release hardening (1–3 intensive days)
- Cross-platform setup instructions and smoke tests (Windows first, Linux/macOS where possible).
- CI, security checks, sample data, contributor docs, license audit, screenshots, tagged release.
**Exit gate:** Another developer can clone, install, analyze a sample capture and reproduce expected results.

**Total estimate:** Approximately 10.5–16 intensive days. These are planning estimates, not guaranteed deadlines. If behind schedule, preserve module boundaries and cut optional UI polish/cloud features before core correctness.

## 8. Acceptance tests and demo scenarios

1. Import a known synthetic PCAP and show correct IPv4/IPv6 and protocol counts.
2. Demonstrate a successful TCP handshake with supporting packet references.
3. Demonstrate a failed/aborted attempt and clearly explain capture limitations.
4. Demonstrate a suspected retransmission and manually compare with Wireshark.
5. Export JSON/HTML reports that reference actual evidence and schema versions.
6. Train Isolation Forest on a reproducible dataset; score held-out flows; show false-positive evaluation.
7. Show a controlled unusual-traffic scenario flagged as anomaly, not automatically attack.
8. Generate local LLM explanation containing evidence, hypotheses and verification steps; verify it doesn't fabricate facts.
9. Disconnect Ollama/cloud services and verify core analyzer still works.
10. Run tests/CI and confirm clean install on a new environment.

## 9. Learning-first Claude operating contract

Claude is a **senior network engineer, ML engineer and mentor**. The user owns implementation. Claude should:
- Read this spec before suggesting any code or changes.
- Start each task with concept, why it matters, dependencies, one small assignment, expected result, verification, and 2–3 knowledge questions.
- Do not write complete functions, modify files, run commands, commit, push or deploy without explicit permission. Short illustrative snippets are allowed when requested.
- Ask the user to attempt solutions first; debug with graduated hints; review their code and tests without silently rewriting it.
- Keep an architectural decision record (`docs/decisions.md`) for changes; propose changes only with tradeoffs and migration impact.
- Track milestones and distinguish **planned**, **implemented**, **tested**, and **released**; never claim a feature works without evidence.
- Design for all phases now, but implement only the current phase. Avoid speculative frameworks and overengineering.
- Prioritize security and privacy; no unauthorized traffic capture or raw sensitive data sent to external services.
- After each day, conduct five interview-style questions and review the answers.

## 10. First action for Claude

1. Read this master specification and the existing four-day NetScope plan.
2. Identify contradictions, hidden dependencies and critical architectural choices; propose minimal decisions without writing code.
3. Produce a small Phase 0 checklist and the first Day 1 lesson.
4. Wait for the user's answer or permission before making any repository changes.

## 11. Future extensions (not commitments)

Native desktop packaging, richer protocol parsers, packet-stream visualization, plugin-based detectors, optional network performance probes, labeled supervised classifiers, and community rule packs. These should plug into existing services/contracts instead of replacing the analysis core.
