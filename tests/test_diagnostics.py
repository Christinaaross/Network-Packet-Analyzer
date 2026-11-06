from netscope.diagnostics import analyze_packets


def test_analyze_packets_flags_unanswered_syn():
    packets = [
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "src_port": 5000,
            "dst_port": 80,
            "tcp_flags": "S",
            "timestamp": 1.0,
        },
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "src_port": 5000,
            "dst_port": 80,
            "tcp_flags": "A",
            "timestamp": 1.2,
        },
    ]

    findings = analyze_packets(packets)

    assert any(f["type"] == "unanswered_syn" for f in findings)


def test_analyze_packets_flags_reset():
    packets = [
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "src_port": 5000,
            "dst_port": 80,
            "tcp_flags": "R",
            "timestamp": 2.0,
        }
    ]

    findings = analyze_packets(packets)

    assert any(f["type"] == "tcp_reset" for f in findings)


def test_analyze_packets_accepts_normal_handshake_without_finding():
    packets = [
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "src_port": 5000,
            "dst_port": 80,
            "tcp_flags": "S",
            "timestamp": 1.0,
        },
        {
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.1",
            "protocol": "TCP",
            "src_port": 80,
            "dst_port": 5000,
            "tcp_flags": "SA",
            "timestamp": 1.1,
        },
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "src_port": 5000,
            "dst_port": 80,
            "tcp_flags": "A",
            "timestamp": 1.2,
        },
    ]

    findings = analyze_packets(packets)

    assert not any(f["type"] == "unanswered_syn" for f in findings)
    assert not any(f["type"] == "tcp_reset" for f in findings)
