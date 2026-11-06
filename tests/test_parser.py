from pathlib import Path

from scapy.all import IP, IPv6, TCP, UDP, Raw, wrpcap

from netscope.parser import parse_capture, parse_packet


def test_parse_packet_ipv4_tcp():
    packet = IP(src="192.168.1.10", dst="10.0.0.5") / TCP(
        sport=12345, dport=80, flags="S", seq=1000
    ) / Raw(b"hello")

    result = parse_packet(packet)

    assert result is not None
    assert result["src_ip"] == "192.168.1.10"
    assert result["dst_ip"] == "10.0.0.5"
    assert result["ip_version"] == 4
    assert result["protocol"] == "TCP"
    assert result["src_port"] == 12345
    assert result["dst_port"] == 80
    assert result["tcp_flags"] == "S"
    assert result["packet_length"] > 0


def test_parse_packet_ipv6_udp():
    packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=5353, dport=53)

    result = parse_packet(packet)

    assert result is not None
    assert result["src_ip"] == "2001:db8::1"
    assert result["dst_ip"] == "2001:db8::2"
    assert result["ip_version"] == 6
    assert result["protocol"] == "UDP"
    assert result["src_port"] == 5353
    assert result["dst_port"] == 53
    assert result["packet_length"] > 0


def test_parse_capture_reads_pcap(tmp_path):
    capture_path = tmp_path / "sample.pcap"
    packets = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="S", seq=1),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=5000, flags="SA", seq=2, ack=2),
    ]
    wrpcap(str(capture_path), packets)

    results = parse_capture(str(capture_path))

    assert len(results) == 2
    assert results[0]["src_ip"] == "10.0.0.1"
    assert results[1]["dst_ip"] == "10.0.0.1"


def test_parse_capture_returns_empty_list_for_missing_file():
    results = parse_capture("this_file_does_not_exist.pcap")
    assert results == []
