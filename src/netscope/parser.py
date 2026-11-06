"""Packet parsing helpers for NetScope."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from scapy.all import IP, IPv6, TCP, UDP, rdpcap

__all__ = ["parse_packet", "parse_capture"]


def _protocol_name(protocol_number: Optional[int]) -> str:
    """Map numeric protocol identifiers to friendly names."""
    if protocol_number is None:
        return "UNKNOWN"

    mapping = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        58: "ICMPv6",
    }
    return mapping.get(protocol_number, str(protocol_number))


def parse_packet(packet: Any) -> Optional[dict[str, Any]]:
    """Normalize a single Scapy packet into a common dictionary format."""
    if packet is None or not hasattr(packet, "haslayer"):
        return None

    if IP in packet:
        ip_layer = packet[IP]
        ip_version = 4
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        protocol_number = int(ip_layer.proto)
    elif IPv6 in packet:
        ip_layer = packet[IPv6]
        ip_version = 6
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        protocol_number = int(ip_layer.nh)
    else:
        return None

    protocol_name = _protocol_name(protocol_number)

    src_port = None
    dst_port = None
    tcp_flags = None

    if TCP in packet:
        tcp_layer = packet[TCP]
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        tcp_flags = tcp_layer.sprintf("%TCP.flags%") or None
    elif UDP in packet:
        udp_layer = packet[UDP]
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ip_version": ip_version,
        "protocol": protocol_name,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags": tcp_flags,
        "packet_length": len(bytes(packet)),
        "timestamp": float(packet.time) if hasattr(packet, "time") and packet.time is not None else None,
    }


def parse_capture(path: str | Path) -> list[dict[str, Any]]:
    """Read a PCAP/PCAPNG file and return a list of normalized packet dictionaries."""
    if path in (None, ""):
        return []

    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        return []

    try:
        packets = rdpcap(str(file_path))
    except Exception:
        return []

    parsed_packets: list[dict[str, Any]] = []
    for packet in packets:
        normalized = parse_packet(packet)
        if normalized is not None:
            parsed_packets.append(normalized)

    return parsed_packets

