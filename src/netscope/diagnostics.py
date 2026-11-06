"""Diagnostic heuristics for TCP traffic."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

__all__ = ["analyze_packets", "detect_unanswered_syns", "detect_resets"]


def _packet_is_tcp(packet: dict[str, Any]) -> bool:
    return isinstance(packet, dict) and str(packet.get("protocol", "")).upper() == "TCP"


def detect_resets(packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find TCP reset packets and return them as findings."""
    findings: list[dict[str, Any]] = []
    for packet in packets or []:
        if not _packet_is_tcp(packet):
            continue
        flags = str(packet.get("tcp_flags", "")).upper()
        if "R" in flags:
            findings.append(
                {
                    "type": "tcp_reset",
                    "src_ip": packet.get("src_ip"),
                    "dst_ip": packet.get("dst_ip"),
                    "src_port": packet.get("src_port"),
                    "dst_port": packet.get("dst_port"),
                    "timestamp": packet.get("timestamp"),
                    "message": "TCP reset observed.",
                }
            )
    return findings


def detect_unanswered_syns(packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag SYN packets whose matching SYN-ACK / ACK handshake is missing."""
    findings: list[dict[str, Any]] = []
    syn_requests: dict[tuple[str, int, str, int], dict[str, Any]] = {}

    for packet in packets or []:
        if not _packet_is_tcp(packet):
            continue

        flags = str(packet.get("tcp_flags", "")).upper()
        if "S" in flags and "A" not in flags:
            key = (packet.get("src_ip"), packet.get("src_port"), packet.get("dst_ip"), packet.get("dst_port"))
            syn_requests[key] = packet

    seen_handshakes: set[tuple[str, int, str, int]] = set()
    for packet in packets or []:
        if not _packet_is_tcp(packet):
            continue

        flags = str(packet.get("tcp_flags", "")).upper()
        if "S" in flags and "A" in flags:
            key = (packet.get("dst_ip"), packet.get("dst_port"), packet.get("src_ip"), packet.get("src_port"))
            if key in syn_requests:
                seen_handshakes.add(key)

    for key, packet in syn_requests.items():
        if key not in seen_handshakes:
            findings.append(
                {
                    "type": "unanswered_syn",
                    "src_ip": packet.get("src_ip"),
                    "dst_ip": packet.get("dst_ip"),
                    "src_port": packet.get("src_port"),
                    "dst_port": packet.get("dst_port"),
                    "timestamp": packet.get("timestamp"),
                    "message": "TCP SYN was observed without a matching SYN-ACK in this capture.",
                }
            )

    return findings


def analyze_packets(packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run the current TCP diagnostics on a list of normalized packets."""
    findings = []
    findings.extend(detect_resets(packets))
    findings.extend(detect_unanswered_syns(packets))
    return findings
