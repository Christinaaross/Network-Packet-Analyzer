"""Flow grouping helpers for NetScope."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

__all__ = ["group_packets_by_flow", "flow_key"]


def flow_key(packet: dict[str, Any]) -> tuple[str, tuple[str, int], tuple[str, int]] | None:
    """Return a canonical bidirectional key for a TCP or UDP packet."""
    if not isinstance(packet, dict):
        return None

    protocol = str(packet.get("protocol", "")).upper()
    if protocol not in {"TCP", "UDP"}:
        return None

    src_ip = packet.get("src_ip")
    dst_ip = packet.get("dst_ip")
    src_port = packet.get("src_port")
    dst_port = packet.get("dst_port")

    if src_ip is None or dst_ip is None or src_port is None or dst_port is None:
        return None

    first_endpoint = (str(src_ip), int(src_port))
    second_endpoint = (str(dst_ip), int(dst_port))
    ordered = tuple(sorted((first_endpoint, second_endpoint)))
    return (protocol, ordered[0], ordered[1])


def group_packets_by_flow(packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group normalized packets into bidirectional network flows."""
    grouped: dict[tuple[str, tuple[str, int], tuple[str, int]], list[dict[str, Any]]] = defaultdict(list)

    for packet in packets or []:
        key = flow_key(packet)
        if key is not None:
            grouped[key].append(packet)

    flows: list[dict[str, Any]] = []
    for key, items in grouped.items():
        protocol, left, right = key
        endpoints = {left, right}

        flow = {
            "protocol": protocol,
            "flow_key": key,
            "endpoints": sorted(endpoints),
            "packet_count": len(items),
            "total_bytes": sum(int(item.get("packet_length", 0) or 0) for item in items),
            "start_time": min(float(item.get("timestamp", 0) or 0) for item in items),
            "end_time": max(float(item.get("timestamp", 0) or 0) for item in items),
        }
        flows.append(flow)

    return flows
