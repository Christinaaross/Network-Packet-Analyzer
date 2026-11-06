from netscope.flows import group_packets_by_flow


def test_group_packets_by_flow_bidirectional_tcp():
    packets = [
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "src_port": 5000,
            "dst_port": 80,
            "packet_length": 100,
            "timestamp": 1.0,
        },
        {
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.1",
            "protocol": "TCP",
            "src_port": 80,
            "dst_port": 5000,
            "packet_length": 150,
            "timestamp": 1.2,
        },
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "src_port": 5000,
            "dst_port": 80,
            "packet_length": 200,
            "timestamp": 1.5,
        },
    ]

    flows = group_packets_by_flow(packets)

    assert len(flows) == 1
    assert flows[0]["packet_count"] == 3
    assert flows[0]["total_bytes"] == 450
    assert set(flows[0]["endpoints"]) == {("10.0.0.1", 5000), ("10.0.0.2", 80)}


def test_group_packets_by_flow_distinguishes_udp_from_tcp():
    packets = [
        {
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol": "UDP",
            "src_port": 50000,
            "dst_port": 53,
            "packet_length": 80,
            "timestamp": 2.0,
        },
        {
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 80,
            "packet_length": 90,
            "timestamp": 2.1,
        },
    ]

    flows = group_packets_by_flow(packets)

    assert len(flows) == 2
    assert {flow["protocol"] for flow in flows} == {"UDP", "TCP"}


def test_group_packets_by_flow_ignores_incomplete_records():
    packets = [
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "TCP"},
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "src_port": 1234,
            "dst_port": 443,
            "packet_length": 120,
            "timestamp": 5.0,
        },
    ]

    flows = group_packets_by_flow(packets)

    assert len(flows) == 1
    assert flows[0]["packet_count"] == 1
