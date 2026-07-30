"""Sanity checks for telemetry_capture's parsing and delta math.

Fixtures below are two REAL `iw dev wlan0 station dump` captures taken ~37s
apart on this dev machine's own WiFi link (not synthetic), so the delta test
exercises actual byte/packet/retry counter deltas, not invented numbers.
"""
from telemetry_capture import compute_deltas, parse_station_dump

DUMP_1 = """Station a8:d4:e0:8f:01:3c (on wlan0)
\tauthorized:\tyes
\tinactive time:\t40 ms
\trx bytes:\t93575924
\trx packets:\t153499
\ttx bytes:\t369260952
\ttx packets:\t295917
\ttx retries:\t2765
\ttx failed:\t0
\tsignal:  \t-35 [-35, -35] dBm
\tsignal avg:\t-34 [-34, -35] dBm
\tbeacon signal avg:\t-33 dBm
\ttx bitrate:\t144.4 MBit/s MCS 15 short GI
\trx bitrate:\t86.7 MBit/s VHT-MCS 8 short GI VHT-NSS 1
\tcurrent time:\t1785417609388 ms
"""

DUMP_2 = """Station a8:d4:e0:8f:01:3c (on wlan0)
\tauthorized:\tyes
\tinactive time:\t77 ms
\trx bytes:\t94103577
\trx packets:\t156679
\ttx bytes:\t385069218
\ttx packets:\t307484
\ttx retries:\t2833
\ttx failed:\t0
\tsignal:  \t-34 [-36, -34] dBm
\tsignal avg:\t-33 [-35, -33] dBm
\tbeacon signal avg:\t-33 dBm
\ttx bitrate:\t78.0 MBit/s MCS 12
\trx bitrate:\t78.0 MBit/s VHT-MCS 8 VHT-NSS 1
\tcurrent time:\t1785417646504 ms
"""

DT_SECONDS = (1785417646504 - 1785417609388) / 1000  # from the captures' own "current time" fields


def test_parse_single_client_all_fields():
    st = parse_station_dump(DUMP_2)
    assert len(st) == 1
    s = st[0]
    assert s["mac"] == "a8:d4:e0:8f:01:3c"
    assert s["rssi_dbm"] == -34
    assert s["rssi_avg_dbm"] == -33
    assert s["tx_mcs"] == 12
    assert s["tx_rate_mbps"] == 78.0
    assert s["rx_mcs"] == 8
    assert s["rx_rate_mbps"] == 78.0
    assert s["tx_bytes"] == 385069218
    assert s["rx_bytes"] == 94103577
    assert s["tx_packets"] == 307484
    assert s["tx_retries"] == 2833


def test_parse_multi_station_dump_splits_correctly():
    two = DUMP_1 + DUMP_2.replace("a8:d4:e0:8f:01:3c", "00:1d:43:20:16:6a")
    st = parse_station_dump(two)
    assert len(st) == 2
    assert st[0]["mac"] == "a8:d4:e0:8f:01:3c"
    assert st[1]["mac"] == "00:1d:43:20:16:6a"
    assert st[0]["tx_bytes"] == 369260952
    assert st[1]["tx_bytes"] == 385069218


def test_compute_deltas_against_real_capture_interval():
    prev = parse_station_dump(DUMP_1)[0]
    curr = parse_station_dump(DUMP_2)[0]
    d = compute_deltas(prev, curr, DT_SECONDS)

    # exact integer deltas — fully independent hand-checkable arithmetic
    assert d["tx_packets_delta"] == 307484 - 295917 == 11567
    assert d["tx_retries_delta"] == 2833 - 2765 == 68
    assert d["retry_rate"] == round(68 / 11567, 4)

    # throughput: tx moved ~15.8MB, rx only ~0.5MB over ~37s — tx should
    # dominate and both should land in a sane single-digit Mbps range
    assert 0 < d["throughput_rx_mbps"] < 1
    assert 3 < d["throughput_tx_mbps"] < 4
    assert d["throughput_tx_mbps"] > d["throughput_rx_mbps"]


def test_compute_deltas_clamps_counter_reset_to_zero():
    # if tx_bytes/packets go backwards (interface reset), deltas must not go negative
    prev = {"tx_bytes": 5000, "rx_bytes": 5000, "tx_packets": 100, "tx_retries": 10}
    curr = {"tx_bytes": 100, "rx_bytes": 100, "tx_packets": 5, "tx_retries": 1}
    d = compute_deltas(prev, curr, 1.0)
    assert d["throughput_tx_mbps"] == 0.0
    assert d["throughput_rx_mbps"] == 0.0
    assert d["tx_packets_delta"] == 0
    assert d["retry_rate"] == 0.0


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("OK")
