#!/usr/bin/env python3
"""Assert-based tests for gn630v_telemetry.py — no framework needed."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gn630v_telemetry import parse_iwpriv_stat, compute_deltas

FIXTURE = Path(__file__).resolve().parent / "testdata" / "gn630v_iwpriv_stat_5g.txt"


def test_parse_real_fixture():
    text = FIXTURE.read_text()
    d = parse_iwpriv_stat(text)
    assert d["tx_success"] == 534, f"tx_success={d['tx_success']}"
    assert d["tx_per_pct"] == 36.6, f"tx_per_pct={d['tx_per_pct']}"
    assert d["rssi0"] == -63, f"rssi0={d['rssi0']}"
    assert d["tx_mcs"] == 2, f"tx_mcs={d['tx_mcs']}"
    assert d["tx_nss"] == 2, f"tx_nss={d['tx_nss']}"
    assert d["bytes_sent"] == 315849, f"bytes_sent={d['bytes_sent']}"
    assert d["tx_phymode"] == "HE_SU", f"tx_phymode={d['tx_phymode']}"
    assert d["temp_c"] == 55, f"temp_c={d['temp_c']}"
    assert d["tx_fail"] == 309, f"tx_fail={d['tx_fail']}"
    assert d["rx_success"] == 4496, f"rx_success={d['rx_success']}"
    assert d["rx_crc"] == 1730, f"rx_crc={d['rx_crc']}"
    assert d["rx_per_pct"] == 27.7, f"rx_per_pct={d['rx_per_pct']}"
    assert d["rssi1"] == -69, f"rssi1={d['rssi1']}"
    assert d["rssi2"] == -109, f"rssi2={d['rssi2']}"
    assert d["rssi3"] == -109, f"rssi3={d['rssi3']}"
    assert d["tx_bw"] == "BW80", f"tx_bw={d['tx_bw']}"
    assert d["tx_gi"] == "0.8us GI", f"tx_gi={d['tx_gi']}"
    assert d["tx_coding"] == "LDPC", f"tx_coding={d['tx_coding']}"
    assert d["rx_mcs"] == 3, f"rx_mcs={d['rx_mcs']}"
    assert d["rx_nss"] == 2, f"rx_nss={d['rx_nss']}"
    assert d["packets_sent"] == 2104, f"packets_sent={d['packets_sent']}"
    assert d["packets_recv"] == 8403, f"packets_recv={d['packets_recv']}"
    assert d["bytes_recv"] == 309069, f"bytes_recv={d['bytes_recv']}"


def test_compute_deltas():
    prev = {
        "bytes_sent": 100000, "bytes_recv": 200000,
        "packets_sent": 500, "packets_recv": 1000,
        "tx_fail": 50, "tx_success": 450,
    }
    curr = {
        "bytes_sent": 110000, "bytes_recv": 220000,
        "packets_sent": 550, "packets_recv": 1100,
        "tx_fail": 60, "tx_success": 490,
    }
    dt = 2.0
    d = compute_deltas(prev, curr, dt)
    assert d["throughput_tx_mbps"] == round(10000 * 8 / 1e6 / 2.0, 3), \
        f"throughput_tx_mbps={d['throughput_tx_mbps']}"
    assert d["throughput_rx_mbps"] == round(20000 * 8 / 1e6 / 2.0, 3), \
        f"throughput_rx_mbps={d['throughput_rx_mbps']}"
    assert d["packets_sent_delta"] == 50, f"packets_sent_delta={d['packets_sent_delta']}"
    assert d["packets_recv_delta"] == 100, f"packets_recv_delta={d['packets_recv_delta']}"
    assert d["tx_fail_delta"] == 10, f"tx_fail_delta={d['tx_fail_delta']}"
    assert d["tx_success_delta"] == 40, f"tx_success_delta={d['tx_success_delta']}"
    expected_retry = round(10 / (40 + 10), 4)
    assert d["retry_rate"] == expected_retry, f"retry_rate={d['retry_rate']}"


def test_compute_deltas_counter_reset():
    """Counters going backwards (reassoc) clamp to 0."""
    prev = {"bytes_sent": 999, "bytes_recv": 999,
            "packets_sent": 999, "packets_recv": 999,
            "tx_fail": 999, "tx_success": 999}
    curr = {"bytes_sent": 10, "bytes_recv": 20,
            "packets_sent": 5, "packets_recv": 8,
            "tx_fail": 1, "tx_success": 4}
    d = compute_deltas(prev, curr, 1.0)
    assert d["throughput_tx_mbps"] == 0.0
    assert d["throughput_rx_mbps"] == 0.0
    assert d["retry_rate"] == 0.0


def test_parse_empty_block():
    d = parse_iwpriv_stat("")
    assert d["rssi0"] == 0
    assert d["rssi1"] == 0
    assert d["rssi2"] == 0
    assert d["rssi3"] == 0
    assert d["tx_success"] == 0
    assert d["temp_c"] == 0
    assert d["tx_nss"] is None
    assert d["tx_phymode"] is None


def test_parse_no_client():
    """A stat block with no RSSI / rate lines parses without raising."""
    text = """rai1      stat:
CurrentTemperature              = 42
Tx success                      = 0
Tx fail count                   = 0, PER=0.0%
Rx success                      = 0
Rx with CRC                     = 0, PER=0.0%
Packets Sent           = 0
Packets Received       = 0
Bytes Sent             = 0
Bytes Received         = 0
"""
    d = parse_iwpriv_stat(text)
    assert d["temp_c"] == 42
    assert d["rssi0"] == 0
    assert d["rssi1"] == 0
    assert d["rssi2"] == 0
    assert d["rssi3"] == 0
    assert d["tx_nss"] is None
    assert d["tx_phymode"] is None
    assert d["tx_success"] == 0


if __name__ == "__main__":
    test_parse_real_fixture()
    test_compute_deltas()
    test_compute_deltas_counter_reset()
    test_parse_empty_block()
    test_parse_no_client()
    print("OK")
    sys.exit(0)
