#!/usr/bin/env python3
"""Poll a GN630v ONT's `iwpriv <if> stat` over telnet and log RSSI/MCS/
throughput/retry telemetry to CSV — the GN630v sibling of telemetry_capture.py.

ponytail: stdlib only, mirrors telemetry_capture.py structure.
"""
import argparse
import csv
import re
import sys
import time
from pathlib import Path

from gn630v_telnet import GN630V

TEMP_RE = re.compile(r"CurrentTemperature\s*=\s*(\d+)")
TX_SUCCESS_RE = re.compile(r"Tx success\s*=\s*(\d+)")
TX_FAIL_RE = re.compile(r"Tx fail count\s*=\s*(\d+),\s*PER=([\d.]+)%")
RX_SUCCESS_RE = re.compile(r"Rx success\s*=\s*(\d+)")
RX_CRC_RE = re.compile(r"Rx with CRC\s*=\s*(\d+),\s*PER=([\d.]+)%")
RSSI_RE = re.compile(r"Rssi:\s+(-?\d+)\s+(-?\d+)\s+(-?\d+)\s+(-?\d+)")
TX_RATE_RE = re.compile(
    r"Last TX Rate\s*=\s*NSS(\d+)_MCS(\d+),\s*(\S+),\s*(\S+\s*\S*),\s*(\S+),\s*(\S+)"
)
RX_RATE_RE = re.compile(
    r"Last RX Rate\s*=\s*NSS(\d+)_MCS(\d+),\s*(\S+),\s*(\S+\s*\S*),\s*(\S+),\s*(\S+)"
)
PKT_SENT_RE = re.compile(r"Packets Sent\s*=\s*(\d+)")
PKT_RECV_RE = re.compile(r"Packets Received\s*=\s*(\d+)")
BYTES_SENT_RE = re.compile(r"Bytes Sent\s*=\s*(\d+)")
BYTES_RECV_RE = re.compile(r"Bytes Received\s*=\s*(\d+)")

CSV_FIELDS = [
    "timestamp", "label", "iface",
    "temp_c",
    "tx_success", "tx_fail", "tx_per_pct",
    "rx_success", "rx_crc", "rx_per_pct",
    "rssi0", "rssi1", "rssi2", "rssi3",
    "tx_nss", "tx_mcs", "tx_bw", "tx_gi", "tx_phymode", "tx_coding",
    "rx_nss", "rx_mcs", "rx_bw", "rx_gi", "rx_phymode", "rx_coding",
    "packets_sent", "packets_recv", "bytes_sent", "bytes_recv",
    "throughput_tx_mbps", "throughput_rx_mbps",
    "packets_sent_delta", "packets_recv_delta",
    "tx_fail_delta", "tx_success_delta", "retry_rate",
]


def parse_iwpriv_stat(text: str) -> dict:
    """Parse one `iwpriv <if> stat` block into a flat dict."""
    d: dict = {
        "temp_c": 0,
        "tx_success": 0, "tx_fail": 0, "tx_per_pct": 0.0,
        "rx_success": 0, "rx_crc": 0, "rx_per_pct": 0.0,
        "rssi0": 0, "rssi1": 0, "rssi2": 0, "rssi3": 0,
        "tx_nss": None, "tx_mcs": None, "tx_bw": None, "tx_gi": None,
        "tx_phymode": None, "tx_coding": None,
        "rx_nss": None, "rx_mcs": None, "rx_bw": None, "rx_gi": None,
        "rx_phymode": None, "rx_coding": None,
        "packets_sent": 0, "packets_recv": 0,
        "bytes_sent": 0, "bytes_recv": 0,
    }
    for line in text.splitlines():
        m = TEMP_RE.search(line)
        if m:
            d["temp_c"] = int(m.group(1))
            continue
        m = TX_FAIL_RE.search(line)
        if m:
            d["tx_fail"] = int(m.group(1))
            d["tx_per_pct"] = float(m.group(2))
            continue
        m = TX_SUCCESS_RE.search(line)
        if m:
            d["tx_success"] = int(m.group(1))
            continue
        m = RX_CRC_RE.search(line)
        if m:
            d["rx_crc"] = int(m.group(1))
            d["rx_per_pct"] = float(m.group(2))
            continue
        m = RX_SUCCESS_RE.search(line)
        if m:
            d["rx_success"] = int(m.group(1))
            continue
        m = RSSI_RE.search(line)
        if m:
            d["rssi0"] = int(m.group(1))
            d["rssi1"] = int(m.group(2))
            d["rssi2"] = int(m.group(3))
            d["rssi3"] = int(m.group(4))
            continue
        m = TX_RATE_RE.search(line)
        if m:
            d["tx_nss"] = int(m.group(1))
            d["tx_mcs"] = int(m.group(2))
            d["tx_bw"] = m.group(3)
            d["tx_gi"] = m.group(4)
            d["tx_phymode"] = m.group(5)
            d["tx_coding"] = m.group(6)
            continue
        m = RX_RATE_RE.search(line)
        if m:
            d["rx_nss"] = int(m.group(1))
            d["rx_mcs"] = int(m.group(2))
            d["rx_bw"] = m.group(3)
            d["rx_gi"] = m.group(4)
            d["rx_phymode"] = m.group(5)
            d["rx_coding"] = m.group(6)
            continue
        m = PKT_SENT_RE.search(line)
        if m:
            d["packets_sent"] = int(m.group(1))
            continue
        m = PKT_RECV_RE.search(line)
        if m:
            d["packets_recv"] = int(m.group(1))
            continue
        m = BYTES_SENT_RE.search(line)
        if m:
            d["bytes_sent"] = int(m.group(1))
            continue
        m = BYTES_RECV_RE.search(line)
        if m:
            d["bytes_recv"] = int(m.group(1))
            continue
    return d


def read_iface_bytes(ont, iface: str) -> tuple:
    """(tx_bytes, rx_bytes) from sysfs; (0, 0) if unavailable.

    The AX3200 (XiaoQiang) `iwpriv <if> stat` exposes NO byte counters, so the
    stat-based throughput reads 0. The kernel does keep them in sysfs — read
    both in one telnet round-trip and grab the first two integers (the shell
    echo/prompt is stripped by taking only the digits we asked cat to print).
    # ponytail: this is TOTAL-iface throughput (all traffic on the radio);
    #           per-station goodput would need iperf3 against a known victim.
    """
    try:
        out = ont.run(
            f"cat /sys/class/net/{iface}/statistics/tx_bytes "
            f"/sys/class/net/{iface}/statistics/rx_bytes"
        )
        nums = re.findall(r"\d+", out)
        if len(nums) >= 2:
            return int(nums[0]), int(nums[1])
    except Exception:
        pass
    return 0, 0


def compute_deltas(prev: dict, curr: dict, dt: float) -> dict:
    """Throughput + retry rate between two snapshots, dt seconds apart."""
    bytes_sent_d = max(0, curr["bytes_sent"] - prev["bytes_sent"])
    bytes_recv_d = max(0, curr["bytes_recv"] - prev["bytes_recv"])
    packets_sent_d = max(0, curr["packets_sent"] - prev["packets_sent"])
    packets_recv_d = max(0, curr["packets_recv"] - prev["packets_recv"])
    tx_fail_d = max(0, curr["tx_fail"] - prev["tx_fail"])
    tx_success_d = max(0, curr["tx_success"] - prev["tx_success"])
    denom = tx_success_d + tx_fail_d
    return {
        "throughput_tx_mbps": round(bytes_sent_d * 8 / 1e6 / dt, 3),
        "throughput_rx_mbps": round(bytes_recv_d * 8 / 1e6 / dt, 3),
        "packets_sent_delta": packets_sent_d,
        "packets_recv_delta": packets_recv_d,
        "tx_fail_delta": tx_fail_d,
        "tx_success_delta": tx_success_d,
        "retry_rate": round(tx_fail_d / denom, 4) if denom else 0.0,
    }


def run(args: argparse.Namespace) -> None:
    out_path = Path(args.out)
    is_new = not out_path.exists()
    prev: dict | None = None
    prev_t: float | None = None
    count = 0

    with out_path.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if is_new:
            writer.writeheader()
            f.flush()

        print(f"Logging to {out_path} (label={args.label}, iface={args.iface}, "
              f"interval={args.interval}s). Ctrl+C to stop.")
        try:
            with GN630V(host=args.host, user=args.user, password=args.password) as ont:
                while True:
                    tick_start = time.time()
                    text = ont.run(f"iwpriv {args.iface} stat")
                    parsed = parse_iwpriv_stat(text)
                    tx_b, rx_b = read_iface_bytes(ont, args.iface)
                    if tx_b:
                        parsed["bytes_sent"] = tx_b
                    if rx_b:
                        parsed["bytes_recv"] = rx_b
                    now = time.time()

                    if prev is not None and prev_t is not None:
                        dt = now - prev_t
                        if dt > 0:
                            deltas = compute_deltas(prev, parsed, dt)
                            row = {
                                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S",
                                                          time.localtime(now)),
                                "label": args.label,
                                "iface": args.iface,
                                **parsed,
                                **deltas,
                            }
                            writer.writerow(row)
                            f.flush()
                            print(f"  temp={row['temp_c']}C  rssi={row['rssi0']}dBm  "
                                  f"tput_tx={row['throughput_tx_mbps']}Mbps  "
                                  f"retry={row['retry_rate']}")
                            count += 1
                            if args.count and count >= args.count:
                                break

                    prev = parsed
                    prev_t = now
                    elapsed = time.time() - tick_start
                    time.sleep(max(0.0, args.interval - elapsed))
        except KeyboardInterrupt:
            print("\nStopped.")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    # Defaults target the Xiaomi AX3200 (RB01) 4x4 — the live rig. wl0 = its
    # MT7915 5GHz radio. (Old GN630v ONT was 192.168.0.1/tmadmin/REDACTED/rai1;
    # pass those via flags to poll the GN630v instead.)
    p.add_argument("--host", default="192.168.31.1", help="router host/IP")
    p.add_argument("--user", default="root", help="telnet user")
    p.add_argument("--password", default="REDACTED", help="telnet password")
    p.add_argument("--iface", default="wl0", help="wireless interface (AX3200 5GHz)")
    p.add_argument("--label", required=True, choices=["normal", "attack"],
                    help="Tags every row")
    p.add_argument("--interval", type=float, default=2.0,
                    help="Seconds between polls")
    p.add_argument("--count", type=int, default=None,
                    help="Stop after N samples (default: run until Ctrl+C)")
    p.add_argument("--out", default="gn630v_telemetry.csv",
                    help="CSV output path (appends if exists)")
    run(p.parse_args())


if __name__ == "__main__":
    main()
