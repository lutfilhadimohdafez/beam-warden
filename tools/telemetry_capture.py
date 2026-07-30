#!/usr/bin/env python3
"""Poll a router's `iw station dump` over SSH and log RSSI/MCS/throughput/retry
telemetry per connected client to CSV — the dataset for Objective 2.

ponytail: shells out to the system `ssh` binary (already used throughout this
project) instead of adding paramiko as a new dependency.
"""
import argparse
import csv
import re
import subprocess
import sys
import time
from pathlib import Path

STATION_RE = re.compile(r"^Station ([0-9A-Fa-f:]{17})")
RATE_MCS_RE = re.compile(r"([\d.]+) MBit/s.*?MCS (\d+)")
LEAD_INT_RE = re.compile(r"-?\d+")

CSV_FIELDS = [
    "timestamp", "label", "mac", "rssi_dbm", "rssi_avg_dbm",
    "tx_mcs", "rx_mcs", "tx_rate_mbps", "rx_rate_mbps",
    "throughput_tx_mbps", "throughput_rx_mbps",
    "tx_packets_delta", "tx_retries_delta", "retry_rate",
]


def parse_station_dump(text: str) -> list[dict]:
    """Parse `iw dev <iface> station dump` output into one dict per client."""
    stations = []
    current: dict | None = None
    for line in text.splitlines():
        m = STATION_RE.match(line)
        if m:
            current = {"mac": m.group(1)}
            stations.append(current)
            continue
        if current is None or ":" not in line:
            continue
        key, _, value = line.strip().partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "signal":
            current["rssi_dbm"] = int(LEAD_INT_RE.match(value).group())
        elif key == "signal avg":
            current["rssi_avg_dbm"] = int(LEAD_INT_RE.match(value).group())
        elif key == "rx bytes":
            current["rx_bytes"] = int(value)
        elif key == "tx bytes":
            current["tx_bytes"] = int(value)
        elif key == "tx packets":
            current["tx_packets"] = int(value)
        elif key == "tx retries":
            current["tx_retries"] = int(value)
        elif key == "tx bitrate":
            rm = RATE_MCS_RE.search(value)
            if rm:
                current["tx_rate_mbps"] = float(rm.group(1))
                current["tx_mcs"] = int(rm.group(2))
        elif key == "rx bitrate":
            rm = RATE_MCS_RE.search(value)
            if rm:
                current["rx_rate_mbps"] = float(rm.group(1))
                current["rx_mcs"] = int(rm.group(2))
    return stations


def compute_deltas(prev: dict, curr: dict, dt: float) -> dict:
    """Throughput + retry rate between two snapshots of the same client, dt seconds apart."""
    tx_bytes_d = max(0, curr["tx_bytes"] - prev["tx_bytes"])
    rx_bytes_d = max(0, curr["rx_bytes"] - prev["rx_bytes"])
    tx_packets_d = max(0, curr["tx_packets"] - prev["tx_packets"])
    tx_retries_d = max(0, curr["tx_retries"] - prev["tx_retries"])
    return {
        "throughput_tx_mbps": round(tx_bytes_d * 8 / 1e6 / dt, 3),
        "throughput_rx_mbps": round(rx_bytes_d * 8 / 1e6 / dt, 3),
        "tx_packets_delta": tx_packets_d,
        "tx_retries_delta": tx_retries_d,
        "retry_rate": round(tx_retries_d / tx_packets_d, 4) if tx_packets_d else 0.0,
    }


def ssh_station_dump(host: str, user: str, iface: str) -> str:
    try:
        result = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"{user}@{host}",
             f"iw dev {iface} station dump"],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        print("ssh timed out", file=sys.stderr)
        return ""
    if result.returncode != 0:
        print(f"ssh failed: {result.stderr.strip()}", file=sys.stderr)
        return ""
    return result.stdout


def run(args: argparse.Namespace) -> None:
    out_path = Path(args.out)
    is_new = not out_path.exists()
    prev: dict[str, tuple[float, dict]] = {}
    deadline = time.time() + args.duration if args.duration else None

    with out_path.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if is_new:
            writer.writeheader()
            f.flush()

        print(f"Logging to {out_path} (label={args.label}, interval={args.interval}s). Ctrl+C to stop.")
        try:
            while deadline is None or time.time() < deadline:
                tick_start = time.time()
                stations = parse_station_dump(ssh_station_dump(args.host, args.user, args.iface))
                now = time.time()
                for st in stations:
                    mac = st["mac"]
                    if mac in prev:
                        prev_t, prev_st = prev[mac]
                        dt = now - prev_t
                        if dt > 0:
                            row = {
                                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)),
                                "label": args.label,
                                "mac": mac,
                                "rssi_dbm": st.get("rssi_dbm"),
                                "rssi_avg_dbm": st.get("rssi_avg_dbm"),
                                "tx_mcs": st.get("tx_mcs"),
                                "rx_mcs": st.get("rx_mcs"),
                                "tx_rate_mbps": st.get("tx_rate_mbps"),
                                "rx_rate_mbps": st.get("rx_rate_mbps"),
                                **compute_deltas(prev_st, st, dt),
                            }
                            writer.writerow(row)
                            f.flush()
                            print(f"  {mac}  rssi={row['rssi_dbm']}dBm  "
                                  f"tput_tx={row['throughput_tx_mbps']}Mbps  retry={row['retry_rate']}")
                    prev[mac] = (now, st)
                elapsed = time.time() - tick_start
                time.sleep(max(0.0, args.interval - elapsed))
        except KeyboardInterrupt:
            print("\nStopped.")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True, help="Router SSH host/IP")
    p.add_argument("--user", default="root", help="SSH user (default: root)")
    p.add_argument("--iface", required=True, help="Wireless interface, e.g. wlan0")
    p.add_argument("--label", required=True, choices=["normal", "attack"],
                    help="Tags every row — run once per state to build the comparison dataset")
    p.add_argument("--interval", type=float, default=2.0, help="Seconds between polls (default: 2)")
    p.add_argument("--duration", type=float, default=None, help="Stop after N seconds (default: run until Ctrl+C)")
    p.add_argument("--out", default="telemetry.csv", help="CSV output path (appends if it exists)")
    run(p.parse_args())


if __name__ == "__main__":
    main()
