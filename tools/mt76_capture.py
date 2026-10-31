#!/usr/bin/env python3
"""Capture REAL mt76 PHY telemetry from an OpenWrt AP to a labelled CSV.

Polls `iw dev <iface> station dump` over SSH every --interval s, computes
throughput/retry deltas (via gn630v_telemetry.compute_deltas), writes one
labelled row per tick. Real hardware only — NO synthesis. Appends if the CSV
already exists, so multi-condition sessions share one file.

    python tools/mt76_capture.py --label normal --condition idle --duration 60 \
        --out data/real_normal.csv

ponytail: thin loop over the mt76 adapter; no new deps.
"""
import argparse
import csv
import time
from pathlib import Path

from mt76_telemetry import SSHConn, parse_iw_station_dump
from gn630v_telemetry import compute_deltas
from rig import RIG  # rig.conf creds, not hardcoded

FIELDS = [
    "timestamp", "label", "condition",
    "throughput_tx_mbps", "throughput_rx_mbps", "retry_rate",
    "tx_per_pct", "rx_per_pct",
    "rssi0", "rssi1", "rssi2", "rssi3", "tx_mcs", "tx_nss",
    # raw counters kept for re-derivation / provenance
    "bytes_sent", "bytes_recv", "packets_sent", "packets_recv", "tx_fail",
]


def run(a: argparse.Namespace) -> None:
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    is_new = not out.exists()
    prev = prev_t = None
    n = 0
    with SSHConn(a.host, a.user, a.password) as c, out.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if is_new:
            w.writeheader()
            f.flush()
        end = time.time() + a.duration if a.duration else None
        print(f"capture: label={a.label} condition={a.condition} iface={a.iface} "
              f"-> {out}")
        while True:
            t0 = time.time()
            cur = parse_iw_station_dump(c.run(f"iw dev {a.iface} station dump"))
            now = time.time()
            if prev is not None and prev_t is not None:
                dt = now - prev_t
                d = compute_deltas(prev, cur, dt) if dt > 0 else {}
                if d:
                    row = {
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S",
                                                   time.localtime(now)),
                        "label": a.label, "condition": a.condition,
                        "throughput_tx_mbps": d["throughput_tx_mbps"],
                        "throughput_rx_mbps": d["throughput_rx_mbps"],
                        "retry_rate": d["retry_rate"],
                        "tx_per_pct": cur["tx_per_pct"], "rx_per_pct": cur["rx_per_pct"],
                        "rssi0": cur["rssi0"], "rssi1": cur["rssi1"],
                        "rssi2": cur["rssi2"], "rssi3": cur["rssi3"],
                        "tx_mcs": cur["tx_mcs"], "tx_nss": cur["tx_nss"],
                        "bytes_sent": cur["bytes_sent"], "bytes_recv": cur["bytes_recv"],
                        "packets_sent": cur["packets_sent"],
                        "packets_recv": cur["packets_recv"], "tx_fail": cur["tx_fail"],
                    }
                    w.writerow(row)
                    f.flush()
                    n += 1
                    print(f"  [{a.condition}] dTXtput={row['throughput_tx_mbps']:>6} "
                          f"dRXtput={row['throughput_rx_mbps']:>6} Mbps  "
                          f"retry={row['retry_rate']}  rssi0={row['rssi0']}  "
                          f"mcs={row['tx_mcs']}")
            prev, prev_t = cur, now
            if a.count and n >= a.count:
                break
            if end and time.time() >= end:
                break
            time.sleep(max(0.0, a.interval - (time.time() - t0)))
    print(f"wrote {n} rows to {out}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default=RIG["ROUTER_HOST"])
    p.add_argument("--user", default=RIG["ROUTER_USER"])
    p.add_argument("--password", default=RIG["ROUTER_PASS"])
    p.add_argument("--iface", default=RIG["ROUTER_AP_IFACE"])
    p.add_argument("--label", default="normal")
    p.add_argument("--condition", default="unknown")
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--duration", type=float, default=0.0, help="seconds (0 = use --count)")
    p.add_argument("--count", type=int, default=0, help="stop after N rows (0 = use --duration)")
    p.add_argument("--out", default="data/real_capture.csv")
    run(p.parse_args())


if __name__ == "__main__":
    main()
