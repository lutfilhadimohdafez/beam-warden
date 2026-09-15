#!/usr/bin/env python3
"""Generate SIMULATED attack telemetry for pipeline demo purposes.

WARNING: This is SYNTHETIC/simulated data derived from the normal baseline,
NOT a real attack capture.  Use only for testing the detector + dashboard
pipeline before real BeamCraft attack data is available.
"""

import argparse
import csv
import os
import random

import numpy as np


def main():
    # ---- this is SYNTHETIC data ----
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normal", default="data/normal_iperf.csv", help="Normal telemetry CSV")
    parser.add_argument("--out", default="data/synthetic_attack.csv", help="Output CSV path")
    parser.add_argument("--normal-rows", type=int, default=50, help="Number of normal rows to copy")
    parser.add_argument("--attack-rows", type=int, default=100, help="Number of attack rows to generate")
    args = parser.parse_args()

    random.seed(42)
    rng = np.random.default_rng(42)

    with open(args.normal, newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        all_rows = list(reader)

    if not fieldnames or not all_rows:
        print("Error: normal CSV is empty or has no header")
        return

    has_label = "label" in fieldnames
    out_fields = fieldnames if has_label else fieldnames + ["label"]

    n_copy = min(args.normal_rows, len(all_rows))
    normal_rows = [dict(r) for r in all_rows[:n_copy]]
    for r in normal_rows:
        if not has_label:
            r["label"] = "normal"

    attack_rows = []
    for i in range(args.attack_rows):
        src = dict(all_rows[i % len(all_rows)])
        jitter = lambda: 1.0 + random.uniform(-0.05, 0.05)

        def to_float(val, default=0.0):
            try:
                return float(val)
            except (ValueError, TypeError):
                return default

        src["throughput_tx_mbps"] = str(to_float(src.get("throughput_tx_mbps")) * 0.20 * jitter())
        src["throughput_rx_mbps"] = str(to_float(src.get("throughput_rx_mbps")) * 0.20 * jitter())
        src["tx_per_pct"] = str(min(100, to_float(src.get("tx_per_pct")) * 3 + 20) * jitter())
        src["rx_per_pct"] = str(min(100, to_float(src.get("rx_per_pct")) * 3 + 10) * jitter())
        src["retry_rate"] = str(min(1.0, to_float(src.get("retry_rate")) * 4 + 0.2) * jitter())
        src["tx_mcs"] = str(max(0, to_float(src.get("tx_mcs")) - 4 + random.uniform(-0.5, 0.5)))
        for rssi_col in ("rssi0", "rssi1", "rssi2", "rssi3"):
            src[rssi_col] = str(to_float(src.get(rssi_col)) - 6 + random.uniform(-1, 1))
        src["label"] = "attack"
        attack_rows.append(src)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=out_fields)
        writer.writeheader()
        writer.writerows(normal_rows)
        writer.writerows(attack_rows)

    print(f"Wrote {n_copy} normal + {args.attack_rows} attack rows to {args.out}")


if __name__ == "__main__":
    main()
