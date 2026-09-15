#!/usr/bin/env python3
"""Train an Isolation Forest anomaly detector on NORMAL WiFi telemetry only.

The model will later flag attack telemetry as anomalous.
"""

import argparse
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import csv

FEATURES = [
    "throughput_tx_mbps",
    "throughput_rx_mbps",
    "retry_rate",
    "tx_per_pct",
    "rx_per_pct",
    "rssi0",
    "rssi1",
    "rssi2",
    "rssi3",
    "tx_mcs",
    "tx_nss",
]


def _coerce(val):
    """Convert a cell to float; return 0.0 for empty/None/non-numeric."""
    if val is None or val == "":
        return 0.0
    try:
        return float(val)
    except (ValueError, TypeError):
        return 0.0


def load_features(csv_path):
    """Load FEATURES columns from a CSV into a numpy array."""
    rows = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append([_coerce(row.get(col)) for col in FEATURES])
    return np.array(rows, dtype=np.float64)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", default="data/normal_iperf.csv", help="Path to normal telemetry CSV")
    parser.add_argument("--out", default="models/detector.joblib", help="Output model path")
    parser.add_argument("--contamination", type=float, default=0.02, help="IsolationForest contamination")
    args = parser.parse_args()

    X = load_features(args.csv)
    n_samples, n_features = X.shape

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iforest = IsolationForest(
        n_estimators=200,
        contamination=args.contamination,
        random_state=42,
    )
    iforest.fit(X_scaled)

    predictions = iforest.predict(X_scaled)
    fp_rate = np.mean(predictions == -1)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump({"model": iforest, "scaler": scaler, "features": FEATURES}, args.out)

    print(f"Trained on {n_samples} samples, {n_features} features")
    print(f"Training false-positive rate: {fp_rate:.4f} ({int(fp_rate * n_samples)}/{n_samples})")
    print(f"Model saved to {args.out}")


if __name__ == "__main__":
    main()
