#!/usr/bin/env python3
"""Evaluate a trained Isolation Forest anomaly detector on labelled data."""

import argparse
import os
import sys

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from train_detector import _coerce


def load_features_for(csv_path, features):
    """Load *features* columns from CSV; fail loud if a column is entirely missing."""
    import csv as _csv

    with open(csv_path, newline="") as f:
        reader = _csv.DictReader(f)
        header = reader.fieldnames or []
        missing = [c for c in features if c not in header]
        if missing:
            print(f"ERROR: {csv_path} missing required columns: {missing}", file=sys.stderr)
            sys.exit(1)
        rows = []
        for row in reader:
            rows.append([_coerce(row.get(col)) for col in features])
    return np.array(rows, dtype=np.float64)


def evaluate(model_path, normal_csv, attack_csv):
    bundle = joblib.load(model_path)
    model = bundle["model"]
    scaler = bundle["scaler"]
    features = bundle["features"]

    X_n = load_features_for(normal_csv, features)
    X_a = load_features_for(attack_csv, features)

    y_n = np.zeros(len(X_n), dtype=int)
    y_a = np.ones(len(X_a), dtype=int)
    X = np.vstack([X_n, X_a])
    y = np.concatenate([y_n, y_a])

    X_s = scaler.transform(X)
    raw_preds = model.predict(X_s)
    preds = np.where(raw_preds == -1, 1, 0)
    scores = -model.decision_function(X_s)

    cm = confusion_matrix(y, preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    precision = precision_score(y, preds, zero_division=0)
    recall = recall_score(y, preds, zero_division=0)
    f1 = f1_score(y, preds, zero_division=0)
    accuracy = accuracy_score(y, preds)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    try:
        auc = roc_auc_score(y, scores)
    except ValueError:
        auc = float("nan")

    lines = [
        "=== Detection Evaluation ===",
        f"Normal samples : {len(X_n)}",
        f"Attack samples : {len(X_a)}",
        f"Total samples  : {len(X)}",
        "",
        "--- Confusion Matrix ---",
        f"TN={tn}  FP={fp}  FN={fn}  TP={tp}",
        "",
        "--- Metrics ---",
        f"Precision        : {precision:.4f}",
        f"Recall (TPR)     : {recall:.4f}",
        f"F1 Score         : {f1:.4f}",
        f"Accuracy         : {accuracy:.4f}",
        f"False-Positive Rate (on normal set) : {fpr:.4f} ({fp}/{fp + tn})",
        f"Detection Rate / TPR (on attack set): {tpr:.4f} ({tp}/{tp + fn})",
        f"ROC-AUC          : {auc:.4f}",
    ]
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, help="Path to detector.joblib")
    parser.add_argument("--normal", required=True, help="Path to normal telemetry CSV")
    parser.add_argument("--attack", required=True, help="Path to attack telemetry CSV")
    parser.add_argument("--out", default=None, help="Optional output file path")
    args = parser.parse_args()

    lines = evaluate(args.model, args.normal, args.attack)
    block = "\n".join(lines)
    print(block)

    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w") as f:
            f.write(block + "\n")
        print(f"\nResults written to {args.out}")


if __name__ == "__main__":
    main()
