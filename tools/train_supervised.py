#!/usr/bin/env python3
"""Supervised BFI-attack detector — model bake-off on REAL labelled telemetry.

Replaces the unsupervised IsolationForest (which only learned "one busy-link
fingerprint"). Trains LogisticRegression / RandomForest / GradientBoosting on
real captured telemetry labelled normal|attack, evaluates on a leakage-aware
split, and saves the best by attack-class F1.

    python tools/train_supervised.py --csv data/real_normal_*.csv data/real_attack_*.csv \
        --out models/detector_supervised.joblib

Honest guards:
  * refuses to train unless BOTH classes (normal AND attack) are present — no
    one-class bogus model, no synthetic fill.
  * groups the train/test split by capture session/condition so adjacent
    autocorrelated 2 s samples don't leak across the split.
  * reports attack precision/recall/F1 + ROC-AUC + confusion (never bare
    accuracy — a trivial "always normal" model scores high and catches nothing).

ponytail: csv + numpy (no pandas — not installed); sklearn Pipeline so the
scaler is fit on train only.
"""
import argparse
import csv
import glob
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

FEATURES = [
    "throughput_tx_mbps", "throughput_rx_mbps", "retry_rate",
    "tx_per_pct", "rx_per_pct",
    "rssi0", "rssi1", "rssi2", "rssi3", "tx_mcs", "tx_nss",
]


def _f(v) -> float:
    """Coerce a CSV cell to float; empty/None -> 0.0 (e.g. mcs when no rate)."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def load_rows(paths: list[str]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Read labelled CSVs -> (X[n,11], y[n] {0,1}, groups[n]).

    y = 1 iff label contains 'attack'. group = f"{file}:{condition}" so a whole
    condition-segment goes wholly to train or test (no temporal leakage).
    """
    X, y, groups = [], [], []
    for path in paths:
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                missing = [k for k in FEATURES if k not in r]
                if missing:
                    sys.exit(f"{path}: missing feature columns {missing}")
                X.append([_f(r[k]) for k in FEATURES])
                y.append(1 if "attack" in (r.get("label", "")).lower() else 0)
                groups.append(f"{Path(path).name}:{r.get('condition', '')}")
    return np.array(X, float), np.array(y, int), np.array(groups)


def evaluate(name, clf, Xtr, ytr, Xte, yte) -> dict:
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)
    try:
        proba = clf.predict_proba(Xte)[:, 1]
        auc = roc_auc_score(yte, proba) if len(set(yte)) > 1 else float("nan")
    except Exception:
        auc = float("nan")
    return {
        "name": name, "clf": clf,
        "precision": precision_score(yte, pred, zero_division=0),
        "recall": recall_score(yte, pred, zero_division=0),
        "f1": f1_score(yte, pred, zero_division=0),
        "roc_auc": auc,
        "confusion": confusion_matrix(yte, pred).tolist(),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", nargs="+", required=True,
                   help="labelled telemetry CSV(s); globs ok")
    p.add_argument("--out", default="models/detector_supervised.joblib")
    p.add_argument("--test-size", type=float, default=0.3)
    p.add_argument("--seed", type=int, default=42)
    a = p.parse_args()

    paths = sorted({f for pat in a.csv for f in glob.glob(pat)})
    if not paths:
        sys.exit(f"no CSVs matched: {a.csv}")
    X, y, groups = load_rows(paths)
    n_norm, n_att = int((y == 0).sum()), int((y == 1).sum())
    print(f"loaded {len(y)} rows from {len(paths)} file(s): "
          f"normal={n_norm} attack={n_att}  features={len(FEATURES)}")

    if n_norm == 0 or n_att == 0:
        have = "normal" if n_att == 0 else "attack"
        sys.exit(f"REFUSING to train: only '{have}' rows present. Supervised "
                 f"training needs BOTH normal AND attack captures. (This is the "
                 f"honest guard — capture the real attack first.)")

    # leakage-aware split: whole condition-segments to one side
    n_groups = len(set(groups))
    if n_groups >= 2:
        gss = GroupShuffleSplit(n_splits=1, test_size=a.test_size, random_state=a.seed)
        tr, te = next(gss.split(X, y, groups))
    else:  # single segment -> fall back to a plain split (note it)
        print("WARN: one group only — using a random split (capture more "
              "conditions/sessions for a leakage-safe eval).")
        idx = np.arange(len(y)); rng = np.random.default_rng(a.seed); rng.shuffle(idx)
        cut = int(len(idx) * (1 - a.test_size)); tr, te = idx[:cut], idx[cut:]
    Xtr, Xte, ytr, yte = X[tr], X[te], y[tr], y[te]
    if len(set(ytr)) < 2 or len(set(yte)) < 2:
        print("WARN: a split lacks both classes — metrics may be degenerate; "
              "capture more balanced data across conditions.")

    models = {
        "logreg": Pipeline([("sc", StandardScaler()),
                            ("clf", LogisticRegression(max_iter=1000,
                                                       class_weight="balanced"))]),
        "rf": Pipeline([("sc", StandardScaler()),
                        ("clf", RandomForestClassifier(n_estimators=200,
                                                       class_weight="balanced",
                                                       random_state=a.seed))]),
        "gbm": Pipeline([("sc", StandardScaler()),
                         ("clf", GradientBoostingClassifier(random_state=a.seed))]),
    }
    results = [evaluate(n, m, Xtr, ytr, Xte, yte) for n, m in models.items()]
    results.sort(key=lambda r: (r["f1"], r["recall"]), reverse=True)

    print(f"\n{'model':8} {'precision':>9} {'recall':>7} {'f1':>6} {'roc_auc':>8}  confusion[[TN,FP],[FN,TP]]")
    for r in results:
        print(f"{r['name']:8} {r['precision']:9.3f} {r['recall']:7.3f} "
              f"{r['f1']:6.3f} {r['roc_auc']:8.3f}  {r['confusion']}")

    best = results[0]
    print(f"\nBEST: {best['name']}  (attack-F1={best['f1']:.3f})")
    out = Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": best["clf"], "features": FEATURES, "kind": best["name"],
        "metrics": {k: best[k] for k in ("precision", "recall", "f1", "roc_auc", "confusion")},
        "trained_on": paths, "n_normal": n_norm, "n_attack": n_att,
    }, out)
    print(f"saved {best['name']} -> {out}")


if __name__ == "__main__":
    main()
