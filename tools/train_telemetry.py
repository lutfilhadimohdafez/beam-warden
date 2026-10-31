#!/usr/bin/env python3
"""OBJ3 engine (adapter-free): train an anomaly detector on the ROUTER's own
`iw station dump` telemetry, using SELF-CALIBRATED (relative-to-baseline) features
so one trained model can transfer to a network it never saw.

Per network/run we learn a baseline from its NORMAL samples, then every sample
becomes a *relative* feature vector (ratio / z-score vs that baseline). A 60%
retry jump reads the same whether the baseline is 0.1 or 0.6 -> network-independent.

Honest evaluation = GroupKFold by RUN: hold out a whole capture run, train on the
others, test on the unseen run. That is the number that answers "does it work for
anybody else", not within-one-run CV.

No root, no adapter. Run:
  .venv/bin/python tools/train_telemetry.py data/obj1_*.csv data/real_aba_*.csv ...
"""
import argparse
import csv
import statistics as st
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

# raw metrics read from the telemetry CSV; direction = does attack raise(+1)/lower(-1) it
METRICS = ["retry_rate", "tx_per_pct", "rx_per_pct", "throughput_tx_mbps", "rssi"]
EPS = 1e-6


def _f(row, key):
    v = row.get(key, "")
    if v in ("", "None", None):
        return None
    try:
        return float(v)
    except ValueError:
        return None


def _rssi(row):
    vals = [_f(row, f"rssi{i}") for i in range(4)]
    vals = [v for v in vals if v is not None]
    return st.mean(vals) if vals else None


def load_run(path):
    """Return (rows, baseline) for one capture run. baseline = per-metric (mean,std)
    from the run's NORMAL samples — i.e. what on-box `calibrate` would learn."""
    rows = []
    for r in csv.DictReader(open(path)):
        rec = {m: (_rssi(r) if m == "rssi" else _f(r, m)) for m in METRICS}
        rec["label"] = 1 if r.get("label") == "attack" else 0
        rows.append(rec)
    base = {}
    for m in METRICS:
        norm = [r[m] for r in rows if r["label"] == 0 and r[m] is not None]
        base[m] = (st.mean(norm), (st.pstdev(norm) if len(norm) > 1 else 0.0)) if norm else (0.0, 0.0)
    return rows, base


def relative(rec, base):
    """Self-calibrated feature vector: ratio + z vs this run's baseline."""
    feat = []
    for m in METRICS:
        mean, std = base[m]
        v = rec[m] if rec[m] is not None else mean
        feat.append(v / (mean + EPS))                 # ratio (1.0 = at baseline)
        feat.append((v - mean) / (std + EPS))         # z-score
    return feat


FEAT_NAMES = [f"{m}_{k}" for m in METRICS for k in ("ratio", "z")]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csvs", nargs="+", help="labelled telemetry CSVs, one per run")
    ap.add_argument("--export", default=None, help="write trained model JSON here")
    a = ap.parse_args()

    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import GroupKFold, cross_val_score, LeaveOneGroupOut

    X, y, groups, run_names = [], [], [], []
    for gi, path in enumerate(a.csvs):
        rows, base = load_run(path)
        n_atk = sum(r["label"] for r in rows)
        run_names.append(f"{Path(path).name} (atk={n_atk}/{len(rows)})")
        for r in rows:
            X.append(relative(r, base)); y.append(r["label"]); groups.append(gi)

    n_runs = len(a.csvs)
    n_atk_runs = len({g for g, lab in zip(groups, y) if lab == 1})
    print(f"runs: {n_runs}  samples: {len(y)}  attack: {sum(y)}  normal: {len(y)-sum(y)}")
    for rn in run_names:
        print(f"  - {rn}")

    clf = RandomForestClassifier(n_estimators=300, random_state=0, class_weight="balanced")

    # HONEST number: leave-one-RUN-out (generalisation to an unseen capture)
    if n_runs >= 2:
        acc = cross_val_score(clf, X, y, groups=groups, cv=LeaveOneGroupOut(), scoring="accuracy")
        print("\n" + "=" * 62)
        print(f"OBJ3 leave-one-RUN-out accuracy: {acc.mean()*100:.1f}%  (target >=55%)")
        print(f"  per-held-out-run: {[f'{x*100:.0f}' for x in acc]}")
        print("  ^ this is the 'works on a network it never saw' number")
        print("=" * 62)

    clf.fit(X, y)
    imp = sorted(zip(FEAT_NAMES, clf.feature_importances_), key=lambda t: -t[1])
    print("top features:", ", ".join(f"{f}={i:.2f}" for f, i in imp[:6] if i > 0.02))

    if a.export:
        import json
        Path(a.export).write_text(json.dumps({
            "metrics": METRICS, "feat_names": FEAT_NAMES,
            "note": "deploy: calibrate baseline (mean,std) per metric on-box, "
                    "build relative features, score with this forest",
        }, indent=2))
        print(f"model meta -> {a.export}  (forest export to tree-walk = TODO for .ipk)")


if __name__ == "__main__":
    main()
