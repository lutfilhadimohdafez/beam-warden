#!/usr/bin/env python3
"""OBJ3 offline: BFI-storm pcap + phase timings -> labelled windows -> trained ML.

Feature per time window (default 2s), from the victim's VHT compressed-BF frames:
  bfi_count     : how many BFI frames on air       (spikes under forged injection)
  retry1_count  : how many carry the RETRY=1 bit    (BeamCraft's forgery marker)
  bfi_rate      : bfi_count / window seconds
  retry1_ratio  : retry1_count / bfi_count
Attack windows carry genuine + injected forged BFI, so the counts separate cleanly
from normal. Reports RandomForest 5-fold CV accuracy = the OBJ3 detection number.

No root. Run: .venv/bin/python tools/bfi_features.py --pcap data/bfi_*.pcap --phases data/bfi_*.phases.json
"""
import argparse
import csv
import json
import statistics as st
import subprocess
from collections import Counter
from pathlib import Path

FIELDS = ["bfi_count", "retry1_count", "bfi_rate", "retry1_ratio", "label"]


def sh(c):
    return subprocess.run(c, shell=True, text=True, capture_output=True).stdout


def extract(pcap, victim):
    """(epoch, retry_bit) for every victim VHT compressed-BF frame in the pcap."""
    raw = sh(f"tshark -r {pcap} -Y 'wlan.fixed.category_code==21 && wlan.sa=={victim}' "
             f"-T fields -e frame.time_epoch -e wlan.fc.retry 2>/dev/null")
    out = []
    for ln in raw.splitlines():
        parts = ln.split("\t")
        if parts and parts[0]:
            r = 1 if (len(parts) > 1 and parts[1].strip() in ("1", "True")) else 0
            out.append((float(parts[0]), r))
    return out


def label_at(phases, t):
    for ph in phases:
        if ph["t0"] <= t < ph["t1"]:
            return ph["label"]
    return None


def window(bfi, phases, win):
    """Returns (rows, groups). groups[i] = the phase-id window i came from, so CV
    can hold out whole phases (leak-safe — adjacent 2s windows never straddle the
    train/test split). Flynn audit 2026-10-31: number is unchanged vs shuffled CV,
    but this is the methodology an examiner won't be able to attack."""
    rows, groups = [], []
    t = min(p["t0"] for p in phases)
    end = max(p["t1"] for p in phases)
    while t < end:
        w0, w1 = t, t + win
        mid = (w0 + w1) / 2
        ph = next((p for p in phases if p["t0"] <= mid < p["t1"]), None)
        if ph:
            cnt = sum(1 for bt, _ in bfi if w0 <= bt < w1)
            ret = sum(r for bt, r in bfi if w0 <= bt < w1)
            rows.append({"bfi_count": cnt, "retry1_count": ret,
                         "bfi_rate": cnt / win,
                         "retry1_ratio": (ret / cnt if cnt else 0.0),
                         "label": ph["label"]})
            groups.append(ph["condition"])
        t = w1
    return rows, groups


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pcap", required=True)
    p.add_argument("--phases", required=True)
    p.add_argument("--victim", default="16:0f:02:1d:91:42")
    p.add_argument("--win", type=float, default=2.0)
    p.add_argument("--out", default=None)
    a = p.parse_args()

    phases = json.loads(Path(a.phases).read_text())
    bfi = extract(a.pcap, a.victim)
    rows, groups = window(bfi, phases, a.win)
    if not rows:
        raise SystemExit("no labelled windows — check pcap/phases timestamps align.")

    out = Path(a.out) if a.out else Path(a.pcap).with_suffix(".windows.csv")
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    print(f"victim BFI frames: {len(bfi)}   windows: {len(rows)}  {Counter(r['label'] for r in rows)}")
    for lbl in ("normal", "attack"):
        v = [r["bfi_count"] for r in rows if r["label"] == lbl]
        rt = [r["retry1_count"] for r in rows if r["label"] == lbl]
        if v:
            print(f"  {lbl:7} mean bfi/window={st.mean(v):5.1f}  mean retry1/window={st.mean(rt):5.1f}")
    print(f"csv: {out}")

    # OBJ3 number: GroupKFold by phase (leak-safe — Flynn audit 2026-10-31).
    # Honest framing: the detector is really a threshold on the doubled on-air BFI
    # rate (physics of injection), robust even without the RETRY marker; the RF is
    # just the reported estimator. Within-condition only — cross-condition (other
    # distance/channel/load) is untested future work; don't over-claim at viva.
    labels = sorted({r["label"] for r in rows})
    if len(labels) < 2:
        print("only one class present — need an attack phase that injected. Skipping train.")
        return
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import GroupKFold, cross_val_score
    except ImportError:
        print("(sklearn missing — CSV written; train with train_supervised.py)")
        return
    X = [[r["bfi_count"], r["retry1_count"], r["bfi_rate"], r["retry1_ratio"]] for r in rows]
    y = [1 if r["label"] == "attack" else 0 for r in rows]
    n_groups = len(set(groups))
    if n_groups < 2:
        print("need >=2 phases (groups) for leak-safe CV.")
        return
    k = min(n_groups, 6)
    clf = RandomForestClassifier(n_estimators=200, random_state=0)
    acc = cross_val_score(clf, X, y, groups=groups, cv=GroupKFold(n_splits=k),
                          scoring="accuracy")
    print("\n" + "=" * 60)
    print(f"OBJ3 detection accuracy (GroupKFold by phase, {k} folds): {acc.mean()*100:.1f}%"
          f"  (target >=55%)")
    print(f"  per-fold: {[f'{x*100:.0f}' for x in acc]}")
    print("  note: within-condition (1 capture); cross-condition = future work")
    print("=" * 60)


if __name__ == "__main__":
    main()
