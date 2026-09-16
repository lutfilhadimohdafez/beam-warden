#!/usr/bin/env python3
"""Generate LABELED synthetic attack BFI features from real pcap data.

Takes real normal BFI frames (from a pcap) and produces synthetic ATTACK BFI
features that mimic a BeamCraft null-steer forge, so the detector can be
trained/validated before the 4x4 AP arrives.

Method: perturb at the ANGLE-MATRIX level (decode → perturb → recompute
features), not at the feature-column level.  More physically defensible.

WARNING: Synthetic attack BFI validates the pipeline, NOT real-world accuracy.
That still needs real attack telemetry from the 4x4 AP.  Label results
accordingly.

Requires: tshark.  stdlib + numpy only (reuses bfi_features decoder).
"""

from __future__ import annotations

import argparse
import csv
import sys
from typing import Dict, List

import numpy as np

from bfi_features import (
    FEATURE_COLUMNS,
    _all_frame_bytes,
    _mimo_and_report,
    _meta_rows,
    compute_NANG,
    decode_angles,
    get_bitwidths,
)


def perturb_angles(
    angles: np.ndarray,
    is_phi: List[bool],
    severity: float,
    rng: np.random.Generator,
) -> np.ndarray:
    """Forge-like perturbation emulating a BeamCraft null-steer attack.

    Three perturbation axes (all scaled by --severity):
    1. Null-steer: push psi toward a BOUNDARY (near 0 or near 0.5) to
       collapse a stream, INCREASING angle spread.
    2. Break subcarrier coherence: inject strong per-subcarrier
       randomization so bfi_subcarrier_var rises well above normal.
    3. Inflate phi variance with per-subcarrier noise.

    Args:
        angles: (NANG, Nst) angle matrix from decode_angles.
        is_phi: per-angle boolean mask (True=phi, False=psi).
        severity: attack intensity multiplier (default 1.0).
        rng: numpy random generator for reproducibility.

    Returns:
        Perturbed angles array, same shape, clamped to valid ranges.
        phi in (0, 2), psi in (0, 0.5).
    """
    pa = angles.copy()
    phi_mask = np.array(is_phi, dtype=bool)
    psi_mask = ~phi_mask
    nang, nst = pa.shape
    eps = 1e-6

    # 1. Null-steer: push psi HARD toward a boundary (0 or 0.5).
    #    Collapses a stream → INCREASES psi spread across the matrix.
    if np.any(psi_mask):
        psi_vals = pa[psi_mask]
        targets = rng.choice([eps, 0.5 - eps], size=psi_vals.shape)
        strength = np.clip(severity * 0.98, 0.0, 1.0)
        pa[psi_mask] = psi_vals + strength * (targets - psi_vals)

    # 2. Inflate phi: scale UP toward upper boundary, then add per-subcarrier
    #    noise.  Scaling changes both mean AND variance together.
    if np.any(phi_mask):
        phi_scale = 1.0 + severity * 0.8   # at sev=1 → multiply by 1.8
        pa[phi_mask] *= phi_scale

    # 3. Break subcarrier coherence: heavy per-subcarrier randomization
    #    so bfi_subcarrier_var spikes well above normal.
    if nst > 1:
        for row in range(nang):
            pa[row] += rng.normal(0, severity * 0.4, size=nst)

    # 4. Alternating kick on phi to destroy subcarrier smoothness
    if np.any(phi_mask) and nst > 1:
        for row in np.where(phi_mask)[0]:
            pa[row] += severity * 0.4 * rng.choice([-1.0, 1.0], size=nst)

    # Clamp to valid ranges: phi in (0, 2), psi in (0, 0.5)
    if np.any(phi_mask):
        pa[phi_mask] = np.clip(pa[phi_mask], eps, 2.0 - eps)
    if np.any(psi_mask):
        pa[psi_mask] = np.clip(pa[psi_mask], eps, 0.5 - eps)

    return pa


def _compute_row(
    angles: np.ndarray,
    is_phi_mask: List[bool],
    phi_history: List[float],
    psi_history: List[float],
    fn: int,
    nr: int,
    nc: int,
    nst: int,
    nang: int,
    window: int,
    label: int,
) -> Dict[str, float | int]:
    """Compute a single feature row from an angle matrix."""
    phi_mask = np.array(is_phi_mask, dtype=bool)
    psi_mask = ~phi_mask

    phi_mean = float(np.mean(angles[phi_mask])) if np.any(phi_mask) else 0.0
    psi_mean = float(np.mean(angles[psi_mask])) if np.any(psi_mask) else 0.0

    phi_history.append(phi_mean)
    psi_history.append(psi_mean)

    if len(phi_history) >= window:
        phi_temp_var = float(np.var(phi_history[-window:]))
        psi_temp_var = float(np.var(psi_history[-window:]))
    else:
        phi_temp_var = 0.0
        psi_temp_var = 0.0

    return {
        "frame": fn,
        "nr": nr,
        "nc": nc,
        "nst": nst,
        "nang": nang,
        "bfi_phi_mean": phi_mean,
        "bfi_psi_mean": psi_mean,
        "bfi_angle_var": float(np.var(angles)),
        "bfi_subcarrier_var": float(np.mean(np.var(angles, axis=1))),
        "bfi_phi_temporal_var": phi_temp_var,
        "bfi_psi_temporal_var": psi_temp_var,
        "label": label,
    }


def extract_normal_and_attack_features(
    pcap: str,
    severity: float = 1.0,
    window: int = 10,
) -> tuple[List[Dict[str, float | int]], List[Dict[str, float | int]]]:
    """Decode all HE BFI frames, compute normal features, then generate
    perturbed attack features from the same angle matrices."""
    rows = _meta_rows(pcap)
    if not rows:
        return [], []

    fb_cache = _all_frame_bytes(pcap, frame_numbers=[r[0] for r in rows])

    normal_features: List[Dict[str, float | int]] = []
    attack_features: List[Dict[str, float | int]] = []

    phi_history_n: List[float] = []
    psi_history_n: List[float] = []
    phi_history_a: List[float] = []
    psi_history_a: List[float] = []

    all_perturbed_angles: List[np.ndarray] = []
    all_is_phi: List[List[bool]] = []

    rng = np.random.default_rng(42)

    for fn, mc_hex, rl in rows:
        info = _mimo_and_report(pcap, fn, mc_hex, rl, frame_bytes_cache=fb_cache)
        Nr = int(info["nr"])
        Nc = int(info["nc"])
        report = info["report"]
        assert isinstance(report, bytes)

        if not report:
            continue

        b_phi, b_psi = get_bitwidths(int(info["feedback_type"]), int(info["codebook"]))
        angles, is_phi_mask, Nst = decode_angles(report, Nr, Nc, b_phi, b_psi)

        if Nst == 0:
            continue

        NANG = compute_NANG(Nr, Nc)

        normal_features.append(_compute_row(
            angles, is_phi_mask,
            phi_history_n, psi_history_n,
            int(fn), Nr, Nc, Nst, NANG, window, label=0,
        ))

        pa = perturb_angles(angles, is_phi_mask, severity, rng)
        all_perturbed_angles.append(pa)
        all_is_phi.append(is_phi_mask)
        attack_features.append(_compute_row(
            pa, is_phi_mask,
            phi_history_a, psi_history_a,
            int(fn), Nr, Nc, Nst, NANG, window, label=1,
        ))

    # Store for self-check in main()
    extract_normal_and_attack_features._perturbed = all_perturbed_angles  # type: ignore[attr-defined]
    extract_normal_and_attack_features._is_phi = all_is_phi  # type: ignore[attr-defined]

    return normal_features, attack_features


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True, help="Input pcap with HE BFI frames")
    parser.add_argument("--out", default="data/bfi_synthetic_attack.csv", help="Output CSV path")
    parser.add_argument("--severity", type=float, default=1.0, help="Attack severity multiplier")
    parser.add_argument("--window", type=int, default=10, help="Rolling window for temporal variance")
    args = parser.parse_args()

    normal, attack = extract_normal_and_attack_features(
        args.pcap, severity=args.severity, window=args.window,
    )

    if not normal:
        print("No HE BFI frames found.", file=sys.stderr)
        sys.exit(1)

    out_fields = FEATURE_COLUMNS + ["label"]

    import os
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=out_fields)
        writer.writeheader()
        writer.writerows(normal)
        writer.writerows(attack)

    # Mean feature deltas
    feature_keys = FEATURE_COLUMNS[5:]  # skip frame/nr/nc/nst/nang
    deltas = {}
    for k in feature_keys:
        n_mean = np.mean([r[k] for r in normal])
        a_mean = np.mean([r[k] for r in attack])
        deltas[k] = a_mean - n_mean

    print(f"{len(normal)} normal + {len(attack)} attack rows -> {args.out}")
    print(f"severity={args.severity}")
    print("Mean feature deltas (attack - normal):")
    for k, v in deltas.items():
        n_mean = np.mean([r[k] for r in normal])
        a_mean = np.mean([r[k] for r in attack])
        print(f"  {k}: {n_mean:.6f} -> {a_mean:.6f}  (delta={v:+.6f})")

    # --- Self-check: IsolationForest detection rate ---
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    feat_keys = FEATURE_COLUMNS[5:]  # skip frame/nr/nc/nst/nang
    X_normal = np.array([[r[k] for k in feat_keys] for r in normal])
    X_attack = np.array([[r[k] for k in feat_keys] for r in attack])

    scaler = StandardScaler().fit(X_normal)
    Xn_s = scaler.transform(X_normal)
    Xa_s = scaler.transform(X_attack)

    iso = IsolationForest(
        n_estimators=200, contamination=0.02, random_state=42,
    ).fit(Xn_s)

    n_pred = iso.predict(Xn_s)
    a_pred = iso.predict(Xa_s)
    detection_rate = np.mean(a_pred == -1)
    fp_rate = np.mean(n_pred == -1)

    print(f"IsolationForest detection rate on attack: {detection_rate:.1%} "
          f"(false positive on normal: {fp_rate:.1%})")
    assert detection_rate >= 0.80, (
        f"Detection rate {detection_rate:.1%} < 80% at severity={args.severity}"
    )
    print(f"[SELF-CHECK PASS] Detection rate {detection_rate:.1%} >= 80%.")

    # 2. All perturbed angle values remain in valid ranges
    for pa, is_phi in zip(
        extract_normal_and_attack_features._perturbed,
        extract_normal_and_attack_features._is_phi,
    ):
        phi_mask = np.array(is_phi, dtype=bool)
        psi_mask = ~phi_mask
        if np.any(phi_mask):
            assert np.all(pa[phi_mask] > 0) and np.all(pa[phi_mask] < 2), (
                f"phi out of (0,2): min={pa[phi_mask].min()}, max={pa[phi_mask].max()}"
            )
        if np.any(psi_mask):
            assert np.all(pa[psi_mask] > 0) and np.all(pa[psi_mask] < 0.5), (
                f"psi out of (0,0.5): min={pa[psi_mask].min()}, max={pa[psi_mask].max()}"
            )
    print("[SELF-CHECK PASS] All perturbed angles in valid (0,2)/(0,0.5) range.")

    # 3. Output CSV columns match FEATURE_COLUMNS + label
    out_cols = FEATURE_COLUMNS + ["label"]
    assert out_fields == out_cols, f"CSV columns mismatch: {out_fields} != {out_cols}"
    print("[SELF-CHECK PASS] CSV columns match FEATURE_COLUMNS + label.")


if __name__ == "__main__":
    main()
