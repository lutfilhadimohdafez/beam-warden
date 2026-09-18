# TASK (QUEUED #3): Synthetic attack BFI generator

DEPENDS ON: tools/bfi_features.py (task #1). Reuse its decoder to get real angle
matrices; do NOT reimplement decoding. Mirror the existing
tools/make_synthetic_attack.py in style/CLI.

You are Flynn. Build `tools/make_synthetic_bfi_attack.py`: take REAL normal BFI
(from data/bfi_he_capture.pcap) and produce LABELED synthetic ATTACK BFI features
that mimic a BeamCraft null-steer forge — so the detector can be trained/validated
before the 4x4 AP arrives. Ponytail: minimal, numpy only.

## Method — perturb at the ANGLE-MATRIX level, then recompute features
(more defensible than perturbing feature columns directly)
1. Decode real frames to angle matrices via task #1's decode.
2. Apply a forge-like perturbation per frame to emulate null-steering:
   - Drive one stream's psi angles toward the codebook boundary (→ energy null),
   - Inflate cross-subcarrier variance of phi (forged reports lose the smooth
     frequency coherence of a real channel),
   - Add small quantization-consistent jitter.
   Make the perturbation STRENGTH a `--severity` float (default 1.0) so we can
   sweep attack intensity. Keep perturbed angles in valid (0,1) range.
3. Recompute the SAME feature set as task #1 from the perturbed angles.
4. Write `data/bfi_synthetic_attack.csv` with a `label` column (0=normal,1=attack).
   Also emit the real-normal features with label 0 (so the file is a mixed,
   labeled eval set), OR write attack-only and document how it pairs with the
   real-normal CSV — match whatever make_synthetic_attack.py does.

## CLI
`python tools/make_synthetic_bfi_attack.py --pcap data/bfi_he_capture.pcap \
   --out data/bfi_synthetic_attack.csv [--severity 1.0]`
Print: N normal, N attack, and mean feature deltas (normal vs attack) so we can
eyeball separability.

## Self-check (ponytail: ONE assert-based check)
- Synthetic attack rows have measurably higher `bfi_angle_var` / `bfi_subcarrier_var`
  than the real-normal rows (assert mean(attack) > mean(normal) on at least one feature).
- All perturbed angle values remain in (0,1).
- Output CSV columns match tools/bfi_features.py output + `label`.

## Honesty note to carry into docs (not code)
Synthetic attack BFI validates the pipeline, NOT real-world accuracy — that still
needs real attack telemetry from the 4x4 AP. Label results accordingly.

## Constraints
One new file. Reuse task #1 decode. No new deps. Don't modify other files.
