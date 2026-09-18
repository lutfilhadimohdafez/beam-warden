# flynn task — ML detection eval harness (`tools/eval_detector.py`)

## Goal
Build a script that evaluates the trained anomaly detector on a labelled
**normal-vs-attack** telemetry pair and prints defensible metrics. This is the
Obj-3 evidence for the viva: it turns "the model is built" into real numbers.

## Context (already in this repo — read these)
- `tools/train_detector.py` — trains an `IsolationForest` on NORMAL telemetry
  only. Saves `models/detector.joblib` = `{"model", "scaler", "features"}`.
  The 11 feature columns live in its `FEATURES` list; also stored in the joblib.
- Data schemas (telemetry, the detector's feature space):
  - Normal: `data/normal_iperf.csv` (150 rows, full telemetry cols),
    `data/normal_calib.csv` (2979 rows, just the 11 FEATURES cols).
  - Attack: `data/synthetic_attack.csv` (150 rows, full telemetry cols).
  - IsolationForest convention: `predict()` returns `-1` = anomaly (= ATTACK
    detected), `+1` = normal. `decision_function()` returns a score
    (lower = more anomalous) — use it for ROC-AUC.

## Build `tools/eval_detector.py`
CLI:
```
python3 tools/eval_detector.py \
    --model models/detector.joblib \
    --normal data/normal_iperf.csv \
    --attack data/synthetic_attack.csv \
    [--out results/eval_<timestamp>.txt]
```
Requirements:
1. Load the joblib; pull `model`, `scaler`, `features` from it (drive column
   selection off the stored `features` list — do NOT re-hardcode column names).
2. Reuse the CSV loading + `_coerce` logic from `train_detector.py` (import it
   or copy the two helpers — keep it DRY, don't reinvent). Both input CSVs may
   have extra columns; select only `features`, coerce empties to 0.0.
3. Build labels: normal rows = 0 (negative), attack rows = 1 (positive).
4. Scale with the loaded `scaler` (`transform`, NOT fit), then:
   - `preds = model.predict(X)` → map `-1 -> 1 (attack)`, `+1 -> 0 (normal)`.
   - `scores = -model.decision_function(X)` (so higher = more attack-like) for ROC-AUC.
5. Report, via `sklearn.metrics`:
   - confusion matrix (TN/FP/FN/TP),
   - precision, recall, f1, accuracy,
   - **false-positive rate** (on the normal set) and **detection/true-positive
     rate** (on the attack set) called out explicitly — these are the two
     numbers the viva panel will ask for,
   - ROC-AUC.
   Print a clean text block; if `--out` given, also write it there
   (mkdir -p the parent).
6. Non-zero exit + clear message if a feature column is entirely missing from
   an input CSV (fail loud, don't silently zero a whole column).

## Test — `tools/test_eval_detector.py`
One pytest file, assert-based, no fixtures/frameworks beyond pytest:
- Train a tiny model in a tmp dir (or load the repo model), build a small
  synthetic normal CSV and an obviously-anomalous attack CSV, run the eval
  function, assert: detection rate on the anomalous set is high (> 0.5) and the
  confusion-matrix cells sum to the row count. Keep it fast (<2s).

## Ponytail rules
- Minimal: one script + one test. No config files, no plotting lib, no class
  hierarchy. Stdlib + numpy + sklearn + joblib only (already deps).
- Metrics come from `sklearn.metrics` — do NOT hand-roll precision/recall.
- Leave ONE runnable self-check (the pytest file). Mark any shortcut with a
  `ponytail:` comment.

## Do NOT
- Do not retrain or overwrite `models/detector.joblib`.
- Do not touch `train_detector.py` beyond importing its helpers.
- Do not add plotting (that's a later, separate task if the viva wants a curve).
