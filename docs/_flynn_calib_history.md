# TASK: Calibration N as a UI field + training-history log

Touch ONLY tools/dashboard.py and tools/dashboard.html. No new deps. Use
.venv/bin/python. Keep EVERYTHING working (tabs incl. Learning, session picker,
charts, tiles, CSI, playback, Mission Control, router feed, live BFI). Preserve
every JS binding id. border-radius 0, no orange borders, wave bg.

## 1. Calibration target N as a UI field (set per run)
Currently `_CALIB_TARGET = 150` is a fixed module constant.
- Add a **"Target samples (N)"** number input in the Learning tab's calibration
  section (default 150, min = _CALIB_MIN=30, sane max e.g. 100000).
- The value is sent with the calibration flow so the user sets N per run:
  - Simplest: `POST /calibrate/target {n:int}` sets a module global `_calib_target`
    (validated >= _CALIB_MIN); OR accept `target` in the existing capture/start call.
  - The auto-capture loop and the progress bar must use this runtime value, not the
    constant. The {type:"calib"} broadcast already sends `target` — make it the
    runtime value.
- Update the progress bar label to make the cadence obvious, e.g.
  "N / <target> normal samples (~2s each)".

## 2. Training-history log (clickable "what this model learned on")
Record provenance every time a model is (re)trained via /calibrate/train:
- Append an entry to `models/training_history.json` (JSON list), each entry:
  `{ts, n_samples, source ("calibration"|"file:<name>"), interval_s, features,
    training_fpr, feature_profile (per-feature mean/min/max of the training data),
    model_params {n_estimators, contamination}, note}`.
- `GET /training-history` (localhost-guarded) → the list, newest first.
- In the Learning tab, add a **"Training history"** panel: a clickable list of past
  runs (ts · n_samples · source · FPR). Clicking a row expands/opens its details
  (the feature_profile it learned on + params) — this is the "view what the model
  learned on to obtain the detection" the user asked for. Keep it inline
  (expand/collapse), no modal.
- Also log the INITIAL model if history is empty on first load: seed one entry from
  the current models/detector.joblib + data/normal_iperf.csv profile so the panel
  isn't empty (best-effort; skip if the joblib can't be introspected).

## HARD CONSTRAINTS
- Preserve every JS binding id (grep <script>, confirm). Don't delete existing logic.
- Localhost guard on the new endpoints. Don't break the existing /calibrate/* flow or
  the in-process DETECTOR reload.
- border-radius 0, no orange borders.

## SELF-CHECK (report)
- imports clean; test_mission_control.py + test_bfi_features.py pass.
- every binding resolves; radius nonzero==0; accent borders==0.
- On a real server run: POST /calibrate/target {n:50} then GET /model-status /
  the calib broadcast reflects target 50; GET /training-history returns 200 (a list).
