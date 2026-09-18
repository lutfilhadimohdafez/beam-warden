# TASK: "Learning" tab — model status, calibration/retrain, live match meter

Touch ONLY tools/dashboard.py and tools/dashboard.html. No new deps (Starlette,
scikit-learn already used via train_detector). Use .venv/bin/python. Keep EVERYTHING
working (tabs, session picker, all charts, tiles, CSI, playback, Mission Control,
router feed). Preserve every JS binding id. Keep border-radius 0, no orange borders,
wave bg. Add a THIRD tab: [ Dashboard ] [ Command Center ] [ Learning ] (+ ML Engine link).

CONTEXT: the IsolationForest detector (models/detector.joblib = {model, scaler,
features}) was trained on data/normal_iperf.csv (normal UNDER iperf load). In a
different live environment (e.g. idle) it flags everything as attack. This tab lets
the user teach it the CURRENT environment's normal, and shows what it has learned.
score_sample() and the DETECTOR global live in dashboard.py; train_detector.py trains
a new model from a CSV.

## Backend (dashboard.py) — all localhost-guarded (reuse _is_loopback)
1. `GET /model-status` → JSON: features list, n training samples (if derivable — else
   from the calibration buffer), contamination, training FPR if known, and the learned
   "normal profile" = per-feature mean/min/max from data/normal_iperf.csv (read it), and
   whether a model is loaded. Also a rolling live anomaly rate (keep a deque of the last
   ~60 is_anomaly results updated in the broadcast path) → return anomaly_rate + match_rate=1-rate.
2. Calibration buffer (module global list). 
   - `POST /calibrate/capture` → append the CURRENT latest live sample's feature values to
     an in-memory buffer (and to a CSV data/normal_calib.csv). Return buffer count + target (150).
   - `POST /calibrate/reset` → clear buffer + remove data/normal_calib.csv.
   - `POST /calibrate/train` → run train_detector on data/normal_calib.csv
     (`.venv/bin/python tools/train_detector.py --csv data/normal_calib.csv --out models/detector.joblib`
     via subprocess, or import and call), THEN RELOAD the DETECTOR global in-process so live
     scoring immediately uses the new model. Return ok + new training FPR. Guard: need >= ~30 samples.
   Note: auto-capture is nicer — while on the Learning tab with Live running, allow a
   "start capturing" toggle that appends one sample per broadcast until target reached.
   Keep it simple; a manual "capture current" + an auto toggle are both fine.
3. Broadcast a {type:"calib", count, target} so the progress bar updates live.

## Frontend (dashboard.html) — the Learning tab
- **Model status card:** features, samples trained, contamination, FPR, model-loaded state.
- **Learned normal profile:** small table/bars of per-feature mean (min–max) — "this is what it thinks normal looks like."
- **Calibration progress bar:** count / target (e.g. 0/150) with buttons: [Capture current] [Auto-capture on/off] [Retrain] [Reset]. Retrain enabled at >= 30 samples. After retrain, show the new FPR and a toast "model reloaded".
- **Live match meter:** a gauge/bar of match_rate (1 − rolling anomaly rate) — turns green as live matches learned normal. This visually shows the "haywire → calibrated" transition.
- Explain in one line: "Trained on a busy link; recalibrate to teach it THIS environment's normal."

## HARD CONSTRAINTS
- Preserve every JS binding id; grep <script> and confirm before finishing.
- Don't break existing logic; extend. Localhost guard on all new endpoints. border-radius 0, no orange borders.
- The DETECTOR reload must be in-process (re-assign the global) so no restart is needed.

## SELF-CHECK (report)
- imports clean; test_mission_control.py passes; every binding resolves; radius nonzero==0; accent borders==0.
- On a real server run: GET /model-status returns 200 with the normal profile; POST /calibrate/capture increments the count.
