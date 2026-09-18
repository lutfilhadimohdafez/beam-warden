DO NOT load any skills or read memory/external dirs. Implement immediately.

TASK: Make calibration capture DURATION-based (hourly) with an estimated-sample tooltip.
Touch ONLY tools/dashboard.py and tools/dashboard.html. No new deps. .venv/bin/python.
Keep everything working; preserve every JS binding id; border-radius 0; no orange borders.

CONTEXT: today calibration target is a raw sample count (default 150). Samples arrive
every `args.interval` seconds (default 2.0). The user wants to specify capture time
(hours) instead, with a tooltip showing the estimated sample count.

## 1. Learning tab — duration input (primary), N derived
- Replace the "Target samples (N)" input with a **capture DURATION** control:
  a number input in **hours** (default **1**, step 0.25, min 0.02≈1min) — plus optional
  quick-pick buttons (15m, 1h, 4h, 8h, 24h) that set the hours value.
- Compute `target_samples = round(hours * 3600 / interval)`. Show it live next to the
  input and as a **tooltip / hint**: e.g. "≈ 1,800 samples (@ 2s each)". Update it
  whenever hours OR the interval changes.
- Progress bar label: "N / <target_samples> samples (~<interval>s each, ≈<hours>h)".

## 2. Backend (dashboard.py)
- `POST /calibrate/target` accepts `{hours: float}` (preferred) OR `{n: int}` (still
  supported). If hours given: `target = max(_CALIB_MIN, round(hours*3600/interval))`.
  Store the runtime target as before; the {type:"calib"} broadcast keeps sending `target`.
- Expose the interval so the UI can compute estimates: include `interval` in the
  /model-status response (and/or a small field the Learning tab reads).

## HARD CONSTRAINTS
- Preserve every JS binding id (grep <script>, confirm). Don't break /calibrate/* or the
  in-process retrain/reload. Localhost guard stays. radius 0, no orange borders.

## SELF-CHECK (report)
- imports clean; test_mission_control.py passes; every binding resolves; radius nonzero==0.
- real server: POST /calibrate/target {hours:1} → returns target ≈ 1800 (at interval 2.0);
  {hours:0.25} → ≈ 450.
