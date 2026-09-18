# TASK: Dashboard v2 — tabs, runtime session selector, restyle

Rework the web dashboard. Touch ONLY: tools/dashboard.py, tools/dashboard.html,
tools/ml.html. No new deps (Starlette + Chart.js already present). Use .venv/bin/python.
Keep ALL existing functionality working: telemetry tiles, all 5 charts, ML anomaly
badge/score, playback/replay bar, Mission Control task runner + console, CSI panel,
websocket message routing (telemetry vs log/status vs bfi_*). Preserve every JS
binding id.

Do the 7 items below EXACTLY. Nothing more.

## 1. Command Center in its OWN TAB
Add a simple tab bar to dashboard.html: **[ Dashboard ] [ Command Center ]** (plus a
plain nav link "ML Engine" → /ml). Tab switching is client-side (show/hide sections,
no reload). MOVE the existing Mission Control block (button grid + status chips +
live console) OUT of the main view INTO the Command Center tab. The Dashboard tab
keeps: session bar (#2), telemetry tiles, charts, ML anomaly, CSI panel, playback.
Default active tab = Dashboard. Remember the active tab in localStorage (wrap in try/catch).

## 2. Runtime session selector (replace launch-only --mode)
Currently the producer is fixed at boot (args.mode in _lifespan). Add a UI + backend
so the user chooses at runtime:
- A "Session" bar at the top of the Dashboard tab with two modes:
  - **Replay**: a dropdown listing files from data/ (both *.csv AND *.pcap), + a Start button.
  - **Live**: fields host / user / password / iface (prefilled from args defaults) + a Connect button.
- Backend:
  - `GET /replay-files` → JSON list of data/*.csv and data/*.pcap (localhost-guarded).
  - `POST /session` (localhost-guarded) body {source:"replay"|"live", file?, host?, user?, password?, iface?}:
    cancel the currently running producer task, reconfigure, and start the chosen producer.
    Keep a module-global reference to the current asyncio producer task; cancel it cleanly before starting the new one.
  - `.csv` replay → existing _producer_replay (telemetry tiles+charts).
  - `.pcap` replay → NEW _producer_pcap: reuse `bfi_features.extract_features(pcap)`,
    stream each row as a message with the bfi_* fields (drives the CSI panel);
    telemetry tile fields may be null/"—".
  - `live` → existing _producer_live with the given host/user/password/iface.
- On boot: if launched with --mode, keep auto-starting that (non-breaking). Otherwise
  show the session bar idle with status "no session — pick a source".
- Broadcast a {type:"session", source, detail} message so the UI shows the active source.

## 3. Remove ALL rounded edges
Set border-radius: 0 everywhere (dashboard.html AND ml.html). Sharp/square corners.
(Grep for border-radius and zero them; also any inline radius.)

## 4. Remove the orange "lining"
Remove accent-colored (orange) BORDERS / outlines / left-bars / underlines. The accent
may remain for text, the status dot, and small fills — but NO orange border lines on
cards/panels/tiles. Use a neutral warm-gray hairline border instead where a border is needed.

## 5. Wave background
Add a subtle animated WAVE background to the page (behind all content, pointer-events:none,
low opacity, dark-appropriate). Use inline SVG waves + a slow CSS transform/translate
animation (GPU: transform/opacity only). Keep it performant and unobtrusive. Apply to
dashboard.html and ml.html for consistency. Keep the existing grain overlay on top.

## 6. Fix ml.html "back to home"
ml.html currently has NO working back-home link. Add a clearly visible
"← Back to Dashboard" link at the top that navigates to `/`. Verify it points to "/".

## 7. Consistency
ml.html gets the same treatment: border-radius 0, no orange lining, wave background,
so the two pages match.

## HARD CONSTRAINTS
- Preserve EVERY id the JS binds to (detectStatus, detectScoreVal, valTxTput, valRetry,
  valTxPer, valRssi, valMcs, valMcsSub, valTemp, all chart canvases chartTxTput/chartRetry/
  chartPer/etc, statusDot, statusText, modeBadge, errorBar, playbackBar + controls, the
  Mission Control button grid/console/chips, CSI panel canvases). Before finishing, grep
  the <script> for every getElementById/querySelector target and confirm each still exists.
- Do not delete existing <script> logic; extend it.
- Keep localhost-only guard on ALL new endpoints (reuse _is_loopback).
- Chart.js stays.

## SELF-CHECK (report results)
- `.venv/bin/python -c "import ...dashboard"` imports clean.
- Existing test_mission_control.py still passes.
- Print: every JS binding id resolves (referenced ⊆ defined); border-radius count == 0;
  /replay-files returns the data files; a POST /session with a replay csv starts a producer
  (can mock/guard hardware).
