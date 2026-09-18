# TASK: Dashboard v3 — showmanship layout + live router feed console

Touch ONLY tools/dashboard.py and tools/dashboard.html. No new deps (Starlette +
Chart.js). Use .venv/bin/python. Keep EVERYTHING working: tabs (Dashboard | Command
Center + ML link), session picker, telemetry tiles, all 5 charts (chartTxTput,
chartRetry, chartPer, chartRssi, chartAnomaly), CSI panel, ML anomaly badge/score,
playback bar, Mission Control task runner+console. Preserve every JS binding id.
Keep: border-radius 0 everywhere, NO orange borders/lining (accent for text/status
only), wave background + grain.

Do these THREE things:

## 1. Backend: stream the RAW router output (authenticity)
In tools/dashboard.py, add the raw source text to each broadcast so the UI can prove
data is real:
- `_producer_live`: after `msg = _build_message(...)`, set `msg["raw"] = text` (the
  literal `iwpriv {iface} stat` output already in the `text` variable).
- `_producer_replay`: set `msg["raw"]` to the raw CSV row being replayed (repr/line).
- `_producer_pcap` (if present): set `msg["raw"]` to a short per-frame summary.
Do NOT break the existing message schema — this is an ADDED field. `raw` may be absent
for error messages.

## 2. Floating "ROUTER FEED" console — draggable + minimizable
Add a floating panel over the Dashboard tab that streams `msg.raw` live:
- Title bar labeled e.g. "ROUTER FEED · live: iwpriv rai1 stat" (reflect the active
  source). The title bar is the DRAG handle (vanilla JS mousedown/mousemove/mouseup;
  also touch events for mobile). Clamp within viewport.
- Buttons on the title bar: **minimize** (collapse to just the title bar) and a
  show/hide toggle (a small launcher button, e.g. bottom-right, reopens it when hidden).
- Body: monospace, dark, scrolling, auto-scroll to newest, timestamp each chunk,
  cap to ~200 lines. This is the "proof it's real from the router" window.
- Default position: bottom-right, minimized-friendly. Remember position + collapsed
  state in localStorage (wrap in try/catch).
- border-radius 0, no orange lining (neutral hairline + terminal styling like the
  Mission Control console).

## 3. Single-viewport, non-scrollable, 3-column showmanship layout (Dashboard tab)
Restructure the Dashboard tab so it fills ONE screen with NO page scroll on desktop,
graphs flanking BOTH sides:
- Use CSS grid at `height: 100dvh` (account for the tab bar + session bar) with
  `overflow: hidden` on desktop. Panels use `min-height: 0` so charts shrink to fit
  instead of overflowing (Chart.js: maintainAspectRatio:false, canvas fills its box).
- Columns: LEFT = 2 charts, CENTER = the hero (detector status + score + key metric
  tiles), RIGHT = the remaining charts + CSI panel. Balance the three columns so it
  reads as a symmetric "command console" (graphs left AND right, hero centered).
  "Right-size" the charts so nothing clips and the screen is filled, not sparse.
- RESPONSIVE: below ~1100px, columns stack and the page MAY scroll (mobile-friendly);
  16px side gutter, no horizontal scroll ever. Above that, single non-scroll screen.
- The Command Center tab and ML page are unaffected by the grid (they can scroll normally).

## HARD CONSTRAINTS
- Preserve every id the JS binds to; grep the <script> for getElementById/querySelector
  targets and confirm each still exists before finishing.
- Do not delete existing <script> logic; extend it.
- Keep localhost guards, Chart.js, websocket routing (telemetry / log / status / bfi_ / raw).

## SELF-CHECK (report)
- `.venv/bin/python -c import dashboard` imports clean; test_mission_control.py passes.
- Every JS binding id resolves; border-radius nonzero count == 0; accent-border count == 0.
- Print confirmation that msg["raw"] is set in live/replay producers.
