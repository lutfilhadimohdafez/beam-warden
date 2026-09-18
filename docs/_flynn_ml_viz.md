DO NOT load any skills or read memory/external dirs. Implement immediately.

TASK: Rebuild the ML Engine page (tools/ml.html) into a LIVE, ANIMATED visualization of
how the detector processes each sample — data → extraction → scaling → isolation forest →
score — plus a visual isolation-forest tree view showing where the current sample lands.
Touch ONLY tools/ml.html and tools/dashboard.py. No new deps (vanilla JS + inline SVG/canvas;
Chart.js already available). Use .venv/bin/python.

STYLE: match the dashboard — dark theme, CSS custom properties, border-radius 0, NO orange
borders/lining (accent for text/nodes only), wave background + grain, a working
"← Back to Dashboard" link to "/". Responsive, no horizontal scroll.

## 1. Backend: expose the real Isolation Forest structure (dashboard.py)
Add `GET /forest-viz` (localhost-guarded) returning JSON from the loaded DETECTOR:
- `features`: DETECTOR["features"] (the 11 names).
- `scaler`: {mean: scaler.mean_.tolist(), scale: scaler.scale_.tolist()} so the page can
  show/compute standardization (x-mean)/scale.
- `trees`: sample the FIRST ~4 estimators; per tree emit arrays from `est.tree_`:
  {children_left, children_right, feature, threshold, n_node_samples} (all .tolist()).
- `n_estimators`, `contamination`, and `max_samples_` (for the c(n) path-length norm).
Guard: if DETECTOR is None return {error} 200-with-empty so the page degrades gracefully.
The live per-sample values + anomaly_score + is_anomaly already arrive over the existing
/ws websocket — reuse them (same message schema the dashboard uses).

## 2. Frontend: animated processing pipeline (the centerpiece)
A left→right pipeline that ANIMATES on every new websocket sample (a moving "sample" token
flows stage to stage; use requestAnimationFrame / CSS transforms, GPU-friendly):
  STAGE 1 RAW  → live telemetry+BFI values arriving (pulse on new sample)
  STAGE 2 EXTRACT → the feature vector (11 telemetry [+ bfi_*]); show the numbers
  STAGE 3 SCALE → show the standardization math per feature: z = (x - mean)/scale,
                  animate raw→scaled values (use the /forest-viz scaler)
  STAGE 4 FOREST → the sample dropping through the trees (see §3)
  STAGE 5 SCORE → path length E(h) → anomaly score s = 2^(-E(h)/c(n)) → NORMAL/ATTACK verdict
Annotate each stage with the ACTUAL math (standardization formula; path length; the score
formula with c(n) = 2H(n-1) - 2(n-1)/n). Keep it legible, not cramped.

## 3. Isolation Forest tree visualization (the "GUI trees")
- Render the ~4 trees from /forest-viz as SVG node-link diagrams (root at top, split nodes
  branching). Keep each tree shallow-rendered (cap drawn depth ~6-8 so it's readable).
- For the CURRENT live sample, compute its path through each drawn tree client-side using the
  node arrays: at node i, go left if scaled_x[feature[i]] <= threshold[i] else right, until a
  leaf; highlight that path and mark the landing node. Show the path length (depth reached).
- Colour by outcome: short average path → anomaly (accent/red highlight), long → normal
  (green). Animate the descent (node-by-node) on each new sample.
- A small legend: "short path = isolates fast = anomaly; long path = normal".

## 4. Keep it honest + live
- Everything driven by REAL data: real tree thresholds, real scaler, real live sample.
- If no live session is running, show the last sample or a gentle "waiting for samples…".

## HARD CONSTRAINTS
- Touch only ml.html + dashboard.py. Don't break existing dashboard routes/bindings.
- Localhost guard on /forest-viz. Performant: no busy loops; rAF; cap tree depth/count.
- border-radius 0, no orange borders, wave bg, back-to-home link works.

## SELF-CHECK (report)
- imports clean; test_mission_control.py passes.
- real server: GET /forest-viz returns 200 with features+scaler+trees (trees non-empty).
- ml.html is valid HTML, references /ws and /forest-viz, has the 5 pipeline stages and the
  SVG tree container, and a working href="/" back link.
