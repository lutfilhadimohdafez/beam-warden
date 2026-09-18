TASK: Move the LIVE Isolation-Forest processing out of the standalone /ml page
(tools/ml.html) into a NEW "ML" tab in the main dashboard (tools/dashboard.html).
Leave /ml as a DOCUMENTATION-ONLY page. FILES: tools/dashboard.html and
tools/ml.html ONLY. No new deps. Minimal, don't break existing tabs/WS.

CONTEXT (verified):
- dashboard.html tab-bar (~line 1226-1230) has buttons: dashboard, command-center,
  learning, plus an "ML Engine ->" <a href="/ml"> link. tab-sections use
  <div class="tab-section" id="tab-NAME"> (active one adds class "active");
  switchTab() (~1707) toggles by data-tab. CSS: .tab-section{display:none}
  .tab-section.active{display:block} (~213).
- dashboard.html has ONE shared WebSocket: ws.onmessage (~2167) -> handleMessage(d)
  (~2017). Each broadcast message d carries anomaly_score + feature fields.
- ml.html LIVE parts to MOVE:
  (a) HTML section "Live Processing Pipeline" (5 pipe-stages, sample-token,
      pipeline-track) ~lines 448-501.
  (b) HTML section "Isolation Forest Trees" (tree-grid, tree-legend, score-box)
      ~lines 503-523.
  (c) Their CSS in ml.html <style>: rules for .pipeline-wrap .pipe-stage*
      .sample-token .pipeline-track .tree-grid .tree-card* .tree-legend
      .score-box .formula .data-table (and .section/.section-head/.section-sub
      /.panel IF not already defined in dashboard.html).
  (d) Their JS (the IIFE near the bottom of ml.html): loadForest() [fetches
      /forest-viz], harmonic(), path-length fn, updateStage1..5(), renderTrees(),
      animatePipeline(), onSample(sample), plus globals forestData/latestSample.
- ml.html DOC parts to KEEP on /ml: sections "Why Isolation Forest" (~525) and
  "The 11 Variables" + its .data-table (~540). Keep the page header/intro.

PART A — dashboard.html:
1. Add tab button after the Learning button:
     <button class="tab-btn" data-tab="ml">ML</button>
2. Add, after the learning tab-section's closing </div> (the block starting
   ~1463), a new section:
     <div class="tab-section" id="tab-ml"> ...moved (a)+(b) HTML verbatim... </div>
3. Add the moved CSS (c) into dashboard.html's <style>. Only add rules NOT already
   present. If any moved class name already exists in dashboard.html with a
   DIFFERENT definition, prefix the moved markup + its CSS with "ml-" to avoid
   collisions. (Check .section/.panel/.formula/.data-table especially.)
4. Add the moved JS (d). CRITICAL: do NOT open a second WebSocket and do NOT copy
   ml.html's connectWS(). Instead drive it from the existing handleMessage(d):
   at the END of handleMessage (~2017) add:
       if (d && d.anomaly_score != null) mlOnSample(d);
   Rename ALL moved globals/functions with an "ml" prefix to avoid clashes:
   mlForestData, mlLatestSample, mlLoadForest, mlRenderTrees, mlOnSample,
   mlAnimatePipeline, mlUpdateStage1.. etc. Call mlLoadForest() once on init
   (fetch /forest-viz). Verify none of these names already exist in dashboard.html.

PART B — ml.html (docs-only):
- DELETE the two live sections (a)+(b) and ALL their JS (loadForest, onSample,
  connectWS, updateStage*, renderTrees, animatePipeline, harmonic, path-length,
  the whole WS block). KEEP "Why Isolation Forest" + "The 11 Variables" + header.
- The page must load with ZERO console errors (remove the now-dead <script> or
  trim it to nothing). Keep only CSS the remaining doc sections use.

PART C — nav: the "ML Engine ->" links (dashboard.html ~1220 and ~1230) still
point to /ml (now docs). Relabel to "ML Docs ->" and keep them working.

SELF-CHECK (assert-style, print PASS/FAIL):
- dashboard.html CONTAINS: data-tab="ml", id="tab-ml", "Live Processing Pipeline",
  "Isolation Forest Trees", mlOnSample, and the handleMessage hook line.
- dashboard.html has NO second `new WebSocket` beyond the existing one.
- ml.html does NOT contain "Live Processing Pipeline", "Isolation Forest Trees",
  connectWS, or onSample; STILL contains "Why Isolation Forest" and "The 11 Variables".
