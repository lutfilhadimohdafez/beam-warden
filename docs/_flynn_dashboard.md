# TASK (QUEUED #4): Dashboard improvements

DEPENDS ON: tasks #1–#3 (BFI features + live stream). Fire after those land so the
CSI panel has real data. Target: tools/dashboard.html (+ minimal tools/dashboard.py
glue). Ponytail: enhance the existing QUAD dashboard, do NOT rewrite it. Keep it
one HTML file + Chart.js already in use. No new frontend deps.

## SCOPE = B: FULL PREMIUM VISUAL REDESIGN (user chose B). Content unchanged.
Reskin the ENTIRE dashboard to a premium, non-generic look. Do NOT add/remove
functionality — every existing element (detect-status, tiles, all charts, playback
bar, replay, mode badge, error bar) AND any CSI/BFI panel added by task #2 must
remain fully wired and working. This is a visual/UX pass only.

The orchestrator will supply DESIGN DIRECTION (palette, type scale, layout system,
motion) from the redesign/taste design standards and paste it at the top of the
build prompt. Follow that direction. In its absence, apply:
- Cohesive dark theme via CSS custom properties on :root (no hardcoded colors
  scattered); one accent, calibrated contrast, AA-legible.
- Clear type hierarchy (distinct display vs label vs value scales), tabular
  numerals for metrics, consistent card/grid rhythm.
- Restrained micro-motion (value transitions, status pulse) — no gratuitous animation.
- Keep the BEAM//WARDEN identity; elevate it, don't cartoon it.
- Fully responsive: 16px side gutter, no horizontal scroll at phone width.

## Constraints
- STRICTLY non-breaking: all IDs the JS binds to (detectStatus, valTxTput, chart
  canvases, playbackBar, etc.) must be preserved. Verify every getElementById /
  querySelector target in the existing JS still resolves after the reskin.
- No backend/schema changes. No new frontend deps beyond the Chart.js already loaded.
- One HTML file. Chart.js stays; restyle chart options (colors/grid/fonts) to match.
- After building, load the page and confirm: detector badge, tiles, every chart,
  and the playback/replay controls all still render and update.
- `# ponytail:` any shortcut with its ceiling.
