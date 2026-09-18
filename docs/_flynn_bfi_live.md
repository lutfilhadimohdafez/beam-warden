# TASK (QUEUED #2): Live BFI feature streaming

DEPENDS ON: tools/bfi_features.py (task #1 — decode + features). Reuse its
functions; do NOT reimplement the decoder. Finalize function names against the
real file at build time.

You are Flynn. Add a LIVE capture mode so BFI/CSI features can stream off-air in
real time (Alfa in monitor mode on the victim's channel), mirroring the offline
pcap path. Ponytail: extend, don't duplicate. stdlib + numpy only.

## What to add
1. In `tools/bfi_features.py`, factor the per-frame decode into a reusable
   `frame_to_features(report_bytes, nr, nc, codebook, feedback_type, window_state) -> dict`
   if task #1 didn't already expose it, then add:
   `stream_features(iface, duration=0, window=10) -> Iterator[dict]`
   - Use `tools/bfi_capture.py::run_tshark_live()` (already exists) to pull live
     category-30 HE frames from the monitor iface.
   - For frames where run_tshark_live doesn't yield raw report bytes, fall back to
     the same raw-slice extraction task #1 uses (tshark -x on the live capture is
     not viable, so prefer a live `tshark -T fields` that includes the mimo control
     + a raw-bytes field; if the report bytes are unavailable live, document the
     limitation clearly and capture-to-tmpfile-then-decode as the fallback).
   - Maintain the trailing-window state across yielded frames for temporal-var features.
2. CLI: `python tools/bfi_features.py --live <iface> [--duration N] [--window 10]`
   prints one feature dict per line (JSON) as frames arrive.

## Dashboard integration (thin — the orchestrator may take this as glue)
Expose the generator cleanly so `tools/dashboard.py` can optionally merge `bfi_*`
features into its message dict before `score_sample()`. Do NOT rip up the existing
iwpriv poll loop — BFI is a PARALLEL stream. Add a `--bfi-iface <iface>` flag to
dashboard that, when set, spawns the BFI stream in a thread and folds the latest
`bfi_*` features into each broadcast message. Keep it optional and non-breaking
(no flag = current behavior exactly).

## Self-check
- `stream_features` on a short live capture (or a tmpfile replay) yields >0 dicts
  with the same keys as the offline CSV.
- Dashboard with NO `--bfi-iface` behaves identically to before (assert message
  schema unchanged).

## Constraints
Minimal diff. Reuse task #1 + bfi_capture.run_tshark_live. No new deps. Don't
break offline mode. `# ponytail:` any live-capture shortcut with its ceiling.
