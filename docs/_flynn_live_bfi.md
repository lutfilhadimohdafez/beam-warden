# TASK: Wire live BFI into the Live session picker

Touch ONLY: tools/dashboard.py, tools/dashboard.html, tools/bfi_features.py.
No new deps. Use .venv/bin/python. Keep EVERYTHING working (tabs incl. Learning,
session picker, charts, tiles, CSI panel, playback, Mission Control, router feed).
Preserve every JS binding id. border-radius 0, no orange borders, wave bg.

GOAL: when the user picks **Live** in the session picker and gives a monitor
interface, start the off-air BFI stream so the CSI panel (bfi_phi_mean, etc.) fills
live. Switching away must STOP the BFI stream cleanly (no orphan tshark/threads).

Current state: `--bfi-iface` at launch starts `_bfi_stream_thread` → `stream_features`
→ updates BFI_LATEST; `_producer_live` already folds it in via `_merge_bfi`. But
/session live does NOT start it, and it can't be stopped on session change.

## 1. Make the BFI stream stoppable (bfi_features.py)
- Add an optional `stop_event: threading.Event | None = None` param to
  `stream_features(iface, duration=0, window=10, stop_event=None)`.
- In its poll loop, break/return when `stop_event is not None and stop_event.is_set()`,
  and ensure the internal tshark subprocess is terminated on exit (it likely already
  cleans up — make sure setting the event ends the loop promptly, < ~1s).
- Keep the existing behavior identical when stop_event is None.

## 2. Manage the BFI thread from /session (dashboard.py)
- Module globals: `_bfi_thread: threading.Thread | None`, `_bfi_stop: threading.Event | None`.
- Refactor `_bfi_stream_thread(iface, window, stop_event)` to pass stop_event into
  stream_features.
- Add helpers `_start_bfi(iface)` and `_stop_bfi()`:
  - `_stop_bfi()`: if a thread is running, set the stop event, join briefly (timeout ~2s),
    clear BFI_LATEST, reset globals.
  - `_start_bfi(iface)`: `_stop_bfi()` first, then create a fresh Event + thread and start it;
    set `args.bfi_iface = iface`.
- In `_session_endpoint`:
  - On EVERY session switch, call `_stop_bfi()` first (so replay/pcap/live-without-bfi
    have no stale BFI stream), then:
  - live branch: read `bfi_iface` from the POST body; if provided and non-empty, call
    `_start_bfi(bfi_iface)`. (host/user/password/iface handling stays as-is.)
- Keep the launch-time `--bfi-iface` path working (lifespan can call `_start_bfi` too).
- Localhost guard already on /session — keep it.

## 3. Live picker UI (dashboard.html)
- In the **Live** session option, add an optional field **"BFI monitor iface"**
  (placeholder `mon0`), with a one-line hint: "off-air CSI; needs monitor mode
  (Command Center → Setup Monitor)".
- Include its value as `bfi_iface` in the POST /session body for live.
- When a live+BFI session is active, reflect it (e.g., the CSI panel header shows
  "live: <iface>"); when off, show "CSI: no BFI source".

## HARD CONSTRAINTS
- Preserve every JS binding id (grep <script>, confirm). Don't delete existing logic.
- Don't break replay/pcap/live-without-bfi. Stopping BFI must not error if none running.
- border-radius 0, no orange borders.

## SELF-CHECK (report)
- imports clean; test_mission_control.py + test_bfi_features.py pass.
- every binding resolves; radius nonzero==0; accent borders==0.
- POST /session live with a bogus bfi_iface starts+then a switch stops the thread
  without crashing the server (guard: it's fine if tshark fails on a bad iface —
  the server must stay up). Report that /session live and /session replay both
  return 200 and the server survives a start→switch cycle.
