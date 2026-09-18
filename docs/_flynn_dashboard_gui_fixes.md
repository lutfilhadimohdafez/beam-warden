# flynn task — dashboard GUI fixes (`tools/dashboard.html` + one endpoint in `tools/dashboard.py`)

Four targeted fixes. Do NOT redesign — match the existing design tokens
(`var(--accent)`, `var(--ok)`, `var(--danger)`, `var(--muted-dim)`, fonts
`--font-display`/`--font-mono`). Keep diffs minimal. Test in a browser at
`http://127.0.0.1:8099/` (server already running in replay mode).

---

## FIX 1 — Connect button becomes a state machine (Dashboard tab, Live source)

Today `#sessionLiveConnect` is a static "Connect" that calls `postSession(...)`
and nothing on the button changes. Make it a 3-state machine. **Do NOT touch the
top-right status indicator (`#statusDot`/`#statusText`) — it is driven by the
WebSocket and must keep working independently.**

Backend fact you can rely on: `POST /session {source:"live", ...}` runs a real
router pre-check and returns HTTP 200 `{"ok":true,"source":"live"}` only when the
router actually connected; on failure it returns `{"ok":false,"error":...}`
(status 502). So a resolved-ok response == truly connected.

Behaviour:
- **Idle** → button label `Connect`, normal style.
- **On click (idle):** label `Connecting…`, `disabled=true`. POST the live
  session. On ok → **Connected** state; on error → back to Idle, keep the
  existing error surfaced via `$sessionStatus` (postSession already does this).
- **Connected** → label `Disconnect`, add the danger style (reuse
  `.session-start-btn` + a modifier or inline `border/color: var(--danger)`),
  `disabled=false`.
- **On click (connected):** POST `/session-stop` (new endpoint below). On ok →
  back to Idle (`Connect`, normal style).

Implementation notes:
- Make `postSession(body)` **return the fetch promise** (it currently returns
  nothing) so the live handler can react to ok/error. Do not change the
  replay/pcap callers' behaviour.
- Track state in a `var liveConnected = false;` (module scope near the other
  session vars ~line 1732).
- Also listen for the session broadcast already handled in `handleMessage`
  (`d.type === "session"` / the code near line 2033 that sets
  `$sessionStatus.textContent`): if a session message arrives with
  `source === "none"`, reset the button to Idle (covers disconnects triggered
  elsewhere).

### New endpoint in `tools/dashboard.py`
Add `async def _session_stop(request)`:
- loopback-only guard (copy `_is_loopback(request)` check from `_session_endpoint`).
- cancel the current producer exactly like the top of `_session_endpoint` does
  (`_current_task.cancel()` + await, set `None`), call `_stop_bfi()`, reset the
  `PLAYBACK` dict the same way, then `await _broadcast({"type":"session",
  "source":"none","detail":"disconnected"})`.
- return `JSONResponse({"ok": True})`.
Register `Route("/session-stop", _session_stop, methods=["POST"])` next to the
existing `/session` route (~line 1289). Factor out shared cancel logic only if
trivial; otherwise a small copy is fine (ponytail: don't over-abstract).

---

## FIX 2 — BFI-monitor input not inline (Dashboard tab, Live fields)

The `#sessionBfiIface` field (label "BFI monitor iface", ~line 1268) has a hint
`<span>` under the input. `.session-fields` uses `align-items: flex-end`, so the
field's *bottom* (the hint) aligns to the row and the input floats ~14px ABOVE
the Host/User/Password/Iface inputs.

Fix so the input sits on the **same horizontal line** as its siblings, hint
still below it. Cleanest: make that `.session-field` `position: relative` and the
hint `position: absolute; top: 100%; left: 0;` (with a small `margin-top`) so the
hint no longer contributes to the field's flex height. Do NOT switch
`.session-fields` to `flex-start` (that misaligns the Connect button). Verify the
hint doesn't overlap the `#sessionStatus` line below.

---

## FIX 3 — Command Center: number the tasks + live monitor state

The task grid (`buildGrid`, ~line 2220) renders 8 unnumbered cards in a flat grid
→ reads as scattered. And `setup_monitor` shows a static "idle" chip even when the
monitor iface is actually up.

### 3a — Number the tasks as a mission sequence
Render the cards in this explicit order (fall back to registry order for any
name not listed), and prefix each card with its step number:
```
1 Setup Monitor Mode   (setup_monitor)
2 Scan Adapters        (scan_adapters)
3 Capture BFI          (capture_bfi)
4 Start Attack         (start_attack)
5 Decode BFI Features  (decode_features)
6 Train Detector       (train_detector)
7 Generate Synthetic   (gen_synthetic)
8 Test Echo            (test_echo)
```
Add a small numbered badge to `.mc-task-header` (a `.mc-task-num` span before the
label: monospace, `var(--accent)`, e.g. circled/boxed index). Keep it subtle and
on-theme. The number is display-only; do NOT change task `name`s / data-attrs /
run-stop wiring.

### 3b — Live "monitor connected" state
- Add a status badge in the MISSION CONTROL header area (near the
  "MISSION CONTROL" section-label, ~line 1397): `<span id="mcMonStatus">`.
- Poll `GET /monitor-status?iface=<current #mcMon value>` on load, every 5s, and
  whenever `#mcMon` changes. Reuse the pattern in `checkMonitorGate()` (~line 2869)
  — do NOT write a new fetch style.
- When `d.is_monitor` is true → badge text `MONITOR <iface> CONNECTED`, green
  (`var(--ok)`); else `MONITOR <iface> DOWN`, muted (`var(--muted-dim)`).
- ALSO reflect it on the `setup_monitor` task chip: when monitor is up, set that
  card's chip to a green "connected" state (reuse `updateChip(name, state)` — add
  a `.mc-chip.connected` style mirroring `.mc-chip.done` if a distinct label is
  wanted, else pass "done"). When monitor goes down and the task isn't running,
  return the chip to "idle". Don't fight a "running" chip (if the task is
  actively running, leave its chip alone).

---

## Ponytail / do-nots
- Minimal diffs, match existing styles, no new libraries, no framework.
- Do NOT alter the top-right WS status indicator behaviour.
- Do NOT change task names, the `/run//stop/` wiring, or the telemetry code.
- Leave a brief `ponytail:` comment on any non-obvious choice.
- Self-verify in the browser: (1) Live Connect shows Connecting→Disconnect and
  back; (2) mon0 input aligns with the row; (3) tasks are numbered 1–8;
  (4) with a monitor iface up the badge + setup_monitor chip both go green.
  (You can't bring up a real monitor iface in this sandbox — at minimum confirm
  the badge renders "DOWN" and the poll fires without console errors.)
