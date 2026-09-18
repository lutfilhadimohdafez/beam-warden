# TASK (PARALLEL — file set: tools/dashboard.py + tools/dashboard.html + tools/tasks.py)
# Mission Control: button-driven task runner with live CLI console

You are Flynn. Turn the EXISTING web dashboard into the single control app: buttons
that run the project's CLI tools as subprocesses, streaming their stdout/stderr live
into a read-only console in the browser. Reuse everything — do NOT build a new app,
do NOT rewrite the dashboard. stdlib + starlette (already used). No new deps.

DISJOINT FROM other flynn workers: touch ONLY tools/dashboard.py,
tools/dashboard.html, and a new tools/tasks.py. Do not touch bfi_features.py,
make_synthetic*, train_detector.py, etc.

## Reuse these existing pieces
- tools/dashboard.py = Starlette + WebSocket (async producer/broadcast). Add the
  runner endpoints here and push log/status messages over the SAME websocket.
- tools/attack_gui.py = has the subprocess + `pkexec` privileged-run + root-kill
  (pkexec pkill) pattern. PORT that command-building/kill logic (do not import Tk).

## tools/tasks.py — the task registry (single source of truth)
A dict: name -> {label, cmd (list, may contain {placeholders}), privileged: bool,
description}. Seed with these (commands as they exist in the repo):
- setup_monitor   (privileged; iw dev set monitor + channel) — reuse attack_gui logic
- scan_adapters   (`iw dev`)
- capture_bfi     (`tshark -i {mon} -w results/sessions/{run}_air.pcap` — privileged if needed)
- start_attack    (the attack_harness/main_su invocation attack_gui builds; privileged)
- train_detector  (`python tools/train_detector.py --csv {csv}`)
- gen_synthetic   (`python tools/make_synthetic_attack.py ...`)
- decode_features (`python tools/bfi_features.py --pcap {pcap} --out {out}`)
Shared params (mon iface, gn630v host, channel, duration) come from a small form at
the top of the panel; {placeholders} fill from those + task inputs.
# ponytail: predefined registry only — NO arbitrary command exec (that's the safe,
# chosen design: read-only console + fixed task list, not an embedded shell).

## dashboard.py — runner endpoints (async, over existing websocket)
- `GET  /tasks`        -> registry + current per-task state (idle/running/done/failed)
- `POST /run/{name}`   -> validate name against registry; spawn via
  asyncio.create_subprocess_exec (pkexec wrapper if privileged); register the PID;
  stream each stdout/stderr line to all websocket clients as
  {type:"log", task, stream:"out"|"err", line}; on exit send
  {type:"status", task, state, code}. Refuse unknown names.
- `POST /stop/{name}`  -> kill the running process (reuse attack_gui's pkexec pkill
  root-kill for privileged ones).
- SECURITY (hard): the run/stop endpoints must only serve when bound to 127.0.0.1.
  Enforce localhost (reject non-loopback client, or bind loopback) and document it.
  `# ponytail: localhost-only; this is a local research rig, not a public service.`

## dashboard.html — Mission Control section (additive, non-breaking)
- A "Mission Control" panel: shared-params form + a button grid built from /tasks +
  a per-task status chip + Stop buttons.
- A live CONSOLE pane: scrolling, monospace, appends {type:"log"} lines (stderr in a
  distinct color), auto-scroll with a pause-on-hover, a Clear button.
- Route websocket messages by `type`: existing telemetry messages keep driving the
  tiles/charts; new log/status messages drive the console/chips. Do NOT break the
  existing telemetry/ML/playback rendering.

## Self-check (ponytail: ONE runnable check)
- A test task running `["echo","hello-mission-control"]` via /run streams a
  {type:"log"} line containing "hello-mission-control" to a connected websocket and
  ends with {type:"status", state:"done", code:0}.
- /tasks returns the registry. Unknown /run/{name} is rejected.
- Assert non-loopback access to /run is refused.
(Use starlette's TestClient / a minimal async test; no hardware.)

## Constraints
- Non-breaking: every existing dashboard element + websocket telemetry keeps working.
- 3 files only (dashboard.py, dashboard.html, tasks.py). No new deps. Port attack_gui
  logic; you may leave attack_gui.py in place (retire later).
- Absorbs the old "concurrent run" idea: capture_bfi is just a task button running
  alongside the always-live telemetry.
