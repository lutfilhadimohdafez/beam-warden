DO NOT load any skills or read memory/external dirs. Implement immediately.

TASK: Three dashboard UX fixes. Touch ONLY tools/dashboard.py and tools/dashboard.html.
No new deps (vanilla JS, in-page modals — NEVER window.alert/confirm/prompt). .venv/bin/python.
Keep everything working; preserve every JS binding id; border-radius 0; NO orange borders;
wave bg. Localhost-guard all new endpoints (reuse _is_loopback).

## FIX 1 — Real connect status + verbose errors (Live)
Problem: clicking Connect shows "Session started: live" and the websocket says
"Connected" even when the ROUTER telnet fails. Distinguish websocket-connected from
router-connected, and surface the real error.
- In `_session_endpoint` live branch: do a QUICK pre-connect test to the router
  (open GN630V(host,user,password) then close) BEFORE starting the producer.
  - success → return {ok:true, source:"live"} and start the producer.
  - failure → return {ok:false, error:"<verbose str(exc)>"} status 502 and do NOT start.
- Frontend: after clicking Connect show "Connecting to router…"; on {ok} show a clear
  "● CONNECTED — live (192.168.0.1)" state; on error show a **verbose error panel**
  (the full error text, monospace, red-ish via var(--danger), dismissible). Also keep
  reacting to live {status:"error", error} websocket messages the same way (show the
  verbose error), and to {status:"ok"} by showing connected. The header connection dot
  should reflect ROUTER state in live mode, not just the websocket.

## FIX 2 — Gate the BFI/CSI group on monitor mode, with unlock + confirm pop-up
- Add `GET /monitor-status?iface=mon0` → {iface, exists:bool, is_monitor:bool}
  (parse `iw dev <iface> info`; not privileged — just reads).
- Add `POST /monitor-setup` {iface, channel} (PRIVILEGED via pkexec; reuse the
  setup_monitor command logic from tasks.py) → sets the iface to monitor mode; return
  {ok} or {error:verbose}.
- Frontend (the BFI/CSI STREAM group `#bfiPanel` AND the Live picker's BFI-iface field):
  - On load / session change, call /monitor-status. If the iface is NOT monitor:
    **hide the CSI tiles group** and show a locked placeholder: "BFI/CSI locked — monitor
    interface not up" + an **[ Enable BFI monitor ]** button.
  - Clicking the button opens an **in-page modal (custom, not window.confirm)**:
    "Set <iface> to monitor mode? This needs admin rights (a system password prompt
    will appear)." with Cancel / Enable. On Enable → POST /monitor-setup; on success
    re-check /monitor-status, unlock (show) the CSI group; on error show the verbose error.
  - When monitor IS up, the group shows normally (current behavior).

## FIX 3 — Stop / shut down the app (it's click-and-go)
- Add `POST /shutdown` (localhost-guarded): stop the current producer + BFI stream, then
  signal the server to exit cleanly (e.g. set a module flag and call
  `os.kill(os.getpid(), signal.SIGTERM)` / uvicorn Server.should_exit). Return {ok} first.
- Frontend: a **"⏻ Shut Down"** button in the header. Click → in-page confirm modal
  ("Stop Beam Warden and close the server?") → POST /shutdown → replace the page body
  with a clean "Beam Warden stopped — you can close this tab." message.
- Do not break normal running when it's not clicked.

## HARD CONSTRAINTS
- Preserve every JS binding id (grep <script>, confirm). Don't break replay/pcap/live,
  Mission Control, Learning tab, CSI panel, /ml. All new endpoints localhost-guarded.
- In-page modals only (no browser dialogs — they block). radius 0, no orange borders.

## SELF-CHECK (report)
- imports clean; test_mission_control.py passes; every binding resolves; radius nonzero==0; accent-borders==0.
- real server: GET /monitor-status?iface=mon0 returns 200 JSON; POST /session live with an
  UNREACHABLE host returns ok:false + verbose error (502) and does NOT hang the server;
  POST /session live with 192.168.0.1 returns ok:true (router is reachable). Do NOT call
  /shutdown in the self-check (it would kill the test server) — just confirm the route exists.
