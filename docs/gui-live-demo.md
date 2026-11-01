# Guided live exhibition demo

The controls are in **Command Center → Guided Live Demo**. The main dashboard
layout is unchanged.

## Before starting

1. Connect the AP to this computer over Ethernet. Plug in the Alfa attack adapter.
2. Connect the protected phone to the configured AP. Keep it stationary, awake,
   and running `iperf3 -s` in Termux.
3. Ensure `rig.conf` identifies this router, AP interface, channel, BSSID, phone IP
   and phone MAC. The router needs the installed Beam Warden service and model.
4. Start the dashboard using `.venv/bin/python tools/dashboard.py`, open
   `http://localhost:8080`, and connect the OpenWrt / mt76 router in Live mode.

## Run through the GUI

1. Open **Command Center**.
2. The preferred demo power defaults to **550 mBm (5.5 dBm)**. This is a request,
   not a verified operating point: the AC2100 has previously rejected fixed
   power with `Not supported (-122)` and remained at 24 dBm. The runner reports
   the power shown by the driver. If fixed power is unsupported, it leaves power
   unchanged and learns the baseline at the current operating point. Other SSH
   or command errors still stop preparation.
3. Click **Prepare + run live demo** and approve the desktop administrator prompt.
4. Follow the progress text. The runner checks the phone, requests AP power,
   learns 20 seconds of loaded normal traffic, then prepares the monitor adapter
   and starts the router watcher. The experiment uses a 12-second baseline and
   two 12-second attack bursts, with a 60-second subprocess timeout. These shorter
   exhibition windows limit adapter exposure; they do not guarantee an attack
   effect or replace the longer research measurement protocol.
5. Switch to **Dashboard** to show throughput/retry charts and the ML estimate.
   Return to Command Center for progress, router-alert evidence and console output.
6. Check Telegram on the phone. A router log entry establishes that the watcher
   alerted; it does **not** establish successful Telegram delivery.

**Stop demo** requests termination and cleanup; it can require another desktop
administrator prompt. On completion or stop, an accepted power setting returns
to auto; if the driver rejected it, power stays unchanged. The temporary demo
watcher stops when power is restored or preparation fails. If power was unchanged
and the watcher started successfully, detection remains running. Start a new
guided run to recalibrate. Returning
to auto power changes the link, so continuing to score the demo baseline would
be misleading.

## What the evidence means

- The main panel runs a local estimate using the shipped model and refreshed
  router baseline. Its timing/station selection can differ from the router's
  watcher. It is not confirmation that the router sent an alert.
- The guided panel separately reports new `ALERT beamforming-attack` entries
  observed in the router's log during this run.
- A finished experiment can report **no confirmed router alert**. Strong links,
  link drift and attacks without measurable degradation remain real limitations.
- Captured experiment CSVs are saved as `results/sessions/demo_*.csv`.
- Session history records the same fixed-power failure, and a later controlled
  rehearsal that caught a transient attack effect after fresh loaded calibration.
  It does not establish that 550 mBm was applied, or guarantee a sustained alert
  at the router's current power. See `docs/detector-characterization.md`.

## Validation status

### Recovery and CLI rehearsal (2026-11-01 evening)

The calibration-output parsing bug and borrowed-phone-server cleanup bug are fixed.
Firmware reload restored 56 VHT feedback frames in an eight-second passive check.
The shortened runner completed a live rehearsal with 81 reported injections and a
17.6% throughput drop, **without a router alert**. Detection remained running.
Telegram is currently disabled on the lab router using `NOTIFY_ENABLED=0`.
See [the recovery record](recovery-2026-11-01.md) for exact evidence and remaining
limitations. The older validation notes below describe the earlier revision.

### History reviewed for the fixed-power failure (2026-11-01)

Reviewed the development session logs and mt76 session matches, project auto-memory,
the project memory's `projects/active/Beam-Warden.md`, and its October 10 diary. The
the project memory project page is older than the later hardware sessions; it is not
the current router runbook. The decisive records are in the development session
`a development session`:

- October 31, 19:30 UTC: fixed 550 mBm failed with `Not supported (-122)`;
  `iw dev ... info` still reported 24 dBm.
- October 31, 19:51 UTC: the session corrected its earlier assumption that the
  power request was harmless, documenting the full-power/covert-effect limit.
  `obj1_auto.py` did not check its power command's exit status, so its level
  labels alone are not evidence that power changed.
- November 1, 02:56–03:03 UTC: the controlled protocol used fresh loaded
  calibration and prompt execution. The recorded rehearsal had no baseline
  alert and a transient attack-window router alert, with a mostly covert
  overall effect. The delivery claims in that session are historical claims;
  the guided runner independently reports only router-log evidence.

The current fix has hardware-free regression coverage. It has not been
rehearsed on the live rig by this change.

Automated tests cover parameter validation, loopback and profile checks,
conflicting-task/session guards, fresh-baseline reload, packet load gating, failed
model output, process-start failure, calibration cancellation, successful-run
cleanup and honest no-alert reporting. Main dashboard markup matches its original
version. Python compilation and inline JavaScript syntax checks pass.

A live hardware rehearsal is still required. The first read-only router probe in
the development sandbox failed before connecting because SSH rejected permissions
on `/etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf`. No attack was started by that
probe.
