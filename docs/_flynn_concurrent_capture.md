# TASK (QUEUED #5): Concurrent run launcher — live dashboard + off-air pcap

REVISED per user: NOT an offline pcap-compare tool. The user wants to run the
off-air capture AND watch the GN630v live telemetry on the dashboard at the SAME
time. These already don't conflict (Alfa=monitor for capture, Intel/eth=client for
telnet telemetry -> different NICs). This task is a thin convenience launcher only.

Ponytail: minimal. This is mostly process orchestration — do NOT add analysis or
comparison logic. stdlib only. If it turns out to be a ~15-line wrapper, that's the
correct size; don't inflate it.

## `tools/run_session.py`
CLI: `python tools/run_session.py --mon <moniface> [--host <gn630v_ip>] \
      [--iface rai1] [--outdir results/sessions] [--run-id NAME]`
Behavior:
- Create a run-id + outdir.
- Start the off-air capture: `tshark -i <mon> -w <outdir>/<run>_air.pcap`
  (saved so it can feed bfi_features.py / training LATER — this task does NOT
  decode it).
- Start the existing live dashboard (tools/dashboard.py) with its normal GN630v
  telnet args so the user watches live telemetry in the browser during the run.
- Both run concurrently until Ctrl-C, then stop BOTH cleanly and print the saved
  pcap path + how to decode it (`python tools/bfi_features.py --pcap <path> ...`).
- `# ponytail:` if launching the dashboard is simplest by just shelling out to the
  existing entrypoint, do that — don't re-implement dashboard startup.

## Practical note to surface to the user (docs, not code)
The laptop must keep a route to the GN630v (ethernet or the Intel NIC as client)
because the Alfa is occupied in monitor mode and can't also be the telnet client.

## Self-check (ponytail: ONE assert-based check)
Dry-run mode (guarded by an env flag or --dry-run) that builds the two commands
and the outdir/manifest WITHOUT launching hardware — assert both command strings
are well-formed and the pcap path is under outdir. No live-hardware in the
automated check.

## Constraints
One new file, thin. Reuse the existing dashboard entrypoint + tshark. No new deps.
Don't modify existing files.
