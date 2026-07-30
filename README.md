# Beam Warden: Beamforming Anomaly Detection Framework

**Final Year Project**

Modern Wi-Fi (802.11ac/ax/be) relies on beamforming to steer signal toward each
client. The channel feedback that makes this possible — Beamforming Feedback
Information (BFI) — is sent in **cleartext with no authentication**, even
under WPA3/PMF. An attacker with commodity hardware can forge BFI and quietly
redirect an access point's beams, cutting a victim's throughput by up to 83%
(the "BeamCraft" attack).

**Beam Warden** replicates that attack in a controlled lab, then detects it —
using a machine learning model (Isolation Forest) trained on router telemetry
(RSSI, MCS, retry rate) to flag anomalous beamforming behaviour in real time,
without needing to touch the Wi-Fi protocol itself.

📡 [Project Overview](https://coldcollectives.my/projects/beam-warden.html) ·
📖 [Tooling Manual](https://coldcollectives.my/projects/beam-warden-docs.html)

## How it works

```
Client <--beamforming--> OpenWrt Router --telemetry--> ML Engine --score--> Dashboard/Alerts
                              ^
                    Attacker forges BFI
```

1. An OpenWrt-based router collects PHY telemetry (RSSI, MCS, retry rate) from
   connected clients.
2. Telemetry is sent to an external ML engine (Isolation Forest, trained
   unsupervised on 24–72h of normal traffic).
3. The engine scores each device for anomalous behaviour and returns a
   verdict to the router's dashboard.
4. On detection: alert (LuCI dashboard + Telegram), with optional
   auto-mitigation (isolate/block the suspect MAC).

## Objectives — status

1. **Replicate** a BeamCraft-style forged-BFI attack — ≥51% attack success
   rate. `BeamCraft_AE/main_su` compiles clean; `tools/attack_gui.py` can
   scan for a monitor-capable NIC, set monitor mode, and launch it. **Not
   yet run against real hardware** (no Alfa AWUS036ACM attached yet).
2. **Automate** PHY telemetry collection (throughput, RSSI) — ≥10 samples,
   ≥15% variance detected between normal and attack states. **Tooling
   built, zero data collected yet** — `tools/telemetry_capture.py` logs
   RSSI/MCS/throughput/retry-rate to CSV, but needs Objective 1's hardware
   run to actually produce normal-vs-attack samples.
3. **Integrate** an ML anomaly detection engine into OpenWrt — ≥55%
   detection accuracy. **Not started** — Isolation Forest (scikit-learn),
   design only so far (see proposal Appendix 16.1).

## Stack

| Layer | Tech |
|---|---|
| Router firmware | OpenWrt 24.10+ (custom package) |
| Attack replication | Kali Linux, Alfa AWUS036ACM (monitor mode + injection) |
| ML engine | Python 3, scikit-learn (Isolation Forest), pandas, numpy |
| Dashboard | OpenWrt LuCI |
| Alerts | Telegram bot |

## Tools

- `tools/attack_gui.py` — Tkinter control panel for the SU (single-user)
  attack: scans WiFi adapters for monitor-mode support, sets a chosen NIC
  into monitor mode on a given channel, patches `BeamCraft_AE/main_su.cpp`
  with the interface/AP MAC/victim MAC/alpha you enter, recompiles it, and
  runs it — all via one `pkexec` prompt. MU (multi-user) mode isn't wired
  in yet (its packet filter targets up to 5 MACs vs SU's 2).
  Run: `python3 tools/attack_gui.py`.
- `tools/test_attack_gui.py` — sanity checks for the source-patching and
  hardware-parsing logic above (`python3 tools/test_attack_gui.py`).
- `tools/telemetry_capture.py` — polls `iw station dump` on the router over
  SSH and logs RSSI/MCS/throughput/retry-rate per client to CSV, labelled
  `normal`/`attack` for the Objective 2 dataset.
  Run: `python3 tools/telemetry_capture.py --host <router-ip> --iface wlan0 --label normal`.
- `tools/test_telemetry_capture.py` — checks the parsing/delta math against
  two real `iw station dump` snapshots (`python3 tools/test_telemetry_capture.py`).
- Full usage guide: [Beam Warden Tooling Manual](https://coldcollectives.my/projects/beam-warden-docs.html)
  — setup, CLI reference, end-to-end workflow, known limitations.

## Repo layout

- `the project proposal` — full project proposal (problem statement,
  feasibility study, specs, Gantt chart, costing).
- `beamcraft_attack (1).pdf` — the BeamCraft paper (IEEE TMC 2026) this
  project's attack replicates; see references below.
- `tools/` — our own scripts (tracked; see above).
- `BeamCraft_AE/`, `BFM-tool/` — external reference repos, cloned as-is
  (gitignored, not part of this project's own git history). `BeamCraft_AE`
  is the attack implementation; `BFM-tool` captures/plots raw BFI packets.

## Team

Muhammad Lutfil Hadi bin Mohd Hafez · a teammate ·
a teammate · a teammate
Supervisor: the supervisor

## References

Key related work: BeamCraft (2026, the attack this project replicates),
LeakyBeam / NDSS 2025 (BFI privacy side-channel), KIT KASTEL (2025, WiFi
surveillance via BFI). Full list in the proposal PDF, section 15.
