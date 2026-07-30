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

## Objectives

1. Replicate a BeamCraft-style forged-BFI attack — ≥51% attack success rate.
2. Automate PHY telemetry collection (throughput, RSSI) — ≥10 samples,
   ≥15% variance detected between normal and attack states.
3. Integrate an ML anomaly detection engine into OpenWrt as a standalone
   package — ≥55% detection accuracy.

## Stack

| Layer | Tech |
|---|---|
| Router firmware | OpenWrt 24.10+ (custom package) |
| Attack replication | Kali Linux, Alfa AWUS036ACM (monitor mode + injection) |
| ML engine | Python 3, scikit-learn (Isolation Forest), pandas, numpy |
| Dashboard | OpenWrt LuCI |
| Alerts | Telegram bot |

## Repo layout

- `the project proposal` — full project proposal (problem statement,
  feasibility study, specs, Gantt chart, costing).
- `BeamCraft_AE/`, `BFM-tool/` — external reference repos (gitignored, not
  part of this project's own history).

## Team

Muhammad Lutfil Hadi bin Mohd Hafez · a teammate ·
a teammate · a teammate
Supervisor: the supervisor

## References

Key related work: BeamCraft (2026, the attack this project replicates),
LeakyBeam / NDSS 2025 (BFI privacy side-channel), KIT KASTEL (2025, WiFi
surveillance via BFI). Full list in the proposal PDF, section 15.
