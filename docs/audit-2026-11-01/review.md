# Beam Warden: proposal, evidence, implementation and rig audit

Audit date: 2026-11-01. Repository HEAD: `0b8748d`; existing uncommitted work was included in the review and preserved. No router settings, attacks, deployments or external messages were initiated.

## Assessment

This is a substantial working research prototype. The strongest contribution is the combination of the experimental MT7615 beamformer patch, real feedback-forgery experiments, automated telemetry, and a compact learned model packaged for OpenWrt. The remaining work is primarily measurement integrity and deployment validation, followed by completion of the proposed router interface.

**The current evidence does not justify marking all three proposal objectives unconditionally complete.** Objective 2 has strong evidence; Objective 1 needs a trial-based success rate; Objective 3 has a reproducible offline result but a material mismatch between training and deployed feature calculation.

## Scope and evidence hierarchy

Reviewed the proposal's objectives, scope, features and security sections; Git history from July through November; current collectors, experiment harnesses, training/export code, router package and dashboard detector path; project documentation and selected archived runs; project-related development history and memory records.

The accompanying files provide an inventory, CSV row/label counts and hashes, and development session index:

- [inventory.csv](inventory.csv): project artifacts, including ignored capture/archive directories and borrowed repositories; excludes Git internals, virtual environments and bytecode.
- [datasets.csv](datasets.csv): available top-level data CSVs and archived session CSVs, with SHA-256 hashes.
- [sessions.csv](sessions.csv): 15 FYP session files and two mt76 session files, with recorded timestamp ranges.

This is a project-wide evidence and implementation audit, not a line-by-line security certification of every dependency. Large packet captures were inventoried, not fully re-decoded; third-party repositories and marketing assets received inventory/context review. The rig was reconstructed from configuration, code, hardware notes and session evidence, not freshly verified on-device. A local USB inventory attempt could not initialize libusb.

Prefer raw measurements and actual code over narrative summaries. Historical assistant statements such as “done,” “verified,” or “Telegram sent” are claims to test, not independent evidence. Local notes contain credentials; they are intentionally omitted here.

## Proposal objective mapping

The controlling wording is section 3 of `the project proposal` (printed page 6).

| Objective | Proposal requirement | Evidence and status | Needed for closure |
|---|---|---|---|
| 1 | BeamCraft-style replication with at least **51% attack success rate** | Forging/injection and substantial throughput degradation are documented. README substitutes throughput loss for trial success rate. **Replication supported; success-rate requirement not established.** | Define a successful trial before testing; retain all valid attempts, failures and invalid trials; report successes/valid trials and confidence interval separately from throughput loss. |
| 2 | Automated throughput/RSSI processing, at least **10 samples**, minimum **15% variance** during attack | Modern labelled telemetry runs contain 30–34 rows each; a separate baseline contains 135. Large throughput changes are directly calculable. **Substantially supported.** | Define “variance” operationally, distinguish percent change from statistical variance, publish an explicit per-run table and retain fixed measurement definitions. |
| 3 | ML engine integrated as a **standalone OpenWrt package**, detection accuracy threshold **55%** | Real `model.awk`, service and `.ipk` exist. Historical five-run offline accuracy reproduced at **80.1% mean across runs**. **Packaging supported; deployed accuracy not established.** | Unify feature extraction, evaluate the actual exported scorer plus load gate and alert persistence, then validate on fresh held-out runs on the router. |

The proposal is internally mixed about external versus router-side inference. Sections 3–4 explicitly require localized standalone inference; the current on-router model is the strongest fit. Use that as the final architecture and explain the earlier external-engine design as development history.

RSSI stability is a useful control. Do not manufacture a 15% RSSI change to meet Objective 2, and do not calculate percent change directly on negative dBm values. Report RSSI changes in dB and throughput changes in percent, with the interpretation of the proposal documented.

## What happened over the past months

Git contains 141 commits at audit time: July 4, August 6, September 53, October 57, November 21. These count changes, not hours or experimental success.

| Period | Work and evidence | How to treat it now |
|---|---|---|
| July | Proposal/repository initialization; BeamCraft GUI and SSH telemetry tooling; BFM-tool exploration | Foundation and tooling history. |
| August | GN630v UART/telnet access; vendor `iwpriv` telemetry collector and architecture notes | Useful hardware learning; GN630v is not the OpenWrt package host. |
| September | Dashboard, HE feedback decoding, AX3200 4×4 captures, Isolation Forest, experiment controls | Preserve real packet captures and engineering work; later data reset invalidates treating old model/results as current proof. |
| October 1–15 | Monitor recovery, channel tuning, GUI stop/cleanup fixes, bursty traffic/A/B/A experiments | Demonstrates repeated operational problems and confounds; older performance claims require provenance review. |
| October 23–30 | AC2100 adoption; experimental mt76 TxBF patch; actual explicit-beamformed transmit status; new SSH telemetry path | Major original engineering contribution. Patch/build material lives outside this repository too. |
| October 30 | Explicit rejection of prior datasets/model; deletion commit `9edf8f0`; new 135-row baseline | Treat as the trust boundary for current quantitative claims. |
| October 31 | Firmware recovery, live/offline forge correction, new attack data, BFI-window detector, throughput-loss experiments | Stronger evidence, still mostly one rig and narrowly controlled conditions. |
| November 1 | Router telemetry RF export/package, alert hook, load gate, drift investigation, guided-demo work | Current deployment direction. The guided demo has newer uncommitted fixes and has not been live-rehearsed as a complete current revision. |

### Memory and session reconciliation

Read the project memory's `projects/active/Beam-Warden.md`, `projects/active/BFM-tool.md`, July 30 diary and October 10 diary, and searched its other records for this project. The project page mixes August state with September updates and still lists missing hardware that later arrived. It is useful history, not the current runbook.

Project memory records cover the AX3200 period, AC2100 transition, October 30 rig, forge geometry, firmware recovery and the superseded BFI detector. The actual FYP JSONL records begin in September; July/August reconstruction relies on Git and diaries. Session `a development session` provides the decisive later evidence:

- October 30 11:02 UTC: earlier data explicitly treated as void, followed by removal of old datasets/model. This conflicts with earlier commits describing some of those files as live captures. Do not resolve the conflict by silently reinstating them as genuine; retain them as unverified historical artifacts if recovered from Git.
- October 31: model export commands identify the exact five training runs; current wildcard commands include later runs and therefore do not reproduce the historical experiment.
- October 31 19:30 UTC onward: fixed-power command rejected with `Not supported (-122)` and reported power remained 24 dBm. Requested 550/600 mBm is not a verified operating point without run-specific readback.
- November 1 02:53 UTC: normal-phase false alarm under RSSI/link drift.
- November 1 03:03 UTC: rehearsal reported a transient router alert but an overall roughly −0.9% effect. The alert timestamp file was treated as delivery proof, although the hook writes it before attempting Telegram delivery.

Do not equate the hardware's explicit-beamformed TX frame counter with a count of distinct sounding handshakes: one sounding result can serve multiple transmitted frames. Keep the counter as evidence of beamformed transmission, alongside actual feedback captures.

## Rig understood from current records

| Role | Hardware/configuration | Caveats |
|---|---|---|
| Current AP and detector host | Redmi AC2100, MT7621 + MT7615 4×4, ImmortalWrt; SSH `192.168.1.1`; AP `phy1-ap0`; configured channel 36; BSSID `5c:02:14:0e:e1:c5` | Experimental TxBF driver is required for this research setup. Old channel 120/124 and AX3200 settings are historical. Current radio width/power require readback. |
| Protected station | Honor X9c, `192.168.1.105`, station MAC `16:0f:02:1d:91:42` | Phone MAC/IP can change; verify association before collecting. Termux iperf3 server, port 5201; historical SSH service corruption, with ADB used as a workaround. |
| Controller/load generator | Linux laptop, this repository and `.venv`, Ethernet connection to AP LAN | Historical laptop Wi-Fi is on upstream `192.168.100.x`, a separate subnet; keep test traffic on the AP LAN. |
| Capture/injection adapter | External Alfa-labelled adapter, operated through `mt7921u`, monitor interface `mon0` | Notes repeatedly call it AWUS036ACM while identifying mt7921u. Preserve this as an identity inconsistency until USB ID/driver/label are verified. Firmware recovery and bounded bursts address observed receive failures. |
| Older APs | AX3200/MT7915 on vendor firmware, previously `192.168.31.1`, `wl0`; GN630v/MT7916, vendor `iwpriv`, UART/telnet | Historical capture/telemetry platforms; do not apply their access commands to the AC2100. |
| Optional compute | Historical `fw-lab` CPU VM over Tailscale | Training/build offload only; not required for runtime inference. |

Research flow: laptop generates downlink load over Ethernet → AC2100 beamforms to phone → external adapter observes and injects feedback → AP station counters feed telemetry and detector. Deployment flow: AP counters → local baseline/features → AWK forest → router log/alert hook. The laptop dashboard is a separate viewer/controller.

The current captured attack geometry is described as **4×1**, supporting the non-square forge path. Do not repeat the stale README statement that all relevant captures are square 2×2.

Driver source/build context: `/home/lutfil/mt7615-txbf/README.md`, its `patches/999-mt7615-experimental-txbf.patch`, `/home/lutfil/mt76`, and `/home/lutfil/mt76-build`. The patch README records ImmortalWrt 25.12.2, kernel 6.12.103, mt76 `39c960c3`, and opt-in `txbf=1`. These are recorded build facts, not a fresh installed-version attestation. Its reset/reinitialization limitation also matters for repeatable experiments.

## Findings in priority order

### P0 — Training and deployment measure different PER features

`tools/mt76_telemetry.py::parse_iw_station_dump` computes `tx_per_pct` as cumulative `100 * tx_failed / packets_sent`. `tools/aba_mt76.py::sample_row` saves that snapshot value. `tools/export_model.py` trains on it.

`openwrt/beamwarden/files/beamwarden.sh::sample` instead computes interval `delta_failed / (delta_packets + delta_failed)`. The current dashboard detector also computes interval PER before scoring.

These differ in time basis, denominator and units. Relative normalization can mostly cancel a constant scale factor if calibration and scoring use that scale consistently; it cannot turn a cumulative statistic into a window statistic. Exported prediction agreement on already-built feature vectors does not validate feature extraction.

**Action:** define a versioned raw-counter/window schema; implement identical station selection, deltas, units, timing, missing-data handling and baseline rules across capture, offline evaluation, router and dashboard. Log raw failed counters in future CSVs: existing experiment CSVs do not retain everything necessary to exactly reconstruct interval PER. Recollect when exact reconstruction is impossible.

### P0 — The 80.1% figure is not a deployed-system evaluation

Reproduced with these exact files, in order:

1. `data/obj1_20261031_070935.csv`
2. `data/obj1_20261031_041217.csv`
3. `data/real_aba_20261031_024424.csv`
4. `data/obj1_20261031_175028.csv`
5. `data/obj1_20261031_182852.csv`

There are 160 rows: 112 attack-labelled and 48 normal. Mean per-run accuracy is 80.1%; rounded folds are 100, 68, 77, 100, 56%. Pooled held-out accuracy is 80.0%, balanced accuracy 85.1%, precision 98.8%, recall 72.3%, F1 83.5%; confusion matrix TN/FP/FN/TP = 47/1/31/81. Always predicting attack already yields 70% pooled accuracy, exceeding the proposal's nominal 55% threshold. Accuracy alone is inadequate evidence.

Additional limitations:

- `load_run()` uses all normal-labelled rows in the held-out run for its baseline, including evaluation normal rows and, for A/B/A, later recovery rows. This assumes oracle knowledge and future calibration samples. A genuinely preceding clean calibration segment should be separate from evaluation.
- CV scores sklearn's model without the deployed packet-activity gate or three-hit alert rule. Measure event recall, detection delay, false alerts/hour and evaluated coverage as well as window accuracy.
- One training run (`041217`) has baseline median throughput only **0.002 Mbps** and settled median zero. This is not evidence of a functioning loaded baseline and requires a documented validity decision before model use.
- Attack phase labels establish experimental exposure, not necessarily successful manipulation. Keep attempted attack, verified injection and measured impact as separate fields.
- All five runs come from one rig; leaving out a run is not testing a new network or hardware platform.
- The exporter emits hard votes from per-tree leaf classes, while sklearn forests combine leaf probabilities. Agreement on the 160 training rows was reproduced, but equivalence for all held-out inputs is not guaranteed. Evaluate the actual AWK output on each held-out fold.

### P0 — Objective 1's success rate and attribution need repair

`tools/obj1_run.py` prints `CLEARS >=51%` for percentage throughput loss. `tools/obj1_auto.py` searches levels and stops at the first qualifying loss; it also ignores the power command's return code. Neither computes the proposal's attack success rate over independently defined trials.

The lag-aware A→B design discards initial ramp bursts and does not require recovery. It can measure a sustained change, but stable RSSI alone does not exclude load, congestion, airtime or driver faults as alternative causes. Predefine settling duration and include matched no-injection/sham runs. Preserve invalid and zero-injection attempts. The current zero-injection branch can print “INCONCLUSIVE” and then still print the threshold-clearing loss, which needs correction.

The historical 69.6% number is based on iperf intervals returned by the harness, whereas saved CSVs contain router throughput sampled on a different cadence. For `070935`, the directly reproducible CSV median change is **30.202 → 8.986 Mbps (70.2%)**, retry **0.3086 → 0.5125**. These are consistent in direction but not the same statistic. Save iperf JSON/intervals with each run so the published headline can be recomputed exactly.

### P1 — Telemetry and runtime edge cases weaken portability

- Python station parsing claims “first station” but does not stop or select at station boundaries: later stations overwrite fields. Missing fields can leave mixed-station values. The shell watcher selects a configured MAC or aggregates all stations. These are incompatible measurement populations.
- Python collectors pad missing RSSI chains with zero; training `_rssi()` includes them. Shell RSSI parsing expects bracketed chains and can misparse a scalar-only `signal:` line. Tests should cover one, two and four chains, scalar RSSI, missing counters and multiple stations.
- Shell deltas have no reset/reassociation guard. Calibration accepts missing/idle traffic and writes a baseline; watcher proceeds with defaults when baseline is absent. Prefer explicit uncalibrated/unavailable states.
- The 3,000-attempts/window gate suppresses light-traffic scoring and resets hit count. It can also suppress scoring during a real collapse. Report these as unobserved windows, not clean normal windows; measure attack coverage before claiming the load problem is fixed.
- `/var/run/beamwarden.base` is volatile. Validate reboot, recalibration and service-start behavior; the package's default interface is `wlan0`, while this rig uses `phy1-ap0`.
- Three consecutive 2-second attack windows imply roughly six seconds of evidence before an alert, plus alignment/processing time. A short transient can be missed despite positive single-window classification.

### P1 — Proposed product features are only partly delivered

The proposal explicitly promises a LuCI-integrated dashboard. The current dashboard runs in Starlette on the laptop; the `.ipk` installs shell/service/config/model/alert files and contains no LuCI application. Build a small LuCI status/config/log interface if retaining that promise.

The proposal also promises attacker identification. Current telemetry identifies the affected client, and `attack_report.py` correctly labels its identity as the target/victim. Forged feedback impersonates that identity, so it is not proof of the attacker's physical MAC. Record “affected station; source unverified” unless independent attribution evidence exists. Automatic blocking of that MAC could disconnect the victim. Mitigation is optional in the proposal and should not displace core validation.

The Telegram hook writes the cooldown timestamp before curl and discards both response and status; a stamp proves an attempt, not delivery. Record HTTP/API success separately and test offline/timeout/retry behavior. No test messages were sent during this audit.

### P1 — Reproducibility spans untracked and external files

The package payload is byte-identical to current source, including `model.awk`. Re-exporting the historical five-file model to `/tmp` also produced a byte-identical model. These are useful positive checks.

However, `041217`, which is part of that model's training set, is currently untracked. `BeamCraft_AE` is ignored by the parent repository and has modified source/binary; the tracked Bug-C patch does not establish that every accumulated modification can be reconstructed. Driver work is in sibling repositories. Pin upstream commits, preserve complete patches and build instructions, record firmware/module hashes, and create a model manifest with exact input hashes and dependency versions.

`data` holds about 5.62 GB and `results` about 0.79 GB. Raw captures and archived session CSVs are largely ignored by Git. Archive them deliberately with hashes and provenance; do not delete historical artifacts while resolving contradictory narratives. Old synthetic generators remain in `tools`; clearly segregate them from research evidence and production training.

### P2 — Documentation and tests lag behind the current system

README still leads with the retired BFI-storm 100% detector, mixes GN630v/AX3200/AC2100 settings, and marks throughput loss as attack success. Some training comments claim cross-network portability from same-rig run holdouts. `docs/ml-engine.md` has the newer architecture but still overstates what its metric validates. The project memory requires a dated correction, not silent replacement of history.

Full `pytest tools -q` stops during collection on:

- `test_attack_gui.py`: removed `extract_current` import.
- `test_bfi_features.py`: removed `compute_NANG` import.
- `test_mission_control.py`: deleted `data/normal_iperf.csv` fixture.

Excluding those three files, **67 tests passed**. This is not a fully passing suite. Repair or retire obsolete tests deliberately, then add meaningful coverage for feature parity, station identity, counter resets, inference failure, gating and package lifecycle.

## Work plan to achieve the proposal

### 1. Freeze definitions and evidence

Produce one experiment manifest schema: run ID; actual firmware/driver/model hashes; station/AP identities; actual channel/width/power; offered traffic; preceding calibration; timestamps; verified injection count; raw counter and iperf paths; validity/exclusion reason. Retain every attempted run. Decide in writing how “success rate” and “15% variance” will be assessed before collecting the confirmatory dataset.

Deliverable: a proposal-to-evidence table with unambiguous formulas and a trusted dataset manifest. Existing historical runs are exploratory evidence until their provenance and validity are resolved.

### 2. Make capture and inference mathematically identical

Fix station selection and feature semantics first. Use per-window raw deltas with explicit elapsed time, units and reset/missing handling. Separate clean calibration from scored evaluation; require adequate load and sufficient samples during calibration. Mirror the definitions in Python and shell, then compare the feature vectors and AWK verdicts from identical saved counter snapshots.

Deliverable: identical offline/router feature vectors within documented numeric tolerance, plus tests of both normal and failure paths. Rebuild the forest only after this contract is stable.

### 3. Run a confirmatory lab campaign

Use the current AC2100/phone rig first. Suggested initial budget: at least 20 independent valid attack trials across several sessions and two or more repeatable link conditions, with matched sham/no-injection trials. This is a practical starting point, not a guarantee of a narrow confidence interval. Retain independent attempt counts and report uncertainty. Keep positions fixed within a trial, verify operating settings, and predeclare warm-up/settling/recovery rules.

Record low-load, heavy-load, changing-load and normal link-drift sessions as negatives. Include short and no-effect attack exposures so coverage limits are visible. If an attack may have persistent effects, use a documented reset/recovery criterion between trials. Only then expand to AX3200/another platform for a portability claim.

Deliverables: Objective 1 successes/valid trials ≥51% under the agreed definition; Objective 2 automated dataset and explicit ≥15% change evidence; confidence intervals, exclusions and controls alongside the headline.

### 4. Evaluate and deploy the actual detector

Hold out complete sessions/conditions before model selection; keep test calibration separate and causal. Compare against majority-class and simple retry/PER/throughput rules. Evaluate the exported AWK scorer, gate, persistence and missing-data behavior as a complete pipeline. Report accuracy, balanced accuracy, precision/recall/F1, confusion matrix, false alerts/hour, event recall, detection delay and coverage.

Deliverable: ≥55% accuracy on the agreed independent test set, with useful class balance and recall; installation/reboot/service recovery evidence; measured CPU/RAM/latency overhead; fresh router logs tied to model and data hashes. Do not equate adapter-free implementation with universal hardware accuracy.

### 5. Finish the proposal-facing product and submission

Add minimal LuCI status/config/log viewing; distinguish local dashboard estimates from router-confirmed alerts; report affected stations honestly; verify Telegram delivery handling. Repair the stale test suite and unify README, architecture, methodology and results around one current system. Preserve BFI-storm detection as an optional research comparator, not the standalone package's score.

Final evidence bundle: reproducible package/model build; pinned driver and attack-tool modifications; run manifest and raw-data archive; evaluation outputs; rig diagram; dated limitations; and a rehearsed current-revision demo. UI polish, additional marketing and speculative adaptive baselines are lower priority than these gaps. Evaluate adaptive baselines only after a fixed, causal baseline is trustworthy, to avoid absorbing attacks into the normal state.

## Verification performed in this audit

- Parsed the local proposal PDF and reviewed relevant sections.
- Indexed project artifacts and historical CSVs; hashed CSV evidence.
- Indexed 17 relevant development session files and searched decisive events; reconciled the project memory diaries/project notes with code and Git.
- Recomputed descriptive telemetry changes and reproduced the exact five-run model evaluation.
- Recomputed pooled held-out classification metrics and majority baseline.
- Regenerated model into `/tmp` only: 160/160 AWK/sklearn agreement on supplied training vectors; byte-identical checked-in model.
- Compared all installed `.ipk` payload files against package source: all matched.
- Ran the full test collection and then the unaffected suite: three collection errors; remaining 67 tests passed.

No fresh RF experiment, packet-level attribution proof, router resource benchmark, current on-device package inspection or Telegram delivery verification was performed. Those remain explicit acceptance work, not assumed successes.

## Follow-up: preserve and validate Wi-Fi 6 interoperability

The AX3200 HE work is an existing foundation, not a future port from scratch. A subsequent offline inspection of `data/bfi_ax3200_4x4.pcap` with tshark found **56 category-30 frames**, all `nc_index=1`, `nr_index=3` (4×2 geometry), codebook 0: **37 feedback_type=0 and 19 feedback_type=1**. Thus this curated capture contains both SU and MU feedback; the older blanket SU description is incomplete.

Git revision `45f7ac0:tools/bfi_features.py` contains the earlier HE angle/feature decoder. The current file was repurposed into a VHT category-21 frame-count detector. `BeamCraft_AE/main_su.cpp` still contains `parse_he_mimo()` and shared geometry-dependent reconstruction math, but uses fixed offsets and does not provide a clean, separately validated VHT/HE dispatch. `tools/bfi_capture.py` recognizes both categories, yet its proposed HE field names (`wlan.he.mimo_control.*`) differ from the working `wlan.he.mimo.*` names in the local tshark inspection. Discovery of available fields currently cannot compensate for requesting the wrong aliases.

Implementation plan: recover the historical HE decoder into a dedicated module, retain the VHT window counter separately, and provide explicit VHT/HE parsers feeding a shared report representation. Detect the actual report category/action; parse lengths, codebook, geometry, grouping and segmentation rather than treating a fixed offset as protocol identification. Use preserved AX3200/GN630v captures as regression fixtures and independent Wireshark dissection as a metadata cross-check. Initially declare only fixture-verified report combinations supported; reject unsupported or truncated reports explicitly.

Keep protocol decoding and firmware telemetry transport independent: AX3200 vendor-firmware `iwpriv`/telnet and OpenWrt `iw`/SSH are distinct backends even though both may serve HE links. Validate the standalone telemetry model on fresh AX3200/HE data separately from proving HE packet decoding. No live replay/injection was performed in this follow-up.
