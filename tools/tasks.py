"""Task registry for Mission Control — single source of truth for CLI tasks.

ponytail: predefined registry only — NO arbitrary command exec.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_TOOLS = Path(__file__).resolve().parent
_BINARY = _ROOT / "BeamCraft_AE" / "main_su"

TASK_REGISTRY: dict[str, dict] = {
    "live_demo": {
        "label": "Guided Live Demo",
        "cmd": [sys.executable, "-u", str(_TOOLS / "live_demo.py"),
                "--mon", "{mon}", "--power", "{demo_power}"],
        "privileged": True,
        "description": "Check the phone, set demo power, freshly calibrate, start the router watcher, then run bounded measured attack bursts. Restores AP power to auto.",
    },
    "test_echo": {
        "label": "Test Echo",
        "cmd": ["echo", "hello-mission-control"],
        "privileged": False,
        "description": "Self-check: streams hello-mission-control and exits.",
    },
    "setup_monitor": {
        "label": "Setup Monitor Mode",
        "cmd": [
            "sh", "-c",
            # SURGICAL fence (2026-10-11): do NOT `systemctl stop NetworkManager`.
            # PROVEN this night (journal 01:03:47): on this box NM manages BOTH
            # the USB-RJ45 (enp0s20, DHCP) and the Intel wlan0, so stopping it
            # tore down ALL uplink — telnet + sounder died — forcing a Recover
            # every single time. The old comment claiming "ethernet stays up" was
            # false. Instead we release ONLY the Alfa phy from NM further down
            # (nmcli set managed no, once it's identified). A monitor-only phy has
            # nothing NM/wpa_supplicant can grab or channel-hop, so no daemon kill
            # is needed and the ethernet + Intel uplink stay up throughout.
            # --- CARD CHECK (never run blind) --- find the Alfa by DRIVER
            # (mt7921u), never by name or phy index — both drift across reloads.
            # If no mt7921u radio is present, building mon0 would land on an empty
            # phy or grab the Intel (weak injection). Abort loud instead.
            "PHY=$(for p in /sys/class/ieee80211/phy*; do "
            "[ \"$(basename $(readlink -f $p/device/driver))\" = mt7921u ] && basename $p; done); "
            "if [ -z \"$PHY\" ]; then echo '*** NO ALFA FOUND: no mt7921u radio present. "
            "Plug the Alfa dongle in and retry — refusing to touch the Intel card. ***'; exit 1; fi; "
            # the Alfa's current managed vif lives under that phy's device dir
            # (whatever its name) — every teardown below is scoped to it, not a
            # hardcoded wlan1, so we can never delete the Intel's interface.
            "VIF=$(ls /sys/class/ieee80211/$PHY/device/net/ 2>/dev/null | grep -vx '{mon}' | head -1); "
            "echo \"ALFA OK: $PHY (mt7921u) vif=${{VIF:-none}} -- this is the attack radio\"; "
            # surgical fence: tell NM to stop managing EVERY vif on the Alfa phy
            # (incl. any p2p-dev) so it won't channel-hop or re-grab it. Scoped
            # strictly to this phy's own vifs — never the Intel's, never the
            # ethernet — so all uplink is left untouched. Replaces the old global
            # `systemctl stop NetworkManager` that killed every NIC.
            "for v in $(ls /sys/class/ieee80211/$PHY/device/net/ 2>/dev/null); do "
            "nmcli device set \"$v\" managed no 2>/dev/null; done; "
            # auto channel detect MUST scan the managed vif BEFORE it becomes mon0
            # (once converted there is no managed vif left to scan).
            "if [ '{channel}' = 'auto' ]; then "
            "  if [ -n \"$VIF\" ]; then ip link set \"$VIF\" up 2>/dev/null; "
            "    SCAN=$(iw dev \"$VIF\" scan 2>/dev/null); "
            "    FREQ=$(echo \"$SCAN\" | grep -A5 'BSS {bssid}' | grep 'freq:' | head -1 | grep -oP '\\d+'); "
            "    WIDTH_RAW=$(echo \"$SCAN\" | grep -A30 'BSS {bssid}' | grep -i 'channel width' | head -1); "
            "  fi; "
            "  if [ -n \"$FREQ\" ]; then "
            "    CH=$(echo \"($FREQ - 5000) / 5\" | bc); "
            "    if echo \"$WIDTH_RAW\" | grep -qi '80'; then W=80; "
            "    elif echo \"$WIDTH_RAW\" | grep -qi '40'; then W=40; "
            "    else W=20; fi; "
            "    echo \"DETECTED AP {bssid}: channel $CH, width ${{W}}MHz\"; "
            "  else "
            "    echo '*** WARNING: scan found no BSS {bssid} — falling back to ch36/80MHz ***'; "
            "    CH=36; W=80; "
            "  fi; "
            "else "
            "  CH={channel}; W={bw}; "
            "fi; "
            # build mon0 on the Alfa's phy (idempotent). Deletes scoped to $VIF
            # (the mt7921u vif) — structurally cannot touch the Intel.
            "if ! iw dev {mon} info 2>/dev/null | grep -q 'type monitor'; then "
            "  iw dev {mon} del 2>/dev/null; "
            "  [ -n \"$VIF\" ] && iw dev \"$VIF\" del 2>/dev/null; "
            "  iw phy $PHY interface add {mon} type monitor; "
            "fi; "
            "ip link set {mon} up; "
            # bandwidth-aware retune
            # NOTE: `set channel N 80MHz` is silently rejected by the mt7921u —
            # 80MHz MUST use `set freq <primary> 80 <center>`. 20/40 are fine.
            "case $W in "
            "20) iw dev {mon} set channel $CH HT20 2>/dev/null;; "
            "40) q=$(( $CH / 4 )); [ $((q % 2)) -eq 1 ] && S=HT40+ || S=HT40-; "
            "    iw dev {mon} set channel $CH $S 2>/dev/null;; "
            "*) PRIM=$((5000 + CH * 5)); "
            "   case $CH in 36|40|44|48) CEN=5210;; 52|56|60|64) CEN=5290;; "
            "   100|104|108|112) CEN=5530;; 116|120|124|128) CEN=5610;; "
            "   132|136|140|144) CEN=5690;; 149|153|157|161) CEN=5775;; *) CEN=$PRIM;; esac; "
            "   iw dev {mon} set freq $PRIM 80 $CEN 2>/dev/null;; "
            "esac; "
            "iw dev {mon} info | grep -E 'type|channel'; "
            # DEAF-CARD CHECK
            "R1=$(cat /sys/class/net/{mon}/statistics/rx_packets 2>/dev/null || echo 0); "
            "sleep 3; "
            "R2=$(cat /sys/class/net/{mon}/statistics/rx_packets 2>/dev/null || echo 0); "
            "if [ \"$R2\" -gt \"$R1\" ]; then "
            "  echo \"RADIO OK: heard $((R2-R1)) packets in 3s\"; "
            "else "
            "  echo \"*** DEAF CARD: 0 packets in 3s on ch$CH -- mt7921u wedged. "
            "Run Reset Monitor (or modprobe -r/modprobe mt7921u) then Setup again BEFORE capturing. ***\"; "
            "fi",
        ],
        "privileged": True,
        "description": "Neutralise wpa_supplicant + NetworkManager, create monitor iface if missing, auto-detect channel (or use manual), then verify the radio is not RX-deaf.",
    },
    "reset_monitor": {
        "label": "Reset Monitor",
        "cmd": [
            "sh", "-c",
            "PHY=$(for p in /sys/class/ieee80211/phy*; do "
            "[ \"$(basename $(readlink -f $p/device/driver))\" = mt7921u ] && basename $p; done); "
            "iw dev {mon} del 2>/dev/null; "
            "iw dev wlan1 del 2>/dev/null; "
            "iw phy $PHY interface add wlan1 type managed 2>/dev/null; "
            "nmcli device set wlan1 managed yes 2>/dev/null; "
            "ip link set wlan1 up 2>/dev/null; "
            "systemctl start NetworkManager 2>/dev/null; "
            "systemctl start wpa_supplicant 2>/dev/null; "
            "iw dev wlan1 info | grep -E 'Interface|type'",
        ],
        "privileged": True,
        "description": "Tear down the monitor iface, restore wlan1 to managed WiFi, and restart NetworkManager + wpa_supplicant.",
    },
    "restore_intel": {
        "label": "Restore Networking",
        "cmd": [
            "sh", "-c",
            # RECOVERY — NIC-AGNOSTIC. Un-break networking after Alfa ops (or a bad
            # setup) left NICs unmanaged/down. Does NOT assume a vendor or name
            # (no hardcoded "Intel"/wlan0): restores EVERY interface except lo, the
            # monitor iface, and the Alfa's own vifs. Portable to any laptop/PC.
            # Cross-machine behaviour: NM-based distros fully reconnect; a box with
            # no NetworkManager degrades gracefully (nmcli calls no-op, `ip link up`
            # fallback still brings links up, `ip -br link` reports); no Alfa present
            # -> nothing to fence, every NIC restored.
            # 1) identify the Alfa (by DRIVER, never name) and its vifs, to skip.
            "ALFA_PHY=$(for p in /sys/class/ieee80211/phy*; do "
            "[ \"$(basename $(readlink -f $p/device/driver) 2>/dev/null)\" = mt7921u ] && basename $p; done); "
            "ALFA_IFS=''; [ -n \"$ALFA_PHY\" ] && ALFA_IFS=$(ls /sys/class/ieee80211/$ALFA_PHY/device/net/ 2>/dev/null); "
            # 2) restart the managers (no-op if absent) -> brings managed NICs back.
            "systemctl start NetworkManager wpa_supplicant 2>/dev/null; sleep 3; "
            # 3) fence the Alfa: unmanage its vifs; delete any non-{mon} vif spun up.
            "if [ -n \"$ALFA_PHY\" ]; then "
            "  for v in $ALFA_IFS; do nmcli device set \"$v\" managed no 2>/dev/null; "
            "    [ \"$v\" != '{mon}' ] && iw dev \"$v\" del 2>/dev/null; done; "
            "fi; "
            # 4) restore EVERY other NIC (wifi + wired, any name), skip lo/{mon}/Alfa.
            "echo '--- restoring NICs ---'; "
            "for dev in /sys/class/net/*; do n=$(basename \"$dev\"); "
            "  [ \"$n\" = lo ] && continue; [ \"$n\" = '{mon}' ] && continue; "
            "  for a in $ALFA_IFS; do [ \"$n\" = \"$a\" ] && continue 2; done; "
            "  nmcli device set \"$n\" managed yes 2>/dev/null; "
            "  ip link set \"$n\" up 2>/dev/null; "
            "  nmcli -w 8 device connect \"$n\" 2>/dev/null; "
            "  echo \"  $n -> restore attempted\"; "
            "done; "
            # 5) report (nmcli, or `ip -br link` fallback where NM is absent).
            "echo '--- device status ---'; "
            "nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device status 2>/dev/null || ip -br link; "
            "echo '--- mon0 preserved? ---'; "
            "iw dev {mon} info 2>/dev/null | grep -E 'type|channel' || echo 'mon0 GONE — rebuild via Setup Monitor before firing'; "
            "echo '--- internet ---'; "
            "ip route get 1.1.1.1 2>/dev/null | head -1 || echo 'no route'",
        ],
        "privileged": True,
        "description": "Recovery: restore ALL default NICs (wifi + wired, any vendor/name) to managed networking after Alfa ops left them down, while fencing only the Alfa phy so mon0 survives. NIC-agnostic — works on any laptop, not just this box's Intel; degrades gracefully with no NetworkManager.",
    },
    "check_channel": {
        "label": "Check Channel",
        "cmd": [
            "sh", "-c",
            "BSSID={bssid}; "
            "if iw dev {mon} info 2>/dev/null | grep -q 'type monitor'; then "
            "  RESULT=$(tshark -i {mon} -a duration:4 "
            "    -Y \"wlan.bssid==$BSSID && wlan.fc.type_subtype==0x0008\" "
            "    -T fields -e radiotap.channel.freq 2>/dev/null | sort | uniq -c | sort -rn | head -1); "
            "  COUNT=$(echo \"$RESULT\" | awk '{{print $1}}'); "
            "  FREQ=$(echo \"$RESULT\" | awk '{{print $2}}'); "
            "  if [ -n \"$FREQ\" ] && [ \"$FREQ\" -gt 0 ] 2>/dev/null; then "
            "    CH=$(( (FREQ - 5000) / 5 )); "
            "    echo \"AP $BSSID: channel $CH ($FREQ MHz), seen ${{COUNT:-0}} beacons\"; "
            "  else "
            "    echo \"AP $BSSID: no beacons seen in 4s on {mon}\"; "
            "  fi; "
            "elif iw dev wlan1 info 2>/dev/null | grep -q 'type managed'; then "
            "  ip link set wlan1 up 2>/dev/null; "
            "  SCAN=$(iw dev wlan1 scan 2>/dev/null); "
            "  FREQ=$(echo \"$SCAN\" | grep -A5 \"BSS $BSSID\" | grep 'freq:' | head -1 | grep -oP '\\d+'); "
            "  WIDTH_RAW=$(echo \"$SCAN\" | grep -A30 \"BSS $BSSID\" | grep -i 'channel width' | head -1); "
            "  if [ -n \"$FREQ\" ]; then "
            "    CH=$(( (FREQ - 5000) / 5 )); "
            "    if echo \"$WIDTH_RAW\" | grep -qi '80'; then W=80; "
            "    elif echo \"$WIDTH_RAW\" | grep -qi '40'; then W=40; "
            "    else W=20; fi; "
            "    echo \"AP $BSSID: channel $CH ($FREQ MHz), width ${{W}}MHz\"; "
            "  else "
            "    echo \"AP $BSSID: not found in scan\"; "
            "  fi; "
            "else "
            "  echo 'No wireless interface available (need mon0 or wlan1)'; "
            "fi",
        ],
        "privileged": True,
        "description": "Non-destructive channel peek: sniffs beacons on mon0 or scans wlan1 to report the target AP's current channel.",
    },
    "recover_monitor": {
        "label": "Recover Alfa (deaf fix)",
        "cmd": [
            "sh", "-c",
            # Reload the mt7921u driver to cure an RX-deaf (wedged) Alfa, then
            # rebuild the monitor iface at the chosen bandwidth and verify RX.
            "iw dev {mon} del 2>/dev/null; "
            "modprobe -r mt7921u; sleep 1; modprobe mt7921u; sleep 3; "
            "PHY=$(for p in /sys/class/ieee80211/phy*; do "
            "[ \"$(basename $(readlink -f $p/device/driver))\" = mt7921u ] && basename $p; done); "
            "for d in /sys/class/ieee80211/$PHY/device/net/*; do "
            "iw dev $(basename $d) del 2>/dev/null; done; "
            "iw phy $PHY interface add {mon} type monitor; "
            "ip link set {mon} up; "
            # 80MHz needs `set freq` on the mt7921u (see setup_monitor note).
            # Sanitize channel/bw first: the GUI may pass 'auto' (or blank). The
            # old code fed that straight into $(( )) -> `set freq 5000 80 5000`
            # -> silent fail -> mon0 stranded on ch1, deaf to the 5GHz target
            # (burned us twice on 2026-10-11). Default to ch36/80 unless the
            # value is a plain number.
            "CH={channel}; case \"$CH\" in ''|*[!0-9]*) CH=36;; esac; "
            "BW={bw}; case \"$BW\" in 20|40) ;; *) BW=80;; esac; "
            "case $BW in "
            "20) iw dev {mon} set channel $CH HT20 2>/dev/null;; "
            "40) q=$(( $CH / 4 )); [ $((q % 2)) -eq 1 ] && S=HT40+ || S=HT40-; "
            "    iw dev {mon} set channel $CH $S 2>/dev/null;; "
            "*) PRIM=$((5000 + $CH * 5)); "
            "   case $CH in 36|40|44|48) CEN=5210;; 52|56|60|64) CEN=5290;; "
            "   100|104|108|112) CEN=5530;; 116|120|124|128) CEN=5610;; "
            "   132|136|140|144) CEN=5690;; 149|153|157|161) CEN=5775;; *) CEN=$PRIM;; esac; "
            "   iw dev {mon} set freq $PRIM 80 $CEN 2>/dev/null;; "
            "esac; "
            "iw dev {mon} info | grep -E 'type|channel'; "
            "R1=$(cat /sys/class/net/{mon}/statistics/rx_packets 2>/dev/null || echo 0); "
            "sleep 3; "
            "R2=$(cat /sys/class/net/{mon}/statistics/rx_packets 2>/dev/null || echo 0); "
            "if [ \"$R2\" -gt \"$R1\" ]; then "
            "  echo \"RADIO OK: heard $((R2-R1)) packets in 3s\"; "
            "else "
            "  echo \"*** DEAF CARD: 0 packets in 3s on ch$CH -- mt7921u wedged. "
            "Run Reset Monitor (or modprobe -r/modprobe mt7921u) then Setup again BEFORE capturing. ***\"; "
            "fi",
        ],
        "privileged": True,
        "description": "Reload the mt7921u driver and rebuild the monitor iface at the chosen bandwidth to cure an RX-deaf (wedged) Alfa, then verify it hears.",
    },
    "scan_adapters": {
        "label": "Scan Adapters",
        "cmd": ["iw", "dev"],
        "privileged": False,
        "description": "List wireless interfaces and their modes.",
    },
    "capture_bfi": {
        "label": "Capture BFI",
        "cmd": [
            "tshark", "-i", "{mon}", "-p", "-w",
            str(_ROOT / "results" / "sessions" / "{run}_air.pcap"),
        ],
        "privileged": False,  # dumpcap has cap_net_raw; user in wireshark group. pkexec/root breaks the file write.
        "description": "Capture beamforming frames to pcap via tshark.",
    },
    "start_attack": {
        "label": "Start Attack",
        "cmd": [
            str(_BINARY),
            "--iface", "{mon}",
            "--ap", "{ap}",
            "--victim", "{victim}",
            "--alpha", "{alpha}",
            "--type", "{type}",
            "--offset", "{offset}",
            # flood stays at the binary default (1 = one injection per UNIQUE
            # forged BFI). 2026-10-11: flood 1 gave -55% MCS drop; a flood-64 run
            # gave only -19% BUT that run was on a just-reset Alfa (Recover Alfa
            # pressed between), so the comparison is confounded. Default (1) is
            # the proven-strong setting; re-test flood as a clean A/B if needed.
        ],
        "privileged": True,
        "description": "Launch BeamCraft beamforming-spoofing attack (flood 1 = strongest; see note).",
    },
    "throughput_test": {
        "label": "BeamCraft Attack — Burst Throughput (A/B/A)",
        "cmd": [
            # sys.executable = the venv python; an absolute path survives pkexec's
            # reset PATH, unlike bare "python".
            # -u: force unbuffered stdout. stdbuf (in dashboard _run_task) only
            # line-buffers libc stdio; Python does its OWN block-buffering over a
            # pipe, and pkexec strips PYTHONUNBUFFERED, so the console stayed EMPTY
            # until the run finished. -u is an argv flag -> survives pkexec.
            #
            # 2026-11-01: repointed from aba_throughput.py (GN630V telnet/iwpriv
            # ONLY — "connection refused" on the AC2100) to obj1_run.py, the proven
            # SSH/mt76 A/B/A path (SSHConn + aba_mt76). obj1_run reads host/user/
            # pass/iface/bssid/victim/channel from rig.conf by default, so the GUI
            # only needs to pass mon/alpha/out. --no-phone-start: the dashboard's
            # demo_live.sh already starts iperf3 on the phone.
            sys.executable, "-u", str(_TOOLS / "obj1_run.py"),
            "--mon", "{mon}",
            "--alpha", "{alpha}",  # attack strength passed to main_su (0=off .. 1=max)
            "--no-phone-start",
            "--out", str(_ROOT / "results" / "sessions" / "{run}_tput.csv"),
        ],
        "privileged": True,
        "description": "OFF->ON->OFF downlink throughput measurement vs the attack "
                       "(SSH/mt76 path, obj1_run.py). Reads the rig from rig.conf; "
                       "needs mon0 hearing + iperf3 -s on the phone (run demo_live.sh "
                       "or Setup Monitor first).",
    },
    "train_detector": {
        "label": "Validate Detector (OBJ3)",
        "cmd": [
            "python", str(_TOOLS / "train_telemetry.py"), "{csv}",
        ],
        "privileged": False,
        "description": "Train + leave-one-run-out validate the RandomForest anomaly "
                       "detector on self-calibrated router-telemetry features (retry/PER/"
                       "RSSI/throughput). Pass one or more labelled telemetry CSVs.",
    },
    "decode_features": {
        "label": "Decode BFI Features",
        "cmd": [
            "python", str(_TOOLS / "bfi_features.py"),
            "--pcap", "{pcap}",
            "--out", "{out}",
        ],
        "privileged": False,
        "description": "Decode HE beamforming reports from pcap to feature CSV.",
    },
}


def resolve_cmd(name: str, params: dict) -> list[str] | None:
    """Resolve {placeholders} in the command list. Returns None if unknown task."""
    entry = TASK_REGISTRY.get(name)
    if entry is None:
        return None
    return [c.format(**params) for c in entry["cmd"]]
