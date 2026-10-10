"""Task registry for Mission Control — single source of truth for CLI tasks.

ponytail: predefined registry only — NO arbitrary command exec.
"""

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_TOOLS = Path(__file__).resolve().parent
_BINARY = _ROOT / "BeamCraft_AE" / "main_su"

TASK_REGISTRY: dict[str, dict] = {
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
            # REAL fence: stop NetworkManager + wpa_supplicant so they cannot
            # re-grab the Alfa phy.  Ethernet (enp0s20...) stays up because a
            # clean systemctl stop does NOT deconfigure already-configured links.
            # Belt-and-suspenders: kill any standalone supplicant on wlan1.
            # Moved OUTSIDE the monitor-exists guard so a re-run re-asserts.
            "systemctl stop NetworkManager wpa_supplicant 2>/dev/null; "
            "pkill -f 'wpa_supplicant.*wlan1' 2>/dev/null; "
            # idempotent: only build the monitor iface when it is NOT already up.
            "if ! iw dev {mon} info 2>/dev/null | grep -q 'type monitor'; then "
            "  PHY=$(for p in /sys/class/ieee80211/phy*; do "
            "  [ \"$(basename $(readlink -f $p/device/driver))\" = mt7921u ] && basename $p; done); "
            "  iw dev {mon} del 2>/dev/null; iw dev wlan1 del 2>/dev/null; "
            "  iw phy $PHY interface add {mon} type monitor; "
            "fi; "
            "ip link set {mon} up; "
            # auto channel detection: scan wlan1 (still exists here) for the
            # target BSSID before converting to mon0.
            "if [ '{channel}' = 'auto' ]; then "
            "  ip link set wlan1 up 2>/dev/null; "
            "  SCAN=$(iw dev wlan1 scan 2>/dev/null); "
            "  FREQ=$(echo \"$SCAN\" | grep -A5 'BSS {bssid}' | grep 'freq:' | head -1 | grep -oP '\\d+'); "
            "  WIDTH_RAW=$(echo \"$SCAN\" | grep -A30 'BSS {bssid}' | grep -i 'channel width' | head -1); "
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
            # bandwidth-aware retune
            "case $W in "
            "20) SPEC=HT20;; "
            "40) q=$(( $CH / 4 )); [ $((q % 2)) -eq 1 ] && SPEC=HT40+ || SPEC=HT40-;; "
            "*) SPEC=80MHz;; "
            "esac; "
            "iw dev {mon} set channel $CH $SPEC 2>/dev/null; "
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
            "case {bw} in "
            "20) SPEC=HT20;; "
            "40) q=$(( {channel} / 4 )); [ $((q % 2)) -eq 1 ] && SPEC=HT40+ || SPEC=HT40-;; "
            "*) SPEC=80MHz;; "
            "esac; "
            "iw dev {mon} set channel {channel} $SPEC 2>/dev/null; "
            "iw dev {mon} info | grep -E 'type|channel'; "
            "R1=$(cat /sys/class/net/{mon}/statistics/rx_packets 2>/dev/null || echo 0); "
            "sleep 3; "
            "R2=$(cat /sys/class/net/{mon}/statistics/rx_packets 2>/dev/null || echo 0); "
            "if [ \"$R2\" -gt \"$R1\" ]; then "
            "  echo \"RADIO OK: heard $((R2-R1)) packets in 3s\"; "
            "else "
            "  echo \"*** DEAF CARD: 0 packets in 3s on ch{channel} -- mt7921u wedged. "
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
        ],
        "privileged": True,
        "description": "Launch BeamCraft beamforming-spoofing attack.",
    },
    "train_detector": {
        "label": "Train Detector",
        "cmd": [
            "python", str(_TOOLS / "train_detector.py"),
            "--csv", "{csv}",
        ],
        "privileged": False,
        "description": "Train IsolationForest anomaly detector on normal telemetry CSV.",
    },
    "gen_synthetic": {
        "label": "Generate Synthetic Attack",
        "cmd": [
            "python", str(_TOOLS / "make_synthetic_attack.py"),
            "--normal", str(_ROOT / "data" / "normal_iperf.csv"),
            "--out", str(_ROOT / "data" / "synthetic_attack.csv"),
        ],
        "privileged": False,
        "description": "Generate synthetic attack telemetry for training.",
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
