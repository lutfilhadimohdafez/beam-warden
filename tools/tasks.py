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
            # idempotent: only build the monitor iface when it is NOT already up.
            # Re-running while it exists used to tear it down (killing the live
            # BFI capture / a running attack) and error with "resource busy" /
            # "already exists". Now we just re-set the channel on the existing one.
            "if ! iw dev {mon} info 2>/dev/null | grep -q 'type monitor'; then "
            "  nmcli device set wlan1 managed no; "
            "  PHY=$(for p in /sys/class/ieee80211/phy*; do "
            "  [ \"$(basename $(readlink -f $p/device/driver))\" = mt7921u ] && basename $p; done); "
            "  iw dev {mon} del 2>/dev/null; iw dev wlan1 del 2>/dev/null; "
            "  iw phy $PHY interface add {mon} type monitor; "
            "fi; "
            "ip link set {mon} up; "  # always (idempotent path too): a DOWN iface captures nothing
            # bandwidth-aware retune: let iw derive the center from channel+width.
            # 40MHz secondary side (+/-) from channel parity in the UNII block
            # (36/44 -> HT40+, 40/48 -> HT40-). Match this to the AP's width or
            # the Alfa may capture nothing. May fail 'busy' if tshark holds it.
            "case {bw} in "
            "20) SPEC=HT20;; "
            "40) q=$(( {channel} / 4 )); [ $((q % 2)) -eq 1 ] && SPEC=HT40+ || SPEC=HT40-;; "
            "*) SPEC=80MHz;; "
            "esac; "
            "iw dev {mon} set channel {channel} $SPEC 2>/dev/null; "
            "iw dev {mon} info | grep -E 'type|channel'",
        ],
        "privileged": True,
        "description": "Create monitor iface if missing + set channel at the chosen bandwidth (idempotent).",
    },
    "reset_monitor": {
        "label": "Reset Monitor",
        "cmd": [
            "sh", "-c",
            # inverse of setup_monitor: tear down the monitor iface and hand the
            # Alfa back to managed WiFi + NetworkManager. ponytail: detect the
            # mt7921u phy (it re-enumerates after a modprobe reload), never hardcode phy0.
            "PHY=$(for p in /sys/class/ieee80211/phy*; do "
            "[ \"$(basename $(readlink -f $p/device/driver))\" = mt7921u ] && basename $p; done); "
            "iw dev {mon} del 2>/dev/null; "
            "iw dev wlan1 del 2>/dev/null; "
            "iw phy $PHY interface add wlan1 type managed 2>/dev/null; "
            "nmcli device set wlan1 managed yes 2>/dev/null; "
            "ip link set wlan1 up 2>/dev/null; "
            "iw dev wlan1 info | grep -E 'Interface|type'",
        ],
        "privileged": True,
        "description": "Tear down the monitor iface and restore wlan1 to managed WiFi + NetworkManager (inverse of Setup Monitor).",
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
