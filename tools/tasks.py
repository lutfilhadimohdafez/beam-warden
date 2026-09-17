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
            "nmcli device set wlan1 managed no; "
            "PHY=$(for p in /sys/class/ieee80211/phy*; do "
            "[ \"$(basename $(readlink -f $p/device/driver))\" = mt7921u ] && basename $p; done); "
            "iw dev {mon} del 2>/dev/null; iw dev wlan1 del 2>/dev/null; "
            "iw phy $PHY interface add {mon} type monitor; "
            "ip link set {mon} up; "
            "iw dev {mon} set channel {channel}; "
            "iw dev {mon} info | grep -E 'type|channel'",
        ],
        "privileged": True,
        "description": "Stop NetworkManager, create monitor interface, set channel.",
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
            "tshark", "-i", "{mon}", "-w",
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
