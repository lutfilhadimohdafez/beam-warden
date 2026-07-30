"""Sanity checks for attack_gui's source-patching, hardware-parsing, and
privileged-command-building logic. No hardware or GUI required."""
from pathlib import Path

from attack_gui import (
    extract_current,
    managed_mode_cmd,
    monitor_mode_cmd,
    parse_iw_dev,
    patch_source,
    phy_supports_monitor,
    run_everything_cmd,
)

SRC = Path(__file__).resolve().parent.parent / "BeamCraft_AE" / "main_su.cpp"

# Captured verbatim from `iw dev` / `iw phy phy0 info` on a real dev machine.
IW_DEV_SAMPLE = """phy#0
\tUnnamed/non-netdev interface
\t\twdev 0x3
\t\taddr a4:c3:f0:cb:fa:5d
\t\ttype P2P-device
\tInterface wlan0
\t\tifindex 5
\t\twdev 0x2
\t\taddr a4:c3:f0:cb:fa:5c
\t\tssid B-37-10_5G
\t\ttype managed
\t\tchannel 48 (5240 MHz), width: 80 MHz, center1: 5210 MHz
\t\ttxpower 22.00 dBm
"""

PHY_INFO_MONITOR_CAPABLE = """Wiphy phy0
\tSupported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * AP
\t\t * AP/VLAN
\t\t * monitor
\t\t * P2P-client
\t\t * P2P-GO
\t\t * P2P-device
\tBand 1:
\t\tCapabilities: 0x11ef
"""

PHY_INFO_NO_MONITOR = """Wiphy phy1
\tSupported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * AP
\tBand 1:
\t\tCapabilities: 0x0
"""


def test_extract_matches_known_defaults():
    current = extract_current(SRC.read_text())
    assert current["iface"] == "wlp88s0"
    assert current["ap_mac"] == "90:de:80:f1:4a:b2"
    assert current["victim_mac"] == "00:1D:43:20:16:6A"
    assert current["alpha"] == "1"


def test_patch_replaces_all_fields_and_is_idempotent():
    original = SRC.read_text()
    patched = patch_source(original, "wlan1mon", "AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB", "0.5")

    assert 'char *dev = "wlan1mon"' in patched
    assert 'pcap_create("wlan1mon", pcap_errbuf)' in patched
    assert "const float alpha = 0.5;" in patched
    assert "AA:AA:AA:AA:AA:AA" in patched and "BB:BB:BB:BB:BB:BB" in patched
    # only the filter_exp string itself must change — trailing `//` comments
    # on the same line (and the unrelated line-28 doc comment) are untouched
    import re as _re

    quoted = _re.search(r'char filter_exp\[\] = "(.*?)";', patched).group(1)
    assert "90:de:80:f1:4a:b2" not in quoted.lower()

    reextracted = extract_current(patched)
    assert reextracted["iface"] == "wlan1mon"
    assert reextracted["ap_mac"] == "AA:AA:AA:AA:AA:AA"
    assert reextracted["victim_mac"] == "BB:BB:BB:BB:BB:BB"
    assert reextracted["alpha"] == "0.5"

    # unrelated code must survive untouched
    assert "re_beamforming" in patched
    assert patched.count("\n") == original.count("\n")


def test_parse_iw_dev_skips_nonnetdev_and_keeps_real_iface():
    entries = parse_iw_dev(IW_DEV_SAMPLE)
    assert len(entries) == 1
    assert entries[0] == {"phy": "phy0", "iface": "wlan0", "mac": "a4:c3:f0:cb:fa:5c", "type": "managed"}


def test_phy_supports_monitor_true_and_false():
    assert phy_supports_monitor(PHY_INFO_MONITOR_CAPABLE) is True
    assert phy_supports_monitor(PHY_INFO_NO_MONITOR) is False
    assert phy_supports_monitor("") is False


def test_monitor_mode_cmd_includes_down_monitor_up_channel():
    cmd = monitor_mode_cmd("wlan1", "153")
    assert cmd == "ip link set wlan1 down && iw dev wlan1 set type monitor && ip link set wlan1 up && iw dev wlan1 set channel 153"


def test_monitor_mode_cmd_without_channel_skips_channel_step():
    cmd = monitor_mode_cmd("wlan1", "")
    assert "set channel" not in cmd


def test_managed_mode_cmd_reverses_monitor_mode():
    cmd = managed_mode_cmd("wlan1")
    assert cmd == "ip link set wlan1 down && iw dev wlan1 set type managed && ip link set wlan1 up"


def test_run_everything_chains_monitor_mode_then_execs_binary():
    cmd = run_everything_cmd("wlan1", "153", "/path/to/main_su")
    assert cmd.startswith(monitor_mode_cmd("wlan1", "153"))
    assert cmd.endswith("&& exec /path/to/main_su")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("OK")
