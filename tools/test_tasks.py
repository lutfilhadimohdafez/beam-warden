from tasks import resolve_cmd, TASK_REGISTRY


def test_setup_monitor_stops_services():
    cmd = resolve_cmd("setup_monitor", {"mon": "mon0", "channel": "48", "bw": "80", "bssid": "5c:02:14:b0:34:13"})
    joined = " ".join(cmd)
    assert "systemctl stop NetworkManager" in joined
    assert "wpa_supplicant" in joined


def test_setup_monitor_has_deaf_card_check():
    cmd = resolve_cmd("setup_monitor", {"mon": "mon0", "channel": "48", "bw": "80", "bssid": "5c:02:14:b0:34:13"})
    joined = " ".join(cmd)
    assert "/sys/class/net/mon0/statistics/rx_packets" in joined
    assert "DEAF CARD" in joined


def test_setup_monitor_auto_channel_scans():
    cmd = resolve_cmd("setup_monitor", {"mon": "mon0", "channel": "auto", "bw": "80", "bssid": "5c:02:14:b0:34:13"})
    joined = " ".join(cmd)
    assert 'iw dev "$VIF" scan' in joined   # scans the Alfa vif, not a hardcoded name
    assert "DETECTED" in joined


def test_setup_monitor_checks_card_before_building():
    # must identify the Alfa by driver and refuse to run if it is absent,
    # instead of blindly building mon0 on the wrong (Intel) radio.
    cmd = resolve_cmd("setup_monitor", {"mon": "mon0", "channel": "auto", "bw": "80", "bssid": "5c:02:14:b0:34:13"})
    joined = " ".join(cmd)
    assert "mt7921u" in joined
    assert "NO ALFA FOUND" in joined
    assert "exit 1" in joined
    assert "wlan1 del" not in joined        # no hardcoded-name teardown survives


def test_check_channel_exists_and_is_privileged():
    entry = TASK_REGISTRY["check_channel"]
    assert entry["privileged"] is True


def test_check_channel_references_bssid():
    cmd = resolve_cmd("check_channel", {"mon": "mon0", "bssid": "5c:02:14:b0:34:13"})
    joined = " ".join(cmd)
    assert "5c:02:14:b0:34:13" in joined


def test_reset_monitor_starts_services():
    cmd = resolve_cmd("reset_monitor", {"mon": "mon0"})
    joined = " ".join(cmd)
    assert "systemctl start NetworkManager" in joined


def test_restore_intel_restarts_nm_and_preserves_mon0():
    cmd = resolve_cmd("restore_intel", {"mon": "mon0"})
    joined = " ".join(cmd)
    assert "systemctl start NetworkManager" in joined   # bring the Intel back
    assert "device connect wlan0" in joined
    assert "mt7921u" in joined                           # fences the Alfa phy
    assert "mon0 preserved" in joined                    # reports mon0 survival


def test_recover_monitor_reloads_driver():
    cmd = resolve_cmd("recover_monitor", {"mon": "mon0", "channel": "36", "bw": "80", "bssid": "5c:02:14:b0:34:13"})
    joined = " ".join(cmd)
    assert "modprobe -r mt7921u" in joined
    assert "modprobe mt7921u" in joined
    assert "DEAF CARD" in joined
    assert "type monitor" in joined