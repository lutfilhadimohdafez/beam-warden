from tasks import resolve_cmd


def test_setup_monitor_uses_nmcli_not_systemctl():
    cmd = resolve_cmd("setup_monitor", {"mon": "mon0", "channel": "48", "bw": "80"})
    joined = " ".join(cmd)
    assert "systemctl stop" not in joined
    assert "nmcli device set wlan1 managed no" in joined


def test_setup_monitor_has_deaf_card_check():
    # must verify the radio actually hears packets, not run blind on a wedged card
    cmd = resolve_cmd("setup_monitor", {"mon": "mon0", "channel": "48", "bw": "80"})
    joined = " ".join(cmd)
    assert "/sys/class/net/mon0/statistics/rx_packets" in joined
    assert "DEAF CARD" in joined
