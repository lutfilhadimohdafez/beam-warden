from tasks import resolve_cmd


def test_setup_monitor_uses_nmcli_not_systemctl():
    cmd = resolve_cmd("setup_monitor", {"mon": "mon0", "channel": "48"})
    joined = " ".join(cmd)
    assert "systemctl stop" not in joined
    assert "nmcli device set wlan1 managed no" in joined
