"""Pure-logic tests for aba_throughput (no hardware, no network)."""

import statistics

from aba_throughput import parse_iperf3_json, phase_stats_tput, verdict_tput


def make_phase(tput, rssi):
    return {"tput": list(tput), "rssi": list(rssi)}


def test_confirmed_drop_steady_rssi():
    off1 = make_phase([100.0, 100.0, 100.0], [-66, -66, -66])
    on = make_phase([40.0, 40.0, 40.0], [-66, -66, -66])
    off2 = make_phase([100.0, 100.0, 100.0], [-66, -66, -66])
    label, detail = verdict_tput(off1, on, off2, inject_count=12, drift_tol=3.0)
    assert label == "ATTACK CONFIRMED"
    assert "60.0%" in detail
    assert "100" in detail and "40" in detail
    assert "OBJ1 51%: CLEARS" in detail
    assert "OBJ2 15%: CLEARS" in detail


def test_confound_when_baseline_drifts():
    off1 = make_phase([100.0, 100.0], [-66, -66])
    on = make_phase([40.0, 40.0], [-63, -63])
    off2 = make_phase([100.0, 100.0], [-60, -60])
    label, _ = verdict_tput(off1, on, off2, inject_count=12, drift_tol=3.0)
    assert label == "CONFOUNDED"


def test_no_effect_flat_tput():
    off1 = make_phase([100.0, 100.0, 100.0], [-66, -66, -66])
    on = make_phase([98.0, 98.0, 98.0], [-66, -66, -66])
    off2 = make_phase([100.0, 100.0, 100.0], [-66, -66, -66])
    label, _ = verdict_tput(off1, on, off2, inject_count=12, drift_tol=3.0)
    assert label == "NO EFFECT"


def test_inconclusive_without_inject():
    off1 = make_phase([100.0, 100.0], [-66, -66])
    on = make_phase([40.0, 40.0], [-66, -66])
    off2 = make_phase([100.0, 100.0], [-66, -66])
    label, _ = verdict_tput(off1, on, off2, inject_count=0, drift_tol=3.0)
    assert label == "INCONCLUSIVE"


def test_jitter_within_phases_is_tolerated():
    off1 = make_phase([100.0, 100.0, 100.0], [-70, -66, -72])
    on = make_phase([40.0, 40.0, 40.0], [-68, -72, -70])
    off2 = make_phase([100.0, 100.0, 100.0], [-71, -65, -69])
    label, detail = verdict_tput(off1, on, off2, inject_count=8, drift_tol=3.0)
    assert label == "ATTACK CONFIRMED"
    assert "60.0%" in detail


def test_inconclusive_missing_tput():
    off1 = make_phase([], [-66, -66])
    on = make_phase([40.0], [-66])
    off2 = make_phase([100.0], [-66])
    label, _ = verdict_tput(off1, on, off2, inject_count=5, drift_tol=3.0)
    assert label == "INCONCLUSIVE"


def test_parse_iperf3_json_intervals_to_mbps():
    data = {
        "intervals": [
            {"sum": {"bits_per_second": 1e8}},
            {"sum": {"bits_per_second": 2e8}},
        ],
    }
    assert parse_iperf3_json(data) == [100.0, 200.0]


def test_parse_iperf3_json_skips_missing_and_empty():
    data = {
        "intervals": [
            {"sum": {"bits_per_second": 1e8}},
            {"sum": {}},
            {},
            {"sum": {"bits_per_second": 5e7}},
        ],
    }
    assert parse_iperf3_json(data) == [100.0, 50.0]
    assert parse_iperf3_json({}) == []
    assert parse_iperf3_json({"intervals": []}) == []


def test_phase_stats_tput_medians_and_counts():
    phase = make_phase([100.0, 40.0, 140.0], [-70, -60, -80, 0])
    st = phase_stats_tput(phase)
    assert st["median_tput"] == 100.0
    assert st["tput_min"] == 40.0
    assert st["tput_max"] == 140.0
    assert st["median_rssi"] == -70
    assert st["rssi_range"] == 20
    assert st["n_tput"] == 3
    assert st["n_rssi"] == 3  # rssi==0 parse-miss skipped


def test_phase_stats_tput_guards_empty():
    st = phase_stats_tput({"tput": [], "rssi": []})
    assert st["median_tput"] is None
    assert st["tput_min"] is None
    assert st["tput_max"] is None
    assert st["median_rssi"] is None
    assert st["rssi_range"] == 0
    assert st["n_tput"] == 0
    assert st["n_rssi"] == 0


def test_phase_stats_tput_median_even_split():
    st = phase_stats_tput(make_phase([10.0, 20.0, 30.0, 40.0], [-66, -70]))
    assert st["median_tput"] == statistics.median([10.0, 20.0, 30.0, 40.0])
    assert st["median_rssi"] == statistics.median([-66, -70])
