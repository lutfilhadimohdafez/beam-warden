"""Pure-logic tests for aba_measure (no hardware, no network)."""

import statistics

from aba_measure import count_injections, phase_stats, rssi_primary, verdict


def make_samples(mcs_list, rssi=-66):
    return [
        {
            "tx_mcs": m,
            "rssi0": rssi,
            "rssi1": rssi - 2,
            "rssi2": rssi - 3,
            "rssi3": rssi - 1,
        }
        for m in mcs_list
    ]


def make_jittery(mcs, rssi_list):
    """Phase where RSSI wobbles sample-to-sample (rssi_primary = rssi0 = r)."""
    return [
        {"tx_mcs": mcs, "rssi0": r, "rssi1": r - 2, "rssi2": r - 3, "rssi3": r - 1}
        for r in rssi_list
    ]


def test_confirmed_drop_steady_rssi():
    off1 = phase_stats(make_samples([9, 9, 9]))
    on = phase_stats(make_samples([4, 4, 4]))
    off2 = phase_stats(make_samples([9, 9, 9]))
    label, detail = verdict(off1, on, off2, inject_count=12, drift_tol=2.0)
    assert label == "ATTACK CONFIRMED"
    assert isinstance(detail, str) and detail


def test_confounded_when_baseline_drifts():
    # OFF baseline slid -70 -> -64 across the cycle = real drift (the exact
    # ghost the "-55%" result was riding on). Must be CONFOUNDED even though
    # MCS "dropped" on ON.
    off1 = phase_stats(make_samples([9, 9, 9], rssi=-70))
    on = phase_stats(make_samples([4, 4, 4], rssi=-67))
    off2 = phase_stats(make_samples([9, 9, 9], rssi=-64))
    label, detail = verdict(off1, on, off2, inject_count=12, drift_tol=3.0)
    assert label == "CONFOUNDED"
    assert "INVALID" in detail


def test_jitter_within_phases_is_tolerated():
    # RSSI wobbles 3-4 dB sample-to-sample but the per-phase MEDIAN is steady
    # at -66 across all three phases. This is a normal clamped handheld — it
    # must NOT confound. MCS drops 9->4 on ON and recovers -> ATTACK CONFIRMED.
    off1 = phase_stats(make_jittery(9, [-66, -64, -68, -66, -65]))
    on = phase_stats(make_jittery(4, [-67, -65, -66, -66, -64]))
    off2 = phase_stats(make_jittery(9, [-66, -67, -65, -66, -64]))
    label, _ = verdict(off1, on, off2, inject_count=12, drift_tol=3.0)
    assert label == "ATTACK CONFIRMED"


def test_no_effect_flat_mcs():
    off1 = phase_stats(make_samples([9, 9, 9]))
    on = phase_stats(make_samples([9, 9, 9]))
    off2 = phase_stats(make_samples([9, 9, 9]))
    label, detail = verdict(off1, on, off2, inject_count=5, drift_tol=2.0)
    assert label == "NO EFFECT"
    assert isinstance(detail, str) and detail


def test_inconclusive_without_inject():
    off1 = phase_stats(make_samples([9, 9, 9]))
    on = phase_stats(make_samples([4, 4, 4]))
    off2 = phase_stats(make_samples([9, 9, 9]))
    label, detail = verdict(off1, on, off2, inject_count=0, drift_tol=2.0)
    assert label == "INCONCLUSIVE"
    assert isinstance(detail, str) and detail


def test_rssi_primary():
    assert rssi_primary({"rssi0": -70, "rssi1": -66, "rssi2": -73, "rssi3": -68}) == -66


def test_phase_stats_median_odd_even_skips_none():
    s = phase_stats(make_samples([9, 9, 4]))
    assert s["median_mcs"] == 9
    assert s["n"] == 3

    s_even = phase_stats(make_samples([9, 4]))
    assert s_even["median_mcs"] == statistics.median([9, 4])

    s_none = phase_stats(make_samples([9, None, 4]))
    assert s_none["median_mcs"] == statistics.median([9, 4])
    assert s_none["n"] == 3

    assert s["rssi_range"] == 0


def test_phase_stats_ignores_rssi_zero_parse_miss():
    # a garbled telnet read yields rssi 0 (parse-miss sentinel); it must not
    # blow the RSSI range and spuriously confound a steady run.
    samples = make_samples([9, 9, 9], rssi=-66)
    samples.append({"tx_mcs": 9, "rssi0": 0, "rssi1": 0, "rssi2": 0, "rssi3": 0})
    s = phase_stats(samples)
    assert s["rssi_range"] == 0  # the 0-sample is dropped, real ones are steady
    assert s["rssi_max"] == -66  # strongest chain = rssi0 = -66


def test_count_injections_prefers_summary():
    lines = [
        "frame 0: ... INJECT=1 (ok)",
        "frame 50: ... INJECT=-1 (FAIL)",
        "=== SUMMARY ===",
        "injected OK: 916   inject FAIL: 3   skipped: 10",
    ]
    assert count_injections(lines) == 916


def test_count_injections_throttled_fallback_counts_ok_only():
    # SIGKILLed before SUMMARY: fall back to throttled lines, OK only.
    lines = [
        "frame 0: ... INJECT=1 (ok)",
        "frame 1: ... INJECT=1 (ok)",
        "frame 2: ... INJECT=-1 (FAIL)",
    ]
    assert count_injections(lines) == 2


def test_count_injections_all_failed_is_zero():
    lines = ["frame 0: ... INJECT=-1 (FAIL)", "frame 1: ... INJECT=-1 (FAIL)"]
    assert count_injections(lines) == 0
