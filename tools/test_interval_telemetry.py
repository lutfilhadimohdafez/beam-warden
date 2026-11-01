"""Counter semantics and station identity checks for real-data capture."""
import csv
from pathlib import Path
import subprocess
import pytest
from mt76_telemetry import parse_iw_station_dump, window_metrics
import export_model


def test_station_selection_never_merges_clients():
    text='Station aa:aa:aa:aa:aa:aa (on ap0)\n tx packets: 100\n tx failed: 20\nStation bb:bb:bb:bb:bb:bb (on ap0)\n tx packets: 500\n'
    assert parse_iw_station_dump(text)['packets_sent']==100
    selected=parse_iw_station_dump(text,'bb:bb:bb:bb:bb:bb')
    assert selected['packets_sent']==500 and selected['tx_failed']==0
    with pytest.raises(ValueError):parse_iw_station_dump(text,'cc:cc:cc:cc:cc:cc')


def test_interval_failure_fraction_matches_router_sample(tmp_path):
    prev=dict(bytes_sent=10_000_000_000,bytes_recv=100,packets_sent=1000,packets_recv=10,tx_fail=200,tx_failed=90)
    curr=dict(bytes_sent=10_004_000_000,bytes_recv=300,packets_sent=1100,packets_recv=20,tx_fail=225,tx_failed=95)
    metrics=window_metrics(prev,curr,2)
    assert metrics['tx_failure_fraction']==5/105
    assert metrics['tx_per_pct']==100*5/105
    source=Path(__file__).resolve().parents[1]/'openwrt/beamwarden/files/beamwarden.sh'
    library=source.read_text().split('\ncase "$1" in')[0].replace('CONF=/etc/beamwarden.conf','CONF=/nonexistent-test-config')
    index=tmp_path/'index';index.write_text('0')
    harness=f'''\nWIN=2
sleep() {{ :; }}
counters() {{
 n=$(cat '{index}'); echo $((n+1)) > '{index}'
 if [ "$n" = 0 ]; then echo '200 1000 90 10000000000 -70'; else echo '225 1100 95 10004000000 -70'; fi
}}
sample
'''
    values=subprocess.check_output(['sh','-c',library+harness],text=True).split()
    assert float(values[0])==pytest.approx(metrics['retry_rate'],abs=1e-5)
    assert float(values[1])==pytest.approx(metrics['tx_failure_fraction'],abs=1e-5)
    assert float(values[2])==metrics['throughput_tx_mbps']
    assert int(values[4])==metrics['active_attempts']


def test_counter_reset_cannot_become_a_normal_window():
    prev=dict(bytes_sent=100,bytes_recv=100,packets_sent=100,packets_recv=100,tx_fail=100,tx_failed=100)
    with pytest.raises(ValueError,match='reset'):window_metrics(prev,dict.fromkeys(prev,0),2)


def test_exporter_rejects_new_data_in_legacy_training(tmp_path):
    path=tmp_path/'capture.csv'
    path.write_text('feature_schema,label\ninterval-v2,normal\n')
    with pytest.raises(ValueError,match='do not mix'):export_model.load_run(path)


def test_baseline_unit_guard_catches_percent_vs_fraction():
    M=export_model.METRICS
    data={m:(1.0,0.1) for m in M}              # CSV normal rows (fraction-scale)
    export_model.check_baseline_units(data,{m:(1.1,0.1) for m in M},'ok.csv')  # same scale: no raise
    bad={m:(1.1,0.1) for m in M};bad[M[1]]=(100.0,1.0)   # PER 100x off = percent vs fraction
    with pytest.raises(ValueError,match='unit'):export_model.check_baseline_units(data,bad,'bad.csv')
