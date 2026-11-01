"""Exercise the actual shell watch loop with controlled counters, no hardware."""
import csv
from pathlib import Path
import shlex
import subprocess


def watch(tmp_path, activity, model='1', grace=0):
    source = Path(__file__).resolve().parents[1] / 'openwrt/beamwarden/files/beamwarden.sh'
    library = source.read_text().split('\ncase "$1" in')[0]
    conf = tmp_path / 'config'
    conf.write_text('')
    library = library.replace('CONF=/etc/beamwarden.conf', 'CONF=' + shlex.quote(str(conf)))
    baseline = tmp_path / 'baseline'
    baseline.write_text('0.1 0.01 0.01 0.01 30 2 -70 1\n')
    model_path = tmp_path / 'model.awk'
    model_path.write_text('{print "' + model + '"}\n')
    samples = tmp_path / 'samples'
    samples.write_text(''.join(f'0.2 0.02 20 -70 {n}\n' for n in activity))
    index = tmp_path / 'index'
    index.write_text('0')
    trace = tmp_path / 'trace.csv'
    # sample runs in a command-substitution subshell, so keep its index in a file.
    # Terminate only this test shell after the final fully processed window.
    harness = f'''
STATE={shlex.quote(str(baseline))}
MODEL={shlex.quote(str(model_path))}
TRACE_FILE={shlex.quote(str(trace))}
LOAD_GRACE_WINDOWS={grace}
ALERT_HOOK=/nonexistent-test-hook
ensure_iface() {{ return 0; }}
log() {{ :; }}
sample() {{
  n=$(cat {shlex.quote(str(index))})
  if [ "$n" -ge {len(activity)} ]; then kill -TERM "$$"; return 1; fi
  n=$((n+1)); echo "$n" > {shlex.quote(str(index))}
  sed -n "${{n}}p" {shlex.quote(str(samples))}
}}
cmd_watch
'''
    subprocess.run(['sh', '-c', library + harness], capture_output=True, timeout=10)
    return list(csv.reader(trace.open()))


def test_trace_distinguishes_gate_prediction_and_alert_persistence(tmp_path):
    rows = watch(tmp_path, [100, 4000, 4000, 100, 4000, 4000, 4000])
    assert [r[6] for r in rows] == ['below_activity_gate','scored','scored','below_activity_gate','scored','scored','scored']
    assert [r[8] for r in rows] == ['0','1','2','0','1','2','3']
    assert [r[9] for r in rows] == ['0','0','0','0','0','0','1']


def test_model_error_is_distinct_from_normal(tmp_path):
    row, = watch(tmp_path, [4000], model='invalid')
    assert row[6] == 'model_error'
    assert row[9] == '0'


def test_trace_storage_is_bounded(tmp_path):
    rows = watch(tmp_path, [100]*125, model='0')
    assert len(rows) == 120


def test_recent_load_scores_collapse_but_disarms_on_idle(tmp_path):
    rows=watch(tmp_path,[4000,1500,1500,2,1500],grace=2)
    assert [r[6] for r in rows]==['scored','recent_load','recent_load','below_activity_gate','below_activity_gate']
    assert rows[2][9]=='1'
