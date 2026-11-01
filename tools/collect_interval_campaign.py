#!/usr/bin/env python3
"""Collect bounded lab trials and label actual router windows by recorded phases.

No phone UI automation. Existing detector/model and thresholds are preserved.
Requires the lab phone's iperf3 server and notifications disabled on the router.
"""
import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

from mt76_telemetry import SSHConn
from rig import RIG

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ['timestamp','feature_schema','label','condition','retry_rate',
          'tx_failure_fraction','throughput_tx_mbps','rssi0','active_attempts']


def label_windows(lines, phases):
    """Exclude the two seconds bordering a phase transition (window overlap)."""
    rows=[]
    for line in lines:
        values=line.split(',')
        if len(values)!=11: continue
        epoch=int(values[0])
        phase=next((p for p in phases if p['start']+2 <= epoch <= p['end']),None)
        if phase is None: continue
        rows.append(dict(timestamp=epoch,feature_schema='interval-v2',
                         label=phase['label'],condition=phase['condition'],
                         retry_rate=values[1],tx_failure_fraction=values[2],
                         throughput_tx_mbps=values[3],rssi0=values[4],active_attempts=values[5]))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--runs',type=int,default=3)
    args=ap.parse_args()
    if os.geteuid()!=0:ap.error('run via pkexec (monitor preparation requires root)')
    if not 1<=args.runs<=5:ap.error('runs must be 1–5')
    def stop(*_):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,stop)
    dest=ROOT/'results'/'interval_campaigns'/time.strftime('%Y%m%d_%H%M%S')
    dest.mkdir(parents=True)
    owner=int(os.environ.get('PKEXEC_UID',ROOT.stat().st_uid))
    os.chown(dest,owner,ROOT.stat().st_gid)
    baselines={}; index=[]
    for i in range(args.runs):
        with SSHConn(RIG['ROUTER_HOST'],RIG['ROUTER_USER'],RIG['ROUTER_PASS']) as c:
            if c.run('. /etc/beamwarden.conf; echo ${NOTIFY_ENABLED:-1}')!='0':
                raise RuntimeError('Disable notifications before diagnostic collection')
            c.run('/etc/init.d/beamwarden running')
            if c.run('. /etc/beamwarden.conf; echo "$TRACE_FILE"')!='/tmp/beamwarden.trace':
                raise RuntimeError('Bounded router trace must be enabled')
        print(f'TRIAL {i+1}/{args.runs}: fresh calibration and two bounded bursts',flush=True)
        started=dt.datetime.now().astimezone()
        proc=subprocess.Popen([sys.executable,'-u',str(ROOT/'tools/live_demo.py'),'--power','550'],
                              stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,start_new_session=True)
        try:
            output,_=proc.communicate(timeout=125)
            result=subprocess.CompletedProcess(proc.args,proc.returncode,output)
        except BaseException:
            proc.send_signal(signal.SIGTERM)
            try: output,_=proc.communicate(timeout=12)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid,signal.SIGKILL)
                subprocess.run(['pkill','-KILL','-x','main_su'],capture_output=True)
                output,_=proc.communicate(timeout=3)
            (dest/f'run_{i+1}.log').write_text(output or '')
            raise
        (dest/f'run_{i+1}.log').write_text(result.stdout)
        print(result.stdout[-2200:],flush=True)
        if result.returncode:raise RuntimeError(f'Trial failed; evidence retained at {dest}')
        phases=[]; end=None; csv_path=None
        for line in result.stdout.splitlines():
            m=re.match(r'\[(\d\d:\d\d:\d\d)\] (?:phase (\S+) \((normal|attack)\)|teardown)',line)
            if m:
                stamp=dt.datetime.combine(started.date(),dt.time.fromisoformat(m[1]),started.tzinfo)
                if stamp.timestamp()<started.timestamp()-3600:stamp+=dt.timedelta(days=1)
                epoch=int(stamp.timestamp())
                if phases:phases[-1]['end']=epoch
                if m[2]:phases.append(dict(start=epoch,label=m[3],condition=m[2],end=epoch))
                else:end=epoch
            if line.startswith('BW_DEMO '):
                event=json.loads(line[8:])
                if event.get('csv'):csv_path=ROOT/event['csv']
        if not csv_path or not phases or end is None:raise RuntimeError('Incomplete phase provenance')
        with SSHConn(RIG['ROUTER_HOST'],RIG['ROUTER_USER'],RIG['ROUTER_PASS']) as c:
            trace=c.run('cat /tmp/beamwarden.trace').splitlines()
            thresholds=c.run('. /etc/beamwarden.conf; echo "${ACTIVE_MIN_PKTS:-3000} ${HITS_TO_ALARM:-3}"')
            model_hash=c.run('sha256sum /etc/beamwarden/model.awk').split()[0]
        rows=label_windows(trace,phases)
        path=dest/f'run_{i+1}.csv'
        with path.open('w') as f:
            w=csv.DictWriter(f,fieldnames=FIELDS);w.writeheader();w.writerows(rows)
        meta=json.loads(csv_path.with_suffix('.baseline.json').read_text())
        baselines[path.name]=meta['baseline']
        (dest/f'run_{i+1}.json').write_text(json.dumps(dict(phases=phases,trace=trace,calibration=meta,
                  source_csv=str(csv_path),thresholds=thresholds,model_hash=model_hash),indent=2))
        index.append(dict(csv=path.name,rows=len(rows),injections_reported=int(re.search(r'injections total:\s*(\d+)',result.stdout)[1]),
                          throughput_drop_pct=float(re.search(r'throughput drop:\s*([-\d.]+)%',result.stdout)[1]),
                          label_definition='attack means verified injection exposure, not proven degradation'))
        (dest/'baselines.json').write_text(json.dumps(baselines,indent=2))
        (dest/'manifest.json').write_text(json.dumps(index,indent=2))
        print('SAVED',path,'rows',len(rows),flush=True)
        if i+1<args.runs:time.sleep(3)
    print('CAMPAIGN_COMPLETE',dest,flush=True)


if __name__=='__main__':main()
