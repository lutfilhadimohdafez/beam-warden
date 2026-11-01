#!/usr/bin/env python3
"""Freeze training on runs 1–2 and evaluate actual exported AWK on run 3.

Candidate output only. No automatic router deployment or threshold tuning.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import subprocess

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, balanced_accuracy_score, confusion_matrix, precision_score, recall_score
from export_model import render_forest

METRICS=['retry_rate','tx_failure_fraction','throughput_tx_mbps','rssi0']


def features(row, baseline):
    result=[]
    for i,metric in enumerate(METRICS):
        mean,std=baseline[2*i:2*i+2]
        value=float(row[metric])
        result.extend([value/(mean+1e-6),(value-mean)/(std+1e-6)])
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('campaign',type=Path)
    ap.add_argument('--out-dir',type=Path)
    a=ap.parse_args(); root=a.campaign
    output=a.out_dir or Path(__file__).resolve().parents[1]/'models/candidates'/root.name
    output.mkdir(parents=True,exist_ok=True)
    baselines=json.loads((root/'baselines.json').read_text())
    manifest=json.loads((root/'manifest.json').read_text())
    if len(manifest)<3 or any(r['injections_reported']<=0 for r in manifest):
        raise ValueError('Need three complete runs with reported injections; retain failures separately')
    runs=[]; hashes={}
    for i in range(1,4):
        path=root/f'run_{i}.csv'
        meta=json.loads(path.with_suffix('.json').read_text())
        gate,persistence=map(int,meta['thresholds'].split())
        rows=list(csv.DictReader(path.open()))
        if any(r['feature_schema']!='interval-v2' for r in rows):raise ValueError('Schema mismatch')
        base=baselines[path.name]
        X=np.array([features(r,base) for r in rows]); y=np.array([int(r['label']=='attack') for r in rows])
        # Predeclared candidate policy: remember substantial load for at most
        # 10 windows; genuinely idle windows (<100 attempts) always disarm it.
        eligible=[]; armed=0
        for row in rows:
            activity=int(row['active_attempts'])
            if activity>=gate:armed=10; eligible.append(True)
            elif activity>=100 and armed>0:armed-=1; eligible.append(True)
            else:armed=0; eligible.append(False)
        active=np.array(eligible)
        runs.append((rows,X,y,active,persistence))
        hashes[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
    trainX=np.concatenate([run[1][run[3]] for run in runs[:2]])
    trainy=np.concatenate([run[2][run[3]] for run in runs[:2]])
    if len(set(trainy))<2:raise ValueError('Training has only one evaluated class')
    forest=RandomForestClassifier(n_estimators=60,max_depth=8,random_state=0,class_weight='balanced').fit(trainX,trainy)
    out=output/'candidate.awk';out.write_text(render_forest(forest))
    rows,X,y,active,persistence=runs[2]
    raw=''.join(' '.join(f'{v:.6g}' for v in values)+'\n' for values in X)
    predictions=np.array([int(x) for x in subprocess.check_output(['awk','-f',str(out)],input=raw,text=True).split()])
    hard=np.array([(np.array([int(tree.predict([values])[0]) for tree in forest.estimators_]).sum()>30) for values in X],dtype=int)
    if not np.array_equal(predictions,hard):raise ValueError('Exported scorer differs from hard-vote forest')
    hits=0; previous=None; alarms=[]
    for row,pred,evaluate in zip(rows,predictions,active):
        epoch=int(row['timestamp'])
        if previous is not None and epoch-previous>3:hits=0
        hits=hits+1 if evaluate and pred else 0
        if hits>=persistence:
            alarms.append(dict(timestamp=epoch,label=row['label']));hits=0
        previous=epoch
    if len(set(y[active]))<2:raise ValueError('Held-out run has only one evaluated class')
    report=dict(training_runs=[1,2],held_out_run=3,input_hashes=hashes,
                evaluated_normal=int(((y==0)&active).sum()),evaluated_attack=int(((y==1)&active).sum()),
                accuracy=float(accuracy_score(y[active],predictions[active])),
                balanced_accuracy=float(balanced_accuracy_score(y[active],predictions[active])),
                precision=float(precision_score(y[active],predictions[active],zero_division=0)),
                recall=float(recall_score(y[active],predictions[active],zero_division=0)),
                confusion_tn_fp_fn_tp=confusion_matrix(y[active],predictions[active],labels=[0,1]).ravel().tolist(),
                attack_coverage=float(active[y==1].mean()),majority_accuracy=float(max(y[active].mean(),1-y[active].mean())),
                alarms=alarms,awk_agreement=True,load_grace_windows=10,activity_floor=100,
                limitations='One rig, small held-out run; boundary-overlap windows excluded; persistence resets over excluded gaps. Not a cross-hardware accuracy claim.')
    report['passes_controlled_trial_gate']=bool(report['evaluated_normal']>=5 and report['evaluated_attack']>=5 and
        report['accuracy']>=.55 and report['accuracy']>report['majority_accuracy'] and report['balanced_accuracy']>=.7 and
        report['recall']>=.7 and report['attack_coverage']>=.5 and
        any(x['label']=='attack' for x in alarms) and not any(x['label']=='normal' for x in alarms))
    (output/'evaluation.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2));print('CANDIDATE',out)


if __name__=='__main__':main()
