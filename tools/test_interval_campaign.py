from collect_interval_campaign import label_windows


def test_labels_exclude_windows_overlapping_phase_boundaries():
    phases=[dict(start=10,end=20,label='normal',condition='baseline'),
            dict(start=20,end=30,label='attack',condition='attack')]
    lines=[f'{t},0.2,0.01,30,-70,4000,scored,0,0,0,1' for t in (10,11,12,19,20,21,22,30,31)]
    rows=label_windows(lines,phases)
    assert [(r['timestamp'],r['label']) for r in rows]==[(12,'normal'),(19,'normal'),(20,'normal'),(22,'attack'),(30,'attack')]
