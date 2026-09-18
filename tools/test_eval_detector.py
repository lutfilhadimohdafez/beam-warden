#!/usr/bin/env python3
"""Tests for eval_detector.py — ponytail: minimal, fast, assert-based."""

import os
import tempfile

import joblib
import numpy as np
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = [
    "throughput_tx_mbps",
    "throughput_rx_mbps",
    "retry_rate",
    "tx_per_pct",
    "rx_per_pct",
    "rssi0",
    "rssi1",
    "rssi2",
    "rssi3",
    "tx_mcs",
    "tx_nss",
]


def _write_csv(path, rows):
    with open(path, "w") as f:
        f.write(",".join(FEATURES) + "\n")
        for r in rows:
            f.write(",".join(str(v) for v in r) + "\n")


def _make_tiny_model(tmpdir):
    rng = np.random.RandomState(42)
    n_train = 200
    X_n = rng.normal(loc=0.0, scale=1.0, size=(n_train, len(FEATURES)))
    scaler = StandardScaler().fit(X_n)
    model = IsolationForest(n_estimators=50, contamination=0.05, random_state=42)
    model.fit(scaler.transform(X_n))

    model_path = os.path.join(tmpdir, "test_model.joblib")
    joblib.dump({"model": model, "scaler": scaler, "features": FEATURES}, model_path)
    return model_path, model, scaler


@pytest.fixture()
def eval_env(tmp_path):
    """Ponytail: one fixture creates model + CSVs, yields paths."""
    model_path, _, _ = _make_tiny_model(str(tmp_path))

    rng = np.random.RandomState(123)
    normal_rows = rng.normal(loc=0.0, scale=1.0, size=(50, len(FEATURES))).tolist()
    normal_csv = str(tmp_path / "normal.csv")
    _write_csv(normal_csv, normal_rows)

    attack_rows = rng.normal(loc=8.0, scale=0.5, size=(50, len(FEATURES))).tolist()
    attack_csv = str(tmp_path / "attack.csv")
    _write_csv(attack_csv, attack_rows)

    return model_path, normal_csv, attack_csv


def test_detection_rate_high(eval_env):
    model_path, normal_csv, attack_csv = eval_env
    from eval_detector import evaluate

    lines = evaluate(model_path, normal_csv, attack_csv)
    tpr_line = [l for l in lines if "Detection Rate" in l][0]
    val = float(tpr_line.split(":")[1].split("(")[0].strip())
    assert val > 0.5, f"Detection rate too low: {val}"


def test_confusion_matrix_sums(eval_env):
    model_path, normal_csv, attack_csv = eval_env
    from eval_detector import evaluate

    lines = evaluate(model_path, normal_csv, attack_csv)
    cm_line = [l for l in lines if l.startswith("TN=")][0]
    parts = cm_line.split()
    vals = {p.split("=")[0]: int(p.split("=")[1]) for p in parts}
    total = vals["TN"] + vals["FP"] + vals["FN"] + vals["TP"]
    assert total == 100, f"CM sum {total} != 100 rows"


def test_evaluate_returns_list_of_strings(eval_env):
    model_path, normal_csv, attack_csv = eval_env
    from eval_detector import evaluate

    result = evaluate(model_path, normal_csv, attack_csv)
    assert isinstance(result, list)
    assert all(isinstance(l, str) for l in result)
    assert any("ROC-AUC" in l for l in result)


def test_main_writes_outfile(eval_env, capsys):
    model_path, normal_csv, attack_csv = eval_env
    from eval_detector import main
    import sys

    out_path = str(os.path.dirname(normal_csv)) + "/eval_out.txt"
    sys.argv = [
        "eval_detector",
        "--model", model_path,
        "--normal", normal_csv,
        "--attack", attack_csv,
        "--out", out_path,
    ]
    main()
    assert os.path.exists(out_path)
    with open(out_path) as f:
        content = f.read()
    assert "Detection Rate" in content


def test_missing_column_exits(tmp_path):
    """Ponytail: fail-loud on missing feature column."""
    model_path, _, _ = _make_tiny_model(str(tmp_path))

    bad_csv = str(tmp_path / "bad.csv")
    with open(bad_csv, "w") as f:
        f.write("throughput_tx_mbps,retry_rate\n")
        f.write("1.0,2.0\n")

    normal_csv = str(tmp_path / "normal.csv")
    _write_csv(normal_csv, [[0.0] * len(FEATURES)])

    from eval_detector import evaluate

    with pytest.raises(SystemExit) as exc_info:
        evaluate(model_path, normal_csv, bad_csv)
    assert exc_info.value.code == 1
