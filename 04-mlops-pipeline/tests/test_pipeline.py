import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402
from src import serve  # noqa: E402
from src.data import FEATURES, generate, validate  # noqa: E402
from src.drift import drift_report, psi  # noqa: E402
from src.train import main as train_main  # noqa: E402


def test_generated_data_is_valid_and_reproducible():
    a, b = generate(1000, seed=1), generate(1000, seed=1)
    assert a.equals(b)
    assert validate(a).ok


def test_validation_catches_bad_data():
    df = generate(500)
    df.loc[0, "hour_of_day"] = 99
    df.loc[1, "ip_reputation"] = np.nan
    report = validate(df)
    assert not report.ok
    assert any("hour_of_day" in e for e in report.errors)
    assert any("nulls" in e for e in report.errors)


def test_psi_stable_vs_shifted():
    rng = np.random.default_rng(0)
    ref = rng.normal(0, 1, 5000)
    assert psi(ref, rng.normal(0, 1, 5000)) < 0.1
    assert psi(ref, rng.normal(1.5, 1, 5000)) > 0.25


def test_drift_report_flags_attacker_shift():
    report = drift_report(generate(4000, seed=1), generate(4000, seed=2, shift=1.0), FEATURES)
    assert report["retrain_recommended"]
    assert "geo_distance_km" in report["drifted_features"]


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    out = tmp_path_factory.mktemp("artifacts")
    assert train_main(["--out", str(out), "--rows", "4000", "--min-pr-auc", "0.3"]) == 0
    return out


def test_training_writes_card_and_passes_gate(trained):
    assert (trained / "model.pkl").exists()
    assert (trained / "model_card.json").exists()


def test_serving_predicts_and_rejects_tampered_model(trained):
    serve._state.clear()
    serve.load(trained)
    client = TestClient(serve.app)
    risky = {"failed_attempts_1h": 8, "hour_of_day": 3, "new_device": 1, "geo_distance_km": 6000, "ip_reputation": 0.9}
    safe = {"failed_attempts_1h": 0, "hour_of_day": 14, "new_device": 0, "geo_distance_km": 2, "ip_reputation": 0.05}
    r1, r2 = client.post("/predict", json=risky).json(), client.post("/predict", json=safe).json()
    assert r1["risk_score"] > r2["risk_score"]
    assert client.post("/predict", json={**safe, "hour_of_day": 30}).status_code == 422

    (trained / "model.pkl").write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="checksum"):
        serve.load(trained)
