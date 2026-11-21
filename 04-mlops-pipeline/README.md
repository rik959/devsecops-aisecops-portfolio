# 04 · MLOps Pipeline: Login-Risk Model

An end-to-end MLOps pipeline for a **security ML use case**: scoring login
attempts for account-takeover risk so risky ones get step-up authentication.

```
generate/ingest ─► validate ─► drift check (PSI) ─► train ─► quality gate ─► model card + checksum ─► serve
      └──────────────── Airflow DAG (weekly, or early on drift) ────────────────┘
```

| Stage | What it does | File |
| --- | --- | --- |
| Data | Seeded synthetic dataset (failed attempts, hour, new device, geo distance, IP reputation) | `src/data.py` |
| Validation | Schema, ranges, nulls, label-rate sanity: fails fast before training | `src/data.py` |
| Drift | Population Stability Index per feature; > 0.25 recommends retraining | `src/drift.py` |
| Training | Gradient boosting with class weighting; operating threshold chosen for a target precision | `src/train.py` |
| Gate | Exits non-zero if PR-AUC < `--min-pr-auc`, so CI blocks weak models | `src/train.py` |
| Tracking | Logs to MLflow when `MLFLOW_TRACKING_URI` is set; always writes `model_card.json` | `src/train.py` |
| Serving | FastAPI `/predict`; **verifies the model's SHA-256 before unpickling** | `src/serve.py` |
| Orchestration | Airflow DAG: validate → drift → train → gate → promote | `dags/login_risk_pipeline.py` |

## Run it

```bash
pip install -r requirements.txt pytest
pytest -q                                  # 6 tests
python -m src.train --out artifacts        # train + gate + model card
uvicorn src.serve:app --port 8080
curl -s localhost:8080/predict -H 'content-type: application/json' \
  -d '{"failed_attempts_1h":8,"hour_of_day":3,"new_device":1,"geo_distance_km":6000,"ip_reputation":0.9}'
```

Typical metrics on the synthetic data: PR-AUC ≈ 0.59, ROC-AUC ≈ 0.84, at
about 13% positives. **PR-AUC is the headline metric** because the positive
class is rare and ROC-AUC flatters imbalanced problems.

## Design choices worth discussing in an interview

- **Threshold chosen for precision, not 0.5:** analysts and users pay for every false alarm, so the operating point is a business decision.
- **Pickle integrity check:** unpickling an untrusted file runs arbitrary code. The checksum in the model card is a minimal control; next steps are signing the artifact and switching to ONNX or skops.
- **Drift is a trigger, not a verdict:** PSI flags *input* shift. Label-based performance monitoring is still needed to catch concept drift.
- **Intended use is in the model card:** "step-up auth / review, not automatic lockout", so a downstream team can't misuse the model silently.
