"""Airflow DAG: validate -> drift check -> (re)train -> gate -> promote.

Retraining is triggered weekly, or early when drift exceeds the PSI threshold.
Each task is a thin wrapper over the tested functions in `src/`.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from airflow.decorators import dag, task

DEFAULT_ARGS = {"owner": "mlops", "retries": 2, "retry_delay": timedelta(minutes=5)}


@dag(
    dag_id="login_risk_training",
    schedule="@weekly",
    start_date=datetime(2026, 1, 1),
    catchup=False,
    default_args=DEFAULT_ARGS,
    tags=["mlops", "security"],
)
def login_risk_training():
    @task
    def validate_data() -> bool:
        from src.data import generate, validate

        report = validate(generate(5000, seed=int(datetime.utcnow().strftime("%Y%m%d"))))
        if not report.ok:
            raise ValueError(report.errors)
        return True

    @task
    def check_drift(_: bool) -> dict:
        from src.data import FEATURES, generate
        from src.drift import drift_report

        reference = generate(5000, seed=42)
        current = generate(5000, seed=43)  # in production: last 7 days of scored traffic
        return drift_report(reference, current, FEATURES)

    @task
    def train_and_gate(drift: dict) -> dict:
        from pathlib import Path

        from src.train import main

        rc = main(["--out", "/opt/airflow/artifacts/candidate", "--min-pr-auc", "0.5"])
        if rc != 0:
            raise RuntimeError("candidate model failed quality gate")
        return {"drift": drift, "candidate": str(Path("/opt/airflow/artifacts/candidate"))}

    @task
    def promote(result: dict) -> None:
        # In production: mlflow.MlflowClient().set_registered_model_alias("login-risk", "champion", version)
        print(f"promoting candidate at {result['candidate']}; drift={result['drift']['drifted_features']}")

    promote(train_and_gate(check_drift(validate_data())))


login_risk_training()
