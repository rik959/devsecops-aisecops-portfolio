"""Training step with a quality gate and experiment tracking.

    python -m src.train --out artifacts/ --min-pr-auc 0.5

* validates data before training (fail fast on bad data),
* time-agnostic stratified split, gradient boosting model,
* picks an operating threshold for a target precision,
* logs to MLflow if it is installed / MLFLOW_TRACKING_URI is set, otherwise
  writes the same metrics + params to artifacts/ (so CI needs no server),
* refuses to "register" a model below the PR-AUC gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score
from sklearn.model_selection import train_test_split

from .data import FEATURES, TARGET, generate, validate

PARAMS = {"learning_rate": 0.08, "max_iter": 300, "max_leaf_nodes": 31,
          "l2_regularization": 1.0, "class_weight": "balanced", "random_state": 7}


def pick_threshold(y_true: np.ndarray, scores: np.ndarray, target_precision: float) -> float:
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    ok = np.where(precision[:-1] >= target_precision)[0]
    return float(thresholds[ok[0]]) if len(ok) else 0.5


def train(n_rows: int = 8000, seed: int = 42, target_precision: float = 0.6) -> tuple[object, dict]:
    df = generate(n_rows, seed=seed)
    report = validate(df)
    if not report.ok:
        raise ValueError("data validation failed: " + "; ".join(report.errors))

    X_train, X_test, y_train, y_test = train_test_split(
        df[FEATURES], df[TARGET], test_size=0.25, stratify=df[TARGET], random_state=seed
    )
    model = HistGradientBoostingClassifier(**PARAMS).fit(X_train, y_train)
    scores = model.predict_proba(X_test)[:, 1]
    threshold = pick_threshold(y_test.to_numpy(), scores, target_precision)
    preds = scores >= threshold

    tp = int(((preds == 1) & (y_test == 1)).sum())
    metrics = {
        "pr_auc": round(float(average_precision_score(y_test, scores)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, scores)), 4),
        "threshold": round(threshold, 4),
        "precision_at_threshold": round(tp / max(int(preds.sum()), 1), 4),
        "recall_at_threshold": round(tp / max(int(y_test.sum()), 1), 4),
        "positive_rate": round(float(df[TARGET].mean()), 4),
        "n_train": len(X_train),
        "n_test": len(X_test),
    }
    return model, metrics


def _log_mlflow(params: dict, metrics: dict, model_path: Path) -> bool:
    if not os.getenv("MLFLOW_TRACKING_URI"):
        return False
    try:
        import mlflow
    except ImportError:
        return False
    mlflow.set_experiment("login-risk")
    with mlflow.start_run():
        mlflow.log_params(params)
        mlflow.log_metrics({k: v for k, v in metrics.items() if isinstance(v, (int, float))})
        mlflow.log_artifact(str(model_path))
    return True


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("artifacts"))
    ap.add_argument("--rows", type=int, default=8000)
    ap.add_argument("--min-pr-auc", type=float, default=0.5)
    args = ap.parse_args(argv)

    model, metrics = train(args.rows)
    args.out.mkdir(parents=True, exist_ok=True)
    model_path = args.out / "model.pkl"
    model_path.write_bytes(pickle.dumps(model))
    digest = hashlib.sha256(model_path.read_bytes()).hexdigest()

    card = {
        "name": "login-risk",
        "features": FEATURES,
        "params": PARAMS,
        "metrics": metrics,
        "model_sha256": digest,
        "gate": {"min_pr_auc": args.min_pr_auc, "passed": metrics["pr_auc"] >= args.min_pr_auc},
        "intended_use": "Rank login attempts for step-up auth / analyst review. Not for automatic account lockout.",
    }
    (args.out / "model_card.json").write_text(json.dumps(card, indent=2))
    tracked = _log_mlflow(PARAMS, metrics, model_path)
    print(json.dumps({"metrics": metrics, "mlflow": tracked, "gate_passed": card["gate"]["passed"]}, indent=2))
    return 0 if card["gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
