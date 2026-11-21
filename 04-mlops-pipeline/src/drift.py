"""Population Stability Index (PSI) drift detection.

PSI = sum((actual% - expected%) * ln(actual% / expected%)) over bins built on
the reference (training) distribution.
Rule of thumb: < 0.1 stable, 0.1-0.25 moderate shift, > 0.25 significant -> retrain.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

EPS = 1e-6


def psi(expected: np.ndarray, actual: np.ndarray, bins: int = 10) -> float:
    expected = np.asarray(expected, dtype=float)
    actual = np.asarray(actual, dtype=float)
    edges = np.unique(np.quantile(expected, np.linspace(0, 1, bins + 1)))
    if len(edges) < 3:  # (near-)constant or binary feature: compare category shares
        cats = np.union1d(np.unique(expected), np.unique(actual))
        e = np.array([(expected == c).mean() for c in cats]) + EPS
        a = np.array([(actual == c).mean() for c in cats]) + EPS
    else:
        edges[0], edges[-1] = -np.inf, np.inf
        e = np.histogram(expected, edges)[0] / len(expected) + EPS
        a = np.histogram(actual, edges)[0] / len(actual) + EPS
    return float(np.sum((a - e) * np.log(a / e)))


def drift_report(reference: pd.DataFrame, current: pd.DataFrame, features: list[str],
                 threshold: float = 0.25) -> dict:
    scores = {f: round(psi(reference[f].to_numpy(), current[f].to_numpy()), 4) for f in features}
    drifted = sorted(f for f, s in scores.items() if s > threshold)
    return {"psi": scores, "drifted_features": drifted, "retrain_recommended": bool(drifted)}
