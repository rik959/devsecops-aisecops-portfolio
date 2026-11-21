"""Synthetic login-risk dataset + data validation.

Use case: score login attempts for account-takeover risk (a security ML
problem). Data is synthetic and seeded so the pipeline is reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

FEATURES = ["failed_attempts_1h", "hour_of_day", "new_device", "geo_distance_km", "ip_reputation"]
TARGET = "is_takeover"

SCHEMA: dict[str, tuple[float, float]] = {
    "failed_attempts_1h": (0, 1000),
    "hour_of_day": (0, 23),
    "new_device": (0, 1),
    "geo_distance_km": (0, 20_050),  # half Earth's circumference
    "ip_reputation": (0, 1),
}


def generate(n: int = 5000, seed: int = 42, shift: float = 0.0) -> pd.DataFrame:
    """`shift` > 0 simulates attacker behaviour drifting (more distant, riskier IPs)."""
    rng = np.random.default_rng(seed)
    df = pd.DataFrame(
        {
            "failed_attempts_1h": rng.poisson(0.5 + shift * 2, n).clip(0, 1000),
            "hour_of_day": rng.integers(0, 24, n),
            "new_device": rng.binomial(1, 0.15 + shift * 0.2, n),
            "geo_distance_km": rng.exponential(150 + shift * 800, n).clip(0, 20_050),
            "ip_reputation": rng.beta(2, 8 - min(shift * 3, 6), n),
        }
    )
    night = ((df.hour_of_day < 6) | (df.hour_of_day > 22)).astype(int)
    logit = (
        -7.0
        + 1.4 * df.failed_attempts_1h
        + 2.5 * df.new_device
        + 0.006 * df.geo_distance_km
        + 8.0 * df.ip_reputation
        + 1.2 * night
    )
    df[TARGET] = rng.binomial(1, 1 / (1 + np.exp(-logit)))
    return df


@dataclass
class ValidationReport:
    ok: bool
    errors: list[str]


def validate(df: pd.DataFrame, require_target: bool = True) -> ValidationReport:
    errors: list[str] = []
    cols = FEATURES + ([TARGET] if require_target else [])
    missing = [c for c in cols if c not in df.columns]
    if missing:
        return ValidationReport(False, [f"missing columns: {missing}"])
    for col, (lo, hi) in SCHEMA.items():
        nulls = int(df[col].isna().sum())
        if nulls:
            errors.append(f"{col}: {nulls} nulls")
        bad = int(((df[col] < lo) | (df[col] > hi)).sum())
        if bad:
            errors.append(f"{col}: {bad} values outside [{lo}, {hi}]")
    if require_target:
        rate = df[TARGET].mean()
        if not 0.001 <= rate <= 0.5:
            errors.append(f"{TARGET}: positive rate {rate:.4f} outside expected [0.001, 0.5]")
    if len(df) < 100:
        errors.append(f"only {len(df)} rows; need at least 100")
    return ValidationReport(not errors, errors)
