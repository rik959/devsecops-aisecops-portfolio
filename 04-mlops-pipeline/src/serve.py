"""Model serving API. Verifies the model file's SHA-256 against the model card
before unpickling, because loading an untrusted pickle executes code."""

from __future__ import annotations

import hashlib
import json
import os
import pickle
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .data import FEATURES

ARTIFACTS = Path(os.getenv("MODEL_DIR", "artifacts"))
app = FastAPI(title="login-risk model", version="1.0.0")
_state: dict = {}


def load(model_dir: Path = ARTIFACTS) -> None:
    card = json.loads((model_dir / "model_card.json").read_text())
    blob = (model_dir / "model.pkl").read_bytes()
    if hashlib.sha256(blob).hexdigest() != card["model_sha256"]:
        raise RuntimeError("model checksum mismatch: refusing to load")
    _state["model"] = pickle.loads(blob)  # noqa: S301 - integrity verified above
    _state["card"] = card


class LoginEvent(BaseModel):
    failed_attempts_1h: int = Field(ge=0, le=1000)
    hour_of_day: int = Field(ge=0, le=23)
    new_device: int = Field(ge=0, le=1)
    geo_distance_km: float = Field(ge=0, le=20_050)
    ip_reputation: float = Field(ge=0, le=1)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "model_loaded": "model" in _state}


@app.post("/predict")
def predict(event: LoginEvent) -> dict:
    if "model" not in _state:
        try:
            load()
        except FileNotFoundError as exc:
            raise HTTPException(503, "model not trained yet") from exc
    row = pd.DataFrame([event.model_dump()])[FEATURES]
    score = float(_state["model"].predict_proba(row)[0, 1])
    threshold = _state["card"]["metrics"]["threshold"]
    return {"risk_score": round(score, 4), "step_up_auth": score >= threshold, "threshold": threshold}
