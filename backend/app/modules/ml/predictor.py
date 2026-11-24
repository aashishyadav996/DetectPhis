"""
ML prediction service.

Loads the model serialized by app/ml_pipeline/train.py and exposes a
single predict_phishing_probability() function for the risk engine.

If no model file exists yet (e.g. fresh clone, before anyone has run
training), this degrades gracefully rather than crashing the API —
consistent with the project's error-handling requirements. The risk
engine must treat a missing ML signal the same way it treats a missing
VirusTotal signal: continue with the remaining signals and say so.
"""
from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd

from app.modules.url_features.extractor import URLFeatures

MODEL_PATH = Path(__file__).parent / "model.joblib"

_model_bundle = None
_load_attempted = False


@dataclass
class MLPrediction:
    available: bool
    phishing_probability: float = 0.0
    model_name: str | None = None
    error: str | None = None


def _load_model():
    global _model_bundle, _load_attempted
    if _load_attempted:
        return _model_bundle
    _load_attempted = True
    if MODEL_PATH.exists():
        _model_bundle = joblib.load(MODEL_PATH)
    return _model_bundle


def predict_phishing_probability(features: URLFeatures) -> MLPrediction:
    bundle = _load_model()
    if bundle is None:
        return MLPrediction(
            available=False,
            error=(
                "No trained model found. Run "
                "`python -m app.ml_pipeline.train --data <your_dataset.csv>` "
                "from the backend/ directory first."
            ),
        )

    feature_columns = bundle["feature_columns"]
    values = [getattr(features, col) for col in feature_columns]
    values = [float(v) if isinstance(v, bool) else v for v in values]
    # Use a DataFrame with matching column names (not a bare list) so this
    # exactly mirrors the pandas-based input the model was trained on —
    # avoids sklearn's "X does not have valid feature names" warning and
    # any silent column-order mismatch.
    row = pd.DataFrame([values], columns=feature_columns)

    if bundle["needs_scaler"] and bundle["scaler"] is not None:
        row = bundle["scaler"].transform(row)

    try:
        proba = bundle["model"].predict_proba(row)[0][1]
    except Exception as exc:  # defensive: never let a prediction error crash /analyze
        return MLPrediction(available=False, error=f"ML prediction failed: {exc}")

    return MLPrediction(
        available=True,
        phishing_probability=round(float(proba), 4),
        model_name=bundle.get("model_name"),
    )
