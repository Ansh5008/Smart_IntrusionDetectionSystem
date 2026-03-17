from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

try:
    from src.preprocess import prepare_inference_data
    from src.randomforest import load_bundle
except ModuleNotFoundError:
    import sys

    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from src.preprocess import prepare_inference_data
    from src.randomforest import load_bundle


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "models" / "model.pkl"
SCALER_PATH = PROJECT_ROOT / "models" / "scaler.pkl"


def _decode_label(raw_prediction: Any, label_encoder: Any | None) -> str:
    if label_encoder is not None and hasattr(label_encoder, "inverse_transform"):
        decoded = label_encoder.inverse_transform([int(raw_prediction)])[0]
        return str(decoded)

    if isinstance(raw_prediction, (int, float)):
        return "ATTACK" if int(raw_prediction) == 1 else "NORMAL"

    return str(raw_prediction)


def load_artifacts() -> dict[str, Any]:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Train the model first.")
    return load_bundle(model_path=MODEL_PATH, scaler_path=SCALER_PATH)


def predict(features: dict[str, Any] | list[float], artifacts: dict[str, Any] | None = None) -> str:
    bundle = artifacts if artifacts is not None else load_artifacts()
    model = bundle["model"]

    if isinstance(features, dict):
        input_df = pd.DataFrame([features])
    else:
        feature_columns = bundle["feature_columns"]
        if len(features) != len(feature_columns):
            raise ValueError(
                f"Expected {len(feature_columns)} features, got {len(features)}. "
                "Provide a feature dict keyed by training column names."
            )
        input_df = pd.DataFrame([features], columns=feature_columns)

    prepared = prepare_inference_data(
        input_df,
        feature_columns=bundle["feature_columns"],
        scaler=bundle.get("scaler"),
    )
    raw_pred = model.predict(prepared)[0]
    decoded = _decode_label(raw_pred, bundle.get("label_encoder"))

    if decoded.strip().lower() in {"benign", "normal"}:
        return "NORMAL"
    return "ATTACK"