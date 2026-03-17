from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

try:
    from src.preprocess import load_csv, prepare_training_data
except ModuleNotFoundError:
    import sys

    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from src.preprocess import load_csv, prepare_training_data


def train_random_forest(
    features: np.ndarray,
    labels: np.ndarray,
    *,
    n_estimators: int = 200,
    max_depth: int | None = 20,
    random_state: int = 42,
) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(features, labels)
    return model


def save_bundle(bundle: dict[str, Any], model_path: Path) -> None:
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path)


def load_bundle(model_path: Path, scaler_path: Path | None = None) -> dict[str, Any]:
    bundle = joblib.load(model_path)
    if not isinstance(bundle, dict) or "model" not in bundle:
        bundle = {"model": bundle}

    if "scaler" not in bundle and scaler_path is not None and scaler_path.exists():
        bundle["scaler"] = joblib.load(scaler_path)

    if "feature_columns" not in bundle:
        scaler = bundle.get("scaler")
        feature_names = getattr(scaler, "feature_names_", None) if scaler is not None else None
        if feature_names:
            bundle["feature_columns"] = list(feature_names)
        else:
            raise ValueError(
                "Feature columns missing from the model bundle. Re-train the model "
                "using the provided training pipeline to persist feature metadata."
            )

    bundle.setdefault("label_encoder", None)
    return bundle


def _default_data_file() -> Path:
    return (
        Path(__file__).resolve().parent.parent
        / "data"
        / "Monday-WorkingHours.pcap_ISCX.csv"
    )


def _default_model_dir() -> Path:
    return (Path(__file__).resolve().parent.parent / "models").resolve()


def _demo_train() -> None:
    data_file = _default_data_file()
    df = load_csv(data_file)
    bundle = prepare_training_data(df=df, label_col="Label")

    X_train, X_test, y_train, y_test = train_test_split(
        bundle.features, bundle.labels, test_size=0.2, random_state=42
    )

    model = train_random_forest(X_train, y_train)
    y_pred = model.predict(X_test)

    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    model_dir = _default_model_dir()
    model_bundle = {
        "model": model,
        "scaler": bundle.scaler,
        "feature_columns": bundle.feature_columns,
        "label_encoder": bundle.label_encoder,
        "label_col": "Label",
    }
    save_bundle(model_bundle, model_dir / "model.pkl")
    joblib.dump(bundle.scaler, model_dir / "scaler.pkl")

    print("Model saved successfully!")


if __name__ == "__main__":
    _demo_train()
