from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import joblib
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

try:
    from src.preprocess import load_csv, prepare_training_data
    from src.randomforest import save_bundle, train_random_forest
except ModuleNotFoundError:
    import sys

    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from src.preprocess import load_csv, prepare_training_data
    from src.randomforest import save_bundle, train_random_forest


def train_from_csv(
    data_path: Path,
    label_col: str,
    model_path: Path,
    scaler_path: Path,
) -> dict[str, Any]:
    df = load_csv(data_path)
    bundle = prepare_training_data(df=df, label_col=label_col)

    X_train, X_test, y_train, y_test = train_test_split(
        bundle.features,
        bundle.labels,
        test_size=0.2,
        random_state=42,
        stratify=bundle.labels,
    )

    model = train_random_forest(X_train, y_train)
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred)

    model_bundle = {
        "model": model,
        "scaler": bundle.scaler,
        "feature_columns": bundle.feature_columns,
        "label_encoder": bundle.label_encoder,
        "label_col": label_col,
    }

    save_bundle(model_bundle, model_path=model_path)
    scaler_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle.scaler, scaler_path)

    return {
        "bundle": model_bundle,
        "accuracy": float(accuracy),
        "report": report,
        "samples": int(len(bundle.labels)),
        "features": int(len(bundle.feature_columns)),
    }


def _default_data_path() -> Path:
    return (Path(__file__).resolve().parent.parent / "data").resolve()


def _default_model_path() -> Path:
    return (Path(__file__).resolve().parent.parent / "models" / "model.pkl").resolve()


def _default_scaler_path() -> Path:
    return (Path(__file__).resolve().parent.parent / "models" / "scaler.pkl").resolve()


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Smart-IDS random forest model.")
    parser.add_argument("--data", type=Path, default=_default_data_path(), help="CSV file or directory")
    parser.add_argument("--label-col", default="Label", help="Label column name")
    parser.add_argument("--model", type=Path, default=_default_model_path(), help="Output model bundle path")
    parser.add_argument("--scaler", type=Path, default=_default_scaler_path(), help="Output scaler path")
    args = parser.parse_args()

    result = train_from_csv(
        data_path=args.data,
        label_col=args.label_col,
        model_path=args.model,
        scaler_path=args.scaler,
    )

    print(f"Training complete on {result['samples']} rows with {result['features']} features")
    print(f"Validation accuracy: {result['accuracy']:.4f}")
    print(result["report"])


if __name__ == "__main__":
    main()
