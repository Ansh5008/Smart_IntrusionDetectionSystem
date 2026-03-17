from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

import joblib
import numpy as np
import pandas as pd


class SimpleLabelEncoder:
    def __init__(self) -> None:
        self.classes_: np.ndarray | None = None
        self._class_to_index: dict[object, int] | None = None

    def fit(self, y: Iterable[object]) -> "SimpleLabelEncoder":
        labels = pd.Series(list(y))
        classes = pd.unique(labels)
        self.classes_ = np.asarray(classes, dtype=object)
        self._class_to_index = {label: idx for idx, label in enumerate(self.classes_)}
        return self

    def transform(self, y: Iterable[object]) -> np.ndarray:
        if self._class_to_index is None:
            raise ValueError("Label encoder has not been fitted.")
        labels = pd.Series(list(y))
        missing = labels[~labels.isin(self.classes_)]
        if not missing.empty:
            raise ValueError(f"Unknown labels encountered: {missing.unique().tolist()}")
        return labels.map(self._class_to_index).to_numpy(dtype=int)

    def fit_transform(self, y: Iterable[object]) -> np.ndarray:
        return self.fit(y).transform(y)

    def inverse_transform(self, y: Sequence[int]) -> np.ndarray:
        if self.classes_ is None:
            raise ValueError("Label encoder has not been fitted.")
        return np.asarray([self.classes_[int(idx)] for idx in y], dtype=object)


class SimpleStandardScaler:
    def __init__(self) -> None:
        self.mean_: np.ndarray | None = None
        self.scale_: np.ndarray | None = None
        self.feature_names_: list[str] | None = None

    def fit(self, X: np.ndarray, feature_names: Sequence[str] | None = None) -> "SimpleStandardScaler":
        values = np.asarray(X, dtype=float)
        self.mean_ = np.nanmean(values, axis=0)
        self.scale_ = np.nanstd(values, axis=0)
        self.scale_[self.scale_ == 0] = 1.0
        if feature_names is not None:
            self.feature_names_ = list(feature_names)
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        if self.mean_ is None or self.scale_ is None:
            raise ValueError("Scaler has not been fitted.")
        values = np.asarray(X, dtype=float)
        return (values - self.mean_) / self.scale_

    def fit_transform(self, X: np.ndarray, feature_names: Sequence[str] | None = None) -> np.ndarray:
        self.fit(X, feature_names=feature_names)
        return self.transform(X)

    def inverse_transform(self, X: np.ndarray) -> np.ndarray:
        if self.mean_ is None or self.scale_ is None:
            raise ValueError("Scaler has not been fitted.")
        values = np.asarray(X, dtype=float)
        return values * self.scale_ + self.mean_


@dataclass
class TrainingBundle:
    features: np.ndarray
    labels: np.ndarray
    scaler: SimpleStandardScaler
    feature_columns: list[str]
    label_encoder: SimpleLabelEncoder


def list_csv_files(data_path: Path) -> list[Path]:
    if data_path.is_file():
        if data_path.suffix.lower() != ".csv":
            raise ValueError(f"Expected a CSV file, got {data_path}")
        return [data_path]

    if not data_path.exists():
        raise FileNotFoundError(f"Path not found: {data_path}")

    files = sorted(data_path.rglob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found under {data_path}")
    return files


def load_csv(data_path: Path) -> pd.DataFrame:
    files = list_csv_files(data_path)
    if len(files) == 1:
        df = pd.read_csv(files[0])
        df.columns = df.columns.astype(str).str.strip()
        return df
    frames = []
    for file in files:
        df = pd.read_csv(file)
        df.columns = df.columns.astype(str).str.strip()
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def _coerce_numeric(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for col in out.columns:
        if not pd.api.types.is_numeric_dtype(out[col]):
            out[col] = pd.to_numeric(out[col], errors="coerce")
    return out


def prepare_training_data(df: pd.DataFrame, label_col: str = "Label") -> TrainingBundle:
    if label_col not in df.columns:
        raise ValueError(f"Label column '{label_col}' not found in dataset.")

    y = df[label_col]
    X = df.drop(columns=[label_col])
    X = _coerce_numeric(X)

    valid_mask = ~X.isna().any(axis=1) & ~pd.isna(y)
    X = X.loc[valid_mask]
    y = y.loc[valid_mask]

    feature_columns = list(X.columns)
    label_encoder = SimpleLabelEncoder()
    labels = label_encoder.fit_transform(y)

    scaler = SimpleStandardScaler()
    features = scaler.fit_transform(X.to_numpy(), feature_names=feature_columns)

    return TrainingBundle(
        features=features,
        labels=labels,
        scaler=scaler,
        feature_columns=feature_columns,
        label_encoder=label_encoder,
    )


def prepare_inference_data(
    df: pd.DataFrame,
    feature_columns: Sequence[str],
    scaler: object | None,
) -> np.ndarray:
    X = df.copy()
    for col in feature_columns:
        if col not in X.columns:
            X[col] = 0
    X = X[list(feature_columns)]
    X = _coerce_numeric(X).fillna(0)
    features = X.to_numpy(dtype=float)

    if scaler is not None and hasattr(scaler, "transform"):
        features = scaler.transform(features)

    return features


def _default_model_dir() -> Path:
    return (Path(__file__).resolve().parent.parent / "models").resolve()


def preprocess_data(file_path: str) -> tuple[np.ndarray, np.ndarray]:
    df = load_csv(Path(file_path))
    bundle = prepare_training_data(df=df, label_col="Label")

    model_dir = _default_model_dir()
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle.scaler, model_dir / "scaler.pkl")

    return bundle.features, bundle.labels


if __name__ == "__main__":
    default_data = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "Monday-WorkingHours.pcap_ISCX.csv"
    )
    X, y = preprocess_data(str(default_data))
    print(f"Preprocessing done. Features shape: {X.shape}, Labels: {len(y)}")
