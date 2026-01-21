from __future__ import annotations

import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib

from .features import extract_pe_features, vectorize_features

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "models" / "classifier.pk1"
DEFAULT_FEATURES_PATH = Path(__file__).resolve().parent / "models" / "features.pkl"


@dataclass(frozen=True)
class ScanResult:
    filename: str
    label: str  # "safe" or "malware"
    malware_probability: Optional[float]
    features: Dict[str, Any]


class MalwareClassifier:
    """Load the bundled scikit-learn model and classify PE files."""

    def __init__(
        self,
        model_path: str | Path = DEFAULT_MODEL_PATH,
        features_path: str | Path = DEFAULT_FEATURES_PATH,
    ) -> None:
        self.model_path = Path(model_path)
        self.features_path = Path(features_path)

        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found: {self.model_path}")
        if not self.features_path.exists():
            raise FileNotFoundError(f"Feature list not found: {self.features_path}")

        self.model = joblib.load(self.model_path)
        with open(self.features_path, "rb") as f:
            self.ordered_features: List[str] = list(pickle.load(f))

    def scan(self, file_path: str | Path) -> ScanResult:
        fpath = Path(file_path)
        feat_dict = extract_pe_features(fpath)
        vec = vectorize_features(feat_dict, self.ordered_features)

        pred = int(self.model.predict([vec])[0])
        label = "malware" if pred == 1 else "safe"

        malware_prob: Optional[float] = None
        if hasattr(self.model, "predict_proba"):
            try:
                proba = self.model.predict_proba([vec])[0]
                malware_prob = float(proba[1])
            except Exception:
                malware_prob = None

        return ScanResult(
            filename=fpath.name,
            label=label,
            malware_probability=malware_prob,
            features=feat_dict,
        )
