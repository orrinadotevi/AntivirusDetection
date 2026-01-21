from pathlib import Path

from antivirus_detection.features import FEATURE_NAMES, extract_pe_features, vectorize_features
from antivirus_detection.model import MalwareClassifier


def test_feature_extraction_has_required_keys():
    sample = Path(__file__).resolve().parents[1] / "JLECmd" / "JLECmd.exe"
    assert sample.exists()

    feats = extract_pe_features(sample)
    for name in FEATURE_NAMES:
        assert name in feats


def test_vectorize_order_and_length():
    sample = Path(__file__).resolve().parents[1] / "JLECmd" / "JLECmd.exe"
    feats = extract_pe_features(sample)
    vec = vectorize_features(feats, FEATURE_NAMES)
    assert len(vec) == len(FEATURE_NAMES)


def test_model_scan_runs():
    sample = Path(__file__).resolve().parents[1] / "JLECmd" / "JLECmd.exe"
    clf = MalwareClassifier()
    res = clf.scan(sample)
    assert res.label in {"safe", "malware"}
