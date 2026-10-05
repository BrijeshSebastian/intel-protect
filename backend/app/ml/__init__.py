"""
Intel-Protect Machine Learning Package.
Exposes registry, inference wrappers, and model utilities.
"""
from backend.app.ml.registry import registry
from backend.app.ml.document_sensitivity import (
    predict_document_sensitivity,
    extract_document_features
)
from backend.app.ml.exposure_classifier import predict_exposure_sensitivity
from backend.app.ml.breach_priority import predict_breach_priority
from backend.app.ml.anomaly_detector import predict_anomaly

__all__ = [
    "registry",
    "predict_document_sensitivity",
    "extract_document_features",
    "predict_exposure_sensitivity",
    "predict_breach_priority",
    "predict_anomaly"
]
