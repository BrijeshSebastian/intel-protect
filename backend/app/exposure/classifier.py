"""
Exposure Sensitivity Classification Module.
Wraps the TF-IDF + Random Forest sensitivity classifier for Exposure Monitor.
"""
from backend.app.ml.exposure_classifier import predict_exposure_sensitivity


def classify_exposure_sensitivity(text: str) -> dict:
    """
    Classifies exposure text into LOW / MEDIUM / HIGH / CRITICAL sensitivity
    using the trained TF-IDF + Random Forest model pipeline.
    """
    return predict_exposure_sensitivity(text)
