"""
Exposure Sensitivity Inference Module.
Transforms text using fitted TfidfVectorizer and classifies sensitivity
(LOW, MEDIUM, HIGH, CRITICAL) using trained Random Forest model.
"""
import numpy as np
from backend.app.ml.registry import registry

def predict_exposure_sensitivity(text: str) -> dict:
    """
    Predicts exposure sensitivity classification for a text snippet.
    """
    if not text or not text.strip():
        return {
            "predicted_label": "LOW",
            "confidence": 1.0,
            "probabilities": {"LOW": 1.0, "MEDIUM": 0.0, "HIGH": 0.0, "CRITICAL": 0.0},
            "model_type": "TF-IDF + Random Forest",
            "is_synthetic_model": True
        }

    tfidf, clf = registry.get_exposure_models()
    vec = tfidf.transform([text])
    pred_label = clf.predict(vec)[0]

    probabilities = {}
    if hasattr(clf, "predict_proba"):
        probs = clf.predict_proba(vec)[0]
        classes = clf.classes_
        probabilities = {cls: round(float(p), 4) for cls, p in zip(classes, probs)}
        confidence = float(np.max(probs))
    else:
        confidence = 0.90

    return {
        "predicted_label": pred_label,
        "confidence": round(confidence, 4),
        "probabilities": probabilities,
        "model_type": "TF-IDF + Random Forest",
        "is_synthetic_model": True
    }
