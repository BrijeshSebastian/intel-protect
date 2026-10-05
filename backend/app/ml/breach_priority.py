"""
Breach Priority Inference Module.
Accepts breach observation metrics and classifies priority (LOW, MEDIUM, HIGH, CRITICAL)
using trained Random Forest priority model.
"""
import pandas as pd
import numpy as np
from backend.app.ml.registry import registry

FEATURE_COLS = [
    "breach_count",
    "email_exposed",
    "phone_exposed",
    "password_exposed",
    "financial_exposed",
    "identity_doc_exposed",
    "address_exposed",
    "credential_exposed",
    "total_data_types",
    "max_breach_severity",
    "days_since_breach"
]

def predict_breach_priority(features_dict: dict) -> dict:
    """
    Predicts breach investigation priority category (LOW, MEDIUM, HIGH, CRITICAL).
    """
    model = registry.get_breach_priority_model()
    df_feat = pd.DataFrame([features_dict])[FEATURE_COLS]

    pred_label = model.predict(df_feat)[0]
    probabilities = {}

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(df_feat)[0]
        classes = model.classes_
        probabilities = {cls: round(float(p), 4) for cls, p in zip(classes, probs)}
        confidence = float(np.max(probs))
    else:
        confidence = 0.85

    return {
        "predicted_priority": pred_label,
        "confidence": round(confidence, 4),
        "probabilities": probabilities,
        "features": features_dict,
        "model_type": "Random Forest",
        "is_synthetic_model": True
    }
