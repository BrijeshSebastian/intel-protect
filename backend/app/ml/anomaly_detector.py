"""
Anomaly Detector Inference Module.
Evaluates exposure profile metrics using trained Isolation Forest to detect
unusual spikes or multi-vector identity compromise events.
"""
import pandas as pd
import numpy as np
from backend.app.ml.registry import registry

FEATURE_COLS = [
    "total_pii_count",
    "sensitive_pii_count",
    "financial_pii_count",
    "credential_count",
    "source_count",
    "exposure_type_count",
    "identity_data_count"
]

def predict_anomaly(profile_metrics: dict) -> dict:
    """
    Evaluates whether an exposure metric profile constitutes an anomaly.
    Returns binary detection flag, normalized anomaly score (0.0 to 1.0), and interpretation.
    """
    model = registry.get_anomaly_model()
    df_feat = pd.DataFrame([profile_metrics])[FEATURE_COLS]

    raw_pred = model.predict(df_feat)[0]  # -1 for anomaly, 1 for inlier
    is_anomaly = bool(raw_pred == -1)

    dec_func = float(model.decision_function(df_feat)[0])
    # Normalized score: 0 (completely standard inlier) to 1 (extreme outlier)
    normalized_score = float(1.0 / (1.0 + np.exp(dec_func * 10)))

    if is_anomaly:
        interpretation = "Anomalous exposure volume detected: high concentration of sensitive or credential assets."
    else:
        interpretation = "Standard exposure pattern within typical operational baseline."

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": round(normalized_score, 4),
        "raw_decision_score": round(dec_func, 4),
        "interpretation": interpretation,
        "features": profile_metrics,
        "model_type": "Isolation Forest",
        "contamination": 0.05,
        "is_synthetic_model": True
    }
