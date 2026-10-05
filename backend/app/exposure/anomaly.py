"""
Exposure Anomaly Detection Module.
Evaluates exposure profile feature vectors using the trained Isolation Forest model.
"""
from backend.app.ml.anomaly_detector import predict_anomaly


def detect_exposure_anomaly(feature_metrics: dict) -> dict:
    """
    Evaluates whether an exposure feature profile represents an unusual anomaly
    using the trained Isolation Forest model.
    Expected feature_metrics keys:
        - total_pii_count
        - sensitive_pii_count
        - financial_pii_count
        - credential_count
        - source_count
        - exposure_type_count
        - identity_data_count
    """
    # Ensure default values for all required feature columns
    normalized_metrics = {
        "total_pii_count": int(feature_metrics.get("total_pii_count", 0)),
        "sensitive_pii_count": int(feature_metrics.get("sensitive_pii_count", 0)),
        "financial_pii_count": int(feature_metrics.get("financial_pii_count", 0)),
        "credential_count": int(feature_metrics.get("credential_count", 0)),
        "source_count": max(1, int(feature_metrics.get("source_count", 1))),
        "exposure_type_count": max(1, int(feature_metrics.get("exposure_type_count", 1))),
        "identity_data_count": int(feature_metrics.get("identity_data_count", 0)),
    }
    return predict_anomaly(normalized_metrics)
