"""
Document Sensitivity Inference Module.
Extracts 11 numerical document features from findings and document metadata,
and applies trained Logistic Regression or Random Forest classifiers to predict sensitivity.
"""
import pandas as pd
import numpy as np
from backend.app.ml.registry import registry

FEATURE_COLS = [
    "pii_count",
    "unique_pii_types",
    "high_risk_count",
    "financial_pii_count",
    "identity_pii_count",
    "credential_count",
    "contact_pii_count",
    "doc_length",
    "avg_confidence",
    "max_confidence",
    "checksum_valid_ratio"
]

def extract_document_features(findings: list[dict], doc_length: int = 0) -> dict:
    """
    Computes the 11 feature vector metrics from detected PII findings and document length.
    """
    pii_count = len(findings)
    if pii_count == 0:
        return {
            "pii_count": 0,
            "unique_pii_types": 0,
            "high_risk_count": 0,
            "financial_pii_count": 0,
            "identity_pii_count": 0,
            "credential_count": 0,
            "contact_pii_count": 0,
            "doc_length": doc_length,
            "avg_confidence": 0.0,
            "max_confidence": 0.0,
            "checksum_valid_ratio": 1.0
        }

    unique_types = len(set(f.get("pii_type") for f in findings))
    high_risk = sum(1 for f in findings if f.get("severity") in ("HIGH", "CRITICAL"))
    financial = sum(1 for f in findings if f.get("pii_type") in ("CARD", "BANK_ACCOUNT"))
    identity = sum(1 for f in findings if f.get("pii_type") in ("AADHAAR", "PAN"))
    credentials = sum(1 for f in findings if f.get("pii_type") in ("CREDENTIAL", "PASSWORD", "TOKEN"))
    contact = sum(1 for f in findings if f.get("pii_type") in ("EMAIL", "PHONE"))

    confidences = [f.get("confidence", 0.9) for f in findings]
    avg_conf = float(np.mean(confidences))
    max_conf = float(np.max(confidences))

    checksummable = [f for f in findings if f.get("checksum_valid") is not None]
    if len(checksummable) > 0:
        valid_count = sum(1 for f in checksummable if f.get("checksum_valid") is True)
        checksum_ratio = float(valid_count / len(checksummable))
    else:
        checksum_ratio = 1.0

    return {
        "pii_count": pii_count,
        "unique_pii_types": unique_types,
        "high_risk_count": high_risk,
        "financial_pii_count": financial,
        "identity_pii_count": identity,
        "credential_count": credentials,
        "contact_pii_count": contact,
        "doc_length": int(doc_length),
        "avg_confidence": round(avg_conf, 4),
        "max_confidence": round(max_conf, 4),
        "checksum_valid_ratio": round(checksum_ratio, 4)
    }

def predict_document_sensitivity(features_or_findings, doc_length: int = 0, model_type: str = "rf") -> dict:
    """
    Predicts document sensitivity category (LOW, MEDIUM, HIGH, CRITICAL).
    Accepts either an existing feature dict or a raw list of findings dictionaries.
    """
    if isinstance(features_or_findings, list):
        feat_dict = extract_document_features(features_or_findings, doc_length)
    else:
        feat_dict = features_or_findings

    model = registry.get_document_sensitivity_model(model_type=model_type)
    df_feat = pd.DataFrame([feat_dict])[FEATURE_COLS]

    pred_label = model.predict(df_feat)[0]
    probabilities = {}

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(df_feat)[0]
        classes = model.classes_
        probabilities = {cls: round(float(p), 4) for cls, p in zip(classes, probs)}
        confidence = float(np.max(probs))
    else:
        confidence = 0.90

    return {
        "predicted_label": pred_label,
        "confidence": round(confidence, 4),
        "probabilities": probabilities,
        "features": feat_dict,
        "model_type": "Random Forest" if model_type == "rf" else "Logistic Regression",
        "is_synthetic_model": True
    }
