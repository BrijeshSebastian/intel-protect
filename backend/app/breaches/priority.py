"""
Breach Priority ML Classifier Wrapper.
Extracts 11 breach observation features and runs inference against Model 3
(Random Forest classifier loaded via MLModelRegistry).
"""
from datetime import date, datetime, timezone
import logging
from typing import Any, Sequence
import numpy as np
import pandas as pd
from backend.app.ml.registry import registry
from backend.app.models.breach import Breach

logger = logging.getLogger(__name__)

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

SEVERITY_ENCODING = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3
}


def extract_breach_features(breaches: Sequence[Breach]) -> pd.DataFrame:
    """
    Extracts the 11-dimensional feature vector from matched Breach records.
    """
    if not breaches:
        return pd.DataFrame([{
            "breach_count": 0,
            "email_exposed": 0,
            "phone_exposed": 0,
            "password_exposed": 0,
            "financial_exposed": 0,
            "identity_doc_exposed": 0,
            "address_exposed": 0,
            "credential_exposed": 0,
            "total_data_types": 0,
            "max_breach_severity": 0,
            "days_since_breach": 3000
        }])[FEATURE_COLS]

    all_data_types = set()
    max_sev = 0
    now_date = datetime.now(timezone.utc).date()
    min_days_since = 9999

    for b in breaches:
        types_list = [str(t).upper() for t in (b.exposed_data_types or [])]
        all_data_types.update(types_list)

        sev_code = SEVERITY_ENCODING.get((b.severity or "LOW").upper(), 0)
        if sev_code > max_sev:
            max_sev = sev_code

        b_date = b.breach_date if isinstance(b.breach_date, date) else now_date
        days = max(0, (now_date - b_date).days)
        if days < min_days_since:
            min_days_since = days

    feat = {
        "breach_count": len(breaches),
        "email_exposed": 1 if any("EMAIL" in t for t in all_data_types) else 0,
        "phone_exposed": 1 if any("PHONE" in t for t in all_data_types) else 0,
        "password_exposed": 1 if any("PASSWORD" in t for t in all_data_types) else 0,
        "financial_exposed": 1 if any(t in ("CARD", "BANK_ACCOUNT", "FINANCIAL") for t in all_data_types) else 0,
        "identity_doc_exposed": 1 if any(t in ("AADHAAR", "PAN", "PASSPORT", "IDENTITY") for t in all_data_types) else 0,
        "address_exposed": 1 if any("ADDRESS" in t for t in all_data_types) else 0,
        "credential_exposed": 1 if any(t in ("API_SECRET", "CREDENTIAL", "TOKEN") for t in all_data_types) else 0,
        "total_data_types": len(all_data_types),
        "max_breach_severity": max_sev,
        "days_since_breach": min_days_since if min_days_since != 9999 else 365
    }

    return pd.DataFrame([feat])[FEATURE_COLS]


def predict_breach_priority(breaches: Sequence[Breach]) -> dict[str, Any]:
    """
    Runs Random Forest classification to evaluate remediation priority.
    Returns:
        {
            "priority_label": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            "confidence": float,
            "probabilities": {"LOW": float, ...}
        }
    """
    if not breaches:
        return {
            "priority_label": "LOW",
            "confidence": 0.99,
            "probabilities": {"LOW": 0.99, "MEDIUM": 0.01, "HIGH": 0.0, "CRITICAL": 0.0}
        }

    try:
        model = registry.get_breach_priority_model()
        X = extract_breach_features(breaches)

        pred_label = model.predict(X)[0]
        probs = model.predict_proba(X)[0]
        classes = list(model.classes_)

        prob_dict = {str(c): round(float(p), 4) for c, p in zip(classes, probs)}
        max_prob = float(np.max(probs))

        return {
            "priority_label": str(pred_label),
            "confidence": round(max_prob, 4),
            "probabilities": prob_dict
        }
    except Exception as e:
        logger.warning(f"Breach priority inference fallback due to: {e}")
        # Deterministic heuristic fallback
        max_sev = max((b.severity or "LOW").upper() for b in breaches)
        return {
            "priority_label": max_sev if max_sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "MEDIUM",
            "confidence": 0.85,
            "probabilities": {}
        }
