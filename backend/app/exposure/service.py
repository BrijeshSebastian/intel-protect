"""
Exposure Monitor Business Service Layer.
Coordinates Custom NER, TF-IDF + Random Forest Sensitivity Classification,
Isolation Forest Anomaly Detection, and Deterministic Exposure Scoring.
Enforces strict user ownership isolation and zero raw PII persistence.
"""
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional, Any
import pandas as pd

from backend.app import db
from backend.app.common.errors import AppError
from backend.app.models.exposure_record import ExposureRecord
from backend.app.exposure.ner import extract_exposure_entities, summarize_entities
from backend.app.exposure.classifier import classify_exposure_sensitivity
from backend.app.exposure.anomaly import detect_exposure_anomaly
from backend.app.exposure.scorer import calculate_exposure_score

logger = logging.getLogger("intel_protect.exposure")

SYNTHETIC_EXPOSURES_CSV = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "synthetic", "synthetic_exposures.csv")
)

_cached_synthetic_df: Optional[pd.DataFrame] = None


def _get_synthetic_corpus() -> pd.DataFrame:
    """Loads and caches synthetic exposures dataset for matching."""
    global _cached_synthetic_df
    if _cached_synthetic_df is None:
        if os.path.exists(SYNTHETIC_EXPOSURES_CSV):
            try:
                _cached_synthetic_df = pd.read_csv(SYNTHETIC_EXPOSURES_CSV)
            except Exception as e:
                logger.warning(f"Failed to load synthetic exposures CSV: {e}")
                _cached_synthetic_df = pd.DataFrame()
        else:
            _cached_synthetic_df = pd.DataFrame()
    return _cached_synthetic_df


def _resolve_exposure_text(identifiers: dict, custom_text: Optional[str] = None) -> tuple[str, str, str]:
    """
    Resolves exposure text to analyze.
    Returns:
        (resolved_text, query_type, query_value_hash)
    """
    if custom_text and custom_text.strip():
        qtype = "custom_text"
        qhash = hashlib.sha256(custom_text.strip().encode("utf-8")).hexdigest()
        return custom_text.strip(), qtype, qhash

    clean_ids = {k: str(v).strip() for k, v in identifiers.items() if v and str(v).strip()}
    if not clean_ids:
        # Default empty search
        return "", "empty", hashlib.sha256(b"empty").hexdigest()

    # Determine query type
    keys = sorted(clean_ids.keys())
    qtype = keys[0] if len(keys) == 1 else "combined"

    # Canonical hash of query identifiers (never store raw values in DB)
    canonical_repr = json.dumps(clean_ids, sort_keys=True)
    qhash = hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()

    # 1. Search synthetic exposure corpus for matching records
    df = _get_synthetic_corpus()
    matched_texts = []

    if not df.empty and "exposure_text" in df.columns:
        for val in clean_ids.values():
            if len(val) >= 4:
                # Substring search in synthetic corpus
                matches = df[df["exposure_text"].str.contains(val, case=False, na=False, regex=False)]
                if not matches.empty:
                    matched_texts.extend(matches["exposure_text"].head(3).tolist())

    if matched_texts:
        combined_text = "\n\n".join(matched_texts)
        return combined_text, qtype, qhash

    # 2. Synthesize a structured observation representing these identifiers
    parts = []
    if "name" in clean_ids:
        parts.append(f"Contact person: {clean_ids['name']}")
    if "email" in clean_ids:
        parts.append(f"Email: {clean_ids['email']}")
    if "phone" in clean_ids:
        parts.append(f"Mobile: {clean_ids['phone']}")
    if "username" in clean_ids:
        parts.append(f"User profile ({clean_ids['username']})")
    if "location" in clean_ids:
        parts.append(f"Location: {clean_ids['location']}")

    # Add other identifiers
    for k, v in clean_ids.items():
        if k not in ("name", "email", "phone", "username", "location"):
            parts.append(f"{k.capitalize()}: {v}")

    synthetic_text = "Public record entry: " + ", ".join(parts) + "."
    return synthetic_text, qtype, qhash


def analyze_exposure(
    identifiers: Optional[dict] = None,
    user_id: str = "",
    custom_text: Optional[str] = None
) -> dict[str, Any]:
    """
    Executes the full Exposure Monitor analysis pipeline:
    1. Resolves exposure observation text and query hash
    2. Runs Custom Regex NER
    3. Runs TF-IDF + Random Forest Sensitivity Classification
    4. Runs Isolation Forest Anomaly Detection
    5. Computes Deterministic Exposure Score & Explainability Breakdown
    6. Persists ExposureRecord with strict user isolation
    """
    identifiers = identifiers or {}
    exposure_text, query_type, query_value_hash = _resolve_exposure_text(identifiers, custom_text)

    # 1. Custom Regex NER Entity Extraction
    entities = extract_exposure_entities(exposure_text)
    entity_summary, category_counts = summarize_entities(entities)

    total_entities = len(entities)
    sensitive_count = sum(
        1 for e in entities
        if e.category in ("financial", "credential") or e.entity_type in ("AADHAAR", "PAN")
    )
    financial_count = category_counts.get("financial", 0)
    credential_count = category_counts.get("credential", 0)
    identity_count = category_counts.get("identity", 0)

    # 2. ML Sensitivity Classification (TF-IDF + Random Forest)
    sensitivity_result = classify_exposure_sensitivity(exposure_text)
    sensitivity_label = sensitivity_result.get("predicted_label", "LOW")
    sensitivity_confidence = float(sensitivity_result.get("confidence", 0.90))

    # 3. ML Anomaly Detection (Isolation Forest)
    # Estimate source count from text headers or default to 1
    source_count = 1 + exposure_text.count("\n\n")
    exposure_type_count = sum(1 for c, cnt in category_counts.items() if cnt > 0)

    anomaly_features = {
        "total_pii_count": total_entities,
        "sensitive_pii_count": sensitive_count,
        "financial_pii_count": financial_count,
        "credential_count": credential_count,
        "source_count": max(1, source_count),
        "exposure_type_count": max(1, exposure_type_count),
        "identity_data_count": identity_count
    }
    anomaly_result = detect_exposure_anomaly(anomaly_features)
    is_anomalous = bool(anomaly_result.get("is_anomaly", False))
    anomaly_score = float(anomaly_result.get("anomaly_score", 0.0))

    # 4. Deterministic Exposure Scoring Engine
    scoring_result = calculate_exposure_score(
        entities=entities,
        sensitivity_label=sensitivity_label,
        sensitivity_confidence=sensitivity_confidence,
        is_anomalous=is_anomalous,
        anomaly_score=anomaly_score
    )

    exposure_score = scoring_result["score"]
    exposure_level = scoring_result["exposure_level"]
    category_scores = scoring_result["category_scores"]
    explanation = scoring_result["explanation"]

    # 5. Persist ExposureRecord to Database
    now_utc = datetime.now(timezone.utc)
    record = ExposureRecord(
        user_id=user_id,
        query_type=query_type,
        query_value_hash=query_value_hash,
        total_entities=total_entities,
        sensitive_count=sensitive_count,
        financial_count=financial_count,
        credential_count=credential_count,
        exposure_score=exposure_score,
        exposure_level=exposure_level,
        sensitivity_label=sensitivity_label,
        sensitivity_confidence=sensitivity_confidence,
        is_anomalous=is_anomalous,
        anomaly_score=anomaly_score,
        category_scores=category_scores,
        entity_summary=entity_summary,
        raw_findings=[e.to_dict() for e in entities],  # Masked representations only
        analyzed_at=now_utc,
        created_at=now_utc
    )

    db.session.add(record)
    db.session.commit()

    logger.info(
        f"Exposure analysis completed: id={record.id}, score={exposure_score}, "
        f"level={exposure_level}, anomalous={is_anomalous}"
    )

    res_dict = record.to_dict(include_findings=True)
    res_dict["explanation"] = explanation

    return {
        "exposure_record": res_dict
    }


def get_user_exposure_history(user_id: str, limit: int = 10, offset: int = 0) -> tuple[list[dict], int]:
    """Retrieves paginated history of exposure records for a user with strict data isolation."""
    query = ExposureRecord.query.filter_by(user_id=user_id).order_by(ExposureRecord.created_at.desc())
    total = query.count()
    records = query.limit(limit).offset(offset).all()
    return [r.to_dict(include_findings=False) for r in records], total


def get_exposure_record_by_id(record_id: str, user_id: str) -> dict[str, Any]:
    """Retrieves full exposure record details with ownership isolation."""
    record = ExposureRecord.query.filter_by(id=record_id, user_id=user_id).first()
    if not record:
        raise AppError("Exposure record not found or access denied.", code="NOT_FOUND", status_code=404)

    # Reconstruct explanation for the record
    entities = record.raw_findings or []
    scoring_result = calculate_exposure_score(
        entities=entities,
        sensitivity_label=record.sensitivity_label,
        sensitivity_confidence=record.sensitivity_confidence,
        is_anomalous=record.is_anomalous,
        anomaly_score=record.anomaly_score
    )

    res_dict = record.to_dict(include_findings=True)
    res_dict["explanation"] = scoring_result["explanation"]
    return res_dict


def delete_exposure_record(record_id: str, user_id: str) -> bool:
    """Deletes an exposure record with ownership isolation."""
    record = ExposureRecord.query.filter_by(id=record_id, user_id=user_id).first()
    if not record:
        raise AppError("Exposure record not found or access denied.", code="NOT_FOUND", status_code=404)

    db.session.delete(record)
    db.session.commit()
    return True
