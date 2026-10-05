"""
Breach Monitor Service Layer.
Orchestrates email breach verification, risk evaluation, priority classification,
recommendation persistence, and user-isolated query execution.
"""
from datetime import datetime, timezone
import hashlib
import logging
import re
from typing import Any, Optional
import uuid
from backend.app import db
from backend.app.common.errors import AppError
from backend.app.models.breach import Breach, BreachResult, BreachExposure
from backend.app.models.recommendation import Recommendation
from backend.app.breaches.provider import get_breach_provider
from backend.app.breaches.scorer import calculate_breach_risk_score
from backend.app.breaches.priority import predict_breach_priority
from backend.app.breaches.recommendations import generate_breach_recommendations

logger = logging.getLogger(__name__)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')


def check_email_breaches(email: str, user_id: str) -> dict[str, Any]:
    """
    Performs full breach intelligence evaluation for an email:
    1. Validates and hashes email (SHA-256)
    2. Queries configured BreachProvider
    3. Calculates deterministic breach risk score
    4. Evaluates ML priority classification
    5. Generates contextual recommendations
    6. Persists BreachResult, BreachExposure, and Recommendation records
    """
    email_clean = (email or "").strip().lower()
    if not email_clean or not EMAIL_REGEX.match(email_clean):
        raise AppError("A valid email address is required for breach monitoring.", code="INVALID_INPUT", status_code=400)

    # Cryptographic hash of email
    query_email_hash = hashlib.sha256(email_clean.encode("utf-8")).hexdigest()

    # 1. Search breaches via provider
    provider = get_breach_provider()
    matched_breaches = provider.search_breaches(email_clean)

    # 2. Deterministic Risk Scoring
    scoring_result = calculate_breach_risk_score(matched_breaches)
    breach_risk_score = scoring_result["score"]
    breach_risk_level = scoring_result["risk_level"]
    explanation = scoring_result["explanation"]

    # 3. ML Priority Classification
    priority_result = predict_breach_priority(matched_breaches)
    priority_label = priority_result["priority_label"]
    priority_confidence = priority_result["confidence"]

    # 4. Compile exposure summary
    exposure_summary: dict[str, int] = {}
    for b in matched_breaches:
        for t in (b.exposed_data_types or []):
            dt_upper = str(t).upper()
            exposure_summary[dt_upper] = exposure_summary.get(dt_upper, 0) + 1

    total_exposures = sum(exposure_summary.values())
    now_utc = datetime.now(timezone.utc)

    # 5. Persist BreachResult
    result_record = BreachResult(
        user_id=uuid.UUID(user_id),
        query_email_hash=query_email_hash,
        breach_count=len(matched_breaches),
        total_exposures=total_exposures,
        priority_label=priority_label,
        priority_confidence=priority_confidence,
        breach_risk_score=breach_risk_score,
        breach_risk_level=breach_risk_level,
        exposure_summary=exposure_summary,
        checked_at=now_utc,
        created_at=now_utc
    )
    db.session.add(result_record)
    db.session.flush()  # Generate ID for foreign keys

    # 6. Persist BreachExposure rows
    for b in matched_breaches:
        for dt in (b.exposed_data_types or []):
            exp_row = BreachExposure(
                breach_id=b.id,
                breach_result_id=result_record.id,
                data_type=str(dt).upper(),
                severity=b.severity,
                created_at=now_utc
            )
            db.session.add(exp_row)

    # 7. Generate & Persist Recommendations
    recs = generate_breach_recommendations(
        user_id=user_id,
        breach_result_id=str(result_record.id),
        breaches=matched_breaches
    )
    for r in recs:
        db.session.add(r)

    db.session.commit()

    logger.info(
        f"Breach check completed: id={result_record.id}, breaches={len(matched_breaches)}, "
        f"score={breach_risk_score}, priority={priority_label}"
    )

    result_dict = result_record.to_dict(include_breaches=False)
    result_dict["explanation"] = explanation

    return {
        "result": result_dict,
        "breaches": [b.to_dict() for b in matched_breaches],
        "recommendations": [r.to_dict() for r in recs]
    }


def get_user_breach_history(user_id: str, limit: int = 10, offset: int = 0) -> tuple[list[dict], int]:
    """Retrieves paginated past breach checks for user with strict data isolation."""
    query = BreachResult.query.filter_by(user_id=user_id).order_by(BreachResult.created_at.desc())
    total = query.count()
    records = query.limit(limit).offset(offset).all()
    return [r.to_dict(include_breaches=True) for r in records], total


def get_breach_result_by_id(result_id: str, user_id: str) -> dict[str, Any]:
    """Retrieves details of a specific breach check with user data isolation."""
    record = BreachResult.query.filter_by(id=result_id, user_id=user_id).first()
    if not record:
        raise AppError("Breach result not found or access denied.", code="NOT_FOUND", status_code=404)

    # Extract unique matched breaches
    breaches_list = []
    if record.exposures:
        seen = set()
        for exp in record.exposures:
            if exp.breach and exp.breach.id not in seen:
                seen.add(exp.breach.id)
                breaches_list.append(exp.breach)

    scoring_result = calculate_breach_risk_score(breaches_list)

    result_dict = record.to_dict(include_breaches=False)
    result_dict["explanation"] = scoring_result["explanation"]

    recs = Recommendation.query.filter_by(breach_result_id=record.id, user_id=user_id).all()

    return {
        "result": result_dict,
        "breaches": [b.to_dict() for b in breaches_list],
        "recommendations": [r.to_dict() for r in recs]
    }


def delete_breach_result(result_id: str, user_id: str) -> bool:
    """Deletes a breach check record with cascade under ownership isolation."""
    record = BreachResult.query.filter_by(id=result_id, user_id=user_id).first()
    if not record:
        raise AppError("Breach result not found or access denied.", code="NOT_FOUND", status_code=404)

    db.session.delete(record)
    db.session.commit()
    logger.info(f"Deleted breach result {result_id} for user {user_id}")
    return True


def get_breach_catalog(limit: int = 50, offset: int = 0) -> tuple[list[dict], int]:
    """Retrieves public catalog of tracked security breaches."""
    query = Breach.query.order_by(Breach.breach_date.desc())
    total = query.count()
    records = query.limit(limit).offset(offset).all()
    return [b.to_dict() for b in records], total


def get_user_recommendations(user_id: str, active_only: bool = True) -> list[dict]:
    """Retrieves security recommendations for a user."""
    query = Recommendation.query.filter_by(user_id=user_id)
    if active_only:
        query = query.filter_by(is_dismissed=False)
    recs = query.order_by(Recommendation.created_at.desc()).all()
    return [r.to_dict() for r in recs]


def dismiss_recommendation(recommendation_id: str, user_id: str) -> dict:
    """Marks a recommendation as dismissed by owner."""
    rec = Recommendation.query.filter_by(id=recommendation_id, user_id=user_id).first()
    if not rec:
        raise AppError("Recommendation not found or access denied.", code="NOT_FOUND", status_code=404)

    rec.is_dismissed = True
    db.session.commit()
    return rec.to_dict()
