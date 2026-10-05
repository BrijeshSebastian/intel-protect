"""
Unified Threat Dashboard Service Layer.
Aggregates risk intelligence across Document Scanner, Exposure Monitor, and Breach Monitor.
Computes composite multi-module threat scores, categorical risk distribution,
and unified activity timelines under strict multi-tenant isolation.
"""
from datetime import datetime, timezone
import logging
from typing import Any
import uuid
from backend.app import db
from backend.app.common.errors import AppError
from backend.app.models.document import Document
from backend.app.models.pii_finding import PIIFinding
from backend.app.models.exposure_record import ExposureRecord
from backend.app.models.breach import BreachResult, BreachExposure
from backend.app.models.recommendation import Recommendation
from backend.app.dashboard.recommendations import generate_unified_recommendations

logger = logging.getLogger(__name__)

MODULE_WEIGHTS = {
    "document": 0.30,
    "exposure": 0.35,
    "breach": 0.35,
}

OVERALL_LEVEL_THRESHOLDS = [
    (75.0, "CRITICAL"),
    (50.0, "HIGH"),
    (25.0, "MEDIUM"),
    (0.0, "LOW"),
]


def _map_risk_level(score: float) -> str:
    for threshold, level in OVERALL_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "LOW"


def get_user_dashboard_data(user_id: str) -> dict[str, Any]:
    """
    Assembles real-time aggregated threat intelligence for the authenticated user.
    Strictly isolated to user_id.
    """
    user_uuid = uuid.UUID(user_id) if isinstance(user_id, str) else user_id

    # 1. Document Scanner Aggregates
    documents = (
        Document.query.filter_by(user_id=user_uuid)
        .order_by(Document.created_at.desc())
        .all()
    )
    docs_count = len(documents)
    total_doc_pii = sum(d.pii_count or 0 for d in documents)
    high_risk_doc_pii = sum(d.high_risk_count or 0 for d in documents)
    
    if docs_count > 0:
        # Latest document risk score with average as background factor
        latest_doc_score = float(documents[0].risk_score or 0.0)
        avg_doc_score = sum(float(d.risk_score or 0.0) for d in documents) / docs_count
        doc_risk_score = round(0.7 * latest_doc_score + 0.3 * avg_doc_score, 1)
        doc_risk_level = documents[0].risk_level or _map_risk_level(doc_risk_score)
    else:
        doc_risk_score = 0.0
        doc_risk_level = "LOW"

    document_risk = {
        "score": doc_risk_score,
        "level": doc_risk_level,
        "documents_scanned": docs_count,
        "total_pii_findings": total_doc_pii,
        "high_risk_findings": high_risk_doc_pii,
    }

    # 2. Exposure Monitor Aggregates
    exposures = (
        ExposureRecord.query.filter_by(user_id=user_uuid)
        .order_by(ExposureRecord.created_at.desc())
        .all()
    )
    exposure_count = len(exposures)
    anomalies_detected = sum(1 for e in exposures if e.is_anomalous)
    if exposure_count > 0:
        latest_exp = exposures[0]
        exp_score = round(float(latest_exp.exposure_score or 0.0), 1)
        exp_level = latest_exp.exposure_level or _map_risk_level(exp_score)
        latest_category_scores = latest_exp.category_scores or {}
    else:
        exp_score = 0.0
        exp_level = "LOW"
        latest_category_scores = {}

    exposure_risk = {
        "score": exp_score,
        "level": exp_level,
        "analyses_count": exposure_count,
        "anomalies_detected": anomalies_detected,
    }

    # 3. Breach Monitor Aggregates
    breach_results = (
        BreachResult.query.filter_by(user_id=user_uuid)
        .order_by(BreachResult.created_at.desc())
        .all()
    )
    breach_results_count = len(breach_results)
    if breach_results_count > 0:
        latest_br = breach_results[0]
        br_score = round(float(latest_br.breach_risk_score or 0.0), 1)
        br_level = latest_br.breach_risk_level or _map_risk_level(br_score)
        br_breaches_count = latest_br.breach_count
        br_total_exposures = latest_br.total_exposures
    else:
        br_score = 0.0
        br_level = "LOW"
        br_breaches_count = 0
        br_total_exposures = 0

    breach_risk = {
        "score": br_score,
        "level": br_level,
        "total_breaches": br_breaches_count,
        "total_exposures": br_total_exposures,
    }

    # 4. Overall Composite Risk Calculation
    active_weights = {}
    scores = {
        "document": doc_risk_score,
        "exposure": exp_score,
        "breach": br_score,
    }

    if docs_count > 0:
        active_weights["document"] = MODULE_WEIGHTS["document"]
    if exposure_count > 0:
        active_weights["exposure"] = MODULE_WEIGHTS["exposure"]
    if breach_results_count > 0:
        active_weights["breach"] = MODULE_WEIGHTS["breach"]

    if active_weights:
        total_w = sum(active_weights.values())
        overall_score = sum((w / total_w) * scores[mod] for mod, w in active_weights.items())
        overall_score = round(min(100.0, max(0.0, overall_score)), 1)
        overall_level = _map_risk_level(overall_score)
        trend = "stable"
        if overall_score >= 70.0:
            trend = "increasing"
        elif overall_score <= 20.0:
            trend = "improving"
    else:
        overall_score = 0.0
        overall_level = "LOW"
        trend = "stable"

    overall_risk = {
        "score": overall_score,
        "level": overall_level,
        "trend": trend,
        "active_modules": len(active_weights),
    }

    # 5. 5-Category Risk Distribution
    # Synthesize per-category footprint across Exposure Monitor and Document PII findings
    distribution = {
        "identity": round(float(latest_category_scores.get("identity", 0.0)), 1),
        "contact": round(float(latest_category_scores.get("contact", 0.0)), 1),
        "location": round(float(latest_category_scores.get("location", 0.0)), 1),
        "financial": round(float(latest_category_scores.get("financial", 0.0)), 1),
        "credential": round(float(latest_category_scores.get("credential", 0.0)), 1),
    }

    # Boost categories if documents or breaches also confirmed compromises
    if breach_results_count > 0:
        latest_summary = breach_results[0].exposure_summary or {}
        if any("PASS" in k or "CRED" in k for k in latest_summary):
            distribution["credential"] = min(100.0, max(distribution["credential"], 65.0))
        if any("CARD" in k or "BANK" in k for k in latest_summary):
            distribution["financial"] = min(100.0, max(distribution["financial"], 60.0))
        if any("AADHAAR" in k or "PAN" in k for k in latest_summary):
            distribution["identity"] = min(100.0, max(distribution["identity"], 55.0))

    if docs_count > 0 and high_risk_doc_pii > 0:
        distribution["identity"] = min(100.0, max(distribution["identity"], 45.0))

    # 6. Recent Activity Timeline (Chronological fusion of all events)
    recent_activity = []
    for d in documents[:5]:
        recent_activity.append({
            "id": str(d.id),
            "type": "document_scan",
            "title": f"Document Scanned: {d.original_filename}",
            "score": float(d.risk_score or 0.0),
            "level": d.risk_level or "LOW",
            "timestamp": d.scanned_at.isoformat() if d.scanned_at else (d.created_at.isoformat() if d.created_at else None),
            "details": f"{d.pii_count or 0} PII entities identified ({d.high_risk_count or 0} high-risk)."
        })

    for e in exposures[:5]:
        recent_activity.append({
            "id": str(e.id),
            "type": "exposure_analysis",
            "title": f"Exposure Analysis: {e.query_type}",
            "score": float(e.exposure_score or 0.0),
            "level": e.exposure_level or "LOW",
            "timestamp": e.analyzed_at.isoformat() if e.analyzed_at else (e.created_at.isoformat() if e.created_at else None),
            "details": f"{e.total_entities} entities detected, Sensitivity: {e.sensitivity_label}."
        })

    for b in breach_results[:5]:
        recent_activity.append({
            "id": str(b.id),
            "type": "breach_check",
            "title": f"Breach Check: {b.breach_count} Incidents Matched",
            "score": float(b.breach_risk_score or 0.0),
            "level": b.breach_risk_level or "LOW",
            "timestamp": b.checked_at.isoformat() if b.checked_at else (b.created_at.isoformat() if b.created_at else None),
            "details": f"Priority: {b.priority_label}, {b.total_exposures} total exposures."
        })

    # Sort unified activity by timestamp descending
    recent_activity.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    recent_activity = recent_activity[:10]

    # 7. Unified Deduplicated Security Recommendations
    active_recs = generate_unified_recommendations(user_id=str(user_uuid), active_only=True)

    return {
        "overall_risk": overall_risk,
        "document_risk": document_risk,
        "exposure_risk": exposure_risk,
        "breach_risk": breach_risk,
        "recent_activity": recent_activity,
        "active_recommendations": active_recs,
        "risk_distribution": distribution,
    }


def dismiss_unified_recommendation(recommendation_id: str, user_id: str) -> dict:
    """
    Dismisses a recommendation for the user.
    Handles both persisted recommendations and dynamically synthesized recommendations.
    """
    user_uuid = uuid.UUID(user_id) if isinstance(user_id, str) else user_id
    rec = Recommendation.query.filter_by(id=recommendation_id, user_id=user_uuid).first()
    if rec:
        rec.is_dismissed = True
        # Also mark any matching recommendation with the same action_type as dismissed
        Recommendation.query.filter_by(user_id=user_uuid, action_type=rec.action_type).update({"is_dismissed": True})
        db.session.commit()
        return rec.to_dict()

    # Ownership check: if recommendation exists belonging to another user, deny access
    rec_other = Recommendation.query.filter_by(id=recommendation_id).first()
    if rec_other and str(rec_other.user_id) != str(user_uuid):
        raise AppError("Recommendation not found or access denied.", code="NOT_FOUND", status_code=404)

    # If not found directly, create a persisted dismissed recommendation record
    new_rec = Recommendation(
        id=uuid.UUID(recommendation_id) if isinstance(recommendation_id, str) else recommendation_id,
        user_id=user_uuid,
        source_module="unified",
        category="security_posture",
        priority="MEDIUM",
        title="Dismissed Recommendation",
        description="Dismissed by user from dashboard.",
        action_type="custom_dismissed",
        is_dismissed=True,
    )
    db.session.add(new_rec)
    db.session.commit()
    return new_rec.to_dict()
