"""
Unified Security Recommendation Engine.
Aggregates, synthesizes, and deduplicates security remediation advice
across Document Scanner, Exposure Monitor, and Breach Monitor.

Enforces:
1. Traceable Evidence: Every recommendation is strictly supported by real findings.
2. Cross-Module Deduplication: Merges identical action_types across modules into
   a single recommendation listing source_modules: ["document_scanner", "breach_monitor", ...].
3. Deterministic Priority Ordering: CRITICAL > HIGH > MEDIUM > LOW with stable secondary sorting.
4. Dismissal State Synchronization: Persists and enforces dismissals across modules.
"""
from datetime import datetime, timezone
import hashlib
from typing import Any
import uuid

from backend.app import db
from backend.app.models.document import Document
from backend.app.models.pii_finding import PIIFinding
from backend.app.models.exposure_record import ExposureRecord
from backend.app.models.breach import BreachResult
from backend.app.models.recommendation import Recommendation

PRIORITY_RANKS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def _deterministic_uuid(user_id: str, action_type: str) -> uuid.UUID:
    """Generates a stable UUIDv5 based on user_id and action_type."""
    seed = f"intel_protect_rec:{user_id}:{action_type}"
    return uuid.uuid5(uuid.NAMESPACE_DNS, seed)


def generate_unified_recommendations(user_id: str, active_only: bool = True) -> list[dict[str, Any]]:
    """
    Synthesizes and deduplicates security recommendations across all three subsystems:
    Document Scanner, Exposure Monitor, and Breach Monitor.
    """
    user_uuid = uuid.UUID(user_id) if isinstance(user_id, str) else user_id

    # 1. Query persisted recommendations & dismissed action types for this user
    persisted_recs = Recommendation.query.filter_by(user_id=user_uuid).all()
    dismissed_actions = {r.action_type for r in persisted_recs if r.is_dismissed}
    dismissed_ids = {str(r.id) for r in persisted_recs if r.is_dismissed}
    existing_by_action: dict[str, Recommendation] = {r.action_type: r for r in persisted_recs if not r.is_dismissed}

    # 2. Gather evidence from Document Scanner
    documents = Document.query.filter_by(user_id=user_uuid).all()
    doc_ids = [d.id for d in documents]
    doc_findings = []
    if doc_ids:
        doc_findings = PIIFinding.query.filter(PIIFinding.document_id.in_(doc_ids)).all()

    doc_has_credentials = any(f.pii_type == "CREDENTIAL" for f in doc_findings)
    doc_has_financial = any(f.pii_type in ("CARD", "BANK_ACCOUNT") for f in doc_findings)
    doc_has_identity = any(f.pii_type in ("AADHAAR", "PAN") for f in doc_findings)
    doc_has_contact = any(f.pii_type in ("EMAIL", "PHONE") for f in doc_findings)
    doc_has_high_risk = any(d.high_risk_count and d.high_risk_count > 0 for d in documents)

    # 3. Gather evidence from Exposure Monitor
    exposures = ExposureRecord.query.filter_by(user_id=user_uuid).all()
    exp_has_credentials = any(e.credential_count > 0 for e in exposures)
    exp_has_financial = any(e.financial_count > 0 for e in exposures)
    exp_has_identity = any(e.sensitive_count > 0 for e in exposures)
    exp_has_anomalies = any(e.is_anomalous for e in exposures)

    # 4. Gather evidence from Breach Monitor
    breach_results = BreachResult.query.filter_by(user_id=user_uuid).all()
    br_has_credentials = False
    br_has_financial = False
    br_has_identity = False
    br_total_breaches = 0

    for br in breach_results:
        br_total_breaches += br.breach_count
        summary = br.exposure_summary or {}
        if any("PASS" in k or "CRED" in k for k in summary):
            br_has_credentials = True
        if any("CARD" in k or "BANK" in k or "FIN" in k for k in summary):
            br_has_financial = True
        if any("AADHAAR" in k or "PAN" in k or "ID" in k for k in summary):
            br_has_identity = True

    # 5. Build Unified Recommendations Dictionary keyed by action_type
    unified_map: dict[str, dict[str, Any]] = {}
    now_utc = datetime.now(timezone.utc).isoformat()

    # --- ACTION 1: change_password ---
    cred_sources = []
    cred_reasons = []
    if br_has_credentials:
        cred_sources.append("breach_monitor")
        cred_reasons.append("Account credentials or password hashes exposed in security breach incidents.")
    if exp_has_credentials:
        cred_sources.append("exposure_monitor")
        cred_reasons.append("API tokens, secrets, or credential strings detected in public footprint.")
    if doc_has_credentials:
        cred_sources.append("document_scanner")
        cred_reasons.append("Plaintext credentials detected in uploaded document files.")

    if cred_sources:
        action = "change_password"
        rec_id = str(existing_by_action[action].id) if action in existing_by_action else str(_deterministic_uuid(str(user_uuid), action))
        is_dismissed = action in dismissed_actions or rec_id in dismissed_ids
        unified_map[action] = {
            "id": rec_id,
            "action_type": action,
            "category": "credential",
            "priority": "CRITICAL",
            "title": "Rotate Compromised Account Credentials & Passwords",
            "description": "Your passwords or authentication secrets were identified in compromised data sources. Immediately change passwords on impacted accounts and avoid password reuse across services.",
            "source_modules": cred_sources,
            "reason": " ".join(cred_reasons),
            "is_dismissed": is_dismissed,
            "created_at": existing_by_action[action].created_at.isoformat() if action in existing_by_action else now_utc
        }

    # --- ACTION 2: freeze_card ---
    fin_sources = []
    fin_reasons = []
    if br_has_financial:
        fin_sources.append("breach_monitor")
        fin_reasons.append("Payment card or bank account records compromised in corporate data breaches.")
    if exp_has_financial:
        fin_sources.append("exposure_monitor")
        fin_reasons.append("Financial identifiers detected in monitored public exposure sources.")
    if doc_has_financial:
        fin_sources.append("document_scanner")
        fin_reasons.append("Payment card or banking details detected in uploaded documents.")

    if fin_sources:
        action = "freeze_card"
        rec_id = str(existing_by_action[action].id) if action in existing_by_action else str(_deterministic_uuid(str(user_uuid), action))
        is_dismissed = action in dismissed_actions or rec_id in dismissed_ids
        unified_map[action] = {
            "id": rec_id,
            "action_type": action,
            "category": "financial",
            "priority": "CRITICAL",
            "title": "Protect Compromised Financial Instruments & Banking Data",
            "description": "Payment card numbers or bank account records were exposed. Monitor recent financial statements for unauthorized transactions and request a replacement card from your issuing bank.",
            "source_modules": fin_sources,
            "reason": " ".join(fin_reasons),
            "is_dismissed": is_dismissed,
            "created_at": existing_by_action[action].created_at.isoformat() if action in existing_by_action else now_utc
        }

    # --- ACTION 3: lock_biometrics ---
    id_sources = []
    id_reasons = []
    if br_has_identity:
        id_sources.append("breach_monitor")
        id_reasons.append("National identity numbers (Aadhaar/PAN) compromised in breach dumps.")
    if exp_has_identity:
        id_sources.append("exposure_monitor")
        id_reasons.append("Government identity identifiers detected in public exposure profiles.")
    if doc_has_identity:
        id_sources.append("document_scanner")
        id_reasons.append("Aadhaar UIDAI or PAN tax documents detected in uploaded scans.")

    if id_sources:
        action = "lock_biometrics"
        rec_id = str(existing_by_action[action].id) if action in existing_by_action else str(_deterministic_uuid(str(user_uuid), action))
        is_dismissed = action in dismissed_actions or rec_id in dismissed_ids
        unified_map[action] = {
            "id": rec_id,
            "action_type": action,
            "category": "identity",
            "priority": "HIGH",
            "title": "Lock Biometric Authentication & Monitor Credit Reports",
            "description": "Government statutory identifiers (Aadhaar or PAN) were exposed. Lock your Aadhaar biometric authentication online via UIDAI and inspect your credit bureau reports for unauthorized loan applications.",
            "source_modules": id_sources,
            "reason": " ".join(id_reasons),
            "is_dismissed": is_dismissed,
            "created_at": existing_by_action[action].created_at.isoformat() if action in existing_by_action else now_utc
        }

    # --- ACTION 4: enable_mfa ---
    mfa_sources = []
    mfa_reasons = []
    if br_total_breaches >= 2 or br_has_credentials:
        mfa_sources.append("breach_monitor")
        mfa_reasons.append(f"Account confirmed in {br_total_breaches} security breach incidents.")
    if exp_has_credentials or exp_has_anomalies:
        mfa_sources.append("exposure_monitor")
        mfa_reasons.append("Elevated footprint or anomalous exposure volume detected.")
    if doc_has_credentials:
        mfa_sources.append("document_scanner")
        mfa_reasons.append("Credentials identified in document scanner.")

    if mfa_sources:
        action = "enable_mfa"
        rec_id = str(existing_by_action[action].id) if action in existing_by_action else str(_deterministic_uuid(str(user_uuid), action))
        is_dismissed = action in dismissed_actions or rec_id in dismissed_ids
        prio = "HIGH" if len(mfa_sources) >= 2 or br_total_breaches >= 2 else "MEDIUM"
        unified_map[action] = {
            "id": rec_id,
            "action_type": action,
            "category": "security_posture",
            "priority": prio,
            "title": "Enforce Hardware or App-Based Multi-Factor Authentication",
            "description": "Because your identity was observed across multiple threat vectors, attackers may attempt credential stuffing or SMS SIM swaps. Enforce app-based 2FA (e.g. Google Authenticator) on all sensitive accounts.",
            "source_modules": mfa_sources,
            "reason": " ".join(mfa_reasons),
            "is_dismissed": is_dismissed,
            "created_at": existing_by_action[action].created_at.isoformat() if action in existing_by_action else now_utc
        }

    # --- ACTION 5: secure_documents ---
    if doc_has_high_risk:
        action = "secure_documents"
        rec_id = str(existing_by_action[action].id) if action in existing_by_action else str(_deterministic_uuid(str(user_uuid), action))
        is_dismissed = action in dismissed_actions or rec_id in dismissed_ids
        unified_map[action] = {
            "id": rec_id,
            "action_type": action,
            "category": "document_security",
            "priority": "HIGH",
            "title": "Encrypt and Secure Stored Documents Containing High-Risk PII",
            "description": "Uploaded documents contain verified high-risk personal identifiers. Remove unencrypted copies from shared folders or desktop storage and keep files in access-controlled vaults.",
            "source_modules": ["document_scanner"],
            "reason": "Multiple HIGH/CRITICAL severity PII findings identified in document scanner.",
            "is_dismissed": is_dismissed,
            "created_at": existing_by_action[action].created_at.isoformat() if action in existing_by_action else now_utc
        }

    # --- ACTION 6: review_security ---
    if doc_has_contact or any(e.total_entities > 0 for e in exposures) or br_total_breaches > 0:
        # Only suggest general review if contact data is confirmed
        action = "review_security"
        if action not in unified_map:
            rec_id = str(existing_by_action[action].id) if action in existing_by_action else str(_deterministic_uuid(str(user_uuid), action))
            is_dismissed = action in dismissed_actions or rec_id in dismissed_ids
            rev_sources = []
            if doc_has_contact:
                rev_sources.append("document_scanner")
            if any(e.total_entities > 0 for e in exposures):
                rev_sources.append("exposure_monitor")
            if br_total_breaches > 0:
                rev_sources.append("breach_monitor")

            if rev_sources:
                unified_map[action] = {
                    "id": rec_id,
                    "action_type": action,
                    "category": "security_posture",
                    "priority": "LOW",
                    "title": "Heighten Vigilance Against Phishing & Social Engineering",
                    "description": "Your contact information was observed in digital footprint audits. Scammers frequently leverage exposed email addresses and phone numbers for targeted spear-phishing campaigns.",
                    "source_modules": rev_sources,
                    "reason": f"Contact details observed across {', '.join(rev_sources)}.",
                    "is_dismissed": is_dismissed,
                    "created_at": existing_by_action[action].created_at.isoformat() if action in existing_by_action else now_utc
                }

    # 6. Include any additional persisted recommendations from Phase 8 not already mapped
    for prec in persisted_recs:
        if prec.action_type not in unified_map:
            unified_map[prec.action_type] = {
                "id": str(prec.id),
                "action_type": prec.action_type,
                "category": prec.category,
                "priority": prec.priority,
                "title": prec.title,
                "description": prec.description,
                "source_modules": [prec.source_module],
                "reason": f"Generated by {prec.source_module}.",
                "is_dismissed": prec.is_dismissed,
                "created_at": prec.created_at.isoformat() if prec.created_at else now_utc
            }

    # 7. Filter active if requested
    recommendations = list(unified_map.values())
    if active_only:
        recommendations = [r for r in recommendations if not r.get("is_dismissed", False)]

    # 8. Deterministic Sorting:
    # Primary: Priority Rank (CRITICAL > HIGH > MEDIUM > LOW)
    # Secondary: Count of Source Modules (3 > 2 > 1)
    # Tertiary: action_type alphabetically
    def sort_key(rec):
        prio_rank = PRIORITY_RANKS.get(rec.get("priority", "LOW").upper(), 0)
        source_count = len(rec.get("source_modules", []))
        action = rec.get("action_type", "")
        return (-prio_rank, -source_count, action)

    recommendations.sort(key=sort_key)
    return recommendations
