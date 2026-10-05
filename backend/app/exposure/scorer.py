"""
Deterministic Exposure Risk Scoring Engine for Exposure Monitor.
Computes an explainable, bounded 0-100 exposure risk score combining
entity categories, TF-IDF + Random Forest sensitivity predictions,
and Isolation Forest anomaly scores.
"""
from typing import Any

EXPOSURE_SCORING_VERSION = "1.0"

# ==============================================================================
# CONFIGURABLE WEIGHTS & CONSTANTS
# ==============================================================================

# 1. Category Weights in Final Composite Score (Sum = 1.0)
CATEGORY_WEIGHTS = {
    "credential": 0.30,  # Highest direct account takeover threat
    "financial": 0.25,   # Direct financial fraud and banking threat
    "identity": 0.25,    # Statutory identity theft & KYC compromise
    "contact": 0.12,     # Phishing, spam, and OTP interception vector
    "location": 0.08,    # Physical location profiling
}

# 2. Entity Base Weights per Category (Capped at 100 per category)
ENTITY_WEIGHTS = {
    # Credential
    "CREDENTIAL": 60.0,
    "JWT": 60.0,
    "API_SECRET": 50.0,
    "PASSWORD": 50.0,
    # Financial
    "FINANCIAL": 45.0,
    "CARD": 45.0,
    "BANK_ACCOUNT": 35.0,
    "IFSC": 15.0,
    # Identity
    "IDENTITY": 40.0,
    "AADHAAR": 45.0,
    "PAN": 35.0,
    "PERSON": 20.0,
    "USERNAME": 15.0,
    # Contact
    "PHONE": 25.0,
    "EMAIL": 20.0,
    # Location
    "LOCATION": 20.0,
}

# 3. Repeat Occurrence Decay Factor
REPEAT_OCCURRENCE_DECAY = 0.60

# 4. ML Sensitivity Label Boost
SENSITIVITY_LABEL_BOOST = {
    "CRITICAL": 20.0,
    "HIGH": 12.0,
    "MEDIUM": 6.0,
    "LOW": 0.0,
}

# 5. Anomaly Boost
ANOMALY_MAX_BOOST = 15.0

# 6. Multi-Vector Synergy Multipliers
COMPOUND_BOOST_FINANCIAL_AND_IDENTITY = 0.10  # +10%
COMPOUND_BOOST_TRIAD_WITH_CREDENTIAL = 0.20   # +20%

# 7. Risk Level Thresholds
EXPOSURE_LEVEL_THRESHOLDS = [
    (75.0, "CRITICAL"),
    (50.0, "HIGH"),
    (25.0, "MEDIUM"),
    (0.0, "LOW"),
]


def calculate_category_scores(entities: list[Any]) -> dict[str, float]:
    """
    Computes bounded (0-100) scores for each exposure category:
    credential, financial, identity, contact, location.
    Applies diminishing returns to repeated entities of the same type.
    """
    cat_accumulators: dict[str, float] = {
        "credential": 0.0,
        "financial": 0.0,
        "identity": 0.0,
        "contact": 0.0,
        "location": 0.0
    }
    type_counts: dict[str, int] = {}

    for e in entities:
        if isinstance(e, dict):
            etype = e.get("entity_type", "UNKNOWN")
            cat = e.get("category", "identity")
            conf = float(e.get("confidence", 0.90))
            vstatus = e.get("validation_status", "STRUCTURAL")
        else:
            etype = getattr(e, "entity_type", "UNKNOWN")
            cat = getattr(e, "category", "identity")
            conf = float(getattr(e, "confidence", 0.90))
            vstatus = getattr(e, "validation_status", "STRUCTURAL")

        cat = cat.lower()
        if cat not in cat_accumulators:
            cat = "identity"

        count = type_counts.get(etype, 0)
        decay = REPEAT_OCCURRENCE_DECAY ** count
        type_counts[etype] = count + 1

        base_wt = ENTITY_WEIGHTS.get(etype, 15.0)

        # Checksum / validation boost or penalty
        val_multiplier = 1.2 if vstatus == "VALID" else (0.4 if vstatus == "INVALID" else 1.0)
        contrib = base_wt * decay * conf * val_multiplier
        cat_accumulators[cat] += contrib

    # Bound each category strictly between 0 and 100
    category_scores = {}
    for cat, raw in cat_accumulators.items():
        category_scores[cat] = round(min(100.0, max(0.0, raw)), 1)

    return category_scores


def calculate_exposure_score(
    entities: list[Any],
    sensitivity_label: str = "LOW",
    sensitivity_confidence: float = 1.0,
    is_anomalous: bool = False,
    anomaly_score: float = 0.0
) -> dict[str, Any]:
    """
    Calculates the composite 0-100 deterministic exposure score.
    Returns:
        {
            "score": float (0.0 to 100.0),
            "exposure_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            "category_scores": {"identity": float, "contact": float, ...},
            "explanation": {
                "sensitive_entities": int,
                "high_sensitivity_records": int,
                "anomalies": int,
                "contributing_factors": list[str]
            }
        }
    """
    if not entities and sensitivity_label.upper() == "LOW" and not is_anomalous:
        return {
            "score": 0.0,
            "exposure_level": "LOW",
            "scoring_version": EXPOSURE_SCORING_VERSION,
            "category_scores": {
                "identity": 0.0,
                "contact": 0.0,
                "location": 0.0,
                "financial": 0.0,
                "credential": 0.0
            },
            "explanation": {
                "sensitive_entities": 0,
                "high_sensitivity_records": 0,
                "anomalies": 0,
                "contributing_factors": ["No personal data exposure detected for the given identifiers."]
            }
        }

    # 1. Compute per-category scores
    category_scores = calculate_category_scores(entities)

    # 2. Maximum category risk + distributed contribution across categories
    max_cat_score = max(category_scores.values()) if category_scores else 0.0
    weighted_cat_sum = sum(
        CATEGORY_WEIGHTS[cat] * category_scores[cat]
        for cat in CATEGORY_WEIGHTS
    )
    # Blend max category (ensures a compromised vector reflects proper severity)
    # with multi-vector breadths
    base_category_score = 0.55 * max_cat_score + 0.45 * (weighted_cat_sum * 1.8)

    # 3. Add ML Sensitivity Classification Boost
    sens_upper = sensitivity_label.upper()
    sens_boost = SENSITIVITY_LABEL_BOOST.get(sens_upper, 0.0)

    # 4. Add Anomaly Detection Boost
    anomaly_boost = 0.0
    if is_anomalous:
        # Scale anomaly boost by anomaly score
        anomaly_boost = ANOMALY_MAX_BOOST * max(0.5, min(1.0, anomaly_score))

    # Base combined score
    combined_score = base_category_score + sens_boost + anomaly_boost

    # 5. Multi-Vector Synergy Multiplier
    has_financial = category_scores.get("financial", 0) > 0
    has_identity = category_scores.get("identity", 0) > 0
    has_credential = category_scores.get("credential", 0) > 0

    synergy_multiplier = 0.0
    if has_credential and has_financial and has_identity:
        synergy_multiplier = COMPOUND_BOOST_TRIAD_WITH_CREDENTIAL
    elif has_financial and has_identity:
        synergy_multiplier = COMPOUND_BOOST_FINANCIAL_AND_IDENTITY

    boosted_score = combined_score * (1.0 + synergy_multiplier)

    # 6. Normalize strictly between 0.0 and 100.0
    final_score = min(100.0, max(0.0, boosted_score))
    final_score = round(final_score, 1)

    # 7. Map to Categorical Exposure Level
    exposure_level = "LOW"
    for threshold, level in EXPOSURE_LEVEL_THRESHOLDS:
        if final_score >= threshold:
            exposure_level = level
            break

    # 8. Compile Contributing Factors
    contributing_factors = []
    sensitive_entities_count = sum(
        1 for e in entities
        if (getattr(e, "category", "") in ("financial", "credential") or
            getattr(e, "entity_type", "") in ("AADHAAR", "PAN", "CARD", "CREDENTIAL"))
    )

    if synergy_multiplier == COMPOUND_BOOST_TRIAD_WITH_CREDENTIAL:
        contributing_factors.append("Multi-vector Triad Synergy: Concurrent exposure of Credential, Financial, and Identity vectors (+20% compound risk).")
    elif synergy_multiplier == COMPOUND_BOOST_FINANCIAL_AND_IDENTITY:
        contributing_factors.append("Compound Synergy: Concurrent exposure of Financial and Identity records (+10% compound risk).")

    if category_scores.get("credential", 0) > 0:
        contributing_factors.append("Exposed account credentials, passwords, or authentication tokens.")
    if category_scores.get("financial", 0) > 0:
        contributing_factors.append("Payment card or bank account records detected in public/paste sources.")
    if category_scores.get("identity", 0) > 0:
        contributing_factors.append("Government identity credentials (Aadhaar/PAN) or personal identity profiles detected.")
    if is_anomalous:
        contributing_factors.append(f"Anomalous exposure volume detected (Isolation Forest anomaly score: {round(anomaly_score, 2)}).")
    if sens_upper in ("HIGH", "CRITICAL"):
        contributing_factors.append(f"ML Classifier evaluated exposure context as {sens_upper} sensitivity.")
    if category_scores.get("contact", 0) > 0 and len(contributing_factors) < 4:
        contributing_factors.append("Direct contact channels (email or phone) exposed to potential phishing/vishing.")

    if not contributing_factors:
        contributing_factors.append("Low-impact exposure records with minimal sensitive attributes.")

    return {
        "score": final_score,
        "exposure_level": exposure_level,
        "scoring_version": EXPOSURE_SCORING_VERSION,
        "category_scores": category_scores,
        "explanation": {
            "sensitive_entities": sensitive_entities_count,
            "high_sensitivity_records": 1 if sens_upper in ("HIGH", "CRITICAL") else 0,
            "anomalies": 1 if is_anomalous else 0,
            "contributing_factors": contributing_factors
        }
    }
