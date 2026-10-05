"""
Deterministic Breach Risk Scoring Engine.
Computes a transparent, reproducible 0-100 breach risk score based on
breach severities, exposed data sensitivity, breach recency, and compound breach frequency.
"""
from datetime import date, datetime, timezone
import math
from typing import Any, Sequence
from backend.app.models.breach import Breach

BREACH_SCORING_VERSION = "1.0"

# 1. Breach Severity Base Weights
SEVERITY_BASE_WEIGHTS = {
    "CRITICAL": 35.0,
    "HIGH": 25.0,
    "MEDIUM": 14.0,
    "LOW": 7.0,
}

# 2. Exposed Data Type Sensitivity Weights
DATA_TYPE_WEIGHTS = {
    # Credentials
    "PASSWORD": 30.0,
    "PASSWORD_HASH": 28.0,
    "API_SECRET": 30.0,
    "CREDENTIAL": 30.0,
    # Financial
    "CARD": 25.0,
    "BANK_ACCOUNT": 25.0,
    "FINANCIAL": 25.0,
    # Identity
    "AADHAAR": 25.0,
    "PAN": 25.0,
    "PASSPORT": 22.0,
    "IDENTITY": 25.0,
    # Contact
    "PHONE": 12.0,
    "ADDRESS": 10.0,
    "EMAIL": 8.0,
    # General / Profile
    "USERNAME": 6.0,
    "DOB": 8.0,
    "NAME": 6.0,
    "IP": 5.0,
}

# 3. Repeat Exposure Decay Factor for same data type across multiple breaches
REPEAT_DATA_TYPE_DECAY = 0.65

# 4. Multi-Breach Multipliers
MULTI_BREACH_MULTIPLIERS = {
    0: 0.0,
    1: 1.0,
    2: 1.15,
    3: 1.25,
}

# 5. Risk Level Categorization Thresholds
BREACH_LEVEL_THRESHOLDS = [
    (75.0, "CRITICAL"),
    (50.0, "HIGH"),
    (25.0, "MEDIUM"),
    (0.0, "LOW"),
]


def calculate_breach_risk_score(breaches: Sequence[Breach]) -> dict[str, Any]:
    """
    Computes deterministic 0-100 breach risk score from matched Breach records.
    """
    if not breaches:
        return {
            "score": 0.0,
            "risk_level": "LOW",
            "scoring_version": BREACH_SCORING_VERSION,
            "breach_count": 0,
            "total_exposures": 0,
            "explanation": {
                "contributing_factors": ["No breach occurrences identified for this email address."],
                "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "high_risk_data_exposed": False
            }
        }

    now_date = datetime.now(timezone.utc).date()
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    contributing_factors = []

    # 1. Accumulate breach incident base weights with recency decay
    breach_incident_score = 0.0
    for b in breaches:
        sev = (b.severity or "MEDIUM").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        base_sev_wt = SEVERITY_BASE_WEIGHTS.get(sev, 14.0)

        # Recency decay
        b_date = b.breach_date if isinstance(b.breach_date, date) else now_date
        days_ago = max(0, (now_date - b_date).days)
        if days_ago <= 365:
            recency_factor = 1.0
        elif days_ago <= 730:
            recency_factor = 0.85
        elif days_ago <= 1095:
            recency_factor = 0.70
        else:
            recency_factor = 0.55

        breach_incident_score += base_sev_wt * recency_factor

    # 2. Accumulate exposed data types with diminishing returns
    data_type_counts: dict[str, int] = {}
    data_type_accum = 0.0
    has_credentials = False
    has_financial = False
    has_identity = False

    for b in breaches:
        types_list = b.exposed_data_types or []
        for dtype in types_list:
            dt_upper = str(dtype).upper()
            curr_count = data_type_counts.get(dt_upper, 0)
            decay = math.pow(REPEAT_DATA_TYPE_DECAY, curr_count)
            data_type_counts[dt_upper] = curr_count + 1

            wt = DATA_TYPE_WEIGHTS.get(dt_upper, 8.0)
            data_type_accum += wt * decay

            if dt_upper in ("PASSWORD", "PASSWORD_HASH", "API_SECRET", "CREDENTIAL"):
                has_credentials = True
            if dt_upper in ("CARD", "BANK_ACCOUNT", "FINANCIAL"):
                has_financial = True
            if dt_upper in ("AADHAAR", "PAN", "PASSPORT", "IDENTITY"):
                has_identity = True

    # 3. Base combined score
    # Balance incident severity (50%) and data type impact (50%)
    combined = 0.50 * breach_incident_score + 0.50 * data_type_accum

    # 4. Multi-breach multiplier
    n_breaches = len(breaches)
    if n_breaches in MULTI_BREACH_MULTIPLIERS:
        multi_mult = MULTI_BREACH_MULTIPLIERS[n_breaches]
    else:
        multi_mult = 1.30  # 4+ breaches

    boosted = combined * multi_mult

    # 5. Compound synergy boost: Credential + Financial or Identity
    synergy_boost = 0.0
    if has_credentials and (has_financial or has_identity):
        synergy_boost = 15.0
        contributing_factors.append("Compound exposure: Account credentials compromised alongside financial or government identity data (+15 pts).")

    raw_final = boosted + synergy_boost
    final_score = min(100.0, max(0.0, round(raw_final, 1)))

    # 6. Map to categorical level
    risk_level = "LOW"
    for threshold, level in BREACH_LEVEL_THRESHOLDS:
        if final_score >= threshold:
            risk_level = level
            break

    # 7. Compile human-readable explanations
    if severity_counts["CRITICAL"] > 0:
        contributing_factors.append(f"{severity_counts['CRITICAL']} CRITICAL severity security breach(es) detected.")
    if severity_counts["HIGH"] > 0:
        contributing_factors.append(f"{severity_counts['HIGH']} HIGH severity incident(s) compromising sensitive customer data.")
    if has_credentials:
        contributing_factors.append("Authentication passwords, hashes, or security tokens exposed in public leaks.")
    if has_financial:
        contributing_factors.append("Payment card or banking identifiers exfiltrated.")
    if has_identity:
        contributing_factors.append("Government identity documents (Aadhaar/PAN) or KYC records exposed.")
    if n_breaches >= 2:
        contributing_factors.append(f"Multi-breach presence across {n_breaches} distinct corporate services increases credential stuffing risk.")

    total_exposures = sum(data_type_counts.values())

    return {
        "score": final_score,
        "risk_level": risk_level,
        "scoring_version": BREACH_SCORING_VERSION,
        "breach_count": n_breaches,
        "total_exposures": total_exposures,
        "explanation": {
            "contributing_factors": contributing_factors,
            "severity_counts": severity_counts,
            "high_risk_data_exposed": has_credentials or has_financial or has_identity
        }
    }
