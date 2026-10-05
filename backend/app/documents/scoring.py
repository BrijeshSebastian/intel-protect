"""
Intel-Protect Deterministic Privacy Risk Scoring Engine.
Calculates a transparent, explainable, bounded 0-100 privacy risk score
from deterministic PII findings, detection confidence, and checksum validations.

Formula and Rules:
1. Base Weights per PII type (Financial and Government Identity have highest weights).
2. Severity Multipliers (CRITICAL: 1.5, HIGH: 1.2, MEDIUM: 1.0, LOW: 0.8).
3. Checksum Verification Factor (Valid Verhoeff/Luhn gives full confidence boost).
4. Sub-linear Diminishing Marginal Returns for repeat occurrences of the same type.
5. Multi-Vector Compounding Boost (combining Financial + Identity + Contact).
6. Strict Bounded Range: 0.0 <= score <= 100.0.
"""
import math
from typing import Any

RISK_SCORING_VERSION = "1.0"

# ==============================================================================
# CONFIGURABLE SCORING WEIGHTS & CONSTANTS
# ==============================================================================

# 1. Base Risk Weights by PII Type
PII_BASE_WEIGHTS = {
    "CARD": 32.0,          # Payment card (direct financial compromise)
    "BANK_ACCOUNT": 28.0,  # Bank account (financial KYC & withdrawal vector)
    "AADHAAR": 28.0,       # Aadhaar (primary national biometric ID)
    "PAN": 24.0,           # PAN (statutory tax and KYC entity ID)
    "PHONE": 10.0,         # Mobile contact (OTP interception / phishing)
    "EMAIL": 8.0,          # Email contact (phishing / credential stuffing)
    "CREDENTIAL": 35.0,    # Passwords / API tokens (direct system access)
}

# Default fallback for unlisted types
DEFAULT_BASE_WEIGHT = 15.0

# 2. Severity Multipliers
SEVERITY_MULTIPLIERS = {
    "CRITICAL": 1.5,
    "HIGH": 1.2,
    "MEDIUM": 1.0,
    "LOW": 0.8,
}

# 3. Checksum Validation Multipliers
CHECKSUM_MULTIPLIERS = {
    True: 1.2,    # Mathematical check digit passed (Verhoeff or Luhn)
    False: 0.3,   # Check digit failed
    None: 1.0,    # No check digit exists for this type
}

# 4. Diminishing Returns Factor for Repeated Occurrences of Same PII Type
# 1st instance: 1.0x, 2nd: 0.6x, 3rd: 0.36x, etc.
REPEAT_OCCURRENCE_DECAY = 0.60

# 5. Multi-Vector Compound Synergy Boosts
COMPOUND_BOOST_FINANCIAL_AND_IDENTITY = 0.15  # +15% if both Financial and Identity PII exist
COMPOUND_BOOST_TRIAD = 0.25                  # +25% if Financial, Identity, AND Contact exist

# 6. Risk Level Categorization Thresholds
RISK_LEVEL_THRESHOLDS = [
    (75.0, "CRITICAL"),
    (50.0, "HIGH"),
    (25.0, "MEDIUM"),
    (0.0, "LOW"),
]


# ==============================================================================
# RISK SCORING ENGINE
# ==============================================================================

def calculate_privacy_risk_score(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Computes a deterministic, transparent 0-100 privacy risk score from PII findings.
    Returns:
        {
            "score": float (0.0 to 100.0),
            "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            "scoring_version": "1.0",
            "explanation": {
                "finding_count": int,
                "high_risk_findings": int,
                "financial_findings": int,
                "identity_findings": int,
                "contact_findings": int,
                "checksum_validated_count": int,
                "compound_boost_percentage": float,
                "contributing_factors": list[str],
                "itemized_breakdown": list[dict]
            }
        }
    """
    if not findings:
        return {
            "score": 0.0,
            "risk_level": "LOW",
            "scoring_version": RISK_SCORING_VERSION,
            "explanation": {
                "finding_count": 0,
                "high_risk_findings": 0,
                "financial_findings": 0,
                "identity_findings": 0,
                "contact_findings": 0,
                "checksum_validated_count": 0,
                "compound_boost_percentage": 0.0,
                "contributing_factors": ["No sensitive PII entities detected in document."],
                "itemized_breakdown": []
            }
        }

    # Count occurrences per PII type to apply diminishing returns decay
    type_counts: dict[str, int] = {}
    itemized_breakdown = []
    raw_accumulated_score = 0.0
    contributing_factors = []

    financial_count = 0
    identity_count = 0
    contact_count = 0
    high_risk_count = 0
    checksum_valid_count = 0

    for f in findings:
        if isinstance(f, dict):
            pii_type = str(f.get("pii_type", "UNKNOWN")).upper()
            severity = str(f.get("severity", "MEDIUM")).upper()
            confidence = float(f.get("confidence", 0.90))
            checksum_valid = f.get("checksum_valid", None)
            masked_value = str(f.get("masked_value", "XXXX"))
        else:
            pii_type = str(getattr(f, "pii_type", "UNKNOWN")).upper()
            severity = str(getattr(f, "severity", "MEDIUM")).upper()
            confidence = float(getattr(f, "confidence", 0.90))
            checksum_valid = getattr(f, "checksum_valid", None)
            masked_value = str(getattr(f, "masked_value", "XXXX"))

        # Ensure confidence is bounded [0.0, 1.0]
        confidence = max(0.0, min(1.0, confidence))

        # Update categories
        if pii_type in ("CARD", "BANK_ACCOUNT"):
            financial_count += 1
        elif pii_type in ("AADHAAR", "PAN"):
            identity_count += 1
        elif pii_type in ("EMAIL", "PHONE"):
            contact_count += 1

        if severity in ("HIGH", "CRITICAL"):
            high_risk_count += 1

        if checksum_valid is True:
            checksum_valid_count += 1

        # Calculate instance decay
        curr_occ = type_counts.get(pii_type, 0)
        decay = math.pow(REPEAT_OCCURRENCE_DECAY, curr_occ)
        type_counts[pii_type] = curr_occ + 1

        # Lookups
        base_weight = PII_BASE_WEIGHTS.get(pii_type, DEFAULT_BASE_WEIGHT)
        sev_multiplier = SEVERITY_MULTIPLIERS.get(severity, 1.0)
        chk_multiplier = CHECKSUM_MULTIPLIERS.get(checksum_valid, 1.0)

        # Finding contribution
        finding_contrib = base_weight * sev_multiplier * chk_multiplier * confidence * decay
        raw_accumulated_score += finding_contrib

        itemized_breakdown.append({
            "pii_type": pii_type,
            "masked_value": masked_value,
            "severity": severity,
            "confidence": round(confidence, 2),
            "checksum_valid": checksum_valid,
            "occurrence_index": curr_occ + 1,
            "contribution": round(finding_contrib, 2)
        })

    # Compound synergy boost calculation
    compound_boost = 0.0
    has_financial = financial_count > 0
    has_identity = identity_count > 0
    has_contact = contact_count > 0

    if has_financial and has_identity and has_contact:
        compound_boost = COMPOUND_BOOST_TRIAD
        contributing_factors.append(
            "Multi-vector identity compromise: Document combines Financial, Identity, and Contact PII (+25% compound boost)."
        )
    elif has_financial and has_identity:
        compound_boost = COMPOUND_BOOST_FINANCIAL_AND_IDENTITY
        contributing_factors.append(
            "High-risk KYC combination: Document combines Financial and Identity documents (+15% compound boost)."
        )

    # Apply compound boost
    boosted_raw_score = raw_accumulated_score * (1.0 + compound_boost)

    # Normalize strictly to [0.0, 100.0]
    final_score = min(100.0, max(0.0, boosted_raw_score))
    final_score = round(final_score, 1)

    # Map to Risk Level
    risk_level = "LOW"
    for threshold, level in RISK_LEVEL_THRESHOLDS:
        if final_score >= threshold:
            risk_level = level
            break

    # Build human-readable contributing factor summary points
    if high_risk_count > 0:
        contributing_factors.append(
            f"Detected {high_risk_count} HIGH/CRITICAL severity findings requiring immediate isolation."
        )
    if "CARD" in type_counts:
        contributing_factors.append(
            f"Payment Card detected with Luhn checksum validation ({type_counts['CARD']} occurrence(s))."
        )
    if "AADHAAR" in type_counts:
        contributing_factors.append(
            f"Aadhaar UIDAI record detected with Verhoeff dihedral D5 validation ({type_counts['AADHAAR']} occurrence(s))."
        )
    if "BANK_ACCOUNT" in type_counts:
        contributing_factors.append(
            f"Bank account number detected with contextual verification ({type_counts['BANK_ACCOUNT']} occurrence(s))."
        )
    if "PAN" in type_counts:
        contributing_factors.append(
            f"Permanent Account Number (PAN) tax identifier detected ({type_counts['PAN']} occurrence(s))."
        )
    if contact_count > 0 and len(contributing_factors) < 5:
        contributing_factors.append(
            f"Contact identifiers detected ({contact_count} email/phone finding(s))."
        )

    return {
        "score": final_score,
        "risk_level": risk_level,
        "scoring_version": RISK_SCORING_VERSION,
        "explanation": {
            "finding_count": len(findings),
            "high_risk_findings": high_risk_count,
            "financial_findings": financial_count,
            "identity_findings": identity_count,
            "contact_findings": contact_count,
            "checksum_validated_count": checksum_valid_count,
            "compound_boost_percentage": round(compound_boost * 100, 1),
            "contributing_factors": contributing_factors,
            "itemized_breakdown": itemized_breakdown
        }
    }
