"""
Contextual Security Recommendation Engine.
Analyzes compromised breach data types and generates actionable, prioritized recommendations.
"""
from datetime import datetime, timezone
from typing import Sequence
import uuid
from backend.app.models.breach import Breach
from backend.app.models.recommendation import Recommendation


def generate_breach_recommendations(
    user_id: str,
    breach_result_id: str,
    breaches: Sequence[Breach]
) -> list[Recommendation]:
    """
    Synthesizes contextual security recommendations for the matched breaches.
    """
    if not breaches:
        return []

    all_data_types = set()
    breach_names = [b.name for b in breaches]
    breaches_summary = ", ".join(breach_names[:3])
    if len(breach_names) > 3:
        breaches_summary += f" and {len(breach_names) - 3} others"

    for b in breaches:
        all_data_types.update(str(t).upper() for t in (b.exposed_data_types or []))

    recommendations: list[Recommendation] = []
    now_utc = datetime.now(timezone.utc)

    # 1. Password / Credential Compromise
    if any(t in ("PASSWORD", "PASSWORD_HASH", "API_SECRET", "CREDENTIAL") for t in all_data_types):
        recommendations.append(Recommendation(
            user_id=uuid.UUID(user_id),
            breach_result_id=uuid.UUID(breach_result_id),
            source_module="breach_monitor",
            category="credential",
            priority="CRITICAL",
            title="Password Hash Exposed in Data Leaks",
            description=f"Your account credentials or password hashes were detected in {breaches_summary}. Immediately update your passwords on this and any services sharing similar credentials.",
            action_type="change_password",
            is_dismissed=False,
            created_at=now_utc
        ))

    # 2. Financial Accounts Compromised
    if any(t in ("CARD", "BANK_ACCOUNT", "FINANCIAL") for t in all_data_types):
        recommendations.append(Recommendation(
            user_id=uuid.UUID(user_id),
            breach_result_id=uuid.UUID(breach_result_id),
            source_module="breach_monitor",
            category="financial",
            priority="CRITICAL",
            title="Payment Card or Banking Data Exfiltrated",
            description=f"Financial payment instruments or bank account details were compromised in {breaches_summary}. Monitor recent account statements for unauthorized transactions and request a card replacement from your financial institution.",
            action_type="freeze_card",
            is_dismissed=False,
            created_at=now_utc
        ))

    # 3. Government Identity / KYC Compromised
    if any(t in ("AADHAAR", "PAN", "PASSPORT", "IDENTITY") for t in all_data_types):
        recommendations.append(Recommendation(
            user_id=uuid.UUID(user_id),
            breach_result_id=uuid.UUID(breach_result_id),
            source_module="breach_monitor",
            category="identity",
            priority="HIGH",
            title="Government Identity Document Leaked",
            description=f"Government-issued identity records (e.g., Aadhaar / PAN) were exposed in {breaches_summary}. Lock your Aadhaar biometric authentication online via UIDAI and monitor your credit bureau reports for unauthorized loan inquiries.",
            action_type="lock_biometrics",
            is_dismissed=False,
            created_at=now_utc
        ))

    # 4. Multi-Factor Authentication (when account credentials, passwords, or emails are exposed)
    if any(t in ("PASSWORD", "PASSWORD_HASH", "API_SECRET", "CREDENTIAL", "EMAIL", "USERNAME") for t in all_data_types):
        recommendations.append(Recommendation(
            user_id=uuid.UUID(user_id),
            breach_result_id=uuid.UUID(breach_result_id),
            source_module="breach_monitor",
            category="security_posture",
            priority="HIGH" if len(breaches) >= 2 else "MEDIUM",
            title="Enable Hardware or App-Based 2FA",
            description=f"Because your account credentials or contact information were confirmed in {len(breaches)} security incident(s), attackers may attempt credential stuffing or SIM swapping. Enforce authenticator-app-based two-factor authentication on all critical accounts.",
            action_type="enable_mfa",
            is_dismissed=False,
            created_at=now_utc
        ))

    # 5. Phishing Awareness
    if any(t in ("EMAIL", "PHONE") for t in all_data_types):
        recommendations.append(Recommendation(
            user_id=uuid.UUID(user_id),
            breach_result_id=uuid.UUID(breach_result_id),
            source_module="breach_monitor",
            category="security_posture",
            priority="MEDIUM",
            title="Heightened Phishing Awareness Required",
            description="Your email and telephone numbers were exposed in public leak repositories. Be on high alert for unsolicited spear-phishing emails, urgent SMS requests, or phone calls claiming to be from official services.",
            action_type="review_security",
            is_dismissed=False,
            created_at=now_utc
        ))

    return recommendations
