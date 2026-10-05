"""
Comprehensive Unit, Property, and Integration Tests for Deterministic Privacy Risk Scoring Engine (scoring.py).
Tests:
- Base weights, severity multipliers, and checksum validation multipliers
- Repeat occurrence diminishing marginal returns decay
- Multi-vector compound synergy boosts (Financial + Identity, Triad)
- Property tests: Strict bounding [0.0, 100.0] across 1,000 permutations
- Property tests: Monotonicity (adding findings never decreases risk)
- Database persistence of risk scores and explanation JSON
- REST API: POST /scan returns risk envelope, GET /<id>/risk with strict user isolation
"""
import io
import random
import uuid
import pytest

from backend.app import db
from backend.app.models.user import User
from backend.app.models.document import Document
from backend.app.models.pii_finding import PIIFinding
from backend.app.common.security import create_access_token
from backend.app.documents.scoring import (
    calculate_privacy_risk_score,
    PII_BASE_WEIGHTS,
    SEVERITY_MULTIPLIERS,
    CHECKSUM_MULTIPLIERS,
    REPEAT_OCCURRENCE_DECAY,
    COMPOUND_BOOST_FINANCIAL_AND_IDENTITY,
    COMPOUND_BOOST_TRIAD,
    RISK_SCORING_VERSION,
)


@pytest.fixture(autouse=True)
def clean_database(app):
    """Clean database before each test execution."""
    with app.app_context():
        PIIFinding.query.delete()
        Document.query.delete()
        User.query.delete()
        db.session.commit()


@pytest.fixture
def auth_user(app):
    """Creates a primary test user and returns (user, token)."""
    with app.app_context():
        user = User(
            email="risk_tester@example.com",
            username="risktester",
            password_hash="argon2_placeholder",
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        token = create_access_token(str(user.id), user.email)
        return user, token


@pytest.fixture
def second_user(app):
    """Creates a second user for data isolation verification."""
    with app.app_context():
        user = User(
            email="risk_second@example.com",
            username="risksecond",
            password_hash="argon2_placeholder",
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        token = create_access_token(str(user.id), user.email)
        return user, token


# ==============================================================================
# 1. UNIT TESTS: DETERMINISTIC SCORING FORMULA
# ==============================================================================

def test_calculate_score_empty_findings():
    """Empty findings list yields 0.0 LOW score with valid explanation structure."""
    result = calculate_privacy_risk_score([])
    assert result["score"] == 0.0
    assert result["risk_level"] == "LOW"
    assert result["scoring_version"] == RISK_SCORING_VERSION
    assert result["explanation"]["finding_count"] == 0
    assert result["explanation"]["high_risk_findings"] == 0
    assert result["explanation"]["compound_boost_percentage"] == 0.0
    assert "No sensitive PII entities detected" in result["explanation"]["contributing_factors"][0]
    assert result["explanation"]["itemized_breakdown"] == []


def test_calculate_score_single_card_luhn_valid():
    """Payment Card with valid Luhn checksum: 32 base * 1.5 critical * 1.2 valid = 57.6 (HIGH)."""
    findings = [{
        "pii_type": "CARD",
        "severity": "CRITICAL",
        "confidence": 1.0,
        "checksum_valid": True,
        "masked_value": "XXXX-XXXX-XXXX-1111"
    }]
    result = calculate_privacy_risk_score(findings)
    assert result["score"] == 57.6
    assert result["risk_level"] == "HIGH"
    assert result["explanation"]["finding_count"] == 1
    assert result["explanation"]["financial_findings"] == 1
    assert result["explanation"]["checksum_validated_count"] == 1


def test_calculate_score_single_card_luhn_failed():
    """Payment Card with failed Luhn checksum: 32 base * 1.5 critical * 0.3 failed = 14.4 (LOW)."""
    findings = [{
        "pii_type": "CARD",
        "severity": "CRITICAL",
        "confidence": 1.0,
        "checksum_valid": False,
        "masked_value": "XXXX-XXXX-XXXX-1112"
    }]
    result = calculate_privacy_risk_score(findings)
    assert result["score"] == 14.4
    assert result["risk_level"] == "LOW"
    assert result["explanation"]["checksum_validated_count"] == 0


def test_calculate_score_single_aadhaar_verhoeff_valid():
    """Aadhaar with valid Verhoeff D5: 28 base * 1.5 critical * 1.2 valid = 50.4 (HIGH)."""
    findings = [{
        "pii_type": "AADHAAR",
        "severity": "CRITICAL",
        "confidence": 1.0,
        "checksum_valid": True,
        "masked_value": "XXXX-XXXX-9012"
    }]
    result = calculate_privacy_risk_score(findings)
    assert result["score"] == 50.4
    assert result["risk_level"] == "HIGH"
    assert result["explanation"]["identity_findings"] == 1
    assert result["explanation"]["checksum_validated_count"] == 1


def test_calculate_score_single_pan():
    """PAN Card: 24 base * 1.2 high * 1.0 = 28.8 (MEDIUM)."""
    findings = [{
        "pii_type": "PAN",
        "severity": "HIGH",
        "confidence": 1.0,
        "checksum_valid": None,
        "masked_value": "ABCDE1234F"
    }]
    result = calculate_privacy_risk_score(findings)
    assert result["score"] == 28.8
    assert result["risk_level"] == "MEDIUM"
    assert result["explanation"]["identity_findings"] == 1


def test_calculate_score_single_email_and_phone():
    """Email (8 * 0.8 = 6.4) and Phone (10 * 1.0 = 10.0) produce LOW risk individually."""
    res_email = calculate_privacy_risk_score([{
        "pii_type": "EMAIL", "severity": "LOW", "confidence": 1.0, "checksum_valid": None
    }])
    assert res_email["score"] == 6.4
    assert res_email["risk_level"] == "LOW"

    res_phone = calculate_privacy_risk_score([{
        "pii_type": "PHONE", "severity": "MEDIUM", "confidence": 1.0, "checksum_valid": None
    }])
    assert res_phone["score"] == 10.0
    assert res_phone["risk_level"] == "LOW"


# ==============================================================================
# 2. DIMINISHING MARGINAL RETURNS (SUB-LINEAR REPEAT DECAY)
# ==============================================================================

def test_diminishing_marginal_returns():
    """Repeat occurrences of the same PII type decay by 0.60^(occ-1)."""
    finding = {
        "pii_type": "PHONE",
        "severity": "MEDIUM",
        "confidence": 1.0,
        "checksum_valid": None
    }
    # 1 phone: 10.0 raw
    res1 = calculate_privacy_risk_score([finding])
    assert res1["score"] == 10.0

    # 2 phones: 10.0 + 10.0 * 0.6 = 16.0
    res2 = calculate_privacy_risk_score([finding, finding])
    assert res2["score"] == 16.0

    # 3 phones: 16.0 + 10.0 * 0.36 = 19.6
    res3 = calculate_privacy_risk_score([finding, finding, finding])
    assert res3["score"] == 19.6

    # Verify strictly diminishing increments: delta(1->2) = 6.0 > delta(2->3) = 3.6
    inc_1_to_2 = res2["score"] - res1["score"]
    inc_2_to_3 = res3["score"] - res2["score"]
    assert inc_1_to_2 > inc_2_to_3


# ==============================================================================
# 3. MULTI-VECTOR COMPOUND SYNERGY BOOSTS
# ==============================================================================

def test_compound_boost_financial_and_identity():
    """Combining Financial (Bank) + Identity (PAN) triggers +15% compound boost."""
    findings = [
        {"pii_type": "BANK_ACCOUNT", "severity": "HIGH", "confidence": 1.0, "checksum_valid": None},  # 28 * 1.2 = 33.6
        {"pii_type": "PAN", "severity": "HIGH", "confidence": 1.0, "checksum_valid": None},          # 24 * 1.2 = 28.8
    ]
    # Raw = 33.6 + 28.8 = 62.4. Boosted = 62.4 * 1.15 = 71.76 -> rounded to 71.8 (HIGH)
    result = calculate_privacy_risk_score(findings)
    assert result["score"] == 71.8
    assert result["risk_level"] == "HIGH"
    assert result["explanation"]["compound_boost_percentage"] == 15.0
    assert any("High-risk KYC combination" in f for f in result["explanation"]["contributing_factors"])


def test_compound_boost_triad():
    """Combining Financial (Card) + Identity (Aadhaar) + Contact (Email) triggers +25% triad boost."""
    findings = [
        {"pii_type": "CARD", "severity": "CRITICAL", "confidence": 1.0, "checksum_valid": True},      # 32 * 1.5 * 1.2 = 57.6
        {"pii_type": "AADHAAR", "severity": "CRITICAL", "confidence": 1.0, "checksum_valid": True},  # 28 * 1.5 * 1.2 = 50.4
        {"pii_type": "EMAIL", "severity": "LOW", "confidence": 1.0, "checksum_valid": None},         # 8 * 0.8 = 6.4
    ]
    # Raw = 57.6 + 50.4 + 6.4 = 114.4. Boosted = 114.4 * 1.25 = 143.0. Bounded strictly to 100.0 (CRITICAL)
    result = calculate_privacy_risk_score(findings)
    assert result["score"] == 100.0
    assert result["risk_level"] == "CRITICAL"
    assert result["explanation"]["compound_boost_percentage"] == 25.0
    assert any("Multi-vector identity compromise" in f for f in result["explanation"]["contributing_factors"])


# ==============================================================================
# 4. PROPERTY TESTS: STRICT BOUNDING & MONOTONICITY
# ==============================================================================

def test_property_strictly_bounded_1000_permutations():
    """Property test: Score must remain strictly bounded in [0.0, 100.0] across 1,000 permutations."""
    pii_types = ["CARD", "BANK_ACCOUNT", "AADHAAR", "PAN", "EMAIL", "PHONE", "CREDENTIAL", "CUSTOM"]
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    checksum_options = [True, False, None]

    rng = random.Random(42)  # Deterministic seed for reproducible property testing

    for _ in range(1000):
        count = rng.randint(0, 50)
        sample_findings = []
        for _ in range(count):
            sample_findings.append({
                "pii_type": rng.choice(pii_types),
                "severity": rng.choice(severities),
                "confidence": rng.uniform(0.1, 1.0),
                "checksum_valid": rng.choice(checksum_options),
                "masked_value": "XXXX-XXXX"
            })

        result = calculate_privacy_risk_score(sample_findings)
        score = result["score"]

        assert 0.0 <= score <= 100.0, f"Score {score} violated bounds [0.0, 100.0]!"
        assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert result["explanation"]["finding_count"] == count


def test_property_monotonicity():
    """Property test: Adding an additional finding to any set must NEVER decrease the risk score."""
    rng = random.Random(99)
    pii_types = ["CARD", "BANK_ACCOUNT", "AADHAAR", "PAN", "EMAIL", "PHONE"]
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    base_findings = []
    for _ in range(50):
        # Calculate current score
        prev_result = calculate_privacy_risk_score(base_findings)

        # Add one new finding
        new_finding = {
            "pii_type": rng.choice(pii_types),
            "severity": rng.choice(severities),
            "confidence": rng.uniform(0.5, 1.0),
            "checksum_valid": True,
            "masked_value": "XXXX"
        }
        base_findings.append(new_finding)

        new_result = calculate_privacy_risk_score(base_findings)
        assert new_result["score"] >= prev_result["score"], (
            f"Monotonicity violated: previous score {prev_result['score']} > new score {new_result['score']}"
        )


# ==============================================================================
# 5. INTEGRATION & API TESTS WITH USER DATA ISOLATION
# ==============================================================================

def test_scan_api_returns_risk_envelope(client, auth_user):
    """POST /api/documents/scan returns complete risk score and explanation envelope."""
    user, token = auth_user
    sample_text = (
        "CONFIDENTIAL KYC DOCUMENT:\n"
        "Customer Name: John Doe\n"
        "Aadhaar Number: 3675 9834 6016\n"  # Valid Verhoeff check digit 6
        "Primary Email: john.doe@secure-vault.io\n"
        "Primary Mobile: +91 98765 43210\n"
    )

    data = {
        "file": (io.BytesIO(sample_text.encode("utf-8")), "kyc_sample.txt")
    }

    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 201
    resp_data = response.get_json()["data"]

    # Verify document record has persisted risk attributes
    doc = resp_data["document"]
    assert "risk_score" in doc
    assert "risk_level" in doc
    assert "scoring_version" in doc
    assert "score_explanation" in doc
    assert doc["risk_score"] > 0.0

    # Verify top-level risk envelope in response
    assert "risk" in resp_data
    risk = resp_data["risk"]
    assert risk["score"] == doc["risk_score"]
    assert risk["risk_level"] == doc["risk_level"]
    assert risk["scoring_version"] == "1.0"
    assert "explanation" in risk
    assert risk["explanation"]["finding_count"] >= 3


def test_get_document_risk_api_isolation(client, auth_user, second_user):
    """GET /api/documents/<id>/risk returns risk details for owner; returns 404 for other users."""
    user1, token1 = auth_user
    user2, token2 = auth_user_2 = second_user

    # 1. User 1 uploads document
    sample_text = "Tax document PAN: ABCDE1234F and Card: 4532 0150 0000 0000"
    data = {"file": (io.BytesIO(sample_text.encode("utf-8")), "tax_form.txt")}

    upload_res = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token1}"}
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.get_json()["data"]["document"]["id"]

    # 2. User 1 successfully inspects risk breakdown
    res_owner = client.get(
        f"/api/documents/{doc_id}/risk",
        headers={"Authorization": f"Bearer {token1}"}
    )
    assert res_owner.status_code == 200
    owner_data = res_owner.get_json()["data"]
    assert owner_data["document_id"] == doc_id
    assert owner_data["risk_score"] > 0.0
    assert owner_data["risk_level"] in ("HIGH", "CRITICAL", "MEDIUM")
    assert "explanation" in owner_data
    assert len(owner_data["explanation"]["contributing_factors"]) > 0

    # 3. User 2 attempts to inspect User 1's document risk -> 404 NOT_FOUND
    res_intruder = client.get(
        f"/api/documents/{doc_id}/risk",
        headers={"Authorization": f"Bearer {token2}"}
    )
    assert res_intruder.status_code == 404
    assert res_intruder.get_json()["error"]["code"] == "NOT_FOUND"

    # 4. Unauthenticated request -> 401
    res_unauth = client.get(f"/api/documents/{doc_id}/risk")
    assert res_unauth.status_code == 401
