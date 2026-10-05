"""
Integration and Unit Tests for Deterministic PII Detection Pipeline (pii_detector.py).
Tests Aadhaar, PAN, Payment Cards, Bank Accounts, Email, Phone, deduplication,
and API findings endpoints with user data isolation.
"""
import io
import uuid
import pytest

from backend.app import db
from backend.app.models.user import User
from backend.app.models.document import Document
from backend.app.models.pii_finding import PIIFinding
from backend.app.common.security import create_access_token
from backend.app.documents.checksum import compute_verhoeff, compute_luhn
from backend.app.documents.pii_detector import (
    detect_pii,
    detect_aadhaar_findings,
    detect_pan_findings,
    detect_card_findings,
    detect_bank_account_findings,
    detect_email_findings,
    detect_phone_findings,
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
    """Creates a test user and returns (user, token)."""
    with app.app_context():
        user = User(
            email="pii_tester@example.com",
            username="piitester",
            password_hash="argon2_placeholder",
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        token = create_access_token(str(user.id), user.email)
        return user, token


@pytest.fixture
def second_user(app):
    """Creates a second user for data isolation tests."""
    with app.app_context():
        user = User(
            email="pii_second@example.com",
            username="piisecond",
            password_hash="argon2_placeholder",
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        token = create_access_token(str(user.id), user.email)
        return user, token


# ==============================================================================
# 1. AADHAAR DETECTION & VERHOEFF VALIDATION
# ==============================================================================

def test_aadhaar_valid_verhoeff_detected():
    """Verify Aadhaar detection with valid Verhoeff check digit."""
    # Generate valid synthetic Aadhaar
    base11 = "29471839201"
    check = compute_verhoeff(base11)
    valid_aadhaar = f"{base11[:4]} {base11[4:8]} {base11[8:]}{check}"

    text = f"Government of India. Resident UIDAI record: Aadhaar No: {valid_aadhaar}. Verified."
    findings = detect_aadhaar_findings(text)

    assert len(findings) == 1
    f = findings[0]
    assert f.pii_type == "AADHAAR"
    assert f.severity == "HIGH"
    assert f.checksum_valid is True
    assert f.confidence >= 0.98
    assert f.masked_value == f"XXXX XXXX {base11[8:]}{check}"
    assert "2947" not in f.context_snippet


def test_aadhaar_invalid_verhoeff_rejected():
    """Verify that 12-digit number with INVALID Verhoeff checksum is REJECTED."""
    base11 = "29471839201"
    correct_check = compute_verhoeff(base11)
    wrong_check = (correct_check + 1) % 10
    invalid_aadhaar = f"{base11[:4]} {base11[4:8]} {base11[8:]}{wrong_check}"

    text = f"Candidate identification reference: {invalid_aadhaar}."
    findings = detect_aadhaar_findings(text)

    assert len(findings) == 0, "Invalid Verhoeff number must not be classified as Aadhaar"


def test_aadhaar_rejects_repeated_digits():
    """Verify rejection of 0000 0000 0000 or 1111 1111 1111."""
    text = "Invalid entries: 0000 0000 0000 and 1111 1111 1111."
    findings = detect_aadhaar_findings(text)
    assert len(findings) == 0


# ==============================================================================
# 2. PAN DETECTION & STRUCTURAL VALIDATION
# ==============================================================================

def test_pan_valid_individual_detected():
    """Verify valid individual PAN (4th letter 'P')."""
    text = "Income Tax Department: Permanent Account Number (PAN) is ABCPD1234F for citizen."
    findings = detect_pan_findings(text)

    assert len(findings) == 1
    f = findings[0]
    assert f.pii_type == "PAN"
    assert f.severity == "HIGH"
    assert f.masked_value == "XXXXX1234X"
    assert f.confidence >= 0.95


def test_pan_company_entity_detected():
    """Verify valid company PAN (4th letter 'C')."""
    text = "Corporate vendor GST filing details: PAN ABCCD5678G."
    findings = detect_pan_findings(text)

    assert len(findings) == 1
    assert findings[0].masked_value == "XXXXX5678X"


def test_pan_invalid_entity_letter_rejected():
    """Verify rejection when 4th letter is not a valid Indian tax entity code."""
    # 'Z' is not a valid status code in Indian PAN
    text = "Tracking reference number: ABCZD1234F."
    findings = detect_pan_findings(text)
    assert len(findings) == 0


def test_pan_lowercase_normalized():
    """Verify lowercase PAN in OCR/document is handled correctly."""
    text = "Scanned tax assessment form: pan number is abcde1234f."
    findings = detect_pan_findings(text)
    assert len(findings) == 1
    assert findings[0].masked_value == "XXXXX1234X"


# ==============================================================================
# 3. PAYMENT CARD DETECTION & LUHN VALIDATION
# ==============================================================================

def test_card_valid_luhn_detected():
    """Verify payment card detection with valid Luhn checksum."""
    # Synthetic Visa
    valid_card = "4532 0151 1283 0366"
    text = f"Payment transaction processed via Credit Card: {valid_card}."
    findings = detect_card_findings(text)

    assert len(findings) == 1
    f = findings[0]
    assert f.pii_type == "CARD"
    assert f.severity == "CRITICAL"
    assert f.checksum_valid is True
    assert f.masked_value == "**** **** **** 0366"
    assert f.confidence >= 0.96


def test_card_invalid_luhn_rejected():
    """Verify that 16-digit sequence with INVALID Luhn checksum is REJECTED."""
    # Invalidate check digit
    invalid_card = "4532 0151 1283 0367"
    text = f"Order reference batch sequence: {invalid_card}."
    findings = detect_card_findings(text)
    assert len(findings) == 0


def test_card_amex_15_digits_detected():
    """Verify 15-digit Amex card."""
    valid_amex = "378282246310005"
    text = f"American Express cardholder billing: {valid_amex}."
    findings = detect_card_findings(text)
    assert len(findings) == 1
    assert findings[0].masked_value.endswith("0005")


# ==============================================================================
# 4. BANK ACCOUNT DETECTION & CONTEXTUAL RULES
# ==============================================================================

def test_bank_account_with_context_detected():
    """Verify bank account detected when accompanied by context keyword."""
    text = "Beneficiary Bank Account Number: 987654321098, Branch: Connaught Place."
    findings = detect_bank_account_findings(text)

    assert len(findings) == 1
    f = findings[0]
    assert f.pii_type == "BANK_ACCOUNT"
    assert f.severity == "HIGH"
    assert f.masked_value == "********1098"
    assert f.confidence >= 0.85


def test_bank_account_with_ifsc_code_high_confidence():
    """Verify bank account paired with IFSC code receives elevated confidence."""
    text = "Account Details: A/C No: 123456789012, IFSC Code: SBIN0001234."
    findings = detect_bank_account_findings(text)

    assert len(findings) == 1
    assert findings[0].confidence >= 0.95


def test_bank_account_without_context_rejected():
    """CRITICAL FALSE-POSITIVE GUARD: Numbers without bank context MUST NOT be flagged as accounts."""
    text = "Shipping tracking number: 987654321098 for warehouse package delivery."
    findings = detect_bank_account_findings(text)
    assert len(findings) == 0


# ==============================================================================
# 5. EMAIL AND PHONE DETECTION
# ==============================================================================

def test_email_detection():
    """Verify RFC 5322 email detection."""
    text = "Please send audit logs to compliance.officer@secure-enterprise.org immediately."
    findings = detect_email_findings(text)

    assert len(findings) == 1
    f = findings[0]
    assert f.pii_type == "EMAIL"
    assert f.severity == "MEDIUM"
    assert "@secure-enterprise.org" in f.masked_value
    assert "compliance.officer" not in f.masked_value


def test_phone_detection_with_prefix():
    """Verify Indian phone with +91 prefix."""
    text = "Emergency contact: +91-9876543210."
    findings = detect_phone_findings(text)

    assert len(findings) == 1
    f = findings[0]
    assert f.pii_type == "PHONE"
    assert f.severity == "MEDIUM"
    assert f.masked_value == "+91-XXXXX-43210"


def test_phone_rejects_order_id_false_positive():
    """Verify that bare 10-digit number with 'Order' or 'Invoice' context is not flagged as phone."""
    text = "Invoice Reference: 9876543210. Billed to client account."
    findings = detect_phone_findings(text)
    assert len(findings) == 0


# ==============================================================================
# 6. UNIFIED DETECTOR & DEDUPLICATION
# ==============================================================================

def test_unified_detector_multi_pii_document():
    """Test unified pipeline on comprehensive synthetic document containing multiple PII types."""
    # Synthetic valid Aadhaar
    base_aadhaar = "31948201938"
    aadhaar_chk = compute_verhoeff(base_aadhaar)
    valid_aadhaar = f"{base_aadhaar[:4]} {base_aadhaar[4:8]} {base_aadhaar[8:]}{aadhaar_chk}"

    # Synthetic valid Card
    valid_card = "4532 0151 1283 0366"

    synthetic_doc = (
        f"EMPLOYEE VERIFICATION REPORT\n"
        f"Name: Ramesh Kumar\n"
        f"Aadhaar Number: {valid_aadhaar}\n"
        f"PAN Number: ABCDP1234F\n"
        f"Salary Account: A/C No 998877665544, IFSC: HDFC0001234\n"
        f"Corporate Card: {valid_card}\n"
        f"Contact Email: ramesh.kumar@example.com\n"
        f"Mobile: +91-9876543210\n"
    )

    findings = detect_pii(synthetic_doc)

    pii_types = [f.pii_type for f in findings]
    assert "AADHAAR" in pii_types
    assert "PAN" in pii_types
    assert "BANK_ACCOUNT" in pii_types
    assert "CARD" in pii_types
    assert "EMAIL" in pii_types
    assert "PHONE" in pii_types
    assert len(findings) == 6


# ==============================================================================
# 7. END-TO-END DOCUMENT SCAN API & FINDINGS PERSISTENCE
# ==============================================================================

def test_document_scan_persists_pii_findings(client, auth_user):
    """Test full API pipeline: upload text -> extract -> detect PII -> save findings in DB."""
    user, token = auth_user

    # Generate synthetic document
    base_aadhaar = "28471930291"
    aadhaar_chk = compute_verhoeff(base_aadhaar)
    valid_aadhaar = f"{base_aadhaar[:4]} {base_aadhaar[4:8]} {base_aadhaar[8:]}{aadhaar_chk}"

    content = (
        f"Audit Doc:\n"
        f"Aadhaar: {valid_aadhaar}\n"
        f"PAN: BKRPP5678M\n"
        f"Card: 4532 0151 1283 0366\n"
    )

    data = {
        "file": (io.BytesIO(content.encode("utf-8")), "audit_pii.txt")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 201
    res_data = response.get_json()["data"]

    doc = res_data["document"]
    findings = res_data["findings"]

    # Verify counts on document record
    assert doc["pii_count"] == 3
    assert doc["high_risk_count"] == 3  # Aadhaar (HIGH), PAN (HIGH), Card (CRITICAL)

    # Verify findings are masked
    for f in findings:
        assert "2847" not in f["masked_value"]
        assert "BKRPP" not in f["masked_value"]
        assert "4532" not in f["masked_value"]

    # Verify database persistence
    db_findings = PIIFinding.query.filter_by(document_id=doc["id"]).all()
    assert len(db_findings) == 3


def test_get_document_findings_user_isolation(client, auth_user, second_user):
    """Verify User 2 cannot access User 1's document findings via GET /findings."""
    user1, token1 = auth_user
    user2, token2 = second_user

    content = "User 1 Confidential Form: PAN ABCDE1234F, Email: secret@example.com"
    upload_res = client.post(
        "/api/documents/scan",
        data={"file": (io.BytesIO(content.encode("utf-8")), "doc1.txt")},
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token1}"}
    )
    doc_id = upload_res.get_json()["data"]["document"]["id"]

    # User 1 accesses findings
    get_res1 = client.get(
        f"/api/documents/{doc_id}/findings",
        headers={"Authorization": f"Bearer {token1}"}
    )
    assert get_res1.status_code == 200
    res1_data = get_res1.get_json()["data"]
    assert res1_data["total_findings"] == 2

    # User 2 attempts to access User 1's findings -> 404
    get_res2 = client.get(
        f"/api/documents/{doc_id}/findings",
        headers={"Authorization": f"Bearer {token2}"}
    )
    assert get_res2.status_code == 404


def test_delete_document_cascades_findings(client, auth_user):
    """Verify that deleting a document record cascades and removes its PII findings from DB."""
    user, token = auth_user

    content = "Test Doc: PAN ABCDE1234F"
    upload_res = client.post(
        "/api/documents/scan",
        data={"file": (io.BytesIO(content.encode("utf-8")), "doc_del.txt")},
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    doc_id = upload_res.get_json()["data"]["document"]["id"]

    assert PIIFinding.query.filter_by(document_id=doc_id).count() == 1

    # Delete document
    del_res = client.delete(
        f"/api/documents/{doc_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert del_res.status_code == 200

    # Verify findings were cascaded and deleted
    assert PIIFinding.query.filter_by(document_id=doc_id).count() == 0
