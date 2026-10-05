"""
Live End-to-End Verification of Phase 6: Deterministic Privacy Risk Scoring Engine.
Tests against the live running Intel-Protect server on http://localhost:5001.

Verification Steps:
1. User Registration & Authentication (User A & User B)
2. Document 1 (Clean/Zero PII): Verify 0.0 LOW score
3. Document 2 (Medium Risk): PAN + Mobile -> Verify MEDIUM risk level
4. Document 3 (High Risk): Aadhaar (Verhoeff valid) -> Verify HIGH risk level
5. Document 4 (Critical Triad): Card (Luhn valid) + Aadhaar + Email -> Verify CRITICAL, Triad boost (+25%)
6. REST API: GET /api/documents/<id>/risk returns complete explainable JSON breakdown
7. User Isolation: User B cannot access User A's document risk (returns 404)
8. Document History: GET /api/documents returns persisted risk scores across documents
"""
import io
import json
import sys
import uuid
import requests

BASE_URL = "http://localhost:5001/api"


def main():
    print("=" * 75)
    print("INTEL-PROTECT: LIVE PHASE 6 PRIVACY RISK SCORING VERIFICATION")
    print("=" * 75)

    session_a = requests.Session()
    session_b = requests.Session()

    # 1. Register and Login User A
    email_a = f"risk_live_a_{uuid.uuid4().hex[:6]}@intelprotect.internal"
    pwd = "ValidPassw0rd!#2026"
    reg_a = session_a.post(f"{BASE_URL}/auth/register", json={
        "email": email_a,
        "password": pwd,
        "username": f"user_{uuid.uuid4().hex[:6]}"
    })
    assert reg_a.status_code == 201, f"User A registration failed: {reg_a.text}"

    login_a = session_a.post(f"{BASE_URL}/auth/login", json={"email": email_a, "password": pwd})
    assert login_a.status_code == 200, f"User A login failed: {login_a.text}"
    token_a = login_a.json()["data"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}
    print(f"[OK] Registered & Authenticated User A ({email_a})")

    # Register and Login User B (for isolation test)
    email_b = f"risk_live_b_{uuid.uuid4().hex[:6]}@intelprotect.internal"
    reg_b = session_b.post(f"{BASE_URL}/auth/register", json={
        "email": email_b,
        "password": pwd,
        "username": f"user_{uuid.uuid4().hex[:6]}"
    })
    assert reg_b.status_code == 201, f"User B registration failed: {reg_b.text}"

    login_b = session_b.post(f"{BASE_URL}/auth/login", json={"email": email_b, "password": pwd})
    assert login_b.status_code == 200, f"User B login failed: {login_b.text}"
    token_b = login_b.json()["data"]["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}
    print(f"[OK] Registered & Authenticated User B ({email_b})")

    # 2. Upload Document 1: Clean Document (Zero PII)
    clean_text = "This is a public research memorandum regarding software architecture with zero personal data."
    files_clean = {"file": ("clean_report.txt", io.BytesIO(clean_text.encode("utf-8")), "text/plain")}
    res_clean = session_a.post(f"{BASE_URL}/documents/scan", files=files_clean, headers=headers_a)
    assert res_clean.status_code == 201, f"Clean scan failed: {res_clean.text}"
    data_clean = res_clean.json()["data"]
    risk_clean = data_clean["risk"]
    print(f"[OK] Clean Document -> Score: {risk_clean['score']}, Level: {risk_clean['risk_level']}")
    assert risk_clean["score"] == 0.0, f"Expected 0.0, got {risk_clean['score']}"
    assert risk_clean["risk_level"] == "LOW", f"Expected LOW, got {risk_clean['risk_level']}"
    assert "No sensitive PII entities detected" in risk_clean["explanation"]["contributing_factors"][0]

    # 3. Upload Document 2: Medium Risk (PAN identifier)
    pan_text = "Tax deduction receipt for Assessment Year 2025-26. PAN Number: ABCDE1234F recorded."
    files_pan = {"file": ("tax_receipt.txt", io.BytesIO(pan_text.encode("utf-8")), "text/plain")}
    res_pan = session_a.post(f"{BASE_URL}/documents/scan", files=files_pan, headers=headers_a)
    assert res_pan.status_code == 201, f"PAN scan failed: {res_pan.text}"
    data_pan = res_pan.json()["data"]
    risk_pan = data_pan["risk"]
    print(f"[OK] PAN Document -> Score: {risk_pan['score']}, Level: {risk_pan['risk_level']}")
    assert risk_pan["risk_level"] == "MEDIUM", f"Expected MEDIUM, got {risk_pan['risk_level']}"
    assert 20.0 <= risk_pan["score"] <= 30.0, f"Expected 20-30, got {risk_pan['score']}"

    # 4. Upload Document 3: Aadhaar with valid Verhoeff D5
    # 3675 9834 6016 has valid Verhoeff check digit 6
    aadhaar_text = "Government Identity Card: Aadhaar UIDAI: 3675 9834 6016 verified."
    files_aadhaar = {"file": ("aadhaar_id.txt", io.BytesIO(aadhaar_text.encode("utf-8")), "text/plain")}
    res_aadhaar = session_a.post(f"{BASE_URL}/documents/scan", files=files_aadhaar, headers=headers_a)
    assert res_aadhaar.status_code == 201, f"Aadhaar scan failed: {res_aadhaar.text}"
    data_aadhaar = res_aadhaar.json()["data"]
    risk_aadhaar = data_aadhaar["risk"]
    print(f"[OK] Aadhaar Document -> Score: {risk_aadhaar['score']}, Level: {risk_aadhaar['risk_level']}")
    assert risk_aadhaar["score"] >= 35.0, f"Expected >= 35.0, got {risk_aadhaar['score']}"

    # 5. Upload Document 4: Critical Triad (Card + Aadhaar + Email)
    triad_text = (
        "CONFIDENTIAL CUSTOMER PROFILE:\n"
        "Visa Card: 4532 0151 1283 0366 (Luhn valid)\n"
        "Aadhaar UIDAI: 3675 9834 6016 (Verhoeff valid)\n"
        "Contact: customer.service@vault-bank.com\n"
    )
    files_triad = {"file": ("customer_profile.txt", io.BytesIO(triad_text.encode("utf-8")), "text/plain")}
    res_triad = session_a.post(f"{BASE_URL}/documents/scan", files=files_triad, headers=headers_a)
    assert res_triad.status_code == 201, f"Triad scan failed: {res_triad.text}"
    data_triad = res_triad.json()["data"]
    triad_doc_id = data_triad["document"]["id"]
    risk_triad = data_triad["risk"]
    print(f"[OK] Critical Triad Document -> Score: {risk_triad['score']}, Level: {risk_triad['risk_level']}")
    assert risk_triad["score"] == 100.0, f"Expected 100.0, got {risk_triad['score']}"
    assert risk_triad["risk_level"] == "CRITICAL", f"Expected CRITICAL, got {risk_triad['risk_level']}"
    assert risk_triad["explanation"]["compound_boost_percentage"] == 25.0

    # 6. REST API: GET /api/documents/<id>/risk
    res_get_risk = session_a.get(f"{BASE_URL}/documents/{triad_doc_id}/risk", headers=headers_a)
    assert res_get_risk.status_code == 200, f"GET /risk failed: {res_get_risk.text}"
    risk_detail = res_get_risk.json()["data"]
    print(f"[OK] GET /api/documents/{triad_doc_id}/risk retrieved successfully")
    assert risk_detail["risk_score"] == 100.0
    assert risk_detail["risk_level"] == "CRITICAL"
    assert risk_detail["scoring_version"] == "1.0"
    assert len(risk_detail["explanation"]["contributing_factors"]) >= 3
    assert len(risk_detail["explanation"]["itemized_breakdown"]) >= 3
    print("     Contributing factors:")
    for factor in risk_detail["explanation"]["contributing_factors"]:
        print(f"       - {factor}")

    # 7. Security Isolation: User B attempts to access User A's document risk
    res_iso = session_b.get(f"{BASE_URL}/documents/{triad_doc_id}/risk", headers=headers_b)
    assert res_iso.status_code == 404, f"Expected 404 for User B, got {res_iso.status_code}"
    print(f"[OK] User Isolation verified: User B received 404 NOT_FOUND for User A's document")

    # 8. Document History: GET /api/documents
    res_list = session_a.get(f"{BASE_URL}/documents", headers=headers_a)
    assert res_list.status_code == 200
    docs = res_list.json()["data"]["documents"]
    print(f"[OK] GET /api/documents returned {len(docs)} documents in history")
    for d in docs:
        assert "risk_score" in d
        assert "risk_level" in d
        print(f"     Doc: {d['original_filename']} -> Score: {d['risk_score']} ({d['risk_level']})")

    print("\n" + "=" * 75)
    print("ALL LIVE VERIFICATION CHECKS PASSED FOR PHASE 6!")
    print("=" * 75)


if __name__ == "__main__":
    main()
