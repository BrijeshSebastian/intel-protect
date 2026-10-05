import os
import sys
import io
import time
import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.app.documents.checksum import compute_verhoeff, compute_luhn

BASE_URL = "http://localhost:5001"

def run_live_pii_verification():
    print("=" * 75)
    print("INTEL-PROTECT — PHASE 4 LIVE END-TO-END PII DETECTION & CHECKSUM VERIFICATION")
    print("=" * 75)

    # 1. Health check
    print("\n[Step 1] Verifying Flask API health and database connectivity...")
    res = requests.get(f"{BASE_URL}/api/health", timeout=5)
    assert res.status_code == 200, f"Health check failed: {res.text}"
    health = res.json()["data"]
    print(f" -> Status:   {health['status']}")
    print(f" -> Database: {health['database']}")
    assert health["database"] == "connected"

    # 2. Authenticate User 1
    print("\n[Step 2] Authenticating primary test user...")
    ts = int(time.time())
    email1 = f"pii_user1_{ts}@example.com"
    pwd = "LivePIITestPassword123!"

    reg1 = requests.post(
        f"{BASE_URL}/api/auth/register",
        json={"email": email1, "username": f"pii_u1_{ts}", "password": pwd, "full_name": "PII Analyst 1"},
        timeout=5
    )
    assert reg1.status_code == 201, f"Registration failed: {reg1.text}"

    login1 = requests.post(f"{BASE_URL}/api/auth/login", json={"email": email1, "password": pwd}, timeout=5)
    assert login1.status_code == 200, f"Login failed: {login1.text}"
    token1 = login1.json()["data"]["access_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}
    print(f" -> User 1 authenticated: {email1}")

    # 3. Construct synthetic document with multiple PII items and lookalikes
    print("\n[Step 3] Preparing synthetic document with 6 PII types and lookalike non-PII...")
    # Aadhaar with valid Verhoeff
    b11 = "29471839201"
    chk_v = compute_verhoeff(b11)
    synthetic_aadhaar = f"{b11[:4]} {b11[4:8]} {b11[8:]}{chk_v}"

    # Card with valid Luhn
    card_base = "453201511283036"
    chk_l = compute_luhn(card_base)
    synthetic_card = f"{card_base[:4]} {card_base[4:8]} {card_base[8:12]} {card_base[12:]}{chk_l}"

    # Invalid Luhn card (lookalike that must be rejected)
    bad_card = "4532 0151 1283 0367"

    synthetic_pan = "ABCPD1234F"
    synthetic_bank = "987654321012"
    synthetic_email = "audit.specialist@intel-protect.local"
    synthetic_phone = "+91-9876543210"

    doc_text = f"""
    INTEL-PROTECT SYNTHETIC COMPLIANCE & PII AUDIT REPORT
    ======================================================
    Customer Record:
    - UIDAI Aadhaar ID: {synthetic_aadhaar}
    - Income Tax PAN: {synthetic_pan}
    - Primary Visa Card: {synthetic_card}
    - Direct Deposit Savings Account: {synthetic_bank} (IFSC: HDFC0001234)
    - Communication Email: {synthetic_email}
    - Emergency Mobile Contact: {synthetic_phone}

    NON-PII SYSTEM METRICS & LOOKALIKES (MUST NOT BE FLAGGED):
    - Commercial Invoice Reference: INV-2026-987654
    - Student Examination Roll: ROLL-1029384756
    - E-commerce Order Tracking: ORD-9876543210
    - Server Timestamp Record: 20261003180000
    - Invalid Luhn Equipment Barcode: {bad_card}
    """

    # 4. Upload document to POST /api/documents/scan
    print("\n[Step 4] Uploading synthetic document to POST /api/documents/scan...")
    files = {"file": ("synthetic_audit.txt", doc_text.encode("utf-8"), "text/plain")}
    upload_res = requests.post(f"{BASE_URL}/api/documents/scan", headers=headers1, files=files, timeout=10)
    assert upload_res.status_code == 201, f"Document scan failed: {upload_res.text}"
    scan_body = upload_res.json()["data"]
    doc = scan_body["document"]
    findings = scan_body["findings"]

    print(f" -> Upload successful!")
    print(f" -> Document ID:     {doc['id']}")
    print(f" -> SHA-256 Hash:    {doc['file_hash']}")
    print(f" -> PII Count:       {doc['pii_count']}")
    print(f" -> High Risk Count: {doc['high_risk_count']}")
    for f in findings:
        print(f"    * Type: {f['pii_type']}, Masked: {f['masked_value']}, Method: {f['detection_method']}, Context: {f.get('context_snippet')}")

    assert doc["pii_count"] == 6, f"Expected 6 PII findings, got {doc['pii_count']}"
    assert len(findings) == 6, f"Expected 6 findings in response, got {len(findings)}"

    # 5. Verify Masking and Checksum Validation on Findings
    print("\n[Step 5] Verifying PII findings integrity, masking, and checksum validations...")
    finding_by_type = {f["pii_type"]: f for f in findings}

    # Verify Aadhaar
    assert "AADHAAR" in finding_by_type
    f_aadhaar = finding_by_type["AADHAAR"]
    print(f" -> Aadhaar:  masked='{f_aadhaar['masked_value']}', checksum_valid={f_aadhaar['checksum_valid']}, method={f_aadhaar['detection_method']}")
    assert f_aadhaar["checksum_valid"] is True
    assert "2947" not in f_aadhaar["masked_value"]
    assert "2947" not in f_aadhaar["context_snippet"]

    # Verify PAN
    assert "PAN" in finding_by_type
    f_pan = finding_by_type["PAN"]
    print(f" -> PAN:      masked='{f_pan['masked_value']}', severity={f_pan['severity']}, confidence={f_pan['confidence']}")
    assert f_pan["masked_value"] == "XXXXX1234X"
    assert "ABCPD" not in f_pan["masked_value"]
    assert "ABCPD" not in f_pan["context_snippet"]

    # Verify Card
    assert "CARD" in finding_by_type
    f_card = finding_by_type["CARD"]
    print(f" -> Card:     masked='{f_card['masked_value']}', checksum_valid={f_card['checksum_valid']}, severity={f_card['severity']}")
    assert f_card["checksum_valid"] is True
    assert "0366" in f_card["masked_value"]
    assert "4532" not in f_card["masked_value"]
    assert "0151" not in f_card["masked_value"]
    assert "0151" not in f_card["context_snippet"]

    # Verify Bank Account
    assert "BANK_ACCOUNT" in finding_by_type
    f_bank = finding_by_type["BANK_ACCOUNT"]
    print(f" -> Bank A/C: masked='{f_bank['masked_value']}', method={f_bank['detection_method']}")
    assert "987654" not in f_bank["masked_value"]
    assert "987654" not in f_bank["context_snippet"]

    # Verify Email & Phone
    assert "EMAIL" in finding_by_type
    assert "PHONE" in finding_by_type
    print(f" -> Email:    masked='{finding_by_type['EMAIL']['masked_value']}'")
    print(f" -> Phone:    masked='{finding_by_type['PHONE']['masked_value']}'")

    # 6. Verify GET /api/documents/<id>/findings
    print("\n[Step 6] Querying GET /api/documents/<id>/findings endpoint...")
    get_res = requests.get(f"{BASE_URL}/api/documents/{doc['id']}/findings", headers=headers1, timeout=5)
    assert get_res.status_code == 200, f"GET /findings failed: {get_res.text}"
    retrieved_findings = get_res.json()["data"]["findings"]
    assert len(retrieved_findings) == 6
    print(f" -> Successfully fetched {len(retrieved_findings)} persisted findings from database.")

    # 7. User Isolation Verification
    print("\n[Step 7] Testing strict multi-tenant data isolation...")
    email2 = f"pii_user2_{ts}@example.com"
    requests.post(
        f"{BASE_URL}/api/auth/register",
        json={"email": email2, "username": f"pii_u2_{ts}", "password": pwd, "full_name": "Unauthorized User"},
        timeout=5
    )
    login2 = requests.post(f"{BASE_URL}/api/auth/login", json={"email": email2, "password": pwd}, timeout=5)
    token2 = login2.json()["data"]["access_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    unauth_get = requests.get(f"{BASE_URL}/api/documents/{doc['id']}/findings", headers=headers2, timeout=5)
    print(f" -> User 2 access attempt returned HTTP {unauth_get.status_code}")
    assert unauth_get.status_code == 404, f"Expected 404 isolation response, got {unauth_get.status_code}"

    # 8. Cascade Deletion Verification
    print("\n[Step 8] Verifying cascade deletion of document and PII findings...")
    del_res = requests.delete(f"{BASE_URL}/api/documents/{doc['id']}", headers=headers1, timeout=5)
    assert del_res.status_code == 200, f"Delete failed: {del_res.text}"

    get_deleted = requests.get(f"{BASE_URL}/api/documents/{doc['id']}/findings", headers=headers1, timeout=5)
    assert get_deleted.status_code == 404
    print(f" -> Document and all related PII findings successfully purged from database.")

    print("\n" + "=" * 75)
    print("ALL PHASE 4 LIVE END-TO-END VERIFICATION CHECKS PASSED (100% SUCCESS)")
    print("=" * 75)

if __name__ == "__main__":
    run_live_pii_verification()
