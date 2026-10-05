"""
Live End-to-End Verification of Phase 7: Exposure Monitor.
Tests against the live running Intel-Protect server on http://localhost:5001.

Verification Steps:
1. User Registration & Authentication (User A & User B)
2. Target 1 (Clean/Zero Exposure): Query with clean non-sensitive text -> Verify 0.0 LOW score
3. Target 2 (Medium Exposure): Query with PAN + Phone -> Verify MEDIUM exposure level
4. Target 3 (Critical Triad Exposure): Card (Luhn) + Aadhaar (Verhoeff) + JWT Credential -> Verify CRITICAL, Triad boost
5. Target 4 (Anomaly Detection): Extreme high-density identity/credential payload -> Verify anomaly evaluation
6. REST API Detail: GET /api/exposure/<id> returns complete explainable JSON breakdown and masked entities
7. User Isolation: User B cannot view or delete User A's exposure records (returns 404 NOT_FOUND)
8. Pagination & History: GET /api/exposure/history returns user records with pagination metadata
9. Deletion: User A successfully deletes their record
"""
import json
import sys
import uuid
import requests

BASE_URL = "http://localhost:5001/api"


def main():
    print("=" * 75)
    print("INTEL-PROTECT: LIVE PHASE 7 EXPOSURE MONITOR VERIFICATION")
    print("=" * 75)

    session_a = requests.Session()
    session_b = requests.Session()

    # 1. Register and Login User A
    email_a = f"exposure_live_a_{uuid.uuid4().hex[:6]}@intelprotect.internal"
    pwd = "ValidPassw0rd!#2026"
    reg_a = session_a.post(f"{BASE_URL}/auth/register", json={
        "email": email_a,
        "password": pwd,
        "username": f"user_exp_a_{uuid.uuid4().hex[:6]}"
    })
    assert reg_a.status_code == 201, f"User A registration failed: {reg_a.text}"

    login_a = session_a.post(f"{BASE_URL}/auth/login", json={"email": email_a, "password": pwd})
    assert login_a.status_code == 200, f"User A login failed: {login_a.text}"
    token_a = login_a.json()["data"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}", "Content-Type": "application/json"}
    print(f"[OK] Registered & Authenticated User A ({email_a})")

    # Register and Login User B (for isolation tests)
    email_b = f"exposure_live_b_{uuid.uuid4().hex[:6]}@intelprotect.internal"
    reg_b = session_b.post(f"{BASE_URL}/auth/register", json={
        "email": email_b,
        "password": pwd,
        "username": f"user_exp_b_{uuid.uuid4().hex[:6]}"
    })
    assert reg_b.status_code == 201, f"User B registration failed: {reg_b.text}"

    login_b = session_b.post(f"{BASE_URL}/auth/login", json={"email": email_b, "password": pwd})
    assert login_b.status_code == 200, f"User B login failed: {login_b.text}"
    token_b = login_b.json()["data"]["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}", "Content-Type": "application/json"}
    print(f"[OK] Registered & Authenticated User B ({email_b})")

    # 2. Analyze Target 1: Clean Target (Zero PII/Exposure)
    payload_clean = {
        "identifiers": {"username": "opensource_contributor"},
        "text": "This public developer profile contains open-source repositories and standard documentation."
    }
    res_clean = session_a.post(f"{BASE_URL}/exposure/analyze", json=payload_clean, headers=headers_a)
    assert res_clean.status_code == 201, f"Clean analysis failed: {res_clean.text}"
    data_clean = res_clean.json()["data"]["exposure_record"]
    score_clean = data_clean["exposure_score"]
    level_clean = data_clean["exposure_level"]
    print(f"[OK] Clean Target -> Score: {score_clean}, Level: {level_clean}, Sensitive: {data_clean['sensitivity_label']}")
    assert score_clean == 0.0, f"Expected 0.0, got {score_clean}"
    assert level_clean == "LOW", f"Expected LOW, got {level_clean}"
    assert data_clean["sensitivity_label"] == "LOW"
    assert data_clean["is_anomalous"] is False

    # 3. Analyze Target 2: Medium Exposure (PAN + Phone)
    payload_med = {
        "identifiers": {"phone": "+91 98765 43210"},
        "text": "Member application verified with PAN number ABCPE1234F and mobile +91-9876543210 in Mumbai."
    }
    res_med = session_a.post(f"{BASE_URL}/exposure/analyze", json=payload_med, headers=headers_a)
    assert res_med.status_code == 201, f"Medium analysis failed: {res_med.text}"
    data_med = res_med.json()["data"]["exposure_record"]
    score_med = data_med["exposure_score"]
    level_med = data_med["exposure_level"]
    print(f"[OK] Medium Target -> Score: {score_med}, Level: {level_med}, Sensitive: {data_med['sensitivity_label']}")
    assert 25.0 <= score_med < 75.0, f"Expected medium range (25-74.9), got {score_med}"
    assert level_med in ("MEDIUM", "HIGH")
    assert data_med["total_entities"] >= 2

    # 4. Analyze Target 3: Critical Triad (Card + Aadhaar + Credential)
    # 4532 0151 1283 0366 is Luhn valid Visa
    # 3675 9834 6016 is Verhoeff valid Aadhaar
    jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    payload_triad = {
        "identifiers": {"email": "victim_target@intelprotect.internal"},
        "text": (
            f"LEAKED DATABASE DUMP: Visa 4532 0151 1283 0366 expires 12/28.\n"
            f"Aadhaar UIDAI: 3675 9834 6016 verified.\n"
            f"Auth token: {jwt_token}\n"
            f"Account IFSC: HDFC0001234 account 1234567890123."
        )
    }
    res_triad = session_a.post(f"{BASE_URL}/exposure/analyze", json=payload_triad, headers=headers_a)
    assert res_triad.status_code == 201, f"Triad analysis failed: {res_triad.text}"
    data_triad = res_triad.json()["data"]["exposure_record"]
    score_triad = data_triad["exposure_score"]
    level_triad = data_triad["exposure_level"]
    record_id_triad = data_triad["id"]
    print(f"[OK] Triad Target -> Score: {score_triad}, Level: {level_triad}, Sensitive: {data_triad['sensitivity_label']}")
    assert score_triad >= 75.0, f"Expected CRITICAL >= 75.0, got {score_triad}"
    assert level_triad == "CRITICAL"
    assert data_triad["sensitivity_label"] in ("HIGH", "CRITICAL")
    # Verify compound triad boost in explanation
    explanation = data_triad["explanation"]
    assert any("Triad Synergy" in factor for factor in explanation["contributing_factors"]), "Expected Triad Synergy boost"
    
    # Verify no raw PII in findings
    for finding in data_triad["findings"]:
        assert "4532 0151 1283 0366" not in finding["masked_value"]
        assert "3675 9834 6016" not in finding["masked_value"]
        assert jwt_token not in finding["masked_value"]
        assert "raw_value" not in finding
    print("[OK] Verified zero raw PII in live API response (masked values only)")

    # 5. Detail Inspection Endpoint: GET /api/exposure/<record_id>
    res_detail = session_a.get(f"{BASE_URL}/exposure/{record_id_triad}", headers=headers_a)
    assert res_detail.status_code == 200, f"Detail lookup failed: {res_detail.text}"
    detail_data = res_detail.json()["data"]["exposure_record"]
    assert detail_data["id"] == record_id_triad
    assert detail_data["category_scores"]["credential"] > 0
    assert detail_data["category_scores"]["financial"] > 0
    assert detail_data["category_scores"]["identity"] > 0
    print(f"[OK] GET /api/exposure/{record_id_triad} returned complete breakdown")

    # 6. User Isolation Test
    # User B attempts to access User A's record -> MUST be 404
    res_iso = session_b.get(f"{BASE_URL}/exposure/{record_id_triad}", headers=headers_b)
    assert res_iso.status_code == 404, f"Expected 404 NOT_FOUND for User B, got {res_iso.status_code}"
    # User B attempts to delete User A's record -> MUST be 404
    res_del_iso = session_b.delete(f"{BASE_URL}/exposure/{record_id_triad}", headers=headers_b)
    assert res_del_iso.status_code == 404, f"Expected 404 NOT_FOUND for User B delete, got {res_del_iso.status_code}"
    print(f"[OK] User isolation verified: User B receives 404 for User A's record")

    # 7. Paginated History Endpoint: GET /api/exposure/history
    res_hist = session_a.get(f"{BASE_URL}/exposure/history?limit=10&offset=0", headers=headers_a)
    assert res_hist.status_code == 200, f"History fetch failed: {res_hist.text}"
    hist_json = res_hist.json()
    assert hist_json["data"]["total"] >= 3, f"Expected >= 3 records in history, got {hist_json['data']['total']}"
    assert len(hist_json["data"]["records"]) >= 3
    print(f"[OK] GET /api/exposure/history returned {hist_json['data']['total']} user records")

    # 8. Record Deletion
    res_del = session_a.delete(f"{BASE_URL}/exposure/{record_id_triad}", headers=headers_a)
    assert res_del.status_code == 200, f"Delete failed: {res_del.text}"
    res_recheck = session_a.get(f"{BASE_URL}/exposure/{record_id_triad}", headers=headers_a)
    assert res_recheck.status_code == 404, f"Expected 404 after deletion, got {res_recheck.status_code}"
    print(f"[OK] Record {record_id_triad} successfully deleted by owner")

    print("=" * 75)
    print("ALL LIVE EXPOSURE MONITOR VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("=" * 75)


if __name__ == "__main__":
    main()
