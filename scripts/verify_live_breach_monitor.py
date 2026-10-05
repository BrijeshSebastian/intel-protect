"""
Live End-to-End Verification of Phase 8: Breach Monitor.
Tests against the live running Intel-Protect server on http://localhost:5001.

Verification Steps:
1. User Registration & Authentication (User A & User B)
2. Target 1 (Clean/Zero Breach): safe_clean@intelprotect.internal -> 0 breaches, 0.0 LOW score
3. Target 2 (Medium Breach): medium_user@intelprotect.internal -> 1-2 breaches, MEDIUM score
4. Target 3 (Critical Breaches & Synergy): victim_critical@intelprotect.internal -> 3+ breaches, CRITICAL score, compound boost
5. Privacy Guarantee: Zero raw email stored, SHA-256 query_email_hash only
6. REST API Detail: GET /api/breaches/<id> returns complete matched breach details
7. Public Catalog: GET /api/breaches/catalog returns monitored breach definitions
8. Active Recommendations: GET /api/recommendations returns contextual remediation advice
9. Dismiss Recommendation: PATCH /api/recommendations/<id>/dismiss marks recommendation dismissed
10. User Isolation: User B cannot view or delete User A's breach check (returns 404 NOT_FOUND)
11. Paginated History: GET /api/breaches/history returns user records with pagination metadata
12. Deletion: User A successfully deletes breach check record
"""
import json
import sys
import uuid
import requests

BASE_URL = "http://localhost:5001/api"


def main():
    print("=" * 75)
    print("INTEL-PROTECT: LIVE PHASE 8 BREACH MONITOR VERIFICATION")
    print("=" * 75)

    session_a = requests.Session()
    session_b = requests.Session()

    # 1. Register and Login User A
    email_a = f"breach_live_a_{uuid.uuid4().hex[:6]}@intelprotect.internal"
    pwd = "ValidPassw0rd!#2026"
    reg_a = session_a.post(f"{BASE_URL}/auth/register", json={
        "email": email_a,
        "password": pwd,
        "username": f"user_brch_a_{uuid.uuid4().hex[:6]}"
    })
    assert reg_a.status_code == 201, f"User A registration failed: {reg_a.text}"

    login_a = session_a.post(f"{BASE_URL}/auth/login", json={"email": email_a, "password": pwd})
    assert login_a.status_code == 200, f"User A login failed: {login_a.text}"
    token_a = login_a.json()["data"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}", "Content-Type": "application/json"}
    print(f"[OK] Registered & Authenticated User A ({email_a})")

    # Register and Login User B (for isolation tests)
    email_b = f"breach_live_b_{uuid.uuid4().hex[:6]}@intelprotect.internal"
    reg_b = session_b.post(f"{BASE_URL}/auth/register", json={
        "email": email_b,
        "password": pwd,
        "username": f"user_brch_b_{uuid.uuid4().hex[:6]}"
    })
    assert reg_b.status_code == 201, f"User B registration failed: {reg_b.text}"

    login_b = session_b.post(f"{BASE_URL}/auth/login", json={"email": email_b, "password": pwd})
    assert login_b.status_code == 200, f"User B login failed: {login_b.text}"
    token_b = login_b.json()["data"]["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}", "Content-Type": "application/json"}
    print(f"[OK] Registered & Authenticated User B ({email_b})")

    # 2. Target 1: Clean Target (Zero Breaches)
    res_clean = session_a.post(f"{BASE_URL}/breaches/check", json={"email": "safe_clean_user@intelprotect.internal"}, headers=headers_a)
    assert res_clean.status_code == 201, f"Clean check failed: {res_clean.text}"
    data_clean = res_clean.json()["data"]
    res_obj_clean = data_clean["result"]
    print(f"[OK] Clean Target -> Breaches: {res_obj_clean['breach_count']}, Score: {res_obj_clean['breach_risk_score']}, Priority: {res_obj_clean['priority_label']}")
    assert res_obj_clean["breach_count"] == 0
    assert res_obj_clean["breach_risk_score"] == 0.0
    assert res_obj_clean["breach_risk_level"] == "LOW"
    assert len(data_clean["breaches"]) == 0

    # 3. Target 2: Medium Breach Target
    res_med = session_a.post(f"{BASE_URL}/breaches/check", json={"email": "medium_warning_user@intelprotect.internal"}, headers=headers_a)
    assert res_med.status_code == 201, f"Medium check failed: {res_med.text}"
    data_med = res_med.json()["data"]
    res_obj_med = data_med["result"]
    print(f"[OK] Medium Target -> Breaches: {res_obj_med['breach_count']}, Score: {res_obj_med['breach_risk_score']}, Priority: {res_obj_med['priority_label']}")
    assert res_obj_med["breach_count"] >= 1
    assert 15.0 <= res_obj_med["breach_risk_score"] < 75.0
    assert len(data_med["breaches"]) >= 1

    # 4. Target 3: Critical Breaches & Multi-Vector Synergy
    res_crit = session_a.post(f"{BASE_URL}/breaches/check", json={"email": "victim_critical_target@intelprotect.internal"}, headers=headers_a)
    assert res_crit.status_code == 201, f"Critical check failed: {res_crit.text}"
    data_crit = res_crit.json()["data"]
    res_obj_crit = data_crit["result"]
    record_id_crit = res_obj_crit["id"]
    print(f"[OK] Critical Target -> Breaches: {res_obj_crit['breach_count']}, Score: {res_obj_crit['breach_risk_score']}, Priority: {res_obj_crit['priority_label']}")
    assert res_obj_crit["breach_count"] >= 3
    assert res_obj_crit["breach_risk_score"] >= 75.0
    assert res_obj_crit["breach_risk_level"] == "CRITICAL"
    assert len(data_crit["breaches"]) >= 3
    assert len(data_crit["recommendations"]) >= 2
    # Verify synergy explanation
    assert any("Compound exposure" in f for f in res_obj_crit["explanation"]["contributing_factors"])

    # 5. Privacy Guarantee: Zero Raw Email & Data Minimization
    assert "victim_critical_target@intelprotect.internal" not in res_obj_crit.values()
    assert len(res_obj_crit["query_email_hash"]) == 64
    assert "user_id" not in res_obj_crit, "user_id should be omitted for data minimization"
    print("[OK] Verified zero raw email storage & data minimization: SHA-256 hash used, user_id omitted")

    # 6. Detail Inspection Endpoint: GET /api/breaches/<id>
    res_detail = session_a.get(f"{BASE_URL}/breaches/{record_id_crit}", headers=headers_a)
    assert res_detail.status_code == 200, f"Detail lookup failed: {res_detail.text}"
    detail_data = res_detail.json()["data"]
    assert detail_data["result"]["id"] == record_id_crit
    assert len(detail_data["breaches"]) >= 3
    print(f"[OK] GET /api/breaches/{record_id_crit} returned complete breakdown and matched breaches")

    # 7. Monitored Breaches Catalog: GET /api/breaches/catalog
    res_cat = session_a.get(f"{BASE_URL}/breaches/catalog", headers=headers_a)
    assert res_cat.status_code == 200, f"Catalog fetch failed: {res_cat.text}"
    cat_data = res_cat.json()["data"]
    assert cat_data["total"] >= 10
    print(f"[OK] GET /api/breaches/catalog returned {cat_data['total']} monitored incident records")

    # 8. Active Recommendations: GET /api/recommendations
    res_recs = session_a.get(f"{BASE_URL}/recommendations", headers=headers_a)
    assert res_recs.status_code == 200, f"Recommendations fetch failed: {res_recs.text}"
    recs_list = res_recs.json()["data"]["recommendations"]
    assert len(recs_list) >= 2
    rec_to_dismiss = recs_list[0]
    print(f"[OK] GET /api/recommendations returned {len(recs_list)} active remediation recommendations")

    # 9. Dismiss Recommendation: PATCH /api/recommendations/<id>/dismiss
    res_dismiss = session_a.patch(f"{BASE_URL}/recommendations/{rec_to_dismiss['id']}/dismiss", headers=headers_a)
    assert res_dismiss.status_code == 200, f"Dismiss failed: {res_dismiss.text}"
    assert res_dismiss.json()["data"]["recommendation"]["is_dismissed"] is True
    print(f"[OK] Recommendation {rec_to_dismiss['id']} successfully dismissed")

    # 10. User Isolation Test
    res_iso = session_b.get(f"{BASE_URL}/breaches/{record_id_crit}", headers=headers_b)
    assert res_iso.status_code == 404, f"Expected 404 NOT_FOUND for User B, got {res_iso.status_code}"
    res_del_iso = session_b.delete(f"{BASE_URL}/breaches/{record_id_crit}", headers=headers_b)
    assert res_del_iso.status_code == 404, f"Expected 404 NOT_FOUND for User B delete, got {res_del_iso.status_code}"
    print("[OK] User isolation verified: User B receives 404 for User A's breach record")

    # 11. Paginated History Endpoint: GET /api/breaches/history
    res_hist = session_a.get(f"{BASE_URL}/breaches/history?limit=10&page=1", headers=headers_a)
    assert res_hist.status_code == 200, f"History fetch failed: {res_hist.text}"
    hist_json = res_hist.json()
    assert hist_json["data"]["total"] >= 3, f"Expected >= 3 records in history, got {hist_json['data']['total']}"
    assert len(hist_json["data"]["records"]) >= 3
    print(f"[OK] GET /api/breaches/history returned {hist_json['data']['total']} user records")

    # 12. Record Deletion
    res_del = session_a.delete(f"{BASE_URL}/breaches/{record_id_crit}", headers=headers_a)
    assert res_del.status_code == 200, f"Delete failed: {res_del.text}"
    res_recheck = session_a.get(f"{BASE_URL}/breaches/{record_id_crit}", headers=headers_a)
    assert res_recheck.status_code == 404, f"Expected 404 after deletion, got {res_recheck.status_code}"
    print(f"[OK] Record {record_id_crit} successfully deleted by owner")

    print("=" * 75)
    print("ALL LIVE BREACH MONITOR VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("=" * 75)


if __name__ == "__main__":
    main()
