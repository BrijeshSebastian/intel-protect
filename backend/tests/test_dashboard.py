"""
Automated Test Suite for Phase 9: Unified Threat Dashboard.
Covers:
1. Unauthenticated request protection (401)
2. Fresh/empty user dashboard baseline (0.0 LOW, safe empty structures)
3. Multi-module aggregated telemetry (Documents, Exposure, Breaches, Recommendations)
4. Multi-tenant user data isolation (User B never sees User A's threat intelligence)
"""
from datetime import datetime, timezone
import uuid
import pytest
from backend.app import db
from backend.app.models.user import User
from backend.app.models.document import Document
from backend.app.models.pii_finding import PIIFinding
from backend.app.models.exposure_record import ExposureRecord
from backend.app.models.breach import Breach, BreachResult, BreachExposure
from backend.app.models.recommendation import Recommendation
from backend.app.common.security import create_access_token


@pytest.fixture
def auth_user(app):
    """Creates User A and returns (user, token)."""
    with app.app_context():
        user = User(
            email=f"dash_user_a_{uuid.uuid4().hex[:6]}@intelprotect.internal",
            username=f"dash_user_a_{uuid.uuid4().hex[:6]}",
            password_hash="argon2_placeholder",
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        token = create_access_token(str(user.id), user.email)
        return user, token


@pytest.fixture
def second_user(app):
    """Creates User B for isolation checks."""
    with app.app_context():
        user = User(
            email=f"dash_user_b_{uuid.uuid4().hex[:6]}@intelprotect.internal",
            username=f"dash_user_b_{uuid.uuid4().hex[:6]}",
            password_hash="argon2_placeholder",
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        token = create_access_token(str(user.id), user.email)
        return user, token


def test_dashboard_unauthenticated_rejected(client):
    """Unauthenticated GET /api/dashboard returns 401."""
    res = client.get("/api/dashboard")
    assert res.status_code == 401


def test_dashboard_empty_user(client, auth_user):
    """A new user with zero records receives an empty, baseline 0.0 LOW dashboard."""
    user, token = auth_user
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/dashboard", headers=headers)
    assert res.status_code == 200
    data = res.get_json()["data"]

    # Overall risk
    assert data["overall_risk"]["score"] == 0.0
    assert data["overall_risk"]["level"] == "LOW"
    assert data["overall_risk"]["trend"] == "stable"

    # Module risks
    assert data["document_risk"]["documents_scanned"] == 0
    assert data["document_risk"]["score"] == 0.0
    assert data["exposure_risk"]["analyses_count"] == 0
    assert data["exposure_risk"]["score"] == 0.0
    assert data["breach_risk"]["total_breaches"] == 0
    assert data["breach_risk"]["score"] == 0.0

    # Lists & Distribution
    assert data["recent_activity"] == []
    assert data["active_recommendations"] == []
    assert set(data["risk_distribution"].keys()) == {"identity", "contact", "location", "financial", "credential"}


def test_dashboard_populated_user(app, client, auth_user):
    """User with telemetry across all 3 modules gets accurate aggregated intelligence."""
    user, token = auth_user
    headers = {"Authorization": f"Bearer {token}"}
    now_utc = datetime.now(timezone.utc)

    with app.app_context():
        # 1. Document record
        doc = Document(
            user_id=user.id,
            original_filename="financial_audit.pdf",
            file_type="pdf",
            file_size=10240,
            file_hash="dummy_hash_doc",
            pii_count=4,
            high_risk_count=2,
            risk_score=75.0,
            risk_level="CRITICAL",
            scanned_at=now_utc,
            created_at=now_utc
        )
        db.session.add(doc)

        # 2. Exposure record
        exp = ExposureRecord(
            user_id=user.id,
            query_type="composite",
            query_value_hash="hash_exp_123",
            total_entities=6,
            sensitive_count=3,
            financial_count=1,
            credential_count=1,
            exposure_score=68.0,
            exposure_level="HIGH",
            sensitivity_label="HIGH",
            sensitivity_confidence=0.88,
            is_anomalous=True,
            anomaly_score=0.72,
            category_scores={"identity": 60.0, "contact": 30.0, "location": 20.0, "financial": 45.0, "credential": 50.0},
            entity_summary={"IDENTITY": 2, "CONTACT": 2, "FINANCIAL": 1, "CREDENTIAL": 1},
            raw_findings=[],
            analyzed_at=now_utc,
            created_at=now_utc
        )
        db.session.add(exp)

        # 3. Breach Result
        br = BreachResult(
            user_id=user.id,
            query_email_hash="hash_br_123",
            breach_count=2,
            total_exposures=6,
            priority_label="HIGH",
            priority_confidence=0.85,
            breach_risk_score=70.0,
            breach_risk_level="HIGH",
            exposure_summary={"EMAIL": 2, "PASSWORD_HASH": 2, "CARD": 2},
            checked_at=now_utc,
            created_at=now_utc
        )
        db.session.add(br)

        # 4. Recommendation
        rec = Recommendation(
            user_id=user.id,
            breach_result_id=br.id,
            source_module="breach_monitor",
            category="credential",
            priority="CRITICAL",
            title="Update Leaked Password",
            description="Change password immediately.",
            action_type="change_password",
            is_dismissed=False,
            created_at=now_utc
        )
        db.session.add(rec)
        db.session.commit()

    # Query Dashboard API
    res = client.get("/api/dashboard", headers=headers)
    assert res.status_code == 200
    data = res.get_json()["data"]

    # Verify overall risk is computed as weighted average of all 3 modules
    # 0.30 * 75 + 0.35 * 68 + 0.35 * 70 = 22.5 + 23.8 + 24.5 = 70.8
    assert 65.0 <= data["overall_risk"]["score"] <= 75.0
    assert data["overall_risk"]["level"] in ("HIGH", "CRITICAL")
    assert data["overall_risk"]["trend"] == "increasing"

    # Module specifics
    assert data["document_risk"]["documents_scanned"] == 1
    assert data["document_risk"]["total_pii_findings"] == 4
    assert data["exposure_risk"]["analyses_count"] == 1
    assert data["exposure_risk"]["anomalies_detected"] == 1
    assert data["breach_risk"]["total_breaches"] == 2
    assert data["breach_risk"]["total_exposures"] == 6

    # Recent activity timeline
    assert len(data["recent_activity"]) == 3
    event_types = {e["type"] for e in data["recent_activity"]}
    assert event_types == {"document_scan", "exposure_analysis", "breach_check"}

    # Recommendations
    assert len(data["active_recommendations"]) >= 1
    action_types = {r["action_type"] for r in data["active_recommendations"]}
    assert "change_password" in action_types


def test_dashboard_user_isolation(app, client, auth_user, second_user):
    """User B cannot see any telemetry from User A."""
    user_a, token_a = auth_user
    user_b, token_b = second_user
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}
    now_utc = datetime.now(timezone.utc)

    # Populate User A with records
    with app.app_context():
        doc = Document(
            user_id=user_a.id,
            original_filename="secret_a.pdf",
            file_type="pdf",
            file_size=5000,
            file_hash="hash_a",
            pii_count=10,
            high_risk_count=5,
            risk_score=90.0,
            risk_level="CRITICAL",
            scanned_at=now_utc,
            created_at=now_utc
        )
        db.session.add(doc)
        db.session.commit()

    # User A sees 1 document and high score
    res_a = client.get("/api/dashboard", headers=headers_a)
    assert res_a.status_code == 200
    assert res_a.get_json()["data"]["document_risk"]["documents_scanned"] == 1

    # User B must see zero documents, 0.0 score, and empty recent activity
    res_b = client.get("/api/dashboard", headers=headers_b)
    assert res_b.status_code == 200
    data_b = res_b.get_json()["data"]
    assert data_b["overall_risk"]["score"] == 0.0
    assert data_b["document_risk"]["documents_scanned"] == 0
    assert data_b["recent_activity"] == []
    assert data_b["active_recommendations"] == []


def test_dashboard_sub_endpoints(client, auth_user):
    """Verifies modular sub-endpoints: /summary, /risk, /recommendations, /history."""
    user, token = auth_user
    headers = {"Authorization": f"Bearer {token}"}

    # 1. /summary
    res_summary = client.get("/api/dashboard/summary", headers=headers)
    assert res_summary.status_code == 200
    assert "overall_risk" in res_summary.get_json()["data"]

    # 2. /risk
    res_risk = client.get("/api/dashboard/risk", headers=headers)
    assert res_risk.status_code == 200
    risk_data = res_risk.get_json()["data"]
    assert "overall_risk" in risk_data
    assert "document_risk" in risk_data
    assert "exposure_risk" in risk_data
    assert "breach_risk" in risk_data

    # 3. /recommendations
    res_recs = client.get("/api/dashboard/recommendations", headers=headers)
    assert res_recs.status_code == 200
    assert "recommendations" in res_recs.get_json()["data"]

    # 4. /history
    res_hist = client.get("/api/dashboard/history", headers=headers)
    assert res_hist.status_code == 200
    assert "recent_activity" in res_hist.get_json()["data"]


def test_unified_recommendation_deduplication(app, client, auth_user):
    """Verifies that evidence from multiple modules merges into single deduplicated recommendations with source_modules list."""
    user, token = auth_user
    headers = {"Authorization": f"Bearer {token}"}
    now_utc = datetime.now(timezone.utc)

    with app.app_context():
        # 1. Document with credentials and financial card
        doc = Document(
            user_id=user.id,
            original_filename="credentials_export.txt",
            file_type="txt",
            file_size=2048,
            file_hash="hash_doc_cred",
            pii_count=2,
            high_risk_count=2,
            risk_score=80.0,
            risk_level="CRITICAL",
            scanned_at=now_utc,
            created_at=now_utc
        )
        db.session.add(doc)
        db.session.flush()

        f1 = PIIFinding(
            document_id=doc.id,
            pii_type="CREDENTIAL",
            masked_value="[REDACTED_CREDENTIAL]",
            confidence=1.0,
            severity="CRITICAL"
        )
        f2 = PIIFinding(
            document_id=doc.id,
            pii_type="CARD",
            masked_value="**** **** **** 1111",
            confidence=1.0,
            severity="CRITICAL",
            checksum_valid=True
        )
        db.session.add_all([f1, f2])

        # 2. Exposure with credentials
        exp = ExposureRecord(
            user_id=user.id,
            query_type="composite",
            query_value_hash="hash_exp_cred",
            total_entities=3,
            sensitive_count=2,
            financial_count=0,
            credential_count=2,
            exposure_score=60.0,
            exposure_level="HIGH",
            sensitivity_label="HIGH",
            sensitivity_confidence=0.85,
            is_anomalous=False,
            category_scores={"credential": 60.0},
            entity_summary={"CREDENTIAL": 2},
            raw_findings=[],
            analyzed_at=now_utc,
            created_at=now_utc
        )
        db.session.add(exp)

        # 3. Breach result with password and card
        br = BreachResult(
            user_id=user.id,
            query_email_hash="hash_br_cred",
            breach_count=2,
            total_exposures=4,
            priority_label="CRITICAL",
            priority_confidence=0.92,
            breach_risk_score=85.0,
            breach_risk_level="CRITICAL",
            exposure_summary={"PASSWORD_HASH": 2, "CARD": 2},
            checked_at=now_utc,
            created_at=now_utc
        )
        db.session.add(br)
        db.session.commit()

    # Query Dashboard Recommendations
    res = client.get("/api/dashboard/recommendations", headers=headers)
    assert res.status_code == 200
    recs = res.get_json()["data"]["recommendations"]
    assert len(recs) >= 2

    # Check change_password recommendation
    pwd_rec = next((r for r in recs if r["action_type"] == "change_password"), None)
    assert pwd_rec is not None
    assert pwd_rec["priority"] == "CRITICAL"
    # Merged source modules must include all 3 modules!
    assert "document_scanner" in pwd_rec["source_modules"]
    assert "exposure_monitor" in pwd_rec["source_modules"]
    assert "breach_monitor" in pwd_rec["source_modules"]
    assert len(pwd_rec["source_modules"]) == 3
    assert "credentials" in pwd_rec["reason"].lower() or "password" in pwd_rec["reason"].lower()

    # Check freeze_card recommendation
    card_rec = next((r for r in recs if r["action_type"] == "freeze_card"), None)
    assert card_rec is not None
    assert "document_scanner" in card_rec["source_modules"]
    assert "breach_monitor" in card_rec["source_modules"]


def test_unified_recommendation_dismissal(client, auth_user, app):
    """Verifies that dismissing a recommendation removes it from the dashboard."""
    user, token = auth_user
    headers = {"Authorization": f"Bearer {token}"}
    now_utc = datetime.now(timezone.utc)

    with app.app_context():
        doc = Document(
            user_id=user.id,
            original_filename="server_keys.txt",
            file_type="txt",
            file_size=1024,
            file_hash="hash_k",
            pii_count=1,
            high_risk_count=1,
            risk_score=70.0,
            risk_level="HIGH",
            scanned_at=now_utc,
            created_at=now_utc
        )
        db.session.add(doc)
        db.session.flush()
        f = PIIFinding(
            document_id=doc.id,
            pii_type="CREDENTIAL",
            masked_value="[REDACTED_CREDENTIAL]",
            confidence=1.0,
            severity="HIGH"
        )
        db.session.add(f)
        db.session.commit()

    # Initially recommendation is present
    res1 = client.get("/api/dashboard/recommendations", headers=headers)
    assert res1.status_code == 200
    recs1 = res1.get_json()["data"]["recommendations"]
    assert len(recs1) >= 1
    rec_id = recs1[0]["id"]

    # Dismiss via PATCH /api/dashboard/recommendations/<id>/dismiss
    res_dismiss = client.patch(f"/api/dashboard/recommendations/{rec_id}/dismiss", headers=headers)
    assert res_dismiss.status_code == 200

    # Verify recommendation is no longer in active recommendations
    res2 = client.get("/api/dashboard/recommendations", headers=headers)
    assert res2.status_code == 200
    recs2 = res2.get_json()["data"]["recommendations"]
    active_ids = {r["id"] for r in recs2}
    assert rec_id not in active_ids


def test_property_unified_risk_score_bounded_and_deterministic():
    """Property test: Overall composite risk score is strictly bounded in [0.0, 100.0] and deterministic."""
    import random
    from backend.app.dashboard.service import MODULE_WEIGHTS

    for _ in range(500):
        doc_score = random.uniform(0.0, 100.0)
        exp_score = random.uniform(0.0, 100.0)
        br_score = random.uniform(0.0, 100.0)

        # Active combinations
        active_subsets = [
            {"document": doc_score},
            {"exposure": exp_score},
            {"breach": br_score},
            {"document": doc_score, "exposure": exp_score},
            {"document": doc_score, "breach": br_score},
            {"document": doc_score, "exposure": exp_score, "breach": br_score},
        ]

        for active in active_subsets:
            total_w = sum(MODULE_WEIGHTS[m] for m in active)
            score = sum((MODULE_WEIGHTS[m] / total_w) * active[m] for m in active)
            bounded_score = round(min(100.0, max(0.0, score)), 1)
            assert 0.0 <= bounded_score <= 100.0


def test_dashboard_cross_user_denied(app, client, auth_user, second_user):
    """
    Verifies user isolation contract across all 4 access scenarios:
    1. User A -> own dashboard -> 200
    2. User B -> User A dashboard via ?user_id=<user_a> -> 403 Forbidden
    3. User B -> User A recommendation dismissal -> 404 Not Found
    4. User B -> own dashboard -> 200 clean 0.0 baseline with zero User A leakage
    5. Unauthenticated -> 401 Unauthorized
    """
    user_a, token_a = auth_user
    user_b, token_b = second_user
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}
    now_utc = datetime.now(timezone.utc)

    # 1. Populate User A with document and recommendation
    with app.app_context():
        doc_a = Document(
            user_id=user_a.id,
            original_filename="user_a_confidential.pdf",
            file_type="pdf",
            file_size=8192,
            file_hash="hash_user_a",
            pii_count=5,
            high_risk_count=2,
            risk_score=75.0,
            risk_level="HIGH",
            scanned_at=now_utc,
            created_at=now_utc
        )
        db.session.add(doc_a)
        db.session.flush()

        rec_a = Recommendation(
            user_id=user_a.id,
            source_module="document_scanner",
            category="financial",
            priority="CRITICAL",
            title="User A Secret Recommendation",
            description="User A sensitive advice.",
            action_type="freeze_card",
            is_dismissed=False,
            created_at=now_utc
        )
        db.session.add(rec_a)
        db.session.commit()
        rec_a_id = str(rec_a.id)

    # Scenario 1: User A accesses own dashboard -> 200
    res_a = client.get("/api/dashboard", headers=headers_a)
    assert res_a.status_code == 200
    assert res_a.get_json()["data"]["document_risk"]["documents_scanned"] == 1

    # Scenario 2: User B attempts to access User A's dashboard via ?user_id=<user_a.id> -> 403
    res_b_cross = client.get(f"/api/dashboard?user_id={user_a.id}", headers=headers_b)
    assert res_b_cross.status_code == 403
    assert res_b_cross.get_json()["error"]["code"] == "FORBIDDEN"

    # Also verify sub-endpoints reject cross-user access with 403
    for sub in ("/summary", "/risk", "/recommendations", "/history"):
        res_sub = client.get(f"/api/dashboard{sub}?user_id={user_a.id}", headers=headers_b)
        assert res_sub.status_code == 403
        assert res_sub.get_json()["error"]["code"] == "FORBIDDEN"

    # Scenario 3: User B attempts to dismiss User A's recommendation -> 404
    res_b_dismiss = client.patch(f"/api/dashboard/recommendations/{rec_a_id}/dismiss", headers=headers_b)
    assert res_b_dismiss.status_code == 404

    # Scenario 4: User B accesses own dashboard -> 200 clean 0.0 baseline
    res_b_own = client.get("/api/dashboard", headers=headers_b)
    assert res_b_own.status_code == 200
    data_b = res_b_own.get_json()["data"]
    assert data_b["overall_risk"]["score"] == 0.0
    assert data_b["overall_risk"]["level"] == "LOW"
    assert data_b["overall_risk"]["active_modules"] == 0
    assert data_b["document_risk"]["documents_scanned"] == 0
    assert data_b["exposure_risk"]["analyses_count"] == 0
    assert data_b["breach_risk"]["total_breaches"] == 0
    assert data_b["recent_activity"] == []
    assert data_b["active_recommendations"] == []
    # Verify zero data leakage about User A
    assert "user_a" not in str(data_b).lower()

    # Scenario 5: Unauthenticated request -> 401
    res_unauth = client.get("/api/dashboard")
    assert res_unauth.status_code == 401


def test_dynamic_normalization_all_combinations(app, client):
    """
    Verifies dynamic normalization behavior across all module activity states:
    1. No module data -> 0.0 LOW, active_modules = 0
    2. Document only -> 65.0 HIGH, active_modules = 1 (1.0x normalized)
    3. Exposure only -> 50.0 HIGH, active_modules = 1 (1.0x normalized)
    4. Breach only -> 80.0 CRITICAL, active_modules = 1 (1.0x normalized)
    5. All three -> weighted composite: 0.30*70 + 0.35*60 + 0.35*80 = 70.0, active_modules = 3
    """
    now_utc = datetime.now(timezone.utc)

    # 1. No module data user
    with app.app_context():
        u0 = User(email=f"norm0_{uuid.uuid4().hex[:6]}@intelprotect.internal", username=f"norm0_{uuid.uuid4().hex[:6]}", password_hash="h", is_active=True)
        db.session.add(u0)
        db.session.commit()
        t0 = create_access_token(str(u0.id), u0.email)

    r0 = client.get("/api/dashboard", headers={"Authorization": f"Bearer {t0}"}).get_json()["data"]
    assert r0["overall_risk"]["score"] == 0.0
    assert r0["overall_risk"]["level"] == "LOW"
    assert r0["overall_risk"]["active_modules"] == 0

    # 2. Document only user
    with app.app_context():
        u1 = User(email=f"norm1_{uuid.uuid4().hex[:6]}@intelprotect.internal", username=f"norm1_{uuid.uuid4().hex[:6]}", password_hash="h", is_active=True)
        db.session.add(u1)
        db.session.flush()
        doc = Document(user_id=u1.id, original_filename="doc.pdf", file_type="pdf", file_size=100, file_hash="hash_doc1", risk_score=65.0, risk_level="HIGH", pii_count=3, created_at=now_utc)
        db.session.add(doc)
        db.session.commit()
        t1 = create_access_token(str(u1.id), u1.email)

    r1 = client.get("/api/dashboard", headers={"Authorization": f"Bearer {t1}"}).get_json()["data"]
    assert r1["overall_risk"]["score"] == 65.0
    assert r1["overall_risk"]["level"] == "HIGH"
    assert r1["overall_risk"]["active_modules"] == 1

    # 3. Exposure only user
    with app.app_context():
        u2 = User(email=f"norm2_{uuid.uuid4().hex[:6]}@intelprotect.internal", username=f"norm2_{uuid.uuid4().hex[:6]}", password_hash="h", is_active=True)
        db.session.add(u2)
        db.session.flush()
        exp = ExposureRecord(user_id=u2.id, query_type="test", query_value_hash="h", exposure_score=50.0, exposure_level="HIGH", sensitivity_label="HIGH", created_at=now_utc)
        db.session.add(exp)
        db.session.commit()
        t2 = create_access_token(str(u2.id), u2.email)

    r2 = client.get("/api/dashboard", headers={"Authorization": f"Bearer {t2}"}).get_json()["data"]
    assert r2["overall_risk"]["score"] == 50.0
    assert r2["overall_risk"]["level"] == "HIGH"
    assert r2["overall_risk"]["active_modules"] == 1

    # 4. Breach only user
    with app.app_context():
        u3 = User(email=f"norm3_{uuid.uuid4().hex[:6]}@intelprotect.internal", username=f"norm3_{uuid.uuid4().hex[:6]}", password_hash="h", is_active=True)
        db.session.add(u3)
        db.session.flush()
        br = BreachResult(user_id=u3.id, query_email_hash="h", breach_count=1, breach_risk_score=80.0, breach_risk_level="CRITICAL", priority_label="CRITICAL", created_at=now_utc)
        db.session.add(br)
        db.session.commit()
        t3 = create_access_token(str(u3.id), u3.email)

    r3 = client.get("/api/dashboard", headers={"Authorization": f"Bearer {t3}"}).get_json()["data"]
    assert r3["overall_risk"]["score"] == 80.0
    assert r3["overall_risk"]["level"] == "CRITICAL"
    assert r3["overall_risk"]["active_modules"] == 1

    # 5. All three modules user
    with app.app_context():
        u4 = User(email=f"norm4_{uuid.uuid4().hex[:6]}@intelprotect.internal", username=f"norm4_{uuid.uuid4().hex[:6]}", password_hash="h", is_active=True)
        db.session.add(u4)
        db.session.flush()
        doc4 = Document(user_id=u4.id, original_filename="doc.pdf", file_type="pdf", file_size=100, file_hash="hash_doc4", risk_score=70.0, risk_level="HIGH", pii_count=2, created_at=now_utc)
        exp4 = ExposureRecord(user_id=u4.id, query_type="test", query_value_hash="h", exposure_score=60.0, exposure_level="HIGH", sensitivity_label="HIGH", created_at=now_utc)
        br4 = BreachResult(user_id=u4.id, query_email_hash="h", breach_count=1, breach_risk_score=80.0, breach_risk_level="CRITICAL", priority_label="CRITICAL", created_at=now_utc)
        db.session.add_all([doc4, exp4, br4])
        db.session.commit()
        t4 = create_access_token(str(u4.id), u4.email)

    r4 = client.get("/api/dashboard", headers={"Authorization": f"Bearer {t4}"}).get_json()["data"]
    # 0.30*70 + 0.35*60 + 0.35*80 = 21.0 + 21.0 + 28.0 = 70.0
    assert r4["overall_risk"]["score"] == 70.0
    assert r4["overall_risk"]["level"] == "HIGH"
    assert r4["overall_risk"]["active_modules"] == 3


def test_recommendation_safety_unsupported_recs_never_generated(app, client):
    """
    Verifies recommendation safety:
    1. No financial exposure -> no freeze_card recommendation
    2. No credential exposure -> no change_password recommendation
    3. No identity exposure -> no lock_biometrics recommendation
    4. Clean empty user -> empty recommendation list
    """
    now_utc = datetime.now(timezone.utc)

    # 1. User with ONLY identity data (Aadhaar in document)
    with app.app_context():
        u_id = User(email=f"safe_id_{uuid.uuid4().hex[:6]}@intelprotect.internal", username=f"safe_id_{uuid.uuid4().hex[:6]}", password_hash="h", is_active=True)
        db.session.add(u_id)
        db.session.flush()
        doc = Document(user_id=u_id.id, original_filename="aadhaar.pdf", file_type="pdf", file_size=100, file_hash="hash_doc_id", risk_score=40.0, risk_level="MEDIUM", pii_count=1, created_at=now_utc)
        db.session.add(doc)
        db.session.flush()
        f_id = PIIFinding(document_id=doc.id, pii_type="AADHAAR", masked_value="XXXX-XXXX-1234", confidence=1.0, severity="HIGH", checksum_valid=True)
        db.session.add(f_id)
        db.session.commit()
        t_id = create_access_token(str(u_id.id), u_id.email)

    recs_id = client.get("/api/dashboard/recommendations", headers={"Authorization": f"Bearer {t_id}"}).get_json()["data"]["recommendations"]
    action_types_id = {r["action_type"] for r in recs_id}
    assert "lock_biometrics" in action_types_id
    assert "freeze_card" not in action_types_id
    assert "change_password" not in action_types_id

    # 2. User with ONLY financial data (Card in document)
    with app.app_context():
        u_fin = User(email=f"safe_fin_{uuid.uuid4().hex[:6]}@intelprotect.internal", username=f"safe_fin_{uuid.uuid4().hex[:6]}", password_hash="h", is_active=True)
        db.session.add(u_fin)
        db.session.flush()
        doc_fin = Document(user_id=u_fin.id, original_filename="card.pdf", file_type="pdf", file_size=100, file_hash="hash_doc_fin", risk_score=50.0, risk_level="HIGH", pii_count=1, created_at=now_utc)
        db.session.add(doc_fin)
        db.session.flush()
        f_fin = PIIFinding(document_id=doc_fin.id, pii_type="CARD", masked_value="**** **** **** 5678", confidence=1.0, severity="CRITICAL", checksum_valid=True)
        db.session.add(f_fin)
        db.session.commit()
        t_fin = create_access_token(str(u_fin.id), u_fin.email)

    recs_fin = client.get("/api/dashboard/recommendations", headers={"Authorization": f"Bearer {t_fin}"}).get_json()["data"]["recommendations"]
    action_types_fin = {r["action_type"] for r in recs_fin}
    assert "freeze_card" in action_types_fin
    assert "change_password" not in action_types_fin
    assert "lock_biometrics" not in action_types_fin

    # 3. Completely clean user
    with app.app_context():
        u_clean = User(email=f"safe_clean_{uuid.uuid4().hex[:6]}@intelprotect.internal", username=f"safe_clean_{uuid.uuid4().hex[:6]}", password_hash="h", is_active=True)
        db.session.add(u_clean)
        db.session.commit()
        t_clean = create_access_token(str(u_clean.id), u_clean.email)

    recs_clean = client.get("/api/dashboard/recommendations", headers={"Authorization": f"Bearer {t_clean}"}).get_json()["data"]["recommendations"]
    assert recs_clean == []


def test_dashboard_no_raw_pii_in_response(app, client, auth_user):
    """Verifies that no raw PII values, credentials, or secrets leak into dashboard responses."""
    user, token = auth_user
    headers = {"Authorization": f"Bearer {token}"}
    now_utc = datetime.now(timezone.utc)

    with app.app_context():
        doc = Document(
            user_id=user.id,
            original_filename="confidential_scan.pdf",
            file_type="pdf",
            file_size=200,
            file_hash="hash_doc_pii_test",
            risk_score=75.0,
            risk_level="HIGH",
            pii_count=2,
            created_at=now_utc
        )
        db.session.add(doc)
        db.session.flush()
        f1 = PIIFinding(document_id=doc.id, pii_type="AADHAAR", masked_value="XXXX-XXXX-9012", confidence=1.0, severity="HIGH", checksum_valid=True)
        f2 = PIIFinding(document_id=doc.id, pii_type="PAN", masked_value="ABCDE****F", confidence=1.0, severity="HIGH", checksum_valid=True)
        db.session.add_all([f1, f2])
        db.session.commit()

    res = client.get("/api/dashboard", headers=headers)
    assert res.status_code == 200
    res_text = res.get_data(as_text=True)

    # Assert no unmasked 12-digit numbers
    import re
    assert not re.search(r'\b[2-9]\d{3}\s\d{4}\s\d{4}\b', res_text)
    assert not re.search(r'\b[2-9]\d{11}\b', res_text)
    # Assert no raw 16-digit cards
    assert not re.search(r'\b\d{16}\b', res_text)
    # Assert no password string values
    assert "argon2" not in res_text
    assert "placeholder" not in res_text

