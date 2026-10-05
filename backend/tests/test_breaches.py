"""
Automated Test Suite for Phase 8: Breach Monitor.
Covers:
1. Synthetic Breach Catalog & Seeding
2. Breach Provider Adapter Pattern (LocalBreachProvider)
3. Deterministic Breach Risk Scoring Engine (unit tests, 1000-permutation property tests, monotonicity)
4. ML Priority Classifier Wrapper (Model 3 Random Forest inference)
5. Contextual Security Recommendation Engine
6. REST API Endpoints with Strict Authentication and Multi-Tenant Isolation
"""
import copy
from datetime import date, timedelta
import random
import uuid
import pytest
from backend.app import db
from backend.app.models.user import User
from backend.app.models.breach import Breach, BreachResult, BreachExposure
from backend.app.models.recommendation import Recommendation
from backend.app.breaches.catalog import seed_synthetic_breaches, SYNTHETIC_BREACH_CATALOG
from backend.app.breaches.provider import LocalBreachProvider
from backend.app.breaches.scorer import calculate_breach_risk_score
from backend.app.breaches.priority import extract_breach_features, predict_breach_priority
from backend.app.breaches.recommendations import generate_breach_recommendations
from backend.app.common.security import create_access_token
from backend.app.breaches.service import check_email_breaches, dismiss_recommendation


@pytest.fixture
def auth_user(app):
    """Creates User A and returns (user, token)."""
    with app.app_context():
        user = User(
            email=f"breach_user_a_{uuid.uuid4().hex[:6]}@intelprotect.internal",
            username=f"breach_user_a_{uuid.uuid4().hex[:6]}",
            password_hash="argon2_placeholder",
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        token = create_access_token(str(user.id), user.email)
        return user, token


@pytest.fixture
def second_user(app):
    """Creates User B for user data isolation tests."""
    with app.app_context():
        user = User(
            email=f"breach_user_b_{uuid.uuid4().hex[:6]}@intelprotect.internal",
            username=f"breach_user_b_{uuid.uuid4().hex[:6]}",
            password_hash="argon2_placeholder",
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        token = create_access_token(str(user.id), user.email)
        return user, token



# ==============================================================================
# 1. CATALOG & SEEDING TESTS
# ==============================================================================

def test_synthetic_breach_catalog_seeding(app):
    """Catalog seeding creates all predefined synthetic breaches in database."""
    with app.app_context():
        seed_synthetic_breaches()
        breaches = Breach.query.all()
        assert len(breaches) >= len(SYNTHETIC_BREACH_CATALOG)
        for b in breaches:
            assert b.name is not None
            assert b.organization is not None
            assert b.breach_date is not None
            assert b.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            assert isinstance(b.exposed_data_types, list)
            assert b.is_synthetic is True


# ==============================================================================
# 2. PROVIDER ADAPTER TESTS
# ==============================================================================

def test_local_breach_provider_clean_email(app):
    """Clean keyword emails return zero breaches."""
    with app.app_context():
        provider = LocalBreachProvider()
        results = provider.search_breaches("safe_user_clean@intelprotect.internal")
        assert len(results) == 0


def test_local_breach_provider_critical_email(app):
    """Critical / victim keyword emails return multiple critical breaches."""
    with app.app_context():
        provider = LocalBreachProvider()
        results = provider.search_breaches("victim_hacked_critical@intelprotect.internal")
        assert len(results) >= 3
        severities = {b.severity for b in results}
        assert "CRITICAL" in severities


def test_local_breach_provider_deterministic_resolution(app):
    """The same email address always yields deterministic breach results."""
    with app.app_context():
        provider = LocalBreachProvider()
        email = "consistent_developer_42@example.com"
        res1 = provider.search_breaches(email)
        res2 = provider.search_breaches(email)
        assert [b.name for b in res1] == [b.name for b in res2]


# ==============================================================================
# 3. DETERMINISTIC SCORING ENGINE TESTS
# ==============================================================================

def test_breach_risk_scoring_empty():
    """Empty breach match returns 0.0 LOW score with explanatory factors."""
    res = calculate_breach_risk_score([])
    assert res["score"] == 0.0
    assert res["risk_level"] == "LOW"
    assert res["breach_count"] == 0
    assert res["total_exposures"] == 0
    assert "No breach occurrences" in res["explanation"]["contributing_factors"][0]


def test_breach_risk_scoring_single_low_breach():
    """Single LOW breach produces score in LOW tier (< 25.0)."""
    b = Breach(
        name="Test Low",
        organization="Test Org",
        breach_date=date(2022, 1, 1),
        discovered_date=date(2022, 1, 5),
        description="Minor scrape",
        affected_count=10000,
        exposed_data_types=["EMAIL", "USERNAME"],
        severity="LOW"
    )
    res = calculate_breach_risk_score([b])
    assert 0.0 < res["score"] < 25.0
    assert res["risk_level"] == "LOW"
    assert res["breach_count"] == 1


def test_breach_risk_scoring_critical_synergy():
    """Critical breach with credentials and financial data triggers compound synergy boost."""
    b1 = Breach(
        name="Test Critical",
        organization="Bank Org",
        breach_date=date.today() - timedelta(days=30),
        discovered_date=date.today() - timedelta(days=25),
        description="Core database breach",
        affected_count=5000000,
        exposed_data_types=["EMAIL", "PASSWORD_HASH", "CARD", "BANK_ACCOUNT", "AADHAAR"],
        severity="CRITICAL"
    )
    b2 = Breach(
        name="Test Cloud",
        organization="Cloud Org",
        breach_date=date.today() - timedelta(days=60),
        discovered_date=date.today() - timedelta(days=55),
        description="CI/CD breach",
        affected_count=1000000,
        exposed_data_types=["API_SECRET", "PASSWORD", "PHONE"],
        severity="CRITICAL"
    )
    res = calculate_breach_risk_score([b1, b2])
    assert res["score"] >= 75.0
    assert res["risk_level"] == "CRITICAL"
    assert any("Compound exposure" in f for f in res["explanation"]["contributing_factors"])


def test_breach_risk_scoring_property_bounded_1000_permutations():
    """Property test: 1,000 permutations must remain strictly within [0.0, 100.0]."""
    all_types = ["EMAIL", "PASSWORD", "PASSWORD_HASH", "CARD", "BANK_ACCOUNT", "AADHAAR", "PAN", "PHONE", "ADDRESS", "USERNAME", "IP", "DOB"]
    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    rng = random.Random(42)

    for _ in range(1000):
        n_breaches = rng.randint(0, 8)
        sample_breaches = []
        for i in range(n_breaches):
            days = rng.randint(10, 3000)
            sample_breaches.append(Breach(
                name=f"Permutation Breach {i}",
                organization="Perm Corp",
                breach_date=date.today() - timedelta(days=days),
                discovered_date=date.today() - timedelta(days=days - 2),
                description="Synthetic test",
                affected_count=rng.randint(1000, 10000000),
                exposed_data_types=rng.sample(all_types, rng.randint(1, min(6, len(all_types)))),
                severity=rng.choice(severities)
            ))

        result = calculate_breach_risk_score(sample_breaches)
        assert 0.0 <= result["score"] <= 100.0
        assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_breach_risk_scoring_property_monotonicity():
    """Property test: Adding breaches never decreases breach risk score."""
    base_breaches = []
    prev_score = 0.0

    new_breach = Breach(
        name="Incremental Breach",
        organization="Corp",
        breach_date=date.today() - timedelta(days=100),
        discovered_date=date.today() - timedelta(days=95),
        description="Incremental",
        affected_count=50000,
        exposed_data_types=["EMAIL", "PASSWORD_HASH"],
        severity="HIGH"
    )

    for _ in range(8):
        base_breaches.append(new_breach)
        res = calculate_breach_risk_score(base_breaches)
        assert res["score"] >= prev_score, f"Monotonicity failed: {res['score']} < {prev_score}"
        prev_score = res["score"]


# ==============================================================================
# 4. ML PRIORITY CLASSIFIER TESTS (MODEL 3)
# ==============================================================================

def test_breach_priority_model_inference():
    """Model 3 Random Forest inference evaluates breach features successfully."""
    b = Breach(
        name="Critical Leak",
        organization="Fintech Inc",
        breach_date=date.today() - timedelta(days=120),
        discovered_date=date.today() - timedelta(days=115),
        description="Critical breach",
        affected_count=2000000,
        exposed_data_types=["EMAIL", "PASSWORD", "CARD", "AADHAAR"],
        severity="CRITICAL"
    )
    result = predict_breach_priority([b])
    assert result["priority_label"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert 0.0 <= result["confidence"] <= 1.0


# ==============================================================================
# 5. RECOMMENDATIONS ENGINE TESTS
# ==============================================================================

def test_generate_recommendations_credentials_and_financial():
    """Generates password change and financial security recommendations for compromised leaks."""
    b = Breach(
        name="CryptoExchange",
        organization="Crypto Corp",
        breach_date=date(2023, 10, 1),
        discovered_date=date(2023, 10, 5),
        description="Exfiltration",
        affected_count=500000,
        exposed_data_types=["EMAIL", "PASSWORD_HASH", "CARD", "PHONE"],
        severity="CRITICAL"
    )
    user_id = str(uuid.uuid4())
    result_id = str(uuid.uuid4())
    recs = generate_breach_recommendations(user_id, result_id, [b])

    assert len(recs) >= 3
    action_types = {r.action_type for r in recs}
    assert "change_password" in action_types
    assert "freeze_card" in action_types
    assert "enable_mfa" in action_types


# ==============================================================================
# 6. REST API & USER ISOLATION TESTS
# ==============================================================================

def test_api_unauthenticated_request_rejected(client):
    """Unauthenticated requests are rejected with 401."""
    res_check = client.post("/api/breaches/check", json={"email": "test@example.com"})
    assert res_check.status_code == 401

    res_hist = client.get("/api/breaches/history")
    assert res_hist.status_code == 401

    res_recs = client.get("/api/recommendations")
    assert res_recs.status_code == 401


def test_api_check_and_retrieve_history(client, auth_user):
    """Authenticated user can check breaches, retrieve history, and inspect recommendations."""
    user, token = auth_user
    headers = {"Authorization": f"Bearer {token}"}

    payload = {"email": "victim_critical_target@intelprotect.internal"}
    res_check = client.post("/api/breaches/check", json=payload, headers=headers)
    assert res_check.status_code == 201
    data = res_check.get_json()["data"]

    result = data["result"]
    assert "id" in result
    assert "user_id" not in result  # Verified data minimization: internal user_id is not exposed
    assert result["breach_count"] >= 3
    assert result["breach_risk_score"] >= 75.0
    assert result["breach_risk_level"] == "CRITICAL"
    assert len(data["breaches"]) >= 3
    assert len(data["recommendations"]) >= 2
    assert "user_id" not in data["recommendations"][0]  # Verified data minimization

    # Query History
    res_hist = client.get("/api/breaches/history", headers=headers)
    assert res_hist.status_code == 200
    hist_data = res_hist.get_json()["data"]
    assert hist_data["total"] == 1
    assert hist_data["records"][0]["id"] == result["id"]
    assert "user_id" not in hist_data["records"][0]

    # Query Active Recommendations
    res_recs = client.get("/api/recommendations", headers=headers)
    assert res_recs.status_code == 200
    recs_list = res_recs.get_json()["data"]["recommendations"]
    assert len(recs_list) >= 2
    assert "user_id" not in recs_list[0]

    # Dismiss first recommendation
    rec_to_dismiss = recs_list[0]
    res_dismiss = client.patch(f"/api/recommendations/{rec_to_dismiss['id']}/dismiss", headers=headers)
    assert res_dismiss.status_code == 200
    assert res_dismiss.get_json()["data"]["recommendation"]["is_dismissed"] is True


def test_api_user_isolation(client, auth_user, second_user):
    """User B cannot view or delete User A's breach check records (must return 404)."""
    user_a, token_a = auth_user
    user_b, token_b = second_user
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # User A creates a breach check
    res_a = client.post("/api/breaches/check", json={"email": "user_a@example.com"}, headers=headers_a)
    assert res_a.status_code == 201
    record_id_a = res_a.get_json()["data"]["result"]["id"]

    # User B attempts to access User A's record -> MUST be 404
    res_b_get = client.get(f"/api/breaches/{record_id_a}", headers=headers_b)
    assert res_b_get.status_code == 404

    # User B attempts to delete User A's record -> MUST be 404
    res_b_del = client.delete(f"/api/breaches/{record_id_a}", headers=headers_b)
    assert res_b_del.status_code == 404

    # User A successfully retrieves their record
    res_a_get = client.get(f"/api/breaches/{record_id_a}", headers=headers_a)
    assert res_a_get.status_code == 200


def test_api_breach_catalog(client, auth_user):
    """Authenticated user can query catalog of monitored breaches (requires Bearer JWT)."""
    user, token = auth_user
    headers = {"Authorization": f"Bearer {token}"}

    res_cat = client.get("/api/breaches/catalog", headers=headers)
    assert res_cat.status_code == 200
    cat_data = res_cat.get_json()["data"]
    assert cat_data["total"] >= 10
    assert len(cat_data["catalog"]) >= 10


def test_raw_email_never_persisted_or_leaked_in_api_response(client, auth_user, app):
    """Verifies raw email and plaintext credentials are never persisted or returned in API."""
    user, token = auth_user
    headers = {"Authorization": f"Bearer {token}"}
    secret_email = "test_confidential_raw_email_99@intelprotect.internal"

    res = client.post("/api/breaches/check", json={"email": secret_email}, headers=headers)
    assert res.status_code == 201

    # Verify response body does not contain raw email
    response_text = res.get_data(as_text=True)
    assert secret_email not in response_text

    # Verify database record does not contain raw email
    with app.app_context():
        latest_record = BreachResult.query.order_by(BreachResult.created_at.desc()).first()
        assert latest_record is not None
        assert secret_email not in latest_record.query_email_hash
        assert len(latest_record.query_email_hash) == 64  # SHA-256


def test_recommendation_safety_corresponds_to_exposed_categories():
    """Recommendations must strictly correspond to actual exposed categories."""
    b_address_only = Breach(
        name="AddressDirectory",
        organization="Directory Corp",
        breach_date=date(2023, 5, 1),
        discovered_date=date(2023, 5, 5),
        description="Physical address exposure",
        affected_count=100000,
        exposed_data_types=["ADDRESS", "NAME"],
        severity="LOW"
    )
    user_id = str(uuid.uuid4())
    result_id = str(uuid.uuid4())
    recs = generate_breach_recommendations(user_id, result_id, [b_address_only])

    action_types = {r.action_type for r in recs}
    # Neither password, financial, identity, nor MFA should be recommended
    assert "change_password" not in action_types
    assert "freeze_card" not in action_types
    assert "lock_biometrics" not in action_types
    assert "enable_mfa" not in action_types
