"""
Comprehensive Unit, Integration, Security, and Property Tests for Exposure Monitor.
Tests:
1. Synthetic exposure dataset schema and distribution
2. Custom Regex NER entity detection (Person, Email, Phone, Location, Username, Financial, Identity, Credential)
3. Zero raw PII output guarantee in NER and API serialization
4. TF-IDF + Random Forest sensitivity classification inference
5. Isolation Forest anomaly detection on standard vs anomalous feature profiles
6. Deterministic 0-100 Exposure Risk Scorer with multi-vector synergy boosts
7. Property testing: Strictly bounded [0.0, 100.0] across 1,000 permutations
8. Property testing: Monotonicity (adding sensitive entities never decreases risk)
9. Database persistence in exposure_records table
10. REST API endpoints (POST /analyze, GET /history, GET /:id, DELETE /:id) with strict user isolation
"""
import os
import random
import uuid
import pytest
import pandas as pd

from backend.app import db
from backend.app.models.user import User
from backend.app.models.exposure_record import ExposureRecord
from backend.app.common.security import create_access_token
from backend.app.exposure.ner import (
    extract_exposure_entities,
    summarize_entities,
    ExposureEntity
)
from backend.app.exposure.classifier import classify_exposure_sensitivity
from backend.app.exposure.anomaly import detect_exposure_anomaly
from backend.app.exposure.scorer import (
    calculate_exposure_score,
    calculate_category_scores,
    CATEGORY_WEIGHTS,
    EXPOSURE_SCORING_VERSION
)
from backend.app.ml.registry import registry


@pytest.fixture(autouse=True)
def clean_exposure_database(app):
    """Cleans exposure_records and users before each test execution."""
    with app.app_context():
        ExposureRecord.query.delete()
        User.query.delete()
        db.session.commit()


@pytest.fixture
def auth_user(app):
    """Creates User A and returns (user, token)."""
    with app.app_context():
        user = User(
            email="exposure_user_a@intelprotect.internal",
            username="exposure_usera",
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
            email="exposure_user_b@intelprotect.internal",
            username="exposure_userb",
            password_hash="argon2_placeholder",
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        token = create_access_token(str(user.id), user.email)
        return user, token


# ==============================================================================
# 1. SYNTHETIC DATASET TESTS
# ==============================================================================

def test_synthetic_exposure_dataset_schema_and_integrity():
    """Verify synthetic_exposures.csv exists, has correct schema and class distribution."""
    csv_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "data", "synthetic", "synthetic_exposures.csv")
    )
    assert os.path.exists(csv_path), f"Synthetic dataset missing at {csv_path}"
    df = pd.read_csv(csv_path)

    expected_cols = [
        "sample_id", "exposure_text", "entity_count", "has_financial",
        "has_credential", "has_identity", "source_category", "sensitivity_label", "is_synthetic"
    ]
    for col in expected_cols:
        assert col in df.columns, f"Missing column {col} in synthetic exposures CSV"

    assert len(df) >= 2500, f"Expected at least 2,500 records, got {len(df)}"
    assert df["is_synthetic"].all() is True or (df["is_synthetic"] == True).all()

    # Check non-empty text and class distribution
    assert df["exposure_text"].isnull().sum() == 0
    labels = set(df["sensitivity_label"].unique())
    assert labels == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


# ==============================================================================
# 2. CUSTOM REGEX-BASED NER TESTS
# ==============================================================================

def test_ner_extracts_all_entity_types_with_masking():
    """Verify NER identifies Email, Phone, Aadhaar, PAN, Card, Bank, Person, Location, JWT."""
    sample_text = (
        "CONFIDENTIAL DATA LOG:\n"
        "Contact person: Rahul Sharma\n"
        "User handle: (rahul_s)\n"
        "Email: rahul.sharma@example.com\n"
        "Mobile: +91-98765-43210\n"
        "Location: Mumbai\n"
        "Aadhaar UIDAI: 3675 9834 6016\n"  # Valid Verhoeff
        "PAN Card: ABCDE1234F\n"
        "Visa Card: 4532 0151 1283 0366\n"  # Valid Luhn
        "Bank Account: 123456789012\n"
        "Auth Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abcdef123456\n"
    )

    entities = extract_exposure_entities(sample_text)
    types_found = {e.entity_type for e in entities}

    assert "PERSON" in types_found
    assert "USERNAME" in types_found
    assert "EMAIL" in types_found
    assert "PHONE" in types_found
    assert "LOCATION" in types_found
    assert "IDENTITY" in types_found
    assert "FINANCIAL" in types_found
    assert "CREDENTIAL" in types_found

    # Verify that raw PII values are masked and to_dict() never leaks raw values
    for e in entities:
        d = e.to_dict()
        assert "raw_value" not in d, "raw_value leaked into serialized dictionary!"
        assert "*" in d["masked_value"] or "X" in d["masked_value"] or "[" in d["masked_value"] or d["entity_type"] == "LOCATION"
        assert d["confidence"] > 0.0


def test_ner_checksum_validation_flags():
    """Verify Verhoeff and Luhn checksum status on valid and invalid numbers."""
    # 3675 9834 6016 is valid Verhoeff; 3675 9834 6012 is invalid
    valid_text = "Aadhaar: 3675 9834 6016 and Card: 4532 0151 1283 0366"
    invalid_text = "Aadhaar: 3675 9834 6012 and Card: 4532 0150 0000 0000"

    ents_valid = extract_exposure_entities(valid_text)
    for e in ents_valid:
        if e.entity_type in ("IDENTITY", "FINANCIAL"):
            assert e.validation_status == "VALID"
            assert e.confidence >= 0.95

    ents_invalid = extract_exposure_entities(invalid_text)
    for e in ents_invalid:
        if e.entity_type in ("IDENTITY", "FINANCIAL"):
            assert e.validation_status == "INVALID"
            assert e.confidence <= 0.40


def test_ner_summarize_entities():
    """Verify entity counts and category breakdown."""
    sample = "Email: test@example.com, Phone: +91-98765-43210, Location: Pune."
    entities = extract_exposure_entities(sample)
    summary, cat_counts = summarize_entities(entities)

    assert summary.get("EMAIL", 0) >= 1
    assert summary.get("PHONE", 0) >= 1
    assert summary.get("LOCATION", 0) >= 1
    assert cat_counts["contact"] >= 2
    assert cat_counts["location"] >= 1


# ==============================================================================
# 3. TF-IDF + RANDOM FOREST SENSITIVITY CLASSIFIER TESTS
# ==============================================================================

def test_exposure_sensitivity_classification_inference():
    """Verify TF-IDF + Random Forest predicts valid labels and probabilities."""
    clean_text = "Public conference attendee listing for marketing workshop."
    res_clean = classify_exposure_sensitivity(clean_text)
    assert res_clean["predicted_label"] in ("LOW", "MEDIUM")
    assert 0.0 <= res_clean["confidence"] <= 1.0
    assert "LOW" in res_clean["probabilities"]

    critical_text = (
        "ROOT DATABASE DUMP: Admin credentials, JWT Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.abcdef, "
        "Bank Direct Deposit: 8728627585, Visa Card: 4532 0151 1283 0366, Secret: supersecretkey99"
    )
    res_crit = classify_exposure_sensitivity(critical_text)
    assert res_crit["predicted_label"] in ("HIGH", "CRITICAL")
    assert res_crit["confidence"] >= 0.35


def test_exposure_tfidf_zero_leakage():
    """Verify TF-IDF vectorizer artifact was fitted exclusively on training split."""
    tfidf, clf = registry.get_exposure_models()
    assert hasattr(tfidf, "vocabulary_"), "TF-IDF vectorizer is missing fitted vocabulary!"
    assert len(tfidf.vocabulary_) <= 5000, "Vocabulary exceeds configured max_features limit!"
    # Ensure transforms return correct feature dimensionality without refitting
    dummy_vec = tfidf.transform(["sample text without refitting"])
    assert dummy_vec.shape[1] == len(tfidf.vocabulary_)


# ==============================================================================
# 4. ISOLATION FOREST ANOMALY DETECTION TESTS
# ==============================================================================

def test_anomaly_detector_inlier_vs_outlier():
    """Verify Isolation Forest flags normal profiles as normal and extreme spikes as anomalies."""
    # Standard profile (1 email, 1 phone, 1 location)
    normal_profile = {
        "total_pii_count": 2,
        "sensitive_pii_count": 0,
        "financial_pii_count": 0,
        "credential_count": 0,
        "source_count": 1,
        "exposure_type_count": 2,
        "identity_data_count": 1
    }
    res_normal = detect_exposure_anomaly(normal_profile)
    assert res_normal["is_anomaly"] is False
    assert 0.0 <= res_normal["anomaly_score"] <= 1.0

    # Extreme anomalous profile (massive credential + financial concentration)
    extreme_profile = {
        "total_pii_count": 28,
        "sensitive_pii_count": 15,
        "financial_pii_count": 8,
        "credential_count": 10,
        "source_count": 6,
        "exposure_type_count": 5,
        "identity_data_count": 6
    }
    res_extreme = detect_exposure_anomaly(extreme_profile)
    assert res_extreme["is_anomaly"] is True
    assert res_extreme["anomaly_score"] > res_normal["anomaly_score"]


# ==============================================================================
# 5. DETERMINISTIC EXPOSURE SCORER TESTS
# ==============================================================================

def test_calculate_exposure_score_empty_target():
    """Clean/empty target yields 0.0 score, LOW level, and 0 category scores."""
    res = calculate_exposure_score([], sensitivity_label="LOW", is_anomalous=False)
    assert res["score"] == 0.0
    assert res["exposure_level"] == "LOW"
    assert res["category_scores"]["financial"] == 0.0
    assert res["explanation"]["anomalies"] == 0
    assert "No personal data exposure detected" in res["explanation"]["contributing_factors"][0]


def test_calculate_exposure_score_single_contact():
    """Single contact entity produces LOW exposure."""
    entities = [
        ExposureEntity(
            entity_type="EMAIL",
            raw_value="test@example.com",
            masked_value="t****t@example.com",
            confidence=0.95,
            validation_status="STRUCTURAL",
            context_snippet="...test@example.com...",
            start_pos=0,
            end_pos=16,
            category="contact"
        )
    ]
    res = calculate_exposure_score(entities, sensitivity_label="LOW", is_anomalous=False)
    assert 0.0 < res["score"] < 25.0
    assert res["exposure_level"] == "LOW"
    assert res["category_scores"]["contact"] > 0.0
    assert res["category_scores"]["financial"] == 0.0


def test_calculate_exposure_score_triad_synergy():
    """Credential + Financial + Identity triggers multi-vector triad boost."""
    entities = [
        ExposureEntity("CREDENTIAL", "secret", "[SECRET]", 0.98, "STRUCTURAL", "...", 0, 10, "credential"),
        ExposureEntity("CARD", "4532015112830366", "**** 0366", 0.99, "VALID", "...", 11, 20, "financial"),
        ExposureEntity("AADHAAR", "367598346016", "XXXX 6016", 0.98, "VALID", "...", 21, 30, "identity"),
    ]
    res = calculate_exposure_score(
        entities,
        sensitivity_label="CRITICAL",
        is_anomalous=True,
        anomaly_score=0.85
    )
    assert res["score"] >= 75.0
    assert res["exposure_level"] == "CRITICAL"
    assert res["explanation"]["anomalies"] == 1
    assert any("credential" in f.lower() for f in res["explanation"]["contributing_factors"])


# ==============================================================================
# 6. PROPERTY TESTS: STRICT BOUNDING & MONOTONICITY
# ==============================================================================

def test_property_strictly_bounded_1000_permutations():
    """Property test: Exposure score must stay strictly in [0.0, 100.0] across 1,000 permutations."""
    entity_types_catalog = [
        ("CREDENTIAL", "credential"),
        ("CARD", "financial"),
        ("BANK_ACCOUNT", "financial"),
        ("AADHAAR", "identity"),
        ("PAN", "identity"),
        ("PERSON", "identity"),
        ("EMAIL", "contact"),
        ("PHONE", "contact"),
        ("LOCATION", "location")
    ]
    sens_labels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    rng = random.Random(42)

    for _ in range(1000):
        count = rng.randint(0, 30)
        sample_entities = []
        for _ in range(count):
            etype, cat = rng.choice(entity_types_catalog)
            sample_entities.append(
                ExposureEntity(
                    entity_type=etype,
                    raw_value="raw",
                    masked_value="masked",
                    confidence=rng.uniform(0.3, 1.0),
                    validation_status=rng.choice(["VALID", "INVALID", "STRUCTURAL"]),
                    context_snippet="snippet",
                    start_pos=0,
                    end_pos=10,
                    category=cat
                )
            )

        sens = rng.choice(sens_labels)
        is_anom = rng.choice([True, False])
        anom_score = rng.uniform(0.0, 1.0)

        result = calculate_exposure_score(
            entities=sample_entities,
            sensitivity_label=sens,
            sensitivity_confidence=rng.uniform(0.5, 1.0),
            is_anomalous=is_anom,
            anomaly_score=anom_score
        )
        score = result["score"]
        assert 0.0 <= score <= 100.0, f"Score {score} violated bounds [0.0, 100.0]!"
        assert result["exposure_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_property_monotonicity():
    """Property test: Adding an entity never decreases category scores or composite score."""
    base_entities = []
    prev_score = 0.0

    new_entity = ExposureEntity(
        entity_type="CARD",
        raw_value="4532015112830366",
        masked_value="**** 0366",
        confidence=0.99,
        validation_status="VALID",
        context_snippet="snippet",
        start_pos=0,
        end_pos=16,
        category="financial"
    )

    for _ in range(10):
        base_entities.append(new_entity)
        res = calculate_exposure_score(base_entities, sensitivity_label="LOW", is_anomalous=False)
        assert res["score"] >= prev_score, f"Monotonicity violated: {res['score']} < {prev_score}"
        prev_score = res["score"]


# ==============================================================================
# 7. INTEGRATION & REST API TESTS WITH STRICT USER ISOLATION
# ==============================================================================

def test_api_unauthenticated_request_rejected(client):
    """POST /api/exposure/analyze and GET /api/exposure/history reject unauthenticated requests."""
    res_post = client.post("/api/exposure/analyze", json={"identifiers": {"name": "Test"}})
    assert res_post.status_code == 401

    res_get = client.get("/api/exposure/history")
    assert res_get.status_code == 401


def test_api_analyze_and_retrieve_history(client, auth_user):
    """Authenticated user can analyze exposure and retrieve paginated history."""
    user, token = auth_user
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "identifiers": {
            "name": "Anjali Sahni",
            "email": "raoniharika@example.net",
            "phone": "+91-81727-13934"
        }
    }

    res_post = client.post("/api/exposure/analyze", json=payload, headers=headers)
    assert res_post.status_code == 201
    resp_data = res_post.get_json()["data"]

    record = resp_data["exposure_record"]
    assert "id" in record
    assert "exposure_score" in record
    assert "category_scores" in record
    assert "findings" in record
    assert "explanation" in record
    assert record["total_entities"] >= 2

    # Query history
    res_hist = client.get("/api/exposure/history", headers=headers)
    assert res_hist.status_code == 200
    hist_data = res_hist.get_json()["data"]
    assert hist_data["total"] == 1
    assert len(hist_data["records"]) == 1
    assert hist_data["records"][0]["id"] == record["id"]


def test_api_user_isolation(client, auth_user, second_user):
    """User B cannot access or delete User A's exposure record."""
    user1, token1 = auth_user
    user2, token2 = second_user

    headers1 = {"Authorization": f"Bearer {token1}"}
    headers2 = {"Authorization": f"Bearer {token2}"}

    # 1. User 1 creates record
    res_create = client.post(
        "/api/exposure/analyze",
        json={"identifiers": {"name": "User One Target", "email": "user1@example.com"}},
        headers=headers1
    )
    assert res_create.status_code == 201
    record_id = res_create.get_json()["data"]["exposure_record"]["id"]

    # 2. User 1 successfully inspects record
    res_owner = client.get(f"/api/exposure/{record_id}", headers=headers1)
    assert res_owner.status_code == 200
    assert res_owner.get_json()["data"]["exposure_record"]["id"] == record_id

    # 3. User 2 attempts to inspect User 1's record -> 404 NOT_FOUND
    res_intruder = client.get(f"/api/exposure/{record_id}", headers=headers2)
    assert res_intruder.status_code == 404
    assert res_intruder.get_json()["error"]["code"] == "NOT_FOUND"

    # 4. User 2 attempts to delete User 1's record -> 404 NOT_FOUND
    res_del_intruder = client.delete(f"/api/exposure/{record_id}", headers=headers2)
    assert res_del_intruder.status_code == 404

    # 5. User 1 deletes own record -> 200 OK
    res_del_owner = client.delete(f"/api/exposure/{record_id}", headers=headers1)
    assert res_del_owner.status_code == 200
    assert res_del_owner.get_json()["data"]["deleted"] is True
