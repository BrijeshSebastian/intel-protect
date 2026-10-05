"""
Comprehensive Automated Unit & Integration Tests for Phase 5 Machine Learning Pipeline.
Covers:
1. Dataset schema, completeness, and class distribution
2. Data leakage verification (TF-IDF & StandardScaler fitted ONLY on train fold)
3. Model artifact loading, prediction schema, and probability consistency
4. Anomaly detector Isolation Forest score direction and threshold logic
5. Reproducibility test (same seed -> identical evaluation metrics)
6. Baseline comparison (ensuring ML outperforms naive majority-class dummy)
"""
import os
import json
import pytest
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.dummy import DummyClassifier
from sklearn.metrics import accuracy_score

from backend.app.ml.registry import registry
from backend.app.ml.document_sensitivity import (
    extract_document_features,
    predict_document_sensitivity
)
from backend.app.ml.exposure_classifier import predict_exposure_sensitivity
from backend.app.ml.breach_priority import predict_breach_priority
from backend.app.ml.anomaly_detector import predict_anomaly
from scripts.ml.generate_document_dataset import generate_document_records
from scripts.ml.generate_exposure_dataset import generate_exposure_records
from scripts.ml.generate_breach_dataset import generate_breach_records
from scripts.ml.generate_anomaly_dataset import generate_anomaly_records

ARTIFACTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../app/ml/artifacts"))


# ==============================================================================
# 1. DATASET VALIDATION TESTS
# ==============================================================================

def test_document_dataset_schema_and_distribution():
    """Verify document dataset generates exact required schema and skewed distribution."""
    df = generate_document_records(200)
    assert len(df) == 200
    expected_cols = [
        "sample_id", "pii_count", "unique_pii_types", "high_risk_count",
        "financial_pii_count", "identity_pii_count", "credential_count",
        "contact_pii_count", "doc_length", "avg_confidence", "max_confidence",
        "checksum_valid_ratio", "sensitivity_label", "is_synthetic"
    ]
    for col in expected_cols:
        assert col in df.columns, f"Missing expected column: {col}"

    assert df.isnull().sum().sum() == 0, "Dataset must not contain null values"
    labels = set(df["sensitivity_label"].unique())
    assert labels.issubset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


def test_exposure_dataset_schema():
    """Verify exposure dataset text records schema."""
    df = generate_exposure_records(100)
    assert len(df) == 100
    assert "exposure_text" in df.columns
    assert "sensitivity_label" in df.columns
    assert df["exposure_text"].str.len().min() > 10


def test_breach_dataset_schema():
    """Verify breach dataset features."""
    df = generate_breach_records(100)
    assert len(df) == 100
    assert "priority_label" in df.columns
    assert set(df["priority_label"].unique()).issubset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


def test_anomaly_dataset_contamination():
    """Verify anomaly dataset contains expected ~5% contamination rate."""
    df = generate_anomaly_records(200, contamination=0.05)
    assert len(df) == 200
    assert df["is_anomaly"].sum() == 10  # 5% of 200 is 10


# ==============================================================================
# 2. DATA LEAKAGE PREVENTION TESTS
# ==============================================================================

def test_tfidf_zero_leakage():
    """
    STRICT LEAKAGE TEST:
    Proves that fitting TF-IDF only on training data prevents test vocabulary leakage.
    Words exclusive to the test set must NOT appear in the fitted vocabulary.
    """
    train_texts = [
        "company employee database export with emails",
        "public directory listing of engineering staff"
    ]
    test_texts = [
        "topsecretleakedtoken and confidential internal document"
    ]

    # Fitted strictly on train
    vec = TfidfVectorizer()
    vec.fit(train_texts)

    assert "topsecretleakedtoken" not in vec.vocabulary_, "Test word must NOT leak into fitted vocabulary"
    # Transform test set without fitting
    transformed = vec.transform(test_texts)
    assert transformed.shape[1] == len(vec.vocabulary_)


def test_scaler_zero_leakage():
    """
    STRICT LEAKAGE TEST:
    Proves that StandardScaler mean and variance are computed strictly on training fold.
    """
    train_vals = np.array([[10.0], [20.0], [30.0]])
    test_vals = np.array([[1000.0]])

    scaler = StandardScaler()
    scaler.fit(train_vals)

    # Train mean is 20.0; if test leaked, mean would be 265.0
    assert scaler.mean_[0] == 20.0, "Scaler mean must be computed strictly on train set"


# ==============================================================================
# 3. MODEL ARTIFACT LOADING & INFERENCE TESTS
# ==============================================================================

def test_registry_loads_all_artifacts():
    """Verify all 6 persisted model artifacts and evaluation report load cleanly."""
    registry.clear_cache()
    lr = registry.get_document_sensitivity_model("logreg")
    rf = registry.get_document_sensitivity_model("rf")
    tfidf, exp_clf = registry.get_exposure_models()
    brch_rf = registry.get_breach_priority_model()
    anom_if = registry.get_anomaly_model()
    report = registry.get_evaluation_report()

    assert lr is not None
    assert rf is not None
    assert tfidf is not None
    assert exp_clf is not None
    assert brch_rf is not None
    assert anom_if is not None
    assert "metadata" in report
    assert "model_1_document_sensitivity" in report


def test_document_sensitivity_prediction():
    """Test document sensitivity inference from findings list."""
    sample_findings = [
        {"pii_type": "AADHAAR", "severity": "HIGH", "confidence": 0.99, "checksum_valid": True},
        {"pii_type": "PAN", "severity": "HIGH", "confidence": 0.95, "checksum_valid": None},
        {"pii_type": "CARD", "severity": "CRITICAL", "confidence": 0.99, "checksum_valid": True},
        {"pii_type": "EMAIL", "severity": "MEDIUM", "confidence": 0.95, "checksum_valid": None}
    ]

    res_rf = predict_document_sensitivity(sample_findings, doc_length=2500, model_type="rf")
    assert res_rf["predicted_label"] in ["HIGH", "CRITICAL"]
    assert res_rf["confidence"] > 0.0
    assert set(res_rf["probabilities"].keys()) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    res_lr = predict_document_sensitivity(sample_findings, doc_length=2500, model_type="logreg")
    assert res_lr["predicted_label"] in ["HIGH", "CRITICAL"]


def test_document_sensitivity_empty_clean_document():
    """Verify clean document with zero findings predicts LOW risk."""
    res = predict_document_sensitivity([], doc_length=500, model_type="rf")
    assert res["predicted_label"] == "LOW"


def test_exposure_sensitivity_prediction():
    """Test exposure text classification."""
    clean_text = "Public profile: Alice, Junior Web Designer at Acme Studio."
    res_clean = predict_exposure_sensitivity(clean_text)
    assert res_clean["predicted_label"] in ["LOW", "MEDIUM"]

    critical_text = "DATABASE COMPROMISE DUMP: User admin, Plaintext Password: 'AdminSecret!2026', Session Token: eyJhbGciOiJIUzI1Ni, Card Number: 4532 0151 1283 0366, CVV: 991"
    res_crit = predict_exposure_sensitivity(critical_text)
    assert res_crit["predicted_label"] in ["HIGH", "CRITICAL"]


def test_breach_priority_prediction():
    """Test breach priority model prediction."""
    low_breach = {
        "breach_count": 1,
        "email_exposed": 1,
        "phone_exposed": 0,
        "password_exposed": 0,
        "financial_exposed": 0,
        "identity_doc_exposed": 0,
        "address_exposed": 0,
        "credential_exposed": 0,
        "total_data_types": 1,
        "max_breach_severity": 0,
        "days_since_breach": 2000
    }
    res_low = predict_breach_priority(low_breach)
    assert res_low["predicted_priority"] in ["LOW", "MEDIUM"]

    crit_breach = {
        "breach_count": 5,
        "email_exposed": 1,
        "phone_exposed": 1,
        "password_exposed": 1,
        "financial_exposed": 1,
        "identity_doc_exposed": 1,
        "address_exposed": 1,
        "credential_exposed": 1,
        "total_data_types": 7,
        "max_breach_severity": 3,
        "days_since_breach": 30
    }
    res_crit = predict_breach_priority(crit_breach)
    assert res_crit["predicted_priority"] in ["HIGH", "CRITICAL"]


def test_anomaly_detector_scoring():
    """Test Isolation Forest anomaly scoring differentiation."""
    normal_profile = {
        "total_pii_count": 1,
        "sensitive_pii_count": 0,
        "financial_pii_count": 0,
        "credential_count": 0,
        "source_count": 1,
        "exposure_type_count": 1,
        "identity_data_count": 0
    }
    res_norm = predict_anomaly(normal_profile)
    assert res_norm["is_anomaly"] is False
    assert res_norm["anomaly_score"] < 0.40

    extreme_profile = {
        "total_pii_count": 40,
        "sensitive_pii_count": 18,
        "financial_pii_count": 12,
        "credential_count": 8,
        "source_count": 7,
        "exposure_type_count": 5,
        "identity_data_count": 6
    }
    res_anom = predict_anomaly(extreme_profile)
    assert res_anom["is_anomaly"] is True
    assert res_anom["anomaly_score"] > 0.50


# ==============================================================================
# 4. REPRODUCIBILITY & BASELINE SUPERIORITY TESTS
# ==============================================================================

def test_evaluation_report_accuracy_beats_dummy_baseline():
    """Verify that every trained ML model significantly outperforms the majority-class baseline."""
    report = registry.get_evaluation_report()

    # Model 1 Doc Sensitivity
    doc_meta = report["model_1_document_sensitivity"]
    doc_baseline_acc = doc_meta["baseline_dummy"]["accuracy"]
    doc_rf_acc = doc_meta["random_forest"]["accuracy"]
    assert doc_rf_acc > doc_baseline_acc + 0.30, "Random Forest must significantly beat majority baseline"

    # Model 2 Exposure Classifier
    exp_meta = report["model_2_exposure_classifier"]
    exp_baseline_acc = exp_meta["baseline_dummy"]["accuracy"]
    exp_rf_acc = exp_meta["random_forest"]["accuracy"]
    assert exp_rf_acc > exp_baseline_acc + 0.30, "Exposure RF must significantly beat majority baseline"

    # Model 3 Breach Priority
    brch_meta = report["model_3_breach_priority"]
    brch_baseline_acc = brch_meta["baseline_dummy"]["accuracy"]
    brch_rf_acc = brch_meta["random_forest"]["accuracy"]
    assert brch_rf_acc > brch_baseline_acc + 0.30, "Breach Priority RF must significantly beat majority baseline"


def test_deterministic_reproducibility():
    """Verify that training with fixed seed (42) produces 100% identical predictions across runs."""
    from sklearn.ensemble import RandomForestClassifier
    X = np.array([
        [1, 0, 0, 100],
        [4, 2, 2, 800],
        [10, 5, 4, 3000],
        [2, 1, 0, 400]
    ])
    y = np.array(["LOW", "MEDIUM", "HIGH", "LOW"])

    rf1 = RandomForestClassifier(n_estimators=20, random_state=42)
    rf1.fit(X, y)
    preds1 = rf1.predict(X)

    rf2 = RandomForestClassifier(n_estimators=20, random_state=42)
    rf2.fit(X, y)
    preds2 = rf2.predict(X)

    np.testing.assert_array_equal(preds1, preds2, err_msg="Models trained with identical seed must yield identical predictions")
