"""
Train Document Sensitivity Classifiers (Model 1).
Implements both Logistic Regression (baseline) and Random Forest (primary)
with strict 80/20 stratified split, StandardScaler fitted exclusively on X_train,
class_weight='balanced', and honest metric evaluation against a Majority-Class Dummy baseline.
"""
import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.dummy import DummyClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score

SEED = 42
DATA_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend/data/synthetic/synthetic_documents.csv"))
ARTIFACTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend/app/ml/artifacts"))

FEATURE_COLS = [
    "pii_count",
    "unique_pii_types",
    "high_risk_count",
    "financial_pii_count",
    "identity_pii_count",
    "credential_count",
    "contact_pii_count",
    "doc_length",
    "avg_confidence",
    "max_confidence",
    "checksum_valid_ratio"
]
TARGET_COL = "sensitivity_label"
LABEL_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def train_document_sensitivity():
    print("=" * 70)
    print("TRAINING MODEL 1: DOCUMENT SENSITIVITY CLASSIFIER")
    print("=" * 70)

    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    df = pd.read_csv(DATA_PATH)
    print(f"Loaded dataset: {len(df)} records from {DATA_PATH}")

    X = df[FEATURE_COLS]
    y = df[TARGET_COL]

    # 1. Stratified 80/20 train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=SEED, stratify=y
    )
    print(f"Train samples: {len(X_train)} | Test samples: {len(X_test)}")
    print(f"Train class distribution:\n{y_train.value_counts(normalize=True).round(3).to_dict()}")

    # 2. Baseline Model: Majority Class
    dummy = DummyClassifier(strategy="most_frequent")
    dummy.fit(X_train, y_train)
    dummy_preds = dummy.predict(X_test)
    dummy_acc = accuracy_score(y_test, dummy_preds)
    dummy_f1_macro = f1_score(y_test, dummy_preds, average="macro", zero_division=0)
    print(f"\n[Baseline] Majority Class Dummy — Accuracy: {dummy_acc*100:.2f}%, Macro F1: {dummy_f1_macro*100:.2f}%")

    # 3. Model 1A: Logistic Regression (Pipeline with StandardScaler fitted ONLY on train)
    print("\n[Training 1A] Logistic Regression with StandardScaler...")
    pipe_lr = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=1000, random_state=SEED))
    ])
    pipe_lr.fit(X_train, y_train)
    lr_preds = pipe_lr.predict(X_test)

    lr_acc = accuracy_score(y_test, lr_preds)
    lr_macro_f1 = f1_score(y_test, lr_preds, average="macro")
    lr_weighted_f1 = f1_score(y_test, lr_preds, average="weighted")
    lr_report = classification_report(y_test, lr_preds, labels=LABEL_ORDER, output_dict=True, zero_division=0)
    lr_cm = confusion_matrix(y_test, lr_preds, labels=LABEL_ORDER).tolist()

    lr_artifact_path = os.path.join(ARTIFACTS_DIR, "sensitivity_logreg.joblib")
    joblib.dump(pipe_lr, lr_artifact_path)
    print(f" -> Saved to: {lr_artifact_path}")
    print(f" -> Accuracy: {lr_acc*100:.2f}% | Macro F1: {lr_macro_f1*100:.2f}% | Weighted F1: {lr_weighted_f1*100:.2f}%")

    # 4. Model 1B: Random Forest Classifier
    print("\n[Training 1B] Random Forest Classifier (n_estimators=100, balanced weights)...")
    rf_clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        class_weight="balanced",
        random_state=SEED,
        n_jobs=-1
    )
    rf_clf.fit(X_train, y_train)
    rf_preds = rf_clf.predict(X_test)

    rf_acc = accuracy_score(y_test, rf_preds)
    rf_macro_f1 = f1_score(y_test, rf_preds, average="macro")
    rf_weighted_f1 = f1_score(y_test, rf_preds, average="weighted")
    rf_report = classification_report(y_test, rf_preds, labels=LABEL_ORDER, output_dict=True, zero_division=0)
    rf_cm = confusion_matrix(y_test, rf_preds, labels=LABEL_ORDER).tolist()

    rf_artifact_path = os.path.join(ARTIFACTS_DIR, "sensitivity_rf.joblib")
    joblib.dump(rf_clf, rf_artifact_path)
    print(f" -> Saved to: {rf_artifact_path}")
    print(f" -> Accuracy: {rf_acc*100:.2f}% | Macro F1: {rf_macro_f1*100:.2f}% | Weighted F1: {rf_weighted_f1*100:.2f}%")

    # Print Confusion Matrix
    print("\nRandom Forest Confusion Matrix (Actual vs Predicted):")
    print(f"Labels: {LABEL_ORDER}")
    for idx, row in enumerate(rf_cm):
        print(f"  {LABEL_ORDER[idx]:8s}: {row}")

    results = {
        "dataset_size": len(df),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "features": FEATURE_COLS,
        "labels": LABEL_ORDER,
        "baseline_dummy": {
            "strategy": "most_frequent",
            "accuracy": round(float(dummy_acc), 4),
            "macro_f1": round(float(dummy_f1_macro), 4)
        },
        "logistic_regression": {
            "parameters": {"class_weight": "balanced", "max_iter": 1000, "random_state": SEED},
            "accuracy": round(float(lr_acc), 4),
            "macro_f1": round(float(lr_macro_f1), 4),
            "weighted_f1": round(float(lr_weighted_f1), 4),
            "classification_report": lr_report,
            "confusion_matrix": lr_cm
        },
        "random_forest": {
            "parameters": {"n_estimators": 100, "max_depth": 12, "class_weight": "balanced", "random_state": SEED},
            "accuracy": round(float(rf_acc), 4),
            "macro_f1": round(float(rf_macro_f1), 4),
            "weighted_f1": round(float(rf_weighted_f1), 4),
            "classification_report": rf_report,
            "confusion_matrix": rf_cm
        }
    }
    return results

if __name__ == "__main__":
    res = train_document_sensitivity()
