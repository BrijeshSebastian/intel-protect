"""
Train Breach Priority Model (Model 3).
Implements Random Forest classifier on 11 breach observation features
with strict 80/20 stratified split, class_weight='balanced', and honest metric reporting.
Persists breach_priority_rf.joblib.
"""
import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.dummy import DummyClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score

SEED = 42
DATA_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend/data/synthetic/synthetic_breaches.csv"))
ARTIFACTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend/app/ml/artifacts"))

FEATURE_COLS = [
    "breach_count",
    "email_exposed",
    "phone_exposed",
    "password_exposed",
    "financial_exposed",
    "identity_doc_exposed",
    "address_exposed",
    "credential_exposed",
    "total_data_types",
    "max_breach_severity",
    "days_since_breach"
]
TARGET_COL = "priority_label"
LABEL_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def train_breach_priority():
    print("=" * 70)
    print("TRAINING MODEL 3: BREACH PRIORITY MODEL (RANDOM FOREST)")
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

    # 2. Baseline Model: Majority Class Dummy
    dummy = DummyClassifier(strategy="most_frequent")
    dummy.fit(X_train, y_train)
    dummy_preds = dummy.predict(X_test)
    dummy_acc = accuracy_score(y_test, dummy_preds)
    dummy_f1_macro = f1_score(y_test, dummy_preds, average="macro", zero_division=0)
    print(f"\n[Baseline] Majority Class Dummy — Accuracy: {dummy_acc*100:.2f}%, Macro F1: {dummy_f1_macro*100:.2f}%")

    # 3. Random Forest Priority Model
    print("\n[Training] Random Forest Priority Classifier (n_estimators=100, class_weight='balanced')...")
    rf_clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight="balanced",
        random_state=SEED,
        n_jobs=-1
    )
    rf_clf.fit(X_train, y_train)
    rf_preds = rf_clf.predict(X_test)

    acc = accuracy_score(y_test, rf_preds)
    macro_f1 = f1_score(y_test, rf_preds, average="macro")
    weighted_f1 = f1_score(y_test, rf_preds, average="weighted")
    report = classification_report(y_test, rf_preds, labels=LABEL_ORDER, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, rf_preds, labels=LABEL_ORDER).tolist()

    # 4. Save Artifact
    artifact_path = os.path.join(ARTIFACTS_DIR, "breach_priority_rf.joblib")
    joblib.dump(rf_clf, artifact_path)
    print(f" -> Saved artifact to: {artifact_path}")
    print(f" -> Measured Accuracy: {acc*100:.2f}% | Macro F1: {macro_f1*100:.2f}% | Weighted F1: {weighted_f1*100:.2f}%")

    print("\nConfusion Matrix (Actual vs Predicted):")
    print(f"Labels: {LABEL_ORDER}")
    for idx, row in enumerate(cm):
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
        "random_forest": {
            "parameters": {
                "n_estimators": 100,
                "max_depth": 10,
                "class_weight": "balanced",
                "random_state": SEED
            },
            "accuracy": round(float(acc), 4),
            "macro_f1": round(float(macro_f1), 4),
            "weighted_f1": round(float(weighted_f1), 4),
            "classification_report": report,
            "confusion_matrix": cm
        }
    }
    return results

if __name__ == "__main__":
    res = train_breach_priority()
