"""
Train Exposure Sensitivity Classifier (Model 2).
Implements TF-IDF vectorization (max_features=5000, ngram_range=(1,2)) fitted EXCLUSIVELY
on train_text, followed by Random Forest classification with class_weight='balanced'.
Persists tfidf_vectorizer.joblib and exposure_classifier.joblib.
"""
import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.dummy import DummyClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score

SEED = 42
DATA_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend/data/synthetic/synthetic_exposures.csv"))
ARTIFACTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend/app/ml/artifacts"))
LABEL_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def train_exposure():
    print("=" * 70)
    print("TRAINING MODEL 2: EXPOSURE SENSITIVITY CLASSIFIER (TF-IDF + RF)")
    print("=" * 70)

    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    df = pd.read_csv(DATA_PATH)
    print(f"Loaded dataset: {len(df)} records from {DATA_PATH}")

    X_text = df["exposure_text"]
    y = df["sensitivity_label"]

    # 1. Stratified 80/20 train/test split
    X_train_text, X_test_text, y_train, y_test = train_test_split(
        X_text, y, test_size=0.20, random_state=SEED, stratify=y
    )
    print(f"Train samples: {len(X_train_text)} | Test samples: {len(X_test_text)}")

    # 2. Baseline Model
    dummy = DummyClassifier(strategy="most_frequent")
    dummy.fit(X_train_text, y_train)
    dummy_preds = dummy.predict(X_test_text)
    dummy_acc = accuracy_score(y_test, dummy_preds)
    dummy_f1_macro = f1_score(y_test, dummy_preds, average="macro", zero_division=0)
    print(f"\n[Baseline] Majority Class Dummy — Accuracy: {dummy_acc*100:.2f}%, Macro F1: {dummy_f1_macro*100:.2f}%")

    # 3. TF-IDF Vectorization: FITTED EXCLUSIVELY ON X_train_text (Zero Leakage)
    print("\n[Preprocessing] Fitting TfidfVectorizer on training fold ONLY...")
    tfidf = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        sublinear_tf=True
    )
    X_train_vec = tfidf.fit_transform(X_train_text)
    X_test_vec = tfidf.transform(X_test_text)
    print(f"TF-IDF vocabulary size: {len(tfidf.vocabulary_)} features")

    # 4. Random Forest Classifier
    print("\n[Training] Random Forest Classifier on TF-IDF features (class_weight='balanced')...")
    rf_clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight="balanced",
        random_state=SEED,
        n_jobs=-1
    )
    rf_clf.fit(X_train_vec, y_train)
    rf_preds = rf_clf.predict(X_test_vec)

    acc = accuracy_score(y_test, rf_preds)
    macro_f1 = f1_score(y_test, rf_preds, average="macro")
    weighted_f1 = f1_score(y_test, rf_preds, average="weighted")
    report = classification_report(y_test, rf_preds, labels=LABEL_ORDER, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, rf_preds, labels=LABEL_ORDER).tolist()

    # 5. Save Artifacts
    tfidf_path = os.path.join(ARTIFACTS_DIR, "tfidf_vectorizer.joblib")
    clf_path = os.path.join(ARTIFACTS_DIR, "exposure_classifier.joblib")
    joblib.dump(tfidf, tfidf_path)
    joblib.dump(rf_clf, clf_path)
    print(f" -> Saved vectorizer to: {tfidf_path}")
    print(f" -> Saved classifier to: {clf_path}")
    print(f" -> Measured Accuracy: {acc*100:.2f}% | Macro F1: {macro_f1*100:.2f}% | Weighted F1: {weighted_f1*100:.2f}%")

    print("\nConfusion Matrix (Actual vs Predicted):")
    print(f"Labels: {LABEL_ORDER}")
    for idx, row in enumerate(cm):
        print(f"  {LABEL_ORDER[idx]:8s}: {row}")

    results = {
        "dataset_size": len(df),
        "train_size": len(X_train_text),
        "test_size": len(X_test_text),
        "vocabulary_size": len(tfidf.vocabulary_),
        "labels": LABEL_ORDER,
        "baseline_dummy": {
            "strategy": "most_frequent",
            "accuracy": round(float(dummy_acc), 4),
            "macro_f1": round(float(dummy_f1_macro), 4)
        },
        "random_forest": {
            "parameters": {
                "max_features": 5000,
                "ngram_range": [1, 2],
                "n_estimators": 100,
                "max_depth": 20,
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
    res = train_exposure()
