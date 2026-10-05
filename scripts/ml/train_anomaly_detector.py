"""
Train Anomaly Detector (Model 4 — Isolation Forest).
Implements unsupervised Isolation Forest on 7 exposure aggregation features
with contamination=0.05. Evaluates against synthetic injected ground-truth anomalies.
Reports anomaly score distributions, detection rate (recall), false positive rate,
and persists anomaly_iforest.joblib.
"""
import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score

SEED = 42
DATA_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend/data/synthetic/synthetic_exposure_anomalies.csv"))
ARTIFACTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend/app/ml/artifacts"))

FEATURE_COLS = [
    "total_pii_count",
    "sensitive_pii_count",
    "financial_pii_count",
    "credential_count",
    "source_count",
    "exposure_type_count",
    "identity_data_count"
]
TARGET_COL = "is_anomaly"

def train_anomaly_detector():
    print("=" * 70)
    print("TRAINING MODEL 4: ANOMALY DETECTOR (ISOLATION FOREST)")
    print("=" * 70)

    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    df = pd.read_csv(DATA_PATH)
    print(f"Loaded dataset: {len(df)} records from {DATA_PATH}")

    X = df[FEATURE_COLS]
    y = df[TARGET_COL]

    # 1. 80/20 Stratified train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=SEED, stratify=y
    )
    print(f"Train samples: {len(X_train)} (Ground-truth anomalies: {y_train.sum()})")
    print(f"Test samples:  {len(X_test)} (Ground-truth anomalies: {y_test.sum()})")

    # 2. Train Isolation Forest (UNSUPERVISED — features only, y is NOT used for fitting)
    contamination = 0.05
    print(f"\n[Training] Isolation Forest (n_estimators=100, contamination={contamination})...")
    iforest = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=SEED,
        n_jobs=-1
    )
    iforest.fit(X_train)

    # 3. Predict on held-out test data
    # IsolationForest returns -1 for outlier/anomaly, 1 for inlier/normal
    raw_preds = iforest.predict(X_test)
    y_pred_binary = np.where(raw_preds == -1, 1, 0)

    # Decision function: lower values mean more anomalous
    dec_scores = iforest.decision_function(X_test)
    # Normalized anomaly score: 0 (normal) to 1 (highly anomalous)
    # scikit-learn decision_function typically ranges from ~ -0.3 to +0.2
    norm_scores = 1.0 / (1.0 + np.exp(dec_scores * 10))

    # 4. Anomaly Evaluation
    prec = precision_score(y_test, y_pred_binary, zero_division=0)
    rec = recall_score(y_test, y_pred_binary, zero_division=0)
    f1 = f1_score(y_test, y_pred_binary, zero_division=0)

    cm = confusion_matrix(y_test, y_pred_binary).tolist()
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred_binary).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # Score distributions by ground truth class
    norm_scores_normal = norm_scores[y_test == 0]
    norm_scores_anom = norm_scores[y_test == 1]

    # 5. Save Artifact
    artifact_path = os.path.join(ARTIFACTS_DIR, "anomaly_iforest.joblib")
    joblib.dump(iforest, artifact_path)
    print(f" -> Saved artifact to: {artifact_path}")
    print(f"\n[Held-out Test Evaluation]")
    print(f" -> Anomaly Detection Rate (Recall): {rec*100:.2f}% ({tp}/{y_test.sum()})")
    print(f" -> Anomaly Precision:               {prec*100:.2f}%")
    print(f" -> Anomaly F1-Score:                {f1*100:.2f}%")
    print(f" -> False Positive Rate (FPR):       {fpr*100:.2f}% ({fp}/{tn+fp})")
    print(f" -> Normal samples mean score:       {np.mean(norm_scores_normal):.4f}")
    print(f" -> Anomalous samples mean score:    {np.mean(norm_scores_anom):.4f}")

    print("\nConfusion Matrix [[TN, FP], [FN, TP]]:")
    print(f"  Normal    (0): TN={tn}, FP={fp}")
    print(f"  Anomalous (1): FN={fn}, TP={tp}")

    results = {
        "dataset_size": len(df),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "features": FEATURE_COLS,
        "contamination": contamination,
        "ground_truth_test_anomalies": int(y_test.sum()),
        "detected_anomalies": int(y_pred_binary.sum()),
        "metrics": {
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "false_positive_rate": round(float(fpr), 4)
        },
        "score_distribution": {
            "normal_mean": round(float(np.mean(norm_scores_normal)), 4),
            "normal_std": round(float(np.std(norm_scores_normal)), 4),
            "anomaly_mean": round(float(np.mean(norm_scores_anom)), 4),
            "anomaly_std": round(float(np.std(norm_scores_anom)), 4)
        },
        "confusion_matrix": cm
    }
    return results

if __name__ == "__main__":
    res = train_anomaly_detector()
