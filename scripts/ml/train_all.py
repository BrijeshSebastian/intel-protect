"""
Master Training and Evaluation Pipeline for Intel-Protect ML Models.
Executes all 4 model training scripts, validates artifacts, compiles
a comprehensive evaluation report, and saves to evaluation_report.json.
"""
import os
import sys
import json
import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from scripts.ml.train_document_sensitivity import train_document_sensitivity
from scripts.ml.train_exposure import train_exposure
from scripts.ml.train_breach_priority import train_breach_priority
from scripts.ml.train_anomaly_detector import train_anomaly_detector

REPORT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend/app/ml/artifacts/evaluation_report.json"))

def train_all_models():
    print("=" * 80)
    print("INTEL-PROTECT — MASTER MACHINE LEARNING TRAINING & EVALUATION PIPELINE")
    print("=" * 80)

    # 1. Document Sensitivity
    doc_res = train_document_sensitivity()

    # 2. Exposure Sensitivity
    exp_res = train_exposure()

    # 3. Breach Priority
    brch_res = train_breach_priority()

    # 4. Anomaly Detection
    ano_res = train_anomaly_detector()

    # Aggregate Master Report
    master_report = {
        "metadata": {
            "project": "Intel-Protect",
            "phase": "Phase 5 — Machine Learning Foundation & Model Training",
            "training_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "random_seed": 42,
            "synthetic_data_disclaimer": "All models are trained exclusively on locally generated synthetic data. Metrics represent evaluation on held-out synthetic test splits and do not establish real-world performance."
        },
        "model_1_document_sensitivity": doc_res,
        "model_2_exposure_classifier": exp_res,
        "model_3_breach_priority": brch_res,
        "model_4_anomaly_detector": ano_res
    }

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(master_report, f, indent=2)

    print("\n" + "=" * 80)
    print(f"MASTER EVALUATION REPORT SAVED TO:\n  {REPORT_PATH}")
    print("=" * 80)

    # Print Comparative Summary Table
    print("\n" + "-" * 80)
    print("SUMMARY OF MEASURED MODEL PERFORMANCE (HELD-OUT TEST SETS)")
    print("-" * 80)
    print(f"{'Model Name':<35} | {'Algorithm':<22} | {'Accuracy':<10} | {'Macro F1':<10} | {'Baseline Acc':<12}")
    print("-" * 80)

    # Doc - LR
    lr_acc = f"{doc_res['logistic_regression']['accuracy']*100:.2f}%"
    lr_f1 = f"{doc_res['logistic_regression']['macro_f1']*100:.2f}%"
    dummy_doc = f"{doc_res['baseline_dummy']['accuracy']*100:.2f}%"
    print(f"{'1. Doc Sensitivity (Baseline)':<35} | {'Logistic Regression':<22} | {lr_acc:<10} | {lr_f1:<10} | {dummy_doc:<12}")

    # Doc - RF
    rf_acc = f"{doc_res['random_forest']['accuracy']*100:.2f}%"
    rf_f1 = f"{doc_res['random_forest']['macro_f1']*100:.2f}%"
    print(f"{'1. Doc Sensitivity (Primary)':<35} | {'Random Forest':<22} | {rf_acc:<10} | {rf_f1:<10} | {dummy_doc:<12}")

    # Exposure - RF
    exp_acc = f"{exp_res['random_forest']['accuracy']*100:.2f}%"
    exp_f1 = f"{exp_res['random_forest']['macro_f1']*100:.2f}%"
    dummy_exp = f"{exp_res['baseline_dummy']['accuracy']*100:.2f}%"
    print(f"{'2. Exposure Sensitivity':<35} | {'TF-IDF + Random Forest':<22} | {exp_acc:<10} | {exp_f1:<10} | {dummy_exp:<12}")

    # Breach - RF
    brch_acc = f"{brch_res['random_forest']['accuracy']*100:.2f}%"
    brch_f1 = f"{brch_res['random_forest']['macro_f1']*100:.2f}%"
    dummy_brch = f"{brch_res['baseline_dummy']['accuracy']*100:.2f}%"
    print(f"{'3. Breach Priority':<35} | {'Random Forest':<22} | {brch_acc:<10} | {brch_f1:<10} | {dummy_brch:<12}")

    # Anomaly
    ano_rec = f"Recall={ano_res['metrics']['recall']*100:.1f}%"
    ano_f1 = f"F1={ano_res['metrics']['f1']*100:.2f}%"
    ano_fpr = f"FPR={ano_res['metrics']['false_positive_rate']*100:.2f}%"
    print(f"{'4. Exposure Anomaly Detector':<35} | {'Isolation Forest':<22} | {ano_rec:<10} | {ano_f1:<10} | {ano_fpr:<12}")
    print("-" * 80)

if __name__ == "__main__":
    train_all_models()
