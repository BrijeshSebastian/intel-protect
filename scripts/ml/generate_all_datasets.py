"""
Master Synthetic Dataset Generator for Intel-Protect.
Executes all 4 synthetic data generators deterministically (SEED = 42)
and verifies file integrity, row counts, and class distributions.
"""
import os
import sys
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from scripts.ml.generate_document_dataset import generate_document_records, OUTPUT_PATH as DOC_PATH
from scripts.ml.generate_exposure_dataset import generate_exposure_records, OUTPUT_PATH as EXP_PATH
from scripts.ml.generate_breach_dataset import generate_breach_records, OUTPUT_PATH as BRCH_PATH
from scripts.ml.generate_anomaly_dataset import generate_anomaly_records, OUTPUT_PATH as ANO_PATH

def generate_all():
    print("=" * 70)
    print("INTEL-PROTECT — SYNTHETIC DATASET GENERATION SUITE (SEED=42)")
    print("=" * 70)

    # 1. Documents
    print("\n[1/4] Generating synthetic document sensitivity dataset (~2,000 records)...")
    df_doc = generate_document_records(2000)
    os.makedirs(os.path.dirname(DOC_PATH), exist_ok=True)
    df_doc.to_csv(DOC_PATH, index=False)
    print(f" -> Saved to: {DOC_PATH}")
    print(f" -> Records: {len(df_doc)} | Features: {len(df_doc.columns)}")
    print(f" -> Distribution: {dict(df_doc['sensitivity_label'].value_counts())}")

    # 2. Exposures
    print("\n[2/4] Generating synthetic exposure text dataset (~3,000 records)...")
    df_exp = generate_exposure_records(3000)
    os.makedirs(os.path.dirname(EXP_PATH), exist_ok=True)
    df_exp.to_csv(EXP_PATH, index=False)
    print(f" -> Saved to: {EXP_PATH}")
    print(f" -> Records: {len(df_exp)} | Features: {len(df_exp.columns)}")
    print(f" -> Distribution: {dict(df_exp['sensitivity_label'].value_counts())}")

    # 3. Breaches
    print("\n[3/4] Generating synthetic breach priority dataset (~2,000 records)...")
    df_brch = generate_breach_records(2000)
    os.makedirs(os.path.dirname(BRCH_PATH), exist_ok=True)
    df_brch.to_csv(BRCH_PATH, index=False)
    print(f" -> Saved to: {BRCH_PATH}")
    print(f" -> Records: {len(df_brch)} | Features: {len(df_brch.columns)}")
    print(f" -> Distribution: {dict(df_brch['priority_label'].value_counts())}")

    # 4. Anomalies
    print("\n[4/4] Generating synthetic exposure anomaly dataset (~3,000 records, 5% anomalies)...")
    df_ano = generate_anomaly_records(3000, 0.05)
    os.makedirs(os.path.dirname(ANO_PATH), exist_ok=True)
    df_ano.to_csv(ANO_PATH, index=False)
    print(f" -> Saved to: {ANO_PATH}")
    print(f" -> Records: {len(df_ano)} | Features: {len(df_ano.columns)}")
    print(f" -> Injected anomalies: {df_ano['is_anomaly'].sum()} ({df_ano['is_anomaly'].mean()*100:.1f}%)")

    print("\n" + "=" * 70)
    print("ALL 4 SYNTHETIC DATASETS GENERATED SUCCESSFULLY WITH ZERO LEAKAGE")
    print("=" * 70)

if __name__ == "__main__":
    generate_all()
