"""
Synthetic Exposure Anomaly Dataset Generator.
Generates ~3,000 exposure feature vectors for Isolation Forest training and validation,
containing ~5% (150 records) realistically injected high-volume / high-severity identity compromise anomalies.
Seed: 42 (reproducible).
"""
import os
import random
import numpy as np
import pandas as pd

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

OUTPUT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend/data/synthetic/synthetic_exposure_anomalies.csv"))

def generate_anomaly_records(n_samples: int = 3000, contamination: float = 0.05) -> pd.DataFrame:
    n_anomalies = int(n_samples * contamination)
    n_normal = n_samples - n_anomalies

    records = []
    sample_id = 1

    # 1. Normal instances (95%)
    for _ in range(n_normal):
        # Routine exposure profiles: low count, single or few sources, minimal credentials
        total_pii = int(np.random.choice([0, 1, 2, 3, 4], p=[0.25, 0.35, 0.25, 0.10, 0.05]))
        sens_pii = int(np.random.choice([0, 1], p=[0.85, 0.15])) if total_pii > 0 else 0
        fin_pii = int(np.random.choice([0, 1], p=[0.90, 0.10])) if total_pii > 0 else 0
        cred_pii = int(np.random.choice([0, 1], p=[0.92, 0.08])) if total_pii > 0 else 0
        sources = int(np.random.choice([1, 2], p=[0.80, 0.20])) if total_pii > 0 else 0
        exp_types = int(np.random.choice([1, 2], p=[0.75, 0.25])) if total_pii > 0 else 0
        id_data = int(np.random.choice([0, 1], p=[0.90, 0.10])) if total_pii > 0 else 0

        records.append({
            "sample_id": f"ANO_{sample_id:05d}",
            "total_pii_count": total_pii,
            "sensitive_pii_count": sens_pii,
            "financial_pii_count": fin_pii,
            "credential_count": cred_pii,
            "source_count": sources,
            "exposure_type_count": exp_types,
            "identity_data_count": id_data,
            "is_anomaly": 0,  # Normal ground truth
            "is_synthetic": True
        })
        sample_id += 1

    # 2. Injected Anomalies (~5%)
    for _ in range(n_anomalies):
        # Outlier exposure profiles: massive PII dump, many sources, multiple credentials and financial assets
        total_pii = int(np.random.uniform(12, 45))
        sens_pii = int(np.random.uniform(6, 20))
        fin_pii = int(np.random.uniform(3, 14))
        cred_pii = int(np.random.uniform(2, 9))
        sources = int(np.random.uniform(3, 8))
        exp_types = int(np.random.uniform(3, 6))
        id_data = int(np.random.uniform(2, 7))

        records.append({
            "sample_id": f"ANO_{sample_id:05d}",
            "total_pii_count": total_pii,
            "sensitive_pii_count": sens_pii,
            "financial_pii_count": fin_pii,
            "credential_count": cred_pii,
            "source_count": sources,
            "exposure_type_count": exp_types,
            "identity_data_count": id_data,
            "is_anomaly": 1,  # Ground truth anomaly
            "is_synthetic": True
        })
        sample_id += 1

    df = pd.DataFrame(records)
    df = df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)
    return df

if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df_ano = generate_anomaly_records(3000, 0.05)
    df_ano.to_csv(OUTPUT_PATH, index=False)
    print(f"Generated {len(df_ano)} synthetic exposure anomaly records saved to:\n  {OUTPUT_PATH}")
    print("\nAnomaly Distribution:")
    print(df_ano["is_anomaly"].value_counts(normalize=True))
