"""
Synthetic Document Sensitivity Dataset Generator.
Generates ~2,000 synthetic document feature vectors modeling realistic PII distributions
and operational class skew (40% LOW, 30% MEDIUM, 20% HIGH, 10% CRITICAL).
Seed: 42 (reproducible).
"""
import os
import random
import numpy as np
import pandas as pd

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

OUTPUT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend/data/synthetic/synthetic_documents.csv"))

def generate_document_records(n_samples: int = 2000) -> pd.DataFrame:
    # Target class distribution: LOW (40%), MEDIUM (30%), HIGH (20%), CRITICAL (10%)
    class_targets = [
        ("LOW", int(n_samples * 0.40)),
        ("MEDIUM", int(n_samples * 0.30)),
        ("HIGH", int(n_samples * 0.20)),
        ("CRITICAL", n_samples - int(n_samples * 0.40) - int(n_samples * 0.30) - int(n_samples * 0.20))
    ]

    records = []
    sample_id = 1

    for label, count in class_targets:
        for _ in range(count):
            if label == "LOW":
                # Routine public/low-risk documents (e.g. public notices, clean letters, basic contact emails)
                contact_count = np.random.choice([0, 1, 2], p=[0.4, 0.4, 0.2])
                identity_count = 0
                financial_count = 0
                credential_count = 0
                high_risk = 0
                doc_len = int(np.random.gamma(shape=3.0, scale=300.0) + 150)
                
                pii_count = contact_count
                unique_types = 1 if contact_count > 0 else 0
                checksum_ratio = 1.0 if pii_count == 0 else 0.0
                avg_conf = np.random.uniform(0.85, 0.95) if pii_count > 0 else 0.0
                max_conf = avg_conf

            elif label == "MEDIUM":
                # Moderate risk documents (e.g. employee invoices, tax filings with single PAN, bank transaction receipts)
                contact_count = np.random.choice([1, 2, 3], p=[0.3, 0.5, 0.2])
                # Usually 1 identity PII or 1 bank account
                identity_count = np.random.choice([0, 1], p=[0.3, 0.7])
                financial_count = 1 if identity_count == 0 else np.random.choice([0, 1], p=[0.7, 0.3])
                credential_count = 0
                high_risk = identity_count + financial_count
                doc_len = int(np.random.gamma(shape=4.0, scale=400.0) + 400)
                
                pii_count = contact_count + identity_count + financial_count
                types = set()
                if contact_count > 0: types.add("CONTACT")
                if identity_count > 0: types.add("IDENTITY")
                if financial_count > 0: types.add("FINANCIAL")
                unique_types = len(types)
                checksum_ratio = 1.0 if (identity_count + financial_count) > 0 else 0.0
                avg_conf = np.random.uniform(0.88, 0.96)
                max_conf = max(avg_conf, np.random.uniform(0.92, 0.99))

            elif label == "HIGH":
                # High sensitivity documents (e.g. loan applications, complete bank statements, verified Aadhaar + PAN)
                contact_count = np.random.choice([1, 2, 3, 4], p=[0.2, 0.4, 0.3, 0.1])
                identity_count = np.random.choice([1, 2], p=[0.4, 0.6])
                financial_count = np.random.choice([1, 2, 3], p=[0.4, 0.4, 0.2])
                credential_count = np.random.choice([0, 1], p=[0.8, 0.2])
                high_risk = identity_count + financial_count + credential_count
                doc_len = int(np.random.gamma(shape=5.0, scale=600.0) + 800)
                
                pii_count = contact_count + identity_count + financial_count + credential_count
                types = {"CONTACT", "IDENTITY", "FINANCIAL"}
                if credential_count > 0: types.add("CREDENTIAL")
                unique_types = len(types)
                checksum_ratio = np.random.uniform(0.85, 1.0)
                avg_conf = np.random.uniform(0.92, 0.98)
                max_conf = np.random.uniform(0.96, 0.99)

            else:  # CRITICAL
                # Critical sensitivity documents (e.g. compromised identity dossiers, card lists, credentials + identity)
                contact_count = np.random.choice([2, 3, 4, 5], p=[0.2, 0.4, 0.3, 0.1])
                identity_count = np.random.choice([2, 3, 4], p=[0.4, 0.4, 0.2])
                financial_count = np.random.choice([2, 3, 4, 5], p=[0.3, 0.4, 0.2, 0.1])
                credential_count = np.random.choice([1, 2, 3], p=[0.5, 0.3, 0.2])
                high_risk = identity_count + financial_count + credential_count
                doc_len = int(np.random.gamma(shape=6.0, scale=800.0) + 1200)
                
                pii_count = contact_count + identity_count + financial_count + credential_count
                types = {"CONTACT", "IDENTITY", "FINANCIAL", "CREDENTIAL"}
                unique_types = len(types) + np.random.choice([0, 1], p=[0.6, 0.4])
                checksum_ratio = np.random.uniform(0.90, 1.0)
                avg_conf = np.random.uniform(0.95, 0.99)
                max_conf = 0.99

            # Realistic boundary noise: 10% chance of transition between adjacent classes
            assigned_label = label
            if np.random.rand() < 0.10:
                transitions = {
                    "LOW": "MEDIUM",
                    "MEDIUM": np.random.choice(["LOW", "HIGH"]),
                    "HIGH": np.random.choice(["MEDIUM", "CRITICAL"]),
                    "CRITICAL": "HIGH"
                }
                assigned_label = transitions[label]

            records.append({
                "sample_id": f"DOC_{sample_id:04d}",
                "pii_count": int(pii_count),
                "unique_pii_types": int(unique_types),
                "high_risk_count": int(high_risk),
                "financial_pii_count": int(financial_count),
                "identity_pii_count": int(identity_count),
                "credential_count": int(credential_count),
                "contact_pii_count": int(contact_count),
                "doc_length": int(doc_len),
                "avg_confidence": round(float(avg_conf), 4),
                "max_confidence": round(float(max_conf), 4),
                "checksum_valid_ratio": round(float(checksum_ratio), 4),
                "sensitivity_label": assigned_label,
                "is_synthetic": True
            })
            sample_id += 1

    df = pd.DataFrame(records)
    # Shuffle deterministically
    df = df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)
    return df

if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df_docs = generate_document_records(2000)
    df_docs.to_csv(OUTPUT_PATH, index=False)
    print(f"Generated {len(df_docs)} synthetic document records saved to:\n  {OUTPUT_PATH}")
    print("\nClass Distribution:")
    print(df_docs["sensitivity_label"].value_value_counts() if hasattr(df_docs["sensitivity_label"], "value_value_counts") else df_docs["sensitivity_label"].value_counts())
    print("\nFeatures Summary:")
    print(df_docs.describe().T[["mean", "std", "min", "max"]])
