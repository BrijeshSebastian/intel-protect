"""
Synthetic Breach Priority Dataset Generator.
Generates ~2,000 synthetic breach check result feature vectors
modeling operational class skew (35% LOW, 35% MEDIUM, 20% HIGH, 10% CRITICAL).
Seed: 42 (reproducible).
"""
import os
import random
import numpy as np
import pandas as pd

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

OUTPUT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend/data/synthetic/synthetic_breaches.csv"))

def generate_breach_records(n_samples: int = 2000) -> pd.DataFrame:
    class_targets = [
        ("LOW", int(n_samples * 0.35)),
        ("MEDIUM", int(n_samples * 0.35)),
        ("HIGH", int(n_samples * 0.20)),
        ("CRITICAL", n_samples - int(n_samples * 0.35) - int(n_samples * 0.35) - int(n_samples * 0.20))
    ]

    records = []
    sample_id = 1

    for label, count in class_targets:
        for _ in range(count):
            if label == "LOW":
                # Typically 1 breach (sometimes 0 or 2), non-sensitive fields (only email, or username), older breaches
                breach_count = int(np.random.choice([1, 2], p=[0.75, 0.25]))
                email_exp = 1
                phone_exp = int(np.random.choice([0, 1], p=[0.8, 0.2]))
                pwd_exp = 0
                fin_exp = 0
                id_exp = 0
                addr_exp = int(np.random.choice([0, 1], p=[0.9, 0.1]))
                cred_exp = 0
                max_sev = int(np.random.choice([0, 1], p=[0.7, 0.3]))  # 0=Low, 1=Medium
                days_since = int(np.random.uniform(700, 3200))  # Older breaches (2 to 9 years ago)

            elif label == "MEDIUM":
                # 1-3 breaches, moderate data exposed (email, phone, address, occasionally hashed old password)
                breach_count = int(np.random.choice([1, 2, 3], p=[0.3, 0.5, 0.2]))
                email_exp = 1
                phone_exp = int(np.random.choice([0, 1], p=[0.4, 0.6]))
                pwd_exp = int(np.random.choice([0, 1], p=[0.7, 0.3]))
                fin_exp = 0
                id_exp = int(np.random.choice([0, 1], p=[0.85, 0.15]))
                addr_exp = int(np.random.choice([0, 1], p=[0.5, 0.5]))
                cred_exp = 0
                max_sev = int(np.random.choice([1, 2], p=[0.6, 0.4]))  # 1=Medium, 2=High
                days_since = int(np.random.uniform(365, 2000))

            elif label == "HIGH":
                # 2-5 breaches, sensitive elements exposed (passwords, identity documents or financial tokens)
                breach_count = int(np.random.choice([2, 3, 4, 5], p=[0.3, 0.4, 0.2, 0.1]))
                email_exp = 1
                phone_exp = int(np.random.choice([0, 1], p=[0.2, 0.8]))
                pwd_exp = int(np.random.choice([0, 1], p=[0.2, 0.8]))
                fin_exp = int(np.random.choice([0, 1], p=[0.4, 0.6]))
                id_exp = int(np.random.choice([0, 1], p=[0.4, 0.6]))
                addr_exp = int(np.random.choice([0, 1], p=[0.3, 0.7]))
                cred_exp = int(np.random.choice([0, 1], p=[0.7, 0.3]))
                max_sev = int(np.random.choice([2, 3], p=[0.7, 0.3]))  # 2=High, 3=Critical
                days_since = int(np.random.uniform(90, 1200))

            else:  # CRITICAL
                # Multiple severe breaches, active credentials, payment data, identity docs, recent activity
                breach_count = int(np.random.choice([3, 4, 5, 6, 7], p=[0.2, 0.3, 0.25, 0.15, 0.1]))
                email_exp = 1
                phone_exp = 1
                pwd_exp = 1
                fin_exp = int(np.random.choice([0, 1], p=[0.1, 0.9]))
                id_exp = int(np.random.choice([0, 1], p=[0.15, 0.85]))
                addr_exp = 1
                cred_exp = int(np.random.choice([0, 1], p=[0.2, 0.8]))
                max_sev = 3  # Critical
                days_since = int(np.random.uniform(15, 500))  # Recent breach

            total_types = sum([email_exp, phone_exp, pwd_exp, fin_exp, id_exp, addr_exp, cred_exp])

            # Inject 12% realistic transition noise between adjacent categories
            assigned_label = label
            if np.random.rand() < 0.12:
                transitions = {
                    "LOW": "MEDIUM",
                    "MEDIUM": random.choice(["LOW", "HIGH"]),
                    "HIGH": random.choice(["MEDIUM", "CRITICAL"]),
                    "CRITICAL": "HIGH"
                }
                assigned_label = transitions[label]

            records.append({
                "sample_id": f"BRCH_{sample_id:04d}",
                "breach_count": breach_count,
                "email_exposed": email_exp,
                "phone_exposed": phone_exp,
                "password_exposed": pwd_exp,
                "financial_exposed": fin_exp,
                "identity_doc_exposed": id_exp,
                "address_exposed": addr_exp,
                "credential_exposed": cred_exp,
                "total_data_types": int(total_types),
                "max_breach_severity": max_sev,
                "days_since_breach": days_since,
                "priority_label": assigned_label,
                "is_synthetic": True
            })
            sample_id += 1

    df = pd.DataFrame(records)
    df = df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)
    return df

if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df_breach = generate_breach_records(2000)
    df_breach.to_csv(OUTPUT_PATH, index=False)
    print(f"Generated {len(df_breach)} synthetic breach priority records saved to:\n  {OUTPUT_PATH}")
    print("\nClass Distribution:")
    print(df_breach["priority_label"].value_counts())
