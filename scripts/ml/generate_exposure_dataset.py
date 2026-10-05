"""
Synthetic Exposure Dataset Generator.
Generates ~3,000 synthetic exposure text records using Faker with realistic PII text fragments
and operational class skew (40% LOW, 30% MEDIUM, 20% HIGH, 10% CRITICAL).
Seed: 42 (reproducible).
"""
import os
import random
import numpy as np
import pandas as pd
from faker import Faker

SEED = 42
random.seed(SEED)
np.random.seed(SEED)
fake = Faker(['en_IN', 'en_US'])
Faker.seed(SEED)

OUTPUT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend/data/synthetic/synthetic_exposures.csv"))

def generate_exposure_records(n_samples: int = 3000) -> pd.DataFrame:
    class_targets = [
        ("LOW", int(n_samples * 0.40)),
        ("MEDIUM", int(n_samples * 0.30)),
        ("HIGH", int(n_samples * 0.20)),
        ("CRITICAL", n_samples - int(n_samples * 0.40) - int(n_samples * 0.30) - int(n_samples * 0.20))
    ]

    records = []
    sample_id = 1

    sources = ["paste_site", "public_bucket", "forum_dump", "code_repo", "dark_forum"]

    for label, count in class_targets:
        for _ in range(count):
            source = random.choice(sources)
            name = fake.name()
            username = fake.user_name()
            company = fake.company()
            job = fake.job()
            city = fake.city()

            if label == "LOW":
                # Public web profile / directory metadata (no credentials, no financial, minimal contact)
                templates = [
                    f"Public engineer bio: {name} ({username}), works as {job} at {company} in {city}. Public GitHub profile contributions.",
                    f"Directory entry for attendee {name}, affiliated with {company}. Registration reference ID #{random.randint(10000, 99999)}.",
                    f"Corporate staff directory: {name}, Team: {fake.bs()}, Location: {city}. Public office listing."
                ]
                text = random.choice(templates)
                entity_count = random.choice([0, 1])
                has_fin = 0
                has_cred = 0
                has_id = 0

            elif label == "MEDIUM":
                # Contact info & business communication
                email = fake.email()
                phone = f"+91-{random.randint(70000, 99999)}-{random.randint(10000, 99999)}"
                pan_masked = f"XXXXX{random.randint(1000, 9999)}X"
                templates = [
                    f"Vendor registration record: Contact person {name}, Corporate Email: {email}, Direct Mobile: {phone}. Vendor PAN: {pan_masked} on file.",
                    f"Employee HR intake roster: {name}, Department: {job}, Corporate Email: {email}, Work Phone: {phone}, Office: {city}.",
                    f"Mailing list subscription export: Member {name} <{email}>, Mobile: {phone}, City: {city}. Verified customer contact."
                ]
                text = random.choice(templates)
                entity_count = random.choice([2, 3, 4])
                has_fin = 0
                has_cred = 0
                has_id = random.choice([0, 1])

            elif label == "HIGH":
                # Sensitive customer records, partial financial / bank tokens, KYC identifiers
                email = fake.email()
                phone = f"+91-{random.randint(70000, 99999)}-{random.randint(10000, 99999)}"
                bank_acc = f"********{random.randint(1000, 9999)}"
                card_partial = f"**** **** **** {random.randint(1000, 9999)}"
                aadhaar_masked = f"XXXX XXXX {random.randint(1000, 9999)}"
                dob = fake.date_of_birth(minimum_age=21, maximum_age=65).strftime("%Y-%m-%d")
                templates = [
                    f"Financial KYC submission: Applicant {name}, DOB: {dob}, Email: {email}, Mobile: {phone}. Bank A/C: {bank_acc}, IFSC: {fake.lexify('????0??????').upper()}. Aadhaar: {aadhaar_masked}.",
                    f"Billing transaction ledger: Customer {name}, Email: {email}, Billed Card: {card_partial}, Expiry: {random.randint(1,12):02d}/{random.randint(26,30)}. Address: {fake.street_address()}, {city}.",
                    f"Account recovery ticket: User {name} ({username}), Primary Email: {email}, Linked Phone: {phone}, Bank Account Number: {bank_acc}, Aadhaar Ref: {aadhaar_masked}."
                ]
                text = random.choice(templates)
                entity_count = random.choice([4, 5, 6])
                has_fin = 1
                has_cred = 0
                has_id = 1

            else:  # CRITICAL
                # Highly compromised credential and financial dumps
                email = fake.email()
                raw_pwd = fake.password(length=14, special_chars=True, digits=True, upper_case=True, lower_case=True)
                salt = fake.sha1()[:16]
                hash_val = fake.sha256()
                card_full = f"4532 {random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}"
                cvv = random.randint(100, 999)
                token = f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{fake.md5()}.{fake.sha1()[:16]}"
                aadhaar_masked = f"XXXX XXXX {random.randint(1000, 9999)}"
                templates = [
                    f"DATABASE COMPROMISE DUMP: User {username}, Email: {email}, Plaintext Password: '{raw_pwd}', Password Hash: {hash_val}, Salt: {salt}, Session Token: {token}.",
                    f"PAYMENT GATEWAY LEAK: Cardholder: {name}, Card Number: {card_full}, CVV: {cvv}, Expiry: 11/29, Billing Address: {fake.address().replace(chr(10), ', ')}. Aadhaar: {aadhaar_masked}.",
                    f"ROOT CREDENTIALS EXPOSURE: Service: {company} API, Admin: {email}, API Secret: {fake.uuid4()}, Auth JWT: {token}, Linked Bank Direct Deposit: {random.randint(1000000000, 9999999999)}."
                ]
                text = random.choice(templates)
                entity_count = random.choice([6, 7, 8, 9])
                has_fin = 1
                has_cred = 1
                has_id = 1

            # Inject 10% realistic boundary label transition noise
            assigned_label = label
            if np.random.rand() < 0.10:
                transitions = {
                    "LOW": "MEDIUM",
                    "MEDIUM": random.choice(["LOW", "HIGH"]),
                    "HIGH": random.choice(["MEDIUM", "CRITICAL"]),
                    "CRITICAL": "HIGH"
                }
                assigned_label = transitions[label]

            records.append({
                "sample_id": f"EXP_{sample_id:05d}",
                "exposure_text": text,
                "entity_count": int(entity_count),
                "has_financial": int(has_fin),
                "has_credential": int(has_cred),
                "has_identity": int(has_id),
                "source_category": source,
                "sensitivity_label": assigned_label,
                "is_synthetic": True
            })
            sample_id += 1

    df = pd.DataFrame(records)
    df = df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)
    return df

if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df_exp = generate_exposure_records(3000)
    df_exp.to_csv(OUTPUT_PATH, index=False)
    print(f"Generated {len(df_exp)} synthetic exposure records saved to:\n  {OUTPUT_PATH}")
    print("\nClass Distribution:")
    print(df_exp["sensitivity_label"].value_counts())
