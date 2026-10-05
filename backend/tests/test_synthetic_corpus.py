"""
Deterministic Benchmark & False-Positive Evaluation on Synthetic Corpus.
Evaluates precision, recall, false-positive rate, and false-negative rate
against synthetic PII positive instances and lookalike negative instances:
- Invoice numbers
- Student roll numbers
- Unix / ISO timestamps
- Order and transaction IDs
- Random 10-digit, 12-digit, 16-digit non-checksum numbers
"""
import pytest
from backend.app.documents.checksum import compute_verhoeff, compute_luhn
from backend.app.documents.pii_detector import detect_pii


# ==============================================================================
# SYNTHETIC BENCHMARK CORPUS
# ==============================================================================

def generate_synthetic_benchmark_dataset():
    """
    Builds a labeled evaluation dataset containing:
    1. Positive samples (genuine synthetic Aadhaar, PAN, Card, Bank with context, Email, Phone)
    2. Negative samples (lookalike non-PII: invoice numbers, timestamps, order IDs, roll numbers, non-Luhn/Verhoeff numbers)
    """
    positives = []
    negatives = []

    # --- Positives (True PII instances) ---
    # Aadhaar (Verhoeff valid)
    for b in ["29471839201", "38192049182", "59102938471", "78192039481", "90192837461"]:
        chk = compute_verhoeff(b)
        positives.append({
            "text": f"Citizen identity card. UIDAI Aadhaar Number: {b[:4]} {b[4:8]} {b[8:]}{chk}.",
            "expected_type": "AADHAAR"
        })

    # PAN (Valid format with valid entity letters)
    for pan in ["ABCDE1234F", "BKRPP5678M", "XYZTC9876Q", "DFGHJ1357K", "LMNPA2468R"]:
        positives.append({
            "text": f"Permanent Account Number (PAN) tax ID: {pan} on file.",
            "expected_type": "PAN"
        })

    # Cards (Luhn valid)
    for card_base in ["453201511283036", "542523343010990", "37828224631000", "601100099013942", "652150123456789"]:
        luhn_chk = compute_luhn(card_base)
        full_card = f"{card_base}{luhn_chk}"
        positives.append({
            "text": f"Payment billed to customer credit card: {full_card}.",
            "expected_type": "CARD"
        })

    # Bank Accounts (With context)
    for acc in ["987654321012", "112233445566", "554433221100", "778899001122"]:
        positives.append({
            "text": f"Direct deposit to savings account number: {acc}.",
            "expected_type": "BANK_ACCOUNT"
        })

    # Emails
    for em in ["security.analyst@example.org", "devops.lead@cloud-systems.io", "audit_team@finance-dept.com"]:
        positives.append({
            "text": f"Forward report to authorized contact: {em}.",
            "expected_type": "EMAIL"
        })

    # Phones (Indian mobile with prefix or formatting)
    for ph in ["+91-9876543210", "+91-8765432109", "09123456789", "+91 7654321098"]:
        positives.append({
            "text": f"Primary emergency contact mobile: {ph}.",
            "expected_type": "PHONE"
        })

    # --- Negatives (Lookalikes that must NOT be flagged as PII) ---
    # Invoices (alphanumeric and numeric)
    negatives.append("Invoice Reference ID: INV-2026-987654 issued by billing department.")
    negatives.append("Invoice number: 9876543210 billed to commercial enterprise.")
    negatives.append("Bill number: 123456789012 for enterprise hardware delivery.")

    # Student IDs / Roll numbers
    negatives.append("University student roll number: ROLL-1029384756 registered for examination.")
    negatives.append("Student enrollment ID: 9876543210 enrolled in semester 4.")

    # Timestamps
    negatives.append("Server ISO timestamp record: 20261003180000 UTC system event.")
    negatives.append("Unix epoch millisecond timestamp: 1727980800000 recorded in database.")

    # Order IDs & Transaction IDs
    negatives.append("E-commerce order ID: ORD-9876543210 dispatched from warehouse.")
    negatives.append("Warehouse batch order: 8877665544 packaged for transit.")
    negatives.append("Gateway transaction identifier: TXN-9876543210123456 completed.")

    # Random 12-digit numbers that FAIL Verhoeff (not Aadhaar)
    negatives.append("Reference batch token: 2947 1839 2018 is assigned to logistics.")
    negatives.append("Serial tracking barcode: 5910 2938 4710 printed on parcel.")

    # Random 16-digit numbers that FAIL Luhn (not payment cards)
    negatives.append("Industrial equipment serial number: 4532 0151 1283 0367.")
    negatives.append("Product activation code: 5425 2334 3010 9904.")

    # Random 10-digit alphanumeric strings that fail PAN format (e.g. wrong 4th letter)
    negatives.append("Hardware motherboard revision: ABCDZ1234F manufactured in 2026.")
    negatives.append("Software license key segment: QWERT9876Y.")

    return positives, negatives


def test_synthetic_corpus_precision_and_recall():
    """
    Evaluates detector against the labeled synthetic benchmark dataset.
    Computes exact TP, FP, TN, FN, Precision, and Recall metrics.
    """
    positives, negatives = generate_synthetic_benchmark_dataset()

    tp = 0
    fn = 0
    for p in positives:
        findings = detect_pii(p["text"])
        types_found = [f.pii_type for f in findings]
        if p["expected_type"] in types_found:
            tp += 1
        else:
            fn += 1

    fp = 0
    tn = 0
    for n_text in negatives:
        findings = detect_pii(n_text)
        if len(findings) == 0:
            tn += 1
        else:
            fp += 1
            print(f"[FALSE POSITIVE DETECTED]: '{n_text}' produced findings: {[f.pii_type for f in findings]}")

    total_samples = len(positives) + len(negatives)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n" + "=" * 60)
    print("SYNTHETIC CORPUS BENCHMARK RESULTS (PHASE 4)")
    print("=" * 60)
    print(f"Total Evaluated Instances: {total_samples}")
    print(f"True Positives  (TP):     {tp} / {len(positives)}")
    print(f"True Negatives  (TN):     {tn} / {len(negatives)}")
    print(f"False Positives (FP):     {fp}")
    print(f"False Negatives (FN):     {fn}")
    print(f"Measured Precision:       {precision * 100:.2f}%")
    print(f"Measured Recall:          {recall * 100:.2f}%")
    print(f"Measured F1-Score:        {f1 * 100:.2f}%")
    print("=" * 60)

    # Statistical assertions
    assert fp == 0, f"Expected 0 false positives on negative corpus, got {fp}"
    assert fn == 0, f"Expected 0 false negatives on positive corpus, got {fn}"
    assert precision == 1.0
    assert recall == 1.0
