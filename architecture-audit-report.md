# Intel-Protect — Architecture Re-Audit Report (Post-Revisions)

> Re-Audit Performed: 2026-10-03  
> Document Under Audit: `intel-protect-architecture.md` (v1.2 Updated)

---

## 1. Executive Summary

All **8 findings** from the initial audit report and the **2 mandatory security enhancements** requested by the user have been formally integrated into `intel-protect-architecture.md`:

1. **Refresh Token Table & Family-Based Reuse Detection**: Added `refresh_tokens` table with cryptographic hashing (`token_hash`), `token_family`, `replaced_by`, and full revocation logic.
2. **HttpOnly Cookie Delivery**: Refresh tokens are excluded from API response JSON bodies and delivered strictly via `HttpOnly; SameSite=Strict; Path=/api/auth` cookies. Access tokens remain in frontend volatile memory only.
3. **Centralized PII-Safe Logging**: Designed a root logger redaction filter catching Aadhaar, PAN, Card, Bank details, Phones, Emails, Passwords, JWTs, Authorization headers, and sensitive payloads. Added `test_pii_safe_logging.py` to the test suite.
4. **Temporary File Crash Recovery**: Added two-tiered cleanup: `try/finally` block for immediate deletion + server startup purge of orphaned files older than 1 hour.
5. **Class Imbalance & Evaluation Strategy**: Documented a realistic operational skew (~40% LOW, 30% MEDIUM, 20% HIGH, 10% CRITICAL), algorithm-level compensation (`class_weight='balanced'`), stratified splits, and mandatory per-class Precision/Recall/F1 reporting.
6. **ML Pipeline Consistency**: Fixed flowchart node `M2` to `train_exposure.py` and added `train_exposure.py` to the file tree.
7. **Database Index Completeness**: Added indexes on `breach_exposures(breach_id)` and `refresh_tokens(token_hash, user_id, token_family)`.
8. **Docker Build-Time Dependency Verification**: Mandated system packages (`tesseract-ocr`, `tesseract-ocr-eng`, OpenCV dependencies) and spaCy model downloads with build-time verification assertions.

---

## 2. Criterion-by-Criterion Re-Audit (20 Points)

| # | Criterion | Status | Evaluation Notes |
|---|-----------|--------|------------------|
| 1 | **Database Normalization** | **PASS** | 3NF compliant; relational integrity with junction tables (`breach_exposures`) and structured JSONB metadata. |
| 2 | **Foreign Keys & Indexes** | **PASS** | Complete FK coverage with CASCADE rules; composite and individual indexes added for all user lookups, breach associations, and token hashes. |
| 3 | **Auth & JWT Security** | **PASS** | Access tokens short-lived (15 min) in memory only; Argon2id password hashing; user-isolated queries; rate limiting on auth routes. |
| 4 | **Refresh Token Storage & Rotation** | **PASS** | Hashed persistence in `refresh_tokens`; HttpOnly delivery; rotation on each use; family-wide revocation upon reuse detection. |
| 5 | **File-Upload Security** | **PASS** | 10 MB limit; MIME magic bytes inspection; UUID temporary names; SHA-256 integrity hash. |
| 6 | **Sensitive Data Leakage Prevention** | **PASS** | Masked API responses; no plaintext PII in database; centralized root logging filter with automated redaction; no tokens in localStorage. |
| 7 | **PII Masking Integrity** | **PASS** | Centralized in `documents/masker.py`; strict masking patterns for Aadhaar, PAN, Cards, Emails, and Phones. |
| 8 | **Race Conditions & Cleanup** | **PASS** | `try/finally` per-request cleanup + startup and background purge for stale files (>1 hour). |
| 9 | **OCR/PDF Security** | **PASS** | PyMuPDF extracts without executing scripts/URIs; Tesseract executes on sanitized image buffers. |
| 10 | **ML Data Leakage Prevention** | **PASS** | Stratified splitting (`stratify=y`); TF-IDF and scalers fit strictly on training fold (`fit_transform`) and applied to test fold (`transform`). |
| 11 | **Class Imbalance Strategy** | **PASS** | Realistic skewed distribution (~40/30/20/10); `class_weight='balanced'` configured; evaluation mandates per-class PRF metrics & confusion matrix. |
| 12 | **Synthetic Dataset Generation** | **PASS** | Fully reproducible (`SEED=42`); Indian-context data using Faker; all records explicitly tagged `is_synthetic: true`. |
| 13 | **ML Model Appropriateness** | **PASS** | Logistic Regression & Random Forest for tabular PII; TF-IDF + RF for exposure text; Isolation Forest for anomaly detection. |
| 14 | **No Assumed or Fabricated Metrics** | **PASS** | No pre-claimed metric numbers; actual numbers generated from `evaluate.py` output; UI displays "Not evaluated yet" until trained. |
| 15 | **Breach Architecture Separation** | **PASS** | Adapter pattern (`BreachProvider`); default `LocalBreachProvider` uses offline synthetic dataset; no external paid API dependencies. |
| 16 | **Local FOSS Feasibility** | **PASS** | 100% free and open-source stack (Python, Flask, React, Vite, Tailwind, PostgreSQL, Tesseract, PyMuPDF, scikit-learn). |
| 17 | **Docker Compose Reproducibility** | **PASS** | Docker build installs system OCR packages, downloads spaCy model, and executes build-time assertions (`tesseract --version`, `spacy.load`). |
| 18 | **API Contract Sufficiency** | **PASS** | Full RESTful coverage across Auth, Documents, Exposure, Breaches, and Dashboard with standard response envelopes. |
| 19 | **Schema Workflow Completeness** | **PASS** | 9 tables comprehensively support the full 20-step user journey from registration to aggregated risk dashboard. |
| 20 | **Appropriate Architectural Scope** | **PASS** | Modular monolith with Flask Blueprints; clear separation of concerns without microservice or distributed queue over-engineering. |

---

## 3. Remaining Minor Observations (Non-Blocking)

1. **Host-Level Tesseract Path on Windows (Low)**:
   - When running outside Docker on Windows bare-metal, the user must install Tesseract (e.g. UB-Mannheim Windows installer) and ensure it is on PATH or configure `TESSERACT_CMD` in `.env`.
   - *Mitigation*: Handled via documentation in `README.md` and fallback configuration check in `backend/app/documents/ocr.py`.
2. **spaCy Model Download on Bare-Metal (Low)**:
   - For non-Docker development, developers need to run `python -m spacy download en_core_web_sm` once after `pip install -r requirements.txt`.
   - *Mitigation*: Included in the setup script / README.

---

## 4. Verification of User-Mandated Decisions

- [x] **Keep Argon2id**: Verified (Section 1.4 & models/user.py)
- [x] **Keep access tokens short-lived (15 min) in frontend memory only**: Verified
- [x] **Keep refresh tokens out of localStorage (HttpOnly cookie + DB hash + family rotation)**: Verified
- [x] **Keep synthetic breach dataset as mandatory offline implementation**: Verified
- [x] **Do not fabricate ML metrics**: Verified
- [x] **Do not use real stolen personal data**: Verified
- [x] **Do not introduce paid APIs or proprietary services into core system**: Verified

---

## Final Architecture Status

```text
ARCHITECTURE STATUS:
APPROVED
```

All architectural prerequisites, security controls, database designs, API contracts, and ML evaluation methodologies are rigorously defined and validated.
