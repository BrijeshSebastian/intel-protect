import os
import uuid
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from flask import current_app

from backend.app import db
from backend.app.models.document import Document
from backend.app.models.pii_finding import PIIFinding
from backend.app.common.validators import validate_uploaded_file, FileValidationError
from backend.app.documents.extractor import extract_text_from_pdf, extract_text_from_txt
from backend.app.documents.ocr import extract_text_from_image, extract_text_from_scanned_pdf
from backend.app.documents.pii_detector import detect_pii
from backend.app.documents.scoring import calculate_privacy_risk_score
from backend.app.common.errors import AppError

logger = logging.getLogger("intel_protect.documents")

# Project temporary directory
TEMP_DIR = Path(os.getenv("TEMP_DIR", "temp/uploads")).resolve()


def ensure_temp_dir() -> Path:
    """Ensures temporary upload directory exists."""
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    return TEMP_DIR


def cleanup_stale_temp_files(max_age_seconds: int = 3600) -> int:
    """
    Crash recovery cleanup:
    Scans temporary upload directory and deletes orphaned files older than max_age_seconds.
    """
    if not TEMP_DIR.exists():
        return 0

    deleted_count = 0
    now = time.time()
    try:
        for file_path in TEMP_DIR.iterdir():
            if file_path.is_file():
                try:
                    file_age = now - file_path.stat().st_mtime
                    if file_age > max_age_seconds:
                        file_path.unlink()
                        deleted_count += 1
                except Exception as e:
                    logger.warning(f"Could not delete stale file {file_path.name}: {e}")
    except Exception as e:
        logger.warning(f"Error during stale temp file scan: {e}")

    if deleted_count > 0:
        logger.info(f"Purged {deleted_count} stale temporary files from {TEMP_DIR}")
    return deleted_count


def process_document_upload(file_storage, user_id: str) -> dict:
    """
    End-to-end document upload and extraction pipeline:
    1. Validate file (magic bytes, size, extension)
    2. Write to UUID-named temporary file
    3. Route to PyMuPDF / OpenCV+Tesseract / TXT parser
    4. Save Document metadata in PostgreSQL
    5. Guaranteed try/finally deletion of temporary source file
    """
    # 1. Multi-layer validation
    safe_filename, file_type, file_size, file_hash = validate_uploaded_file(file_storage)

    # 2. Allocate randomized temporary destination
    ensure_temp_dir()
    temp_filename = f"{uuid.uuid4().hex}.{file_type}"
    temp_path = TEMP_DIR / temp_filename

    ocr_applied = False
    extracted_text = ""
    page_count = 1

    try:
        # Save securely to temporary storage
        file_storage.seek(0)
        file_storage.save(str(temp_path))
        logger.info(f"Saved temporary file for processing: {temp_filename} (type={file_type}, size={file_size}b)")

        # 3. Extraction based on file format
        if file_type == "txt":
            extracted_text = extract_text_from_txt(str(temp_path))
            page_count = 1
        elif file_type == "pdf":
            extracted_text, page_count = extract_text_from_pdf(str(temp_path))

            # Scanned PDF fallback: If text-based extraction returned empty, perform OCR
            if not extracted_text or not extracted_text.strip():
                logger.info("PDF text empty. Invoking scanned-PDF OCR fallback pipeline.")
                ocr_text, ocr_pages = extract_text_from_scanned_pdf(str(temp_path))
                if ocr_text and ocr_text.strip():
                    extracted_text = ocr_text
                    ocr_applied = True
        elif file_type in ("png", "jpg"):
            extracted_text = extract_text_from_image(str(temp_path))
            ocr_applied = True
            page_count = 1

        # 4. Generate safe preview (first 500 characters)
        preview = extracted_text[:500].strip() if extracted_text else ""

        # 5. Execute Deterministic PII Detection Pipeline
        detected_findings = detect_pii(extracted_text)
        pii_count = len(detected_findings)
        high_risk_count = sum(1 for f in detected_findings if f.severity in ("HIGH", "CRITICAL"))
        now_utc = datetime.now(timezone.utc)

        # 6. Execute Deterministic Privacy Risk Scoring Engine
        findings_dicts = [
            {
                "pii_type": f.pii_type,
                "masked_value": f.masked_value,
                "confidence": f.confidence,
                "severity": f.severity,
                "checksum_valid": f.checksum_valid,
            }
            for f in detected_findings
        ]
        risk_result = calculate_privacy_risk_score(findings_dicts)

        # 7. Persist Document record
        doc_record = Document(
            user_id=user_id,
            original_filename=safe_filename,
            file_type=file_type,
            file_size=file_size,
            file_hash=file_hash,
            extracted_text_preview=preview,
            extracted_text=extracted_text,
            ocr_applied=ocr_applied,
            page_count=page_count,
            pii_count=pii_count,
            high_risk_count=high_risk_count,
            risk_score=risk_result["score"],
            risk_level=risk_result["risk_level"],
            scoring_version=risk_result["scoring_version"],
            score_explanation=risk_result["explanation"],
            scanned_at=now_utc,
            created_at=now_utc
        )

        db.session.add(doc_record)
        db.session.flush()  # Allocate doc_record.id for foreign keys

        # 7. Persist PII Findings (masked values and metadata only)
        for f in detected_findings:
            finding_record = PIIFinding(
                document_id=doc_record.id,
                pii_type=f.pii_type,
                masked_value=f.masked_value,
                confidence=f.confidence,
                severity=f.severity,
                checksum_valid=f.checksum_valid,
                detection_method=f.detection_method,
                context_snippet=f.context_snippet,
                position_start=f.position_start,
                position_end=f.position_end,
                created_at=now_utc
            )
            db.session.add(finding_record)

        db.session.commit()

        logger.info(
            f"Document processed: id={doc_record.id}, ocr={ocr_applied}, "
            f"pii_count={pii_count}, high_risk={high_risk_count}"
        )
        return doc_record.to_dict(include_full_text=True, include_findings=True)

    finally:
        # 8. CRITICAL SECURITY GUARANTEE: Delete source temporary file immediately
        import gc
        gc.collect()
        if temp_path.exists():
            try:
                temp_path.unlink()
                logger.debug(f"Temporary file deleted: {temp_filename}")
            except Exception as e:
                # Windows handle release retry
                try:
                    time.sleep(0.05)
                    gc.collect()
                    if temp_path.exists():
                        temp_path.unlink()
                except Exception as inner_e:
                    logger.warning(f"Failed to delete temp file {temp_filename}: {inner_e}")


def get_user_documents(user_id: str, limit: int = 20, offset: int = 0) -> tuple[list[dict], int]:
    """Retrieve paginated list of user's scanned documents."""
    query = Document.query.filter_by(user_id=user_id).order_by(Document.created_at.desc())
    total = query.count()
    records = query.limit(limit).offset(offset).all()
    return [r.to_dict(include_full_text=False) for r in records], total


def get_document_by_id(document_id: str, user_id: str) -> dict:
    """Retrieve document details with strict user data isolation."""
    doc = Document.query.filter_by(id=document_id, user_id=user_id).first()
    if not doc:
        raise AppError("Document not found or access denied.", code="NOT_FOUND", status_code=404)
    return doc.to_dict(include_full_text=True, include_findings=True)


def get_document_findings(document_id: str, user_id: str) -> tuple[dict, list[dict]]:
    """
    Retrieve PII findings for a document with user ownership verification.
    Guarantees that User A cannot inspect User B's findings.
    """
    doc = Document.query.filter_by(id=document_id, user_id=user_id).first()
    if not doc:
        raise AppError("Document not found or access denied.", code="NOT_FOUND", status_code=404)
    findings = PIIFinding.query.filter_by(document_id=doc.id).order_by(PIIFinding.position_start.asc()).all()
    return doc.to_dict(include_full_text=False), [f.to_dict() for f in findings]


def delete_document(document_id: str, user_id: str) -> bool:
    """Deletes document record and cascades to pii_findings with user isolation."""
    doc = Document.query.filter_by(id=document_id, user_id=user_id).first()
    if not doc:
        raise AppError("Document not found or access denied.", code="NOT_FOUND", status_code=404)

    db.session.delete(doc)
    db.session.commit()
    return True


def get_document_risk(document_id: str, user_id: str) -> dict:
    """
    Retrieve deterministic privacy risk score breakdown for a document.
    Enforces user data isolation.
    """
    doc = Document.query.filter_by(id=document_id, user_id=user_id).first()
    if not doc:
        raise AppError("Document not found or access denied.", code="NOT_FOUND", status_code=404)
    return {
        "document_id": str(doc.id),
        "original_filename": doc.original_filename,
        "risk_score": doc.risk_score if doc.risk_score is not None else 0.0,
        "risk_level": doc.risk_level or "LOW",
        "scoring_version": doc.scoring_version or "1.0",
        "explanation": doc.score_explanation or {},
        "scanned_at": doc.scanned_at.isoformat() if doc.scanned_at else None,
    }
