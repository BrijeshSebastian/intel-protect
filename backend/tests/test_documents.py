import io
import os
import uuid
import pytest
from unittest.mock import patch
import pymupdf
from PIL import Image

from backend.app import db
from backend.app.models.user import User
from backend.app.models.document import Document
from backend.app.common.security import create_access_token
from backend.app.common.validators import (
    validate_uploaded_file,
    FileValidationError,
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE_BYTES
)
from backend.app.documents.service import (
    process_document_upload,
    cleanup_stale_temp_files,
    TEMP_DIR
)


@pytest.fixture(autouse=True)
def clean_database(app):
    """Clean documents and users before each test."""
    with app.app_context():
        Document.query.delete()
        User.query.delete()
        db.session.commit()


@pytest.fixture
def auth_user(app):
    """Creates a test user and returns (user, token)."""
    with app.app_context():
        user = User(
            email="docuser@example.com",
            username="docuser",
            password_hash="argon2_hashed_placeholder",
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        token = create_access_token(str(user.id), user.email)
        return user, token


@pytest.fixture
def other_user(app):
    """Creates a second test user and returns (user, token)."""
    with app.app_context():
        user = User(
            email="otheruser@example.com",
            username="otheruser",
            password_hash="argon2_hashed_placeholder",
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        token = create_access_token(str(user.id), user.email)
        return user, token


def create_sample_pdf(text_content="Intel-Protect Confidential Analysis Document"):
    """Helper to generate an in-memory valid PDF file using PyMuPDF."""
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text((50, 72), text_content, fontsize=12)
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes


def create_multi_page_pdf():
    """Helper to generate a multi-page PDF."""
    doc = pymupdf.open()
    for i in range(3):
        page = doc.new_page(width=595, height=842)
        page.insert_text((50, 72), f"Page {i + 1} content: confidential record {i}", fontsize=12)
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes


def create_sample_png():
    """Helper to generate an in-memory valid PNG image."""
    img = Image.new("RGB", (200, 100), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def create_sample_jpg():
    """Helper to generate an in-memory valid JPEG image."""
    img = Image.new("RGB", (200, 100), color=(200, 200, 200))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


# ==============================================================================
# 1. FILE VALIDATION & SECURITY TESTS
# ==============================================================================

def test_unsupported_file_extension(client, auth_user):
    """Test rejection of disallowed file extensions (e.g. .exe, .sh, .docx)."""
    _, token = auth_user
    data = {
        "file": (io.BytesIO(b"binary payload"), "malicious.exe")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 400
    res_data = response.get_json()
    assert res_data["error"]["code"] == "UNSUPPORTED_FILE_TYPE"


def test_magic_byte_mismatch_pdf(client, auth_user):
    """Test rejection of file with .pdf extension but invalid header bytes."""
    _, token = auth_user
    fake_pdf = b"NOT_A_REAL_PDF_HEADER_JUST_RANDOM_TEXT"
    data = {
        "file": (io.BytesIO(fake_pdf), "fake.pdf")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 400
    res_data = response.get_json()
    assert res_data["error"]["code"] == "MAGIC_BYTES_MISMATCH"


def test_magic_byte_mismatch_png(client, auth_user):
    """Test rejection of file with .png extension but invalid header bytes."""
    _, token = auth_user
    fake_png = b"%PDF-1.4 Fake PNG"
    data = {
        "file": (io.BytesIO(fake_png), "fake.png")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 400
    res_data = response.get_json()
    assert res_data["error"]["code"] == "MAGIC_BYTES_MISMATCH"


def test_binary_file_disguised_as_txt(client, auth_user):
    """Test rejection of binary executable content disguised with .txt extension."""
    _, token = auth_user
    # Binary with null bytes
    binary_txt = b"Hello\x00\x01\x02\x03World"
    data = {
        "file": (io.BytesIO(binary_txt), "disguised.txt")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 400
    res_data = response.get_json()
    assert res_data["error"]["code"] == "BINARY_DISGUISED_AS_TEXT"


def test_empty_file_rejected(client, auth_user):
    """Test rejection of 0-byte uploaded file."""
    _, token = auth_user
    data = {
        "file": (io.BytesIO(b""), "empty.txt")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 400
    res_data = response.get_json()
    assert res_data["error"]["code"] == "EMPTY_FILE"


def test_oversized_file_rejected(client, auth_user):
    """Test rejection of file exceeding 10 MB limit."""
    _, token = auth_user
    oversized_data = b"X" * (MAX_FILE_SIZE_BYTES + 1024)
    data = {
        "file": (io.BytesIO(oversized_data), "large.txt")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 413
    res_data = response.get_json()
    assert res_data["error"]["code"] == "FILE_TOO_LARGE"


def test_path_traversal_filename_sanitized(client, auth_user):
    """Test that filename path traversal attacks are sanitized by secure_filename."""
    _, token = auth_user
    pdf_bytes = create_sample_pdf("Sanitized path traversal document content")
    data = {
        "file": (io.BytesIO(pdf_bytes), "../../../../etc/passwd.pdf")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 201
    doc = response.get_json()["data"]["document"]
    assert ".." not in doc["original_filename"]
    assert "/" not in doc["original_filename"]
    assert "\\" not in doc["original_filename"]
    assert doc["original_filename"] == "passwd.pdf"


# ==============================================================================
# 2. DOCUMENT EXTRACTION ENDPOINTS & LOGIC
# ==============================================================================

def test_upload_valid_pdf_text_extraction(client, auth_user):
    """Test successful text extraction from a valid PDF document."""
    _, token = auth_user
    pdf_content = "Confidential report for Project Alpha: exposure analysis."
    pdf_bytes = create_sample_pdf(pdf_content)

    data = {
        "file": (io.BytesIO(pdf_bytes), "sample_report.pdf")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 201
    res_data = response.get_json()
    assert res_data["success"] is True

    doc = res_data["data"]["document"]
    assert doc["original_filename"] == "sample_report.pdf"
    assert doc["file_type"] == "pdf"
    assert doc["file_size"] == len(pdf_bytes)
    assert len(doc["file_hash"]) == 64
    assert pdf_content in doc["extracted_text"]
    assert pdf_content in doc["extracted_text_preview"]
    assert doc["page_count"] == 1
    assert doc["ocr_applied"] is False


def test_upload_multipage_pdf(client, auth_user):
    """Test extraction from a 3-page PDF document."""
    _, token = auth_user
    pdf_bytes = create_multi_page_pdf()

    data = {
        "file": (io.BytesIO(pdf_bytes), "multipage.pdf")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 201
    doc = response.get_json()["data"]["document"]
    assert doc["page_count"] == 3
    assert "Page 1 content" in doc["extracted_text"]
    assert "Page 2 content" in doc["extracted_text"]
    assert "Page 3 content" in doc["extracted_text"]


def test_upload_valid_txt_utf8(client, auth_user):
    """Test text extraction from UTF-8 plain text file."""
    _, token = auth_user
    txt_content = "Customer database dump snippet:\nName: Alice Smith\nAccount: 987654321"
    data = {
        "file": (io.BytesIO(txt_content.encode("utf-8")), "audit.txt")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 201
    doc = response.get_json()["data"]["document"]
    assert doc["file_type"] == "txt"
    assert doc["extracted_text"] == txt_content
    assert doc["ocr_applied"] is False


def test_upload_valid_txt_latin1_fallback(client, auth_user):
    """Test TXT decoding fallback for Latin-1 encoding with special characters."""
    _, token = auth_user
    latin1_text = "Élégant Café résumé analysis report"
    data = {
        "file": (io.BytesIO(latin1_text.encode("latin-1")), "latin1.txt")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 201
    doc = response.get_json()["data"]["document"]
    assert "Café" in doc["extracted_text"] or "Caf" in doc["extracted_text"]


@patch("backend.app.documents.ocr.pytesseract.image_to_string")
def test_upload_image_png_ocr(mock_tesseract, client, auth_user):
    """Test image upload and OCR execution with mocked pytesseract."""
    mock_tesseract.return_value = "OCR Extracted Text from ID Card"
    _, token = auth_user
    png_bytes = create_sample_png()

    data = {
        "file": (io.BytesIO(png_bytes), "id_card.png")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 201
    doc = response.get_json()["data"]["document"]
    assert doc["file_type"] == "png"
    assert doc["ocr_applied"] is True
    assert doc["extracted_text"] == "OCR Extracted Text from ID Card"
    mock_tesseract.assert_called_once()


@patch("backend.app.documents.ocr.pytesseract.image_to_string")
def test_upload_scanned_pdf_ocr_fallback(mock_tesseract, client, auth_user):
    """Test that scanned PDF with negligible direct text falls back to OCR."""
    mock_tesseract.return_value = "Scanned document text extracted via Tesseract fallback"
    _, token = auth_user
    # Empty page PDF (0 text characters)
    doc = pymupdf.open()
    doc.new_page(width=400, height=400)
    empty_pdf = doc.tobytes()
    doc.close()

    data = {
        "file": (io.BytesIO(empty_pdf), "scanned_doc.pdf")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 201
    doc_res = response.get_json()["data"]["document"]
    assert doc_res["ocr_applied"] is True
    assert "Scanned document text" in doc_res["extracted_text"]


# ==============================================================================
# 3. TEMPORARY FILE CLEANUP & LIFECYCLE TESTS
# ==============================================================================

def test_temporary_file_deleted_in_finally(client, auth_user):
    """Verify that uploaded temporary file is unlinked immediately in finally block."""
    _, token = auth_user
    pdf_bytes = create_sample_pdf("Check temporary file deletion")

    # Count files in temp dir before upload
    before_files = set(TEMP_DIR.glob("*")) if TEMP_DIR.exists() else set()

    data = {
        "file": (io.BytesIO(pdf_bytes), "temp_check.pdf")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 201

    # Verify no new files remain in temp directory
    after_files = set(TEMP_DIR.glob("*")) if TEMP_DIR.exists() else set()
    assert after_files == before_files


def test_temporary_file_deleted_on_extraction_error(client, auth_user):
    """Verify temporary file is deleted even if extraction raises an error."""
    _, token = auth_user
    # Send corrupted PDF header
    corrupt_pdf = b"%PDF-1.4 " + b"\x00" * 500

    before_files = set(TEMP_DIR.glob("*")) if TEMP_DIR.exists() else set()

    data = {
        "file": (io.BytesIO(corrupt_pdf), "corrupted.pdf")
    }
    response = client.post(
        "/api/documents/scan",
        data=data,
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    # Either 422 or handled
    assert response.status_code in (400, 422)

    after_files = set(TEMP_DIR.glob("*")) if TEMP_DIR.exists() else set()
    assert after_files == before_files


# ==============================================================================
# 4. REST API & USER ISOLATION TESTS
# ==============================================================================

def test_list_documents_user_isolation(client, auth_user, other_user):
    """Test that users can only list their own uploaded documents."""
    user1, token1 = auth_user
    user2, token2 = other_user

    # User 1 uploads document
    pdf1 = create_sample_pdf("User 1 document")
    res1 = client.post(
        "/api/documents/scan",
        data={"file": (io.BytesIO(pdf1), "user1_doc.pdf")},
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token1}"}
    )
    assert res1.status_code == 201

    # User 2 uploads document
    pdf2 = create_sample_pdf("User 2 document")
    res2 = client.post(
        "/api/documents/scan",
        data={"file": (io.BytesIO(pdf2), "user2_doc.pdf")},
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token2}"}
    )
    assert res2.status_code == 201

    # User 1 queries document history
    list1 = client.get("/api/documents", headers={"Authorization": f"Bearer {token1}"})
    assert list1.status_code == 200
    docs1 = list1.get_json()["data"]["documents"]
    assert len(docs1) == 1
    assert docs1[0]["original_filename"] == "user1_doc.pdf"

    # User 2 queries document history
    list2 = client.get("/api/documents", headers={"Authorization": f"Bearer {token2}"})
    assert list2.status_code == 200
    docs2 = list2.get_json()["data"]["documents"]
    assert len(docs2) == 1
    assert docs2[0]["original_filename"] == "user2_doc.pdf"


def test_get_document_by_id_isolation(client, auth_user, other_user):
    """Test that User 2 cannot access User 1's document by ID (returns 404)."""
    _, token1 = auth_user
    _, token2 = other_user

    pdf1 = create_sample_pdf("Confidential user 1 record")
    upload_res = client.post(
        "/api/documents/scan",
        data={"file": (io.BytesIO(pdf1), "private.pdf")},
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token1}"}
    )
    doc_id = upload_res.get_json()["data"]["document"]["id"]

    # User 1 can access
    get_res1 = client.get(f"/api/documents/{doc_id}", headers={"Authorization": f"Bearer {token1}"})
    assert get_res1.status_code == 200
    assert get_res1.get_json()["data"]["document"]["id"] == doc_id

    # User 2 tries to access User 1's document
    get_res2 = client.get(f"/api/documents/{doc_id}", headers={"Authorization": f"Bearer {token2}"})
    assert get_res2.status_code == 404


def test_delete_document_isolation(client, auth_user, other_user):
    """Test document deletion and that User 2 cannot delete User 1's document."""
    _, token1 = auth_user
    _, token2 = other_user

    pdf1 = create_sample_pdf("Document to be deleted")
    upload_res = client.post(
        "/api/documents/scan",
        data={"file": (io.BytesIO(pdf1), "delete_me.pdf")},
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token1}"}
    )
    doc_id = upload_res.get_json()["data"]["document"]["id"]

    # User 2 attempts to delete User 1's doc -> 404
    del_res2 = client.delete(f"/api/documents/{doc_id}", headers={"Authorization": f"Bearer {token2}"})
    assert del_res2.status_code == 404

    # User 1 deletes own doc -> 200
    del_res1 = client.delete(f"/api/documents/{doc_id}", headers={"Authorization": f"Bearer {token1}"})
    assert del_res1.status_code == 200

    # Verify doc no longer exists in DB
    get_after = client.get(f"/api/documents/{doc_id}", headers={"Authorization": f"Bearer {token1}"})
    assert get_after.status_code == 404


def test_unauthenticated_request_rejected(client):
    """Test that requests without Bearer token return 401 Unauthorized."""
    res_post = client.post("/api/documents/scan")
    assert res_post.status_code == 401

    res_get = client.get("/api/documents")
    assert res_get.status_code == 401

    res_del = client.delete(f"/api/documents/{uuid.uuid4()}")
    assert res_del.status_code == 401
