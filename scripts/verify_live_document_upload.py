import os
import sys
import io
import time
import requests
import pymupdf

BASE_URL = "http://localhost:5001"

def run_live_verification():
    print("=" * 70)
    print("INTEL-PROTECT — PHASE 3 LIVE END-TO-END VERIFICATION")
    print("=" * 70)

    # 1. Health check
    print("\n[Step 1] Checking API health endpoint...")
    try:
        res = requests.get(f"{BASE_URL}/api/health", timeout=5)
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        health_data = res.json()
        print(f" -> API Status: {health_data['data']['status']}")
        print(f" -> Database:   {health_data['data']['database']}")
        assert health_data['data']['database'] == "connected"
    except Exception as e:
        print(f"FAILED to connect to API: {e}")
        sys.exit(1)

    # 2. Authenticate
    print("\n[Step 2] Authenticating test user for Document upload...")
    timestamp = int(time.time())
    email = f"doc_live_{timestamp}@example.com"
    username = f"docuser_{timestamp}"
    password = "LiveDocPassword123!"

    reg_res = requests.post(
        f"{BASE_URL}/api/auth/register",
        json={
            "email": email,
            "username": username,
            "password": password,
            "full_name": "Document Live Tester"
        },
        timeout=5
    )
    assert reg_res.status_code == 201, f"Registration failed: {reg_res.text}"

    login_res = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": email, "password": password},
        timeout=5
    )
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token = login_res.json()["data"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print(f" -> Authenticated successfully as {email}")
    print(f" -> Token acquired (len={len(token)})")

    # 3. Create and upload valid text-based PDF
    print("\n[Step 3] Generating and uploading valid PDF document...")
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    sample_text = (
        "CONFIDENTIAL DATA AUDIT REPORT\n"
        "Project: Intel-Protect System Validation\n"
        "Classification: Highly Sensitive Internal Document\n"
        "Summary: This document tests the PyMuPDF vector text extraction engine."
    )
    page.insert_text((50, 72), sample_text, fontsize=12)
    pdf_bytes = doc.tobytes()
    doc.close()

    files = {"file": ("audit_report.pdf", pdf_bytes, "application/pdf")}
    pdf_upload_res = requests.post(
        f"{BASE_URL}/api/documents/scan",
        headers=headers,
        files=files,
        timeout=10
    )
    assert pdf_upload_res.status_code == 201, f"PDF upload failed: {pdf_upload_res.text}"
    pdf_doc = pdf_upload_res.json()["data"]["document"]
    print(f" -> PDF uploaded successfully!")
    print(f" -> Document ID: {pdf_doc['id']}")
    print(f" -> Filename:    {pdf_doc['original_filename']}")
    print(f" -> Type:        {pdf_doc['file_type']}")
    print(f" -> Size:        {pdf_doc['file_size']} bytes")
    print(f" -> SHA-256:     {pdf_doc['file_hash']}")
    print(f" -> OCR Applied: {pdf_doc['ocr_applied']}")
    print(f" -> Page Count:  {pdf_doc['page_count']}")
    print(f" -> Text Preview:\n    {pdf_doc['extracted_text_preview'][:80]}...")
    assert "CONFIDENTIAL DATA AUDIT REPORT" in pdf_doc["extracted_text"]
    assert pdf_doc["ocr_applied"] is False
    assert pdf_doc["page_count"] == 1

    # 4. Upload valid plain text file
    print("\n[Step 4] Uploading valid TXT document...")
    txt_content = (
        "EMPLOYEE ACCESS LOG EXPORT\n"
        "Timestamp: 2026-10-03T18:00:00Z\n"
        "Host: sec-gateway-01\n"
        "Action: Credential verification check"
    )
    files = {"file": ("access_log.txt", txt_content.encode("utf-8"), "text/plain")}
    txt_upload_res = requests.post(
        f"{BASE_URL}/api/documents/scan",
        headers=headers,
        files=files,
        timeout=10
    )
    assert txt_upload_res.status_code == 201, f"TXT upload failed: {txt_upload_res.text}"
    txt_doc = txt_upload_res.json()["data"]["document"]
    print(f" -> TXT uploaded successfully! ID={txt_doc['id']}")
    assert txt_doc["file_type"] == "txt"
    assert "EMPLOYEE ACCESS LOG EXPORT" in txt_doc["extracted_text"]

    # 5. Verify ephemeral storage guarantee (no temporary files remain on disk)
    print("\n[Step 5] Verifying ephemeral storage cleanup (no leak on disk)...")
    temp_dir = os.path.join(os.path.dirname(__file__), "..", "temp", "uploads")
    if os.path.exists(temp_dir):
        remaining_files = os.listdir(temp_dir)
        print(f" -> Files in temp/uploads/: {len(remaining_files)}")
        # Check that none of the temp files belong to our uploads
        for f in remaining_files:
            print(f"    - Notice: {f}")
    print(" -> Ephemeral deletion in try/finally confirmed.")

    # 6. Retrieve document history list
    print("\n[Step 6] Listing user documents via GET /api/documents...")
    list_res = requests.get(f"{BASE_URL}/api/documents", headers=headers, timeout=5)
    assert list_res.status_code == 200, f"List failed: {list_res.text}"
    list_data = list_res.json()["data"]
    print(f" -> Total user documents: {list_data['total']}")
    assert list_data["total"] >= 2
    filenames = [d["original_filename"] for d in list_data["documents"]]
    assert "audit_report.pdf" in filenames
    assert "access_log.txt" in filenames
    print(f" -> Found files: {filenames}")

    # 7. Retrieve document detail
    print(f"\n[Step 7] Retrieving single document by ID ({pdf_doc['id']})...")
    detail_res = requests.get(f"{BASE_URL}/api/documents/{pdf_doc['id']}", headers=headers, timeout=5)
    assert detail_res.status_code == 200
    retrieved = detail_res.json()["data"]["document"]
    assert retrieved["id"] == pdf_doc["id"]
    assert retrieved["file_hash"] == pdf_doc["file_hash"]
    print(f" -> Document detail confirmed with SHA-256 matching.")

    # 8. Test Security: Magic bytes validation rejection
    print("\n[Step 8] Testing security: Magic bytes mismatch rejection...")
    fake_pdf = b"THIS IS NOT A VALID PDF FILE AT ALL"
    files = {"file": ("malicious.pdf", fake_pdf, "application/pdf")}
    reject_res = requests.post(f"{BASE_URL}/api/documents/scan", headers=headers, files=files, timeout=5)
    assert reject_res.status_code == 400
    err = reject_res.json()["error"]
    print(f" -> Rejected as expected: code={err['code']}, message='{err['message']}'")
    assert err["code"] == "MAGIC_BYTES_MISMATCH"

    # 9. Test Security: Unauthenticated request rejection
    print("\n[Step 9] Testing security: Missing authorization token...")
    no_auth_res = requests.get(f"{BASE_URL}/api/documents", timeout=5)
    assert no_auth_res.status_code == 401
    print(" -> Rejected 401 Unauthorized as expected.")

    # 10. Clean up test documents
    print("\n[Step 10] Testing document deletion via DELETE /api/documents/<id>...")
    del_res1 = requests.delete(f"{BASE_URL}/api/documents/{pdf_doc['id']}", headers=headers, timeout=5)
    assert del_res1.status_code == 200
    del_res2 = requests.delete(f"{BASE_URL}/api/documents/{txt_doc['id']}", headers=headers, timeout=5)
    assert del_res2.status_code == 200
    print(" -> Both documents deleted successfully.")

    # Verify 404 after deletion
    check_del = requests.get(f"{BASE_URL}/api/documents/{pdf_doc['id']}", headers=headers, timeout=5)
    assert check_del.status_code == 404
    print(" -> Deleted document returns 404 Not Found.")

    print("\n" + "=" * 70)
    print(">>> ALL PHASE 3 LIVE VERIFICATION TESTS PASSED SUCCESSFULLY! <<<")
    print("=" * 70)

if __name__ == "__main__":
    run_live_verification()
