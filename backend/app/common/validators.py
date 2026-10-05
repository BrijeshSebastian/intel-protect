import os
import hashlib
from werkzeug.utils import secure_filename
from backend.app.common.errors import AppError

# Configuration constants
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "txt"}

# Known file magic signatures
MAGIC_SIGNATURES = {
    "pdf": [b"%PDF-"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
}


class FileValidationError(AppError):
    def __init__(self, message="Invalid file uploaded.", code="FILE_VALIDATION_ERROR", status_code=400):
        super().__init__(message=message, code=code, status_code=status_code)


def validate_uploaded_file(file_storage) -> tuple[str, str, int, str]:
    """
    Performs multi-layer file validation:
    1. Presence and non-empty check
    2. Path traversal sanitization
    3. Extension allowlist check
    4. Size limit enforcement
    5. Content magic-bytes inspection (not trusting Content-Type header)
    6. SHA-256 integrity hash calculation
    
    Returns:
        (sanitized_filename, normalized_extension, file_size, file_sha256)
    """
    if not file_storage or not file_storage.filename:
        raise FileValidationError("No file selected for upload.", code="NO_FILE_PROVIDED")

    # 1. Sanitize filename against path traversal
    raw_filename = os.path.basename(file_storage.filename)
    safe_name = secure_filename(raw_filename)
    if not safe_name:
        raise FileValidationError("Invalid filename provided.", code="INVALID_FILENAME")

    # 2. Check extension
    if "." not in safe_name:
        raise FileValidationError("File lacks an extension.", code="MISSING_EXTENSION")

    ext = safe_name.rsplit(".", 1)[1].lower()
    if ext == "jpeg":
        ext = "jpg"

    if ext not in ALLOWED_EXTENSIONS:
        raise FileValidationError(
            f"Unsupported file type '.{ext}'. Allowed types: PDF, PNG, JPG, JPEG, TXT.",
            code="UNSUPPORTED_FILE_TYPE"
        )

    # 3. Read content bytes into memory for inspection
    file_bytes = file_storage.read()
    file_size = len(file_bytes)

    # Reset stream pointer for downstream consumers
    file_storage.seek(0)

    # 4. Check size bounds
    if file_size == 0:
        raise FileValidationError("The uploaded file is empty (0 bytes).", code="EMPTY_FILE")

    if file_size > MAX_FILE_SIZE_BYTES:
        raise FileValidationError(
            f"File size exceeds the 10 MB limit (received {file_size / (1024*1024):.2f} MB).",
            code="FILE_TOO_LARGE",
            status_code=413
        )

    # 5. Magic bytes inspection
    if ext in MAGIC_SIGNATURES:
        signatures = MAGIC_SIGNATURES[ext]
        matches_magic = any(file_bytes.startswith(sig) for sig in signatures)
        if not matches_magic:
            raise FileValidationError(
                f"File content does not match genuine {ext.upper()} format (magic bytes mismatch).",
                code="MAGIC_BYTES_MISMATCH"
            )
    elif ext == "txt":
        # Validate that text file contains valid UTF-8/ASCII without null bytes or binary executables
        if b"\x00" in file_bytes[:1024]:
            raise FileValidationError(
                "Binary or executable file disguised as a text file.",
                code="BINARY_DISGUISED_AS_TEXT"
            )
        try:
            file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                file_bytes.decode("latin-1")
            except Exception:
                raise FileValidationError(
                    "Text file encoding is unreadable or malformed.",
                    code="INVALID_TEXT_ENCODING"
                )

    # 6. Compute SHA-256
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    return safe_name, ext, file_size, file_hash
