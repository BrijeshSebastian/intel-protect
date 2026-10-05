import re
import logging

# Centralized regex patterns for sensitive data redaction in logs
# NOTE: Longer numeric patterns (e.g. 16-digit cards) are matched BEFORE shorter ones (e.g. 12-digit Aadhaar)
REDACTION_PATTERNS = [
    # Authorization header / Bearer token
    (re.compile(r'(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9_\-\.]+', re.IGNORECASE), r'\1[REDACTED:JWT]'),
    (re.compile(r'\bBearer\s+[A-Za-z0-9_\-\.]+\b', re.IGNORECASE), '[REDACTED:JWT]'),

    # Raw JWT tokens (header.payload.signature)
    (re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'), '[REDACTED:JWT]'),

    # Refresh tokens in cookies or logs (refresh_token=...)
    (re.compile(r'(?i)(refresh_token=)[A-Za-z0-9_\-]{20,}', re.IGNORECASE), r'\1[REDACTED:REFRESH_TOKEN]'),

    # Passwords in JSON / query params / key-value logs
    (re.compile(r'(?i)(["\']?password["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1[REDACTED:PASSWORD]\3'),

    # Credit/Debit Card numbers (13-19 digits, 4-4-4-4 or continuous)
    (re.compile(r'\b(?:\d{4}[-\s]){3}\d{4}\b|\b\d{16}\b'), '[REDACTED:CARD]'),

    # Aadhaar numbers (12 digits: 4-4-4 or continuous 12 digits)
    (re.compile(r'\b(?:\d{4}[-\s]){2}\d{4}\b|\b\d{12}\b'), '[REDACTED:AADHAAR]'),

    # PAN numbers (Indian Permanent Account Number: 5 letters, 4 digits, 1 letter)
    (re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b', re.IGNORECASE), '[REDACTED:PAN]'),

    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), '[REDACTED:EMAIL]'),

    # Phone numbers (Indian phone numbers: +91 or starting with 6-9, 10 digits)
    (re.compile(r'\b(?:\+91[-\s]?)?[6-9]\d{9}\b'), '[REDACTED:PHONE]'),

    # Bank Account numbers (with account context keyword)
    (re.compile(r'(?i)(account(?:\s*number|\s*no)?\s*[:=]?\s*)(\d{9,18})', re.IGNORECASE), r'\1[REDACTED:BANK_ACCOUNT]'),
]


def redact_sensitive_string(text: str) -> str:
    """Redacts sensitive PII and credential patterns from text string."""
    if not isinstance(text, str):
        return text

    sanitized = text
    for pattern, replacement in REDACTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


class PIIRedactionFilter(logging.Filter):
    """
    Logging filter that intercepts all logging records and
    automatically sanitizes message text and format arguments.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = redact_sensitive_string(record.msg)

            if record.args:
                if isinstance(record.args, dict):
                    record.args = {k: redact_sensitive_string(v) if isinstance(v, str) else v for k, v in record.args.items()}
                elif isinstance(record.args, tuple):
                    record.args = tuple(redact_sensitive_string(arg) if isinstance(arg, str) else arg for arg in record.args)
        except Exception:
            pass  # Ensure logging never crashes the application

        return True


def setup_pii_safe_logging():
    """Attaches the PIIRedactionFilter to the root logger and all active handlers."""
    redaction_filter = PIIRedactionFilter()
    root_logger = logging.getLogger()
    root_logger.addFilter(redaction_filter)

    for handler in root_logger.handlers:
        handler.addFilter(redaction_filter)
