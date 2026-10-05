import logging
from backend.app.common.logging import redact_sensitive_string, PIIRedactionFilter


def test_redact_aadhaar_numbers():
    text = "User Aadhaar number is 1234 5678 9012 and unspaced 987654321098."
    redacted = redact_sensitive_string(text)
    assert "1234 5678 9012" not in redacted
    assert "987654321098" not in redacted
    assert "[REDACTED:AADHAAR]" in redacted


def test_redact_pan_numbers():
    text = "Account verification PAN: ABCDE1234F submitted."
    redacted = redact_sensitive_string(text)
    assert "ABCDE1234F" not in redacted
    assert "[REDACTED:PAN]" in redacted


def test_redact_credit_cards():
    text = "Processed transaction with card 4111 2222 3333 4444."
    redacted = redact_sensitive_string(text)
    assert "4111 2222 3333 4444" not in redacted
    assert "[REDACTED:CARD]" in redacted


def test_redact_emails_and_phones():
    text = "Contact user at test.user@example.com or phone +91 9876543210."
    redacted = redact_sensitive_string(text)
    assert "test.user@example.com" not in redacted
    assert "+91 9876543210" not in redacted
    assert "[REDACTED:EMAIL]" in redacted
    assert "[REDACTED:PHONE]" in redacted


def test_redact_credentials_and_tokens():
    text = 'Incoming auth request: {"password": "SuperSecret123!", "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak"}'
    redacted = redact_sensitive_string(text)
    assert "SuperSecret123!" not in redacted
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted
    assert "[REDACTED:PASSWORD]" in redacted
    assert "[REDACTED:JWT]" in redacted


def test_logging_filter_redacts_record_message():
    log_filter = PIIRedactionFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="User rahul@example.com logged in with PAN ABCDE9999Z",
        args=(),
        exc_info=None
    )
    log_filter.filter(record)
    assert "rahul@example.com" not in record.msg
    assert "ABCDE9999Z" not in record.msg
    assert "[REDACTED:EMAIL]" in record.msg
    assert "[REDACTED:PAN]" in record.msg
