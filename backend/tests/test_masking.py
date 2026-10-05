"""
Unit tests for centralized PII Masking module (masker.py).
Ensures zero sensitive plaintext leaks into API responses, database previews, or logs.
"""
import pytest
from backend.app.documents.masker import (
    mask_aadhaar,
    mask_pan,
    mask_card,
    mask_bank_account,
    mask_email,
    mask_phone,
    mask_pii_value,
    mask_context_snippet
)


def test_mask_aadhaar():
    """Verify Aadhaar masking maintains 4-4-4 spacing and exposes only last 4 digits."""
    raw = "2345 6789 0123"
    masked = mask_aadhaar(raw)
    assert masked == "XXXX XXXX 0123"
    assert "2345" not in masked
    assert "6789" not in masked


def test_mask_pan():
    """Verify PAN masking: format XXXXX1234X."""
    raw = "ABCDE1234F"
    masked = mask_pan(raw)
    assert masked == "XXXXX1234X"
    assert "ABCDE" not in masked
    assert "F" not in masked[-1]  # Last check letter is masked


def test_mask_card_16_digits():
    """Verify 16-digit payment card masking: format **** **** **** 1234."""
    raw = "4532 0151 1283 0366"
    masked = mask_card(raw)
    assert masked == "**** **** **** 0366"
    assert "4532" not in masked
    assert "0151" not in masked


def test_mask_card_15_digits_amex():
    """Verify 15-digit Amex card masking."""
    raw = "378282246310005"
    masked = mask_card(raw)
    assert masked.endswith("0005")
    assert "3782" not in masked


def test_mask_bank_account():
    """Verify bank account masking hides prefix and keeps only last 4 digits."""
    raw = "987654321098"
    masked = mask_bank_account(raw)
    assert masked.endswith("098") or masked.endswith("1098")
    assert masked == "********1098"
    assert "987654" not in masked


def test_mask_email():
    """Verify email masking preserves domain while redacting username."""
    raw = "rahul.sharma@example.com"
    masked = mask_email(raw)
    assert "@example.com" in masked
    assert "rahul.sharma" not in masked
    assert masked.startswith("r")


def test_mask_phone():
    """Verify Indian phone masking."""
    raw = "+91-9876543210"
    masked = mask_phone(raw)
    assert masked == "+91-XXXXX-43210"
    assert "98765" not in masked

    raw10 = "9876543210"
    masked10 = mask_phone(raw10)
    assert masked10 == "XXXXXX3210"


def test_mask_context_snippet_replaces_sensitive_value():
    """Verify context snippet masking replaces the sensitive plaintext with masked value."""
    snippet = "Account holder details: Rahul Sharma, Aadhaar No: 2345 6789 0123 verified successfully."
    raw_val = "2345 6789 0123"
    masked_val = "XXXX XXXX 0123"
    safe = mask_context_snippet(snippet, raw_val, masked_val)

    assert raw_val not in safe
    assert masked_val in safe
    assert "Account holder details" in safe
    assert "verified successfully" in safe


def test_mask_pii_value_dispatcher():
    """Verify central dispatcher correctly calls specific maskers."""
    assert mask_pii_value("AADHAAR", "234567890123") == "XXXX XXXX 0123"
    assert mask_pii_value("PAN", "ABCDE1234F") == "XXXXX1234X"
    assert mask_pii_value("CARD", "4532015112830366") == "**** **** **** 0366"
    assert mask_pii_value("BANK_ACCOUNT", "123456789012") == "********9012"
    assert "@example.com" in mask_pii_value("EMAIL", "test@example.com")
