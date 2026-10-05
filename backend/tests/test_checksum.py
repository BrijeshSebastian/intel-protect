"""
Unit tests for deterministic checksum validation algorithms:
1. Verhoeff Algorithm (Aadhaar UIDAI)
2. Luhn Modulo-10 Algorithm (Payment Cards ISO/IEC 7812)
"""
import pytest
from backend.app.documents.checksum import (
    validate_verhoeff,
    compute_verhoeff,
    validate_luhn,
    compute_luhn,
)


# ==============================================================================
# 1. VERHOEFF ALGORITHM TESTS
# ==============================================================================

class TestVerhoeffAlgorithm:
    """Rigorous mathematical tests for Verhoeff dihedral group D5 checksum."""

    # Known valid Verhoeff vectors
    VALID_VERHOEFF_NUMBERS = [
        "236",          # 23 + check 6
        "123451",       # 12345 + check 1
        "1428570",      # 142857 + check 0
        "8473644",      # 847364 + check 4
        "50403020106",  # 10 digits + check 6
    ]

    def test_compute_and_validate_verhoeff(self):
        """Test that compute_verhoeff yields digits that pass validate_verhoeff."""
        base_numbers = [
            "12345",
            "98765432101",   # 11-digit Aadhaar base
            "20987654321",   # Another 11-digit base
            "54321678901",
            "36758492019",
        ]
        for base in base_numbers:
            check_digit = compute_verhoeff(base)
            full_number = f"{base}{check_digit}"
            assert validate_verhoeff(full_number) is True, f"Failed for {full_number}"

    def test_known_valid_verhoeff_vectors(self):
        """Verify known valid test vectors."""
        for num in self.VALID_VERHOEFF_NUMBERS:
            assert validate_verhoeff(num) is True

    def test_verhoeff_detects_single_digit_substitutions(self):
        """Verhoeff is mathematically proven to detect 100% of single-digit substitution errors."""
        base = "20987654321"
        check = compute_verhoeff(base)
        valid = f"{base}{check}"
        assert validate_verhoeff(valid) is True

        # Mutate every single digit and verify detection
        for pos in range(len(valid)):
            original_digit = int(valid[pos])
            for replacement in range(10):
                if replacement == original_digit:
                    continue
                mutated = valid[:pos] + str(replacement) + valid[pos + 1:]
                assert validate_verhoeff(mutated) is False, f"Failed to detect substitution at {pos}"

    def test_verhoeff_detects_adjacent_transpositions(self):
        """Verhoeff is mathematically proven to detect 100% of single adjacent transpositions."""
        base = "24987654321"
        check = compute_verhoeff(base)
        valid = f"{base}{check}"
        assert validate_verhoeff(valid) is True

        # Swap every adjacent pair
        for pos in range(len(valid) - 1):
            if valid[pos] == valid[pos + 1]:
                continue
            transposed = valid[:pos] + valid[pos + 1] + valid[pos] + valid[pos + 2:]
            assert validate_verhoeff(transposed) is False, f"Failed to detect transposition at {pos}"

    def test_verhoeff_with_spaces_and_hyphens(self):
        """Test that formatting characters (spaces, hyphens) are normalized correctly."""
        base = "21987654321"
        check = compute_verhoeff(base)
        # 12-digit Aadhaar style
        spaced = f"{base[:4]} {base[4:8]} {base[8:]}{check}"
        hyphenated = f"{base[:4]}-{base[4:8]}-{base[8:]}{check}"
        assert validate_verhoeff(spaced) is True
        assert validate_verhoeff(hyphenated) is True

    def test_verhoeff_invalid_inputs(self):
        """Test rejection of non-numeric, empty, or None inputs."""
        assert validate_verhoeff("") is False
        assert validate_verhoeff("ABCD") is False
        assert validate_verhoeff(None) is False
        assert validate_verhoeff("1234ABCD5678") is False


# ==============================================================================
# 2. LUHN ALGORITHM TESTS
# ==============================================================================

class TestLuhnAlgorithm:
    """Rigorous tests for ISO/IEC 7812 Luhn Mod-10 checksum validation."""

    # Standard synthetic test card numbers that pass Luhn
    VALID_LUHN_CARDS = [
        "4532015112830366",   # Synthetic Visa 16-digit
        "5425233430109903",   # Synthetic MasterCard 16-digit
        "378282246310005",    # Synthetic Amex 15-digit
        "6011000990139424",   # Synthetic Discover 16-digit
        "6521501234567893",   # Synthetic RuPay 16-digit
    ]

    def test_compute_and_validate_luhn(self):
        """Test compute_luhn check digit generation and validation."""
        partial_cards = [
            "453201511283036",   # 15 digits
            "542523343010990",   # 15 digits
            "37828224631000",    # 14 digits
            "601100099013942",   # 15 digits
        ]
        for partial in partial_cards:
            check_digit = compute_luhn(partial)
            full_card = f"{partial}{check_digit}"
            assert validate_luhn(full_card) is True, f"Failed for {full_card}"

    def test_known_valid_luhn_cards(self):
        """Verify known valid synthetic card vectors."""
        for card in self.VALID_LUHN_CARDS:
            assert validate_luhn(card) is True

    def test_luhn_detects_single_digit_errors(self):
        """Test that altering any single digit invalidates Luhn checksum."""
        valid_card = "4532015112830366"
        assert validate_luhn(valid_card) is True

        for pos in range(len(valid_card)):
            original = int(valid_card[pos])
            for replacement in range(10):
                if replacement == original:
                    continue
                mutated = valid_card[:pos] + str(replacement) + valid_card[pos + 1:]
                assert validate_luhn(mutated) is False, f"Luhn failed to catch error at {pos}"

    def test_luhn_with_formatting(self):
        """Test Luhn validation with standard 4-4-4-4 spaces and hyphens."""
        card_spaced = "4532 0151 1283 0366"
        card_hyphenated = "4532-0151-1283-0366"
        assert validate_luhn(card_spaced) is True
        assert validate_luhn(card_hyphenated) is True

    def test_luhn_length_boundaries(self):
        """Test that numbers shorter than 13 digits or longer than 19 digits are rejected."""
        # 12 digits (too short for ISO 7812)
        assert validate_luhn("123456789012") is False
        # 20 digits (too long)
        assert validate_luhn("12345678901234567890") is False

    def test_luhn_invalid_inputs(self):
        """Test rejection of non-numeric, empty, or None inputs."""
        assert validate_luhn("") is False
        assert validate_luhn("4532ABCD12830366") is False
        assert validate_luhn(None) is False
