"""
Deterministic Checksum Validation Algorithms.
Provides mathematically rigorous Verhoeff (Aadhaar) and Luhn (Payment Cards) checksum validation.
"""
import re


# ==============================================================================
# 1. VERHOEFF ALGORITHM (Aadhaar 12-digit Checksum)
# Based on the dihedral group D5 permutation tables.
# ==============================================================================

# Multiplication table d based on D5 dihedral group
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

# Permutation table p
VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

# Inverse table inv
VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(number_str: str) -> bool:
    """
    Validates a numeric string using the Verhoeff check digit algorithm.
    Required for UIDAI Aadhaar number verification.

    Args:
        number_str: Numeric string (e.g. 12 digits for Aadhaar).
    Returns:
        True if check digit is valid according to Verhoeff, False otherwise.
    """
    if not number_str or not isinstance(number_str, str):
        return False

    # Strip any whitespace or hyphens
    clean_num = re.sub(r"[\s\-]", "", number_str)
    if not clean_num.isdigit():
        return False

    c = 0
    # Process digits in reverse order
    for i, digit_char in enumerate(reversed(clean_num)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(digit_char)]]

    return c == 0


def compute_verhoeff(number_str: str) -> int:
    """
    Computes the Verhoeff check digit for an input string of digits.
    Used for generating valid synthetic Aadhaar test vectors.
    """
    clean_num = re.sub(r"[\s\-]", "", str(number_str))
    if not clean_num.isdigit():
        raise ValueError("Input must consist solely of digits.")

    c = 0
    # Process existing digits reversed with offset index starting at 1
    for i, digit_char in enumerate(reversed(clean_num)):
        c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][int(digit_char)]]

    return VERHOEFF_INV[c]


# ==============================================================================
# 2. LUHN ALGORITHM (Payment Card Mod-10 Checksum)
# Validates ISO/IEC 7812 credit and debit card numbers.
# ==============================================================================

def validate_luhn(card_number_str: str) -> bool:
    """
    Validates a payment card number using the Luhn Modulo 10 algorithm.
    Handles spaces and hyphens commonly present in card numbers.

    Args:
        card_number_str: String containing 13 to 19 digits.
    Returns:
        True if Luhn checksum is valid, False otherwise.
    """
    if not card_number_str or not isinstance(card_number_str, str):
        return False

    clean_card = re.sub(r"[\s\-]", "", card_number_str)
    if not clean_card.isdigit():
        return False

    # Card numbers range from 13 to 19 digits (ISO/IEC 7812)
    if len(clean_card) < 13 or len(clean_card) > 19:
        return False

    total = 0
    num_digits = len(clean_card)
    parity = num_digits % 2

    for i, char in enumerate(clean_card):
        digit = int(char)
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return (total % 10) == 0


def compute_luhn(partial_num_str: str) -> int:
    """
    Computes the Luhn check digit for a partial card number.
    Used for generating valid synthetic card numbers in test fixtures.
    """
    clean_num = re.sub(r"[\s\-]", "", str(partial_num_str))
    if not clean_num.isdigit():
        raise ValueError("Input must consist solely of digits.")

    total = 0
    # From right to left, every second digit is doubled starting from position 0 of reversed partial
    for i, char in enumerate(reversed(clean_num)):
        digit = int(char)
        if i % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return (10 - (total % 10)) % 10
