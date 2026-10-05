"""
Centralized PII Masking Module.
Ensures zero raw sensitive information is returned in API responses or persisted in findings.
"""
import re


def mask_aadhaar(val: str) -> str:
    """
    Masks a 12-digit Aadhaar number:
    Format: XXXX XXXX 1234 (retains only the final 4 digits).
    """
    digits = re.sub(r"\D", "", val)
    if len(digits) != 12:
        return "XXXX XXXX " + (digits[-4:] if len(digits) >= 4 else "XXXX")
    return f"XXXX XXXX {digits[-4:]}"


def mask_pan(val: str) -> str:
    """
    Masks a 10-character PAN number:
    Format: XXXXX1234X (masks first 5 letters and final check letter, keeps numeric section).
    """
    clean = re.sub(r"\s", "", val).upper()
    if len(clean) != 10:
        return "XXXXX" + (clean[5:9] if len(clean) >= 9 else "XXXX") + "X"
    return f"XXXXX{clean[5:9]}X"


def mask_card(val: str) -> str:
    """
    Masks a payment card number:
    Format: **** **** **** 1234 (preserves only the last 4 digits).
    """
    digits = re.sub(r"\D", "", val)
    last_four = digits[-4:] if len(digits) >= 4 else "****"
    if len(digits) == 16:
        return f"**** **** **** {last_four}"
    elif len(digits) == 15:
        return f"**** ****** *{last_four}"
    else:
        num_masked = max(len(digits) - 4, 6)
        return "*" * num_masked + last_four


def mask_bank_account(val: str) -> str:
    """
    Masks a bank account number:
    Format: ******7890 (retains only the final 4 digits).
    """
    digits = re.sub(r"\D", "", val)
    if len(digits) <= 4:
        return "****"
    masked_prefix = "*" * max(len(digits) - 4, 6)
    return f"{masked_prefix}{digits[-4:]}"


def mask_email(val: str) -> str:
    """
    Masks an email address:
    Format: r****a@domain.com (first char + **** + last char of username + @ + domain).
    """
    clean = val.strip()
    if "@" not in clean:
        return "*****@masked.local"
    user_part, domain_part = clean.split("@", 1)
    if len(user_part) <= 2:
        masked_user = user_part[0] + "***" if len(user_part) >= 1 else "***"
    else:
        masked_user = f"{user_part[0]}****{user_part[-1]}"
    return f"{masked_user}@{domain_part}"


def mask_phone(val: str) -> str:
    """
    Masks an Indian phone number:
    Format: +91-XXXXX-98765 or XXXXXX1234 (preserves last 4-5 digits).
    """
    digits = re.sub(r"\D", "", val)
    last_digits = digits[-4:] if len(digits) >= 4 else "XXXX"
    if digits.startswith("91") and len(digits) == 12:
        return f"+91-XXXXX-{digits[-5:]}"
    elif len(digits) >= 10:
        return f"XXXXXX{digits[-4:]}"
    return f"***-***-{last_digits}"


def mask_pii_value(pii_type: str, raw_value: str) -> str:
    """
    Central dispatcher that masks raw PII values by category.
    """
    if not raw_value:
        return "[MASKED]"

    p_type = pii_type.upper()
    if p_type == "AADHAAR":
        return mask_aadhaar(raw_value)
    elif p_type == "PAN":
        return mask_pan(raw_value)
    elif p_type in ("CARD", "CREDIT_CARD", "DEBIT_CARD"):
        return mask_card(raw_value)
    elif p_type in ("BANK_ACCOUNT", "ACCOUNT_NUMBER"):
        return mask_bank_account(raw_value)
    elif p_type == "EMAIL":
        return mask_email(raw_value)
    elif p_type == "PHONE":
        return mask_phone(raw_value)
    else:
        # Generic fallback
        if len(raw_value) > 4:
            return "*" * (len(raw_value) - 4) + raw_value[-4:]
        return "****"


def mask_context_snippet(raw_snippet: str, raw_value: str, masked_value: str) -> str:
    """
    Replaces the raw sensitive value within a surrounding context snippet
    to prevent any leakage of unmasked data into context previews.
    """
    if not raw_snippet or not raw_value:
        return ""
    # Safe substitution
    return raw_snippet.replace(raw_value, masked_value)
