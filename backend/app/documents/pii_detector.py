"""
Rule-Based PII Detection Engine.
Deterministic multi-pattern regex extraction, contextual verification,
and checksum validation (Verhoeff for Aadhaar, Luhn for Payment Cards).
"""
import re
from dataclasses import dataclass
from typing import Optional

from backend.app.documents.checksum import validate_verhoeff, validate_luhn
from backend.app.documents.masker import mask_pii_value, mask_context_snippet


@dataclass
class PIIDetectionResult:
    pii_type: str
    raw_value: str
    masked_value: str
    confidence: float
    severity: str
    checksum_valid: Optional[bool]
    detection_method: str
    context_snippet: str
    position_start: int
    position_end: int

    def to_dict(self):
        return {
            "pii_type": self.pii_type,
            "masked_value": self.masked_value,
            "confidence": round(self.confidence, 4),
            "severity": self.severity,
            "checksum_valid": self.checksum_valid,
            "detection_method": self.detection_method,
            "context_snippet": self.context_snippet,
            "position_start": self.position_start,
            "position_end": self.position_end,
        }


# ==============================================================================
# COMPILED REGEX PATTERNS
# ==============================================================================

# 1. Aadhaar: 12 digits, first digit [2-9], optional 4-4-4 spaces or hyphens
AADHAAR_REGEX = re.compile(
    r"(?<!\d)([2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4})(?!\d)"
)

# 2. PAN: 5 uppercase letters, 4 digits, 1 uppercase letter
PAN_REGEX = re.compile(
    r"(?<![A-Za-z0-9])([A-Za-z]{5}\d{4}[A-Za-z])(?![A-Za-z0-9])"
)

# 3. Payment Cards: 13-19 digits, major card network prefixes, with optional spaces/hyphens
CARD_REGEX = re.compile(
    r"(?<!\d)(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2})|3[47]\d{2}|3(?:0[0-5]|[68]\d)\d|8[1-9]\d{2}|60\d{2})"
    r"[\s\-]?(?:\d{4}[\s\-]?\d{4}[\s\-]?\d{1,7}|\d{6}[\s\-]?\d{4,5}|\d{4}[\s\-]?\d{4}[\s\-]?\d{4})"
    r"(?!\d)"
)
# Secondary fallback for generic 13-19 digits card candidates
GENERIC_CARD_REGEX = re.compile(
    r"(?<!\d)(\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{1,7})(?!\d)"
)

# 4. Bank Account: 9 to 18 digits (strictly requires contextual keywords nearby)
BANK_ACCOUNT_REGEX = re.compile(
    r"(?<!\d)(\d{9,18})(?!\d)"
)

# 5. Email: RFC 5322 pattern with word boundaries
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# 6. Phone: Indian mobile numbers (starts with 6-9, optional +91 or 0 prefix)
PHONE_REGEX = re.compile(
    r"(?<!\d)(?:(?:\+91[\s\-]?)?|(?:0)?[6-9]\d{4}[\s\-]?\d{5})(?!\d)"
)
INDIAN_PHONE_STRICT = re.compile(
    r"(?<!\d)(?:(?:\+91[\s\-]?)?(?:0)?([6-9]\d{9})|(?:\+91[\s\-]?)?(?:0)?([6-9]\d{4}[\s\-]\d{5}))(?!\d)"
)

# Indian IFSC Code
IFSC_REGEX = re.compile(
    r"(?<![A-Za-z0-9])([A-Za-z]{4}0[A-Za-z0-9]{6})(?![A-Za-z0-9])"
)

# Context keyword indicators
CONTEXT_KEYWORDS = {
    "AADHAAR": ["aadhaar", "uidai", "aadhar", "uid", "unique identification", "mera aadhaar"],
    "PAN": ["pan", "permanent account", "income tax", "nsdl", "uti", "pan card"],
    "CARD": ["card", "credit", "debit", "visa", "mastercard", "rupay", "amex", "cvv", "expiry", "valid thru"],
    "BANK": [
        "account", "bank account", "a/c", "a/c no", "ac no", "acc no", "account number",
        "saving account", "current account", "bank a/c", "s/b a/c", "c/a a/c", "beneficiary", "ifsc"
    ],
    "PHONE": ["phone", "mobile", "mob", "cell", "contact", "tel", "call", "whatsapp"],
}


# ==============================================================================
# CONTEXT EXTRACTOR HELPER
# ==============================================================================

def get_surrounding_context(text: str, start: int, end: int, window: int = 50) -> tuple[str, str]:
    """
    Extracts surrounding text snippet within window characters of start and end.
    Returns (raw_snippet, lowercase_snippet_for_keyword_matching).
    """
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    raw_snippet = text[ctx_start:ctx_end].replace("\n", " ").replace("\r", " ")
    # Clean multiple spaces
    raw_snippet = re.sub(r"\s+", " ", raw_snippet).strip()
    return raw_snippet, raw_snippet.lower()


def has_context_keywords(snippet_lower: str, keywords: list[str]) -> bool:
    """Checks whether any contextual keyword appears in the snippet."""
    return any(kw in snippet_lower for kw in keywords)


# ==============================================================================
# INDIVIDUAL PII DETECTORS
# ==============================================================================

def detect_aadhaar_findings(text: str) -> list[PIIDetectionResult]:
    """
    Detects Aadhaar candidates and applies strict Verhoeff checksum validation.
    Rejects format invalid or Verhoeff failed candidates.
    """
    findings = []
    for match in AADHAAR_REGEX.finditer(text):
        raw_val = match.group(1)
        clean_digits = re.sub(r"\D", "", raw_val)

        # Aadhaar must be exactly 12 digits
        if len(clean_digits) != 12:
            continue

        # Reject identical repeated patterns like 0000 0000 0000 or 1111 1111 1111
        if len(set(clean_digits)) == 1:
            continue

        # CRITICAL VALIDATION: Verhoeff Checksum
        is_verhoeff_valid = validate_verhoeff(clean_digits)
        if not is_verhoeff_valid:
            # Deterministic rule: Invalid checksum is NOT an Aadhaar number
            continue

        raw_snippet, snippet_lower = get_surrounding_context(text, match.start(), match.end())
        has_context = has_context_keywords(snippet_lower, CONTEXT_KEYWORDS["AADHAAR"])
        has_bank = has_context_keywords(snippet_lower, CONTEXT_KEYWORDS["BANK"])

        # If surrounding text has explicit bank account keywords and no Aadhaar keywords,
        # it is a bank account, not an Aadhaar number
        if has_bank and not has_context:
            continue

        confidence = 0.99 if has_context else 0.98
        detection_method = "regex+verhoeff+context" if has_context else "regex+verhoeff"

        masked_val = mask_pii_value("AADHAAR", clean_digits)
        safe_snippet = mask_context_snippet(raw_snippet, raw_val, masked_val)

        findings.append(PIIDetectionResult(
            pii_type="AADHAAR",
            raw_value=raw_val,
            masked_value=masked_val,
            confidence=confidence,
            severity="HIGH",
            checksum_valid=True,
            detection_method=detection_method,
            context_snippet=safe_snippet,
            position_start=match.start(),
            position_end=match.end(),
        ))

    return findings


def detect_pan_findings(text: str) -> list[PIIDetectionResult]:
    """
    Detects Indian Permanent Account Numbers (PAN).
    Validates structural pattern (5 letters, 4 digits, 1 letter) with valid 4th entity letter.
    """
    findings = []
    for match in PAN_REGEX.finditer(text):
        raw_val = match.group(1).upper()

        entity_letter = raw_val[3]
        is_statutory = entity_letter in "ABCFGHLJPT"

        raw_snippet, snippet_lower = get_surrounding_context(text, match.start(), match.end())
        has_context = has_context_keywords(snippet_lower, CONTEXT_KEYWORDS["PAN"])

        # False-positive guard: If 4th letter is not a statutory entity code,
        # it is only classified as PAN if surrounding text explicitly contains PAN context.
        if not is_statutory and not has_context:
            continue

        if is_statutory:
            confidence = 0.99 if has_context else 0.95
            detection_method = "regex+pattern+context" if has_context else "regex+pattern"
        else:
            confidence = 0.88 if has_context else 0.80
            detection_method = "regex+context"

        masked_val = mask_pii_value("PAN", raw_val)
        safe_snippet = mask_context_snippet(raw_snippet, match.group(1), masked_val)

        findings.append(PIIDetectionResult(
            pii_type="PAN",
            raw_value=raw_val,
            masked_value=masked_val,
            confidence=confidence,
            severity="HIGH",
            checksum_valid=None,
            detection_method=detection_method,
            context_snippet=safe_snippet,
            position_start=match.start(),
            position_end=match.end(),
        ))

    return findings


def detect_card_findings(text: str) -> list[PIIDetectionResult]:
    """
    Detects credit/debit card numbers and validates via Luhn Mod-10 checksum algorithm.
    Rejects Luhn-invalid candidates to prevent false positives from long numbers.
    """
    findings = []
    matches = list(CARD_REGEX.finditer(text)) + list(GENERIC_CARD_REGEX.finditer(text))
    seen_spans = set()

    for match in matches:
        span = (match.start(), match.end())
        if span in seen_spans:
            continue
        seen_spans.add(span)

        raw_val = match.group(0)
        clean_digits = re.sub(r"\D", "", raw_val)

        # Card numbers are 13 to 19 digits
        if len(clean_digits) < 13 or len(clean_digits) > 19:
            continue

        # CRITICAL VALIDATION: Luhn Checksum
        is_luhn_valid = validate_luhn(clean_digits)
        if not is_luhn_valid:
            # Deterministic rule: Non-Luhn numbers are NOT payment cards
            continue

        raw_snippet, snippet_lower = get_surrounding_context(text, match.start(), match.end())
        has_context = has_context_keywords(snippet_lower, CONTEXT_KEYWORDS["CARD"])

        confidence = 0.99 if has_context else 0.96
        detection_method = "regex+luhn+context" if has_context else "regex+luhn"

        masked_val = mask_pii_value("CARD", clean_digits)
        safe_snippet = mask_context_snippet(raw_snippet, raw_val, masked_val)

        findings.append(PIIDetectionResult(
            pii_type="CARD",
            raw_value=raw_val,
            masked_value=masked_val,
            confidence=confidence,
            severity="CRITICAL",
            checksum_valid=True,
            detection_method=detection_method,
            context_snippet=safe_snippet,
            position_start=match.start(),
            position_end=match.end(),
        ))

    return findings


def detect_bank_account_findings(text: str) -> list[PIIDetectionResult]:
    """
    Detects bank account numbers (9-18 digits).
    STRICT CONTEXT REQUIREMENT:
    Because bank accounts have no universal checksum, bank account candidates
    MUST have contextual keywords in surrounding text (e.g. account, a/c, bank)
    or an IFSC code present in the document.
    """
    findings = []
    # Check if document has an IFSC code anywhere
    has_ifsc_in_doc = bool(IFSC_REGEX.search(text))

    for match in BANK_ACCOUNT_REGEX.finditer(text):
        raw_val = match.group(1)
        clean_digits = raw_val.strip()

        # Reject all identical digits
        if len(set(clean_digits)) == 1:
            continue

        # Ignore if preceded by phone prefix or phone keywords
        prefix_slice = text[max(0, match.start() - 15):match.start()].lower()
        if any(pk in prefix_slice for pk in ["mobile", "phone", "mob", "cell", "tel", "+91"]):
            continue
        if match.start() > 0 and text[match.start() - 1] in ("+", "-"):
            continue

        raw_snippet, snippet_lower = get_surrounding_context(text, match.start(), match.end())
        has_bank_context = has_context_keywords(snippet_lower, CONTEXT_KEYWORDS["BANK"])
        has_aadhaar_context = has_context_keywords(snippet_lower, CONTEXT_KEYWORDS["AADHAAR"])
        has_ifsc_nearby = bool(IFSC_REGEX.search(raw_snippet))

        # Discard candidate if anti-keywords are present and no explicit bank keyword
        anti_keywords = ["timestamp", "epoch", "order", "invoice", "barcode", "serial", "tracking", "roll", "version"]
        if any(ak in snippet_lower for ak in anti_keywords) and not has_bank_context:
            continue

        # If it has Aadhaar context and passed Verhoeff, defer to Aadhaar
        if len(clean_digits) == 12 and validate_verhoeff(clean_digits) and has_aadhaar_context:
            continue

        # STRICT FALSE-POSITIVE PREVENTION:
        # Discard candidate if there is NO bank context and NO IFSC in nearby context
        if not has_bank_context and not has_ifsc_nearby:
            continue

        confidence = 0.95 if (has_bank_context and (has_ifsc_nearby or has_ifsc_in_doc)) else 0.85
        detection_method = "regex+context"

        masked_val = mask_pii_value("BANK_ACCOUNT", clean_digits)
        safe_snippet = mask_context_snippet(raw_snippet, raw_val, masked_val)

        findings.append(PIIDetectionResult(
            pii_type="BANK_ACCOUNT",
            raw_value=raw_val,
            masked_value=masked_val,
            confidence=confidence,
            severity="HIGH",
            checksum_valid=None,  # No universal checksum exists for bank accounts
            detection_method=detection_method,
            context_snippet=safe_snippet,
            position_start=match.start(),
            position_end=match.end(),
        ))

    return findings


def detect_email_findings(text: str) -> list[PIIDetectionResult]:
    """
    Detects valid RFC 5322 email addresses.
    """
    findings = []
    for match in EMAIL_REGEX.finditer(text):
        raw_val = match.group(0)

        raw_snippet, _ = get_surrounding_context(text, match.start(), match.end())
        masked_val = mask_pii_value("EMAIL", raw_val)
        safe_snippet = mask_context_snippet(raw_snippet, raw_val, masked_val)

        findings.append(PIIDetectionResult(
            pii_type="EMAIL",
            raw_value=raw_val,
            masked_value=masked_val,
            confidence=0.95,
            severity="MEDIUM",
            checksum_valid=None,
            detection_method="regex",
            context_snippet=safe_snippet,
            position_start=match.start(),
            position_end=match.end(),
        ))

    return findings


def detect_phone_findings(text: str) -> list[PIIDetectionResult]:
    """
    Detects Indian mobile numbers (10 digits starting with 6-9, optional +91/0 prefix).
    Prevents false positives on random 10-digit integers by requiring formatting or phone context.
    """
    findings = []
    for match in INDIAN_PHONE_STRICT.finditer(text):
        raw_val = match.group(0).strip()
        clean_digits = re.sub(r"\D", "", raw_val)

        # Normalize to 10 digits
        if clean_digits.startswith("91") and len(clean_digits) == 12:
            phone_10 = clean_digits[2:]
        elif clean_digits.startswith("0") and len(clean_digits) == 11:
            phone_10 = clean_digits[1:]
        elif len(clean_digits) == 10:
            phone_10 = clean_digits
        else:
            continue

        if not phone_10.startswith(("6", "7", "8", "9")):
            continue

        # Reject all repeated digits
        if len(set(phone_10)) <= 2:
            continue

        raw_snippet, snippet_lower = get_surrounding_context(text, match.start(), match.end())
        has_phone_context = has_context_keywords(snippet_lower, CONTEXT_KEYWORDS["PHONE"])
        has_prefix = "+91" in raw_val or raw_val.startswith("0") or " " in raw_val or "-" in raw_val

        # False-positive guard: If it's a bare 10-digit string with NO prefix and NO phone context,
        # but surrounded by words like "PIN", "Order", "Roll", "ID", "Invoice", reject it!
        if not has_prefix and not has_phone_context:
            anti_keywords = ["order", "invoice", "roll", "student", "pin", "txn", "ref", "bill"]
            if any(ak in snippet_lower for ak in anti_keywords):
                continue
            # Standalone unformatted number has lower confidence
            confidence = 0.75
        else:
            confidence = 0.90 if has_phone_context else 0.85

        masked_val = mask_pii_value("PHONE", clean_digits)
        safe_snippet = mask_context_snippet(raw_snippet, raw_val, masked_val)

        findings.append(PIIDetectionResult(
            pii_type="PHONE",
            raw_value=raw_val,
            masked_value=masked_val,
            confidence=confidence,
            severity="MEDIUM",
            checksum_valid=None,
            detection_method="regex+context" if has_phone_context else "regex",
            context_snippet=safe_snippet,
            position_start=match.start(),
            position_end=match.end(),
        ))

    return findings


# ==============================================================================
# UNIFIED PII DETECTION PIPELINE & DEDUPLICATION
# ==============================================================================

def detect_pii(text: str) -> list[PIIDetectionResult]:
    """
    Runs the complete deterministic PII detection pipeline over document text:
    1. Runs all specialized detectors (Aadhaar, PAN, Card, Bank Account, Email, Phone)
    2. Enforces checksum algorithms (Verhoeff for Aadhaar, Luhn for Cards)
    3. Enforces contextual requirements (Bank accounts)
    4. Deduplicates overlapping spans and duplicate findings
    5. Returns ordered list of PIIDetectionResult objects
    """
    if not text or not isinstance(text, str):
        return []

    all_findings: list[PIIDetectionResult] = []

    # Run detectors
    all_findings.extend(detect_aadhaar_findings(text))
    all_findings.extend(detect_pan_findings(text))
    all_findings.extend(detect_card_findings(text))
    all_findings.extend(detect_bank_account_findings(text))
    all_findings.extend(detect_email_findings(text))
    all_findings.extend(detect_phone_findings(text))

    # Priority ranking for resolving span overlaps (e.g., card vs bank vs aadhaar)
    type_priority = {
        "CARD": 5,        # Highest priority (CRITICAL)
        "AADHAAR": 4,     # Verhoeff validated
        "PAN": 3,
        "BANK_ACCOUNT": 2,
        "PHONE": 1,
        "EMAIL": 1,
    }

    # Sort by start offset ascending, then by priority descending
    all_findings.sort(key=lambda f: (f.position_start, -type_priority.get(f.pii_type, 0)))

    # Deduplicate overlapping spans
    filtered_findings: list[PIIDetectionResult] = []
    last_end = -1

    for f in all_findings:
        # Check for span overlap with previous finding
        if f.position_start >= last_end:
            filtered_findings.append(f)
            last_end = f.position_end
        else:
            # Overlapping spans: if current finding has higher priority, replace
            prev = filtered_findings[-1]
            if type_priority.get(f.pii_type, 0) > type_priority.get(prev.pii_type, 0):
                filtered_findings[-1] = f
                last_end = f.position_end

    return filtered_findings
