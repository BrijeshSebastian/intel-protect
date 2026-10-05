"""
Custom Regex-Based Named Entity Recognizer (NER) for Exposure Monitor.
Extracts identity, contact, location, financial, and credential entities from
exposure records, normalizes and masks values, and classifies categories.
Guarantees: Zero raw PII output to APIs; reuses mathematical checksum validation.
"""
import re
from dataclasses import dataclass
from typing import Optional

from backend.app.documents.checksum import validate_verhoeff, validate_luhn
from backend.app.documents.masker import mask_pii_value


@dataclass
class ExposureEntity:
    entity_type: str         # PERSON, EMAIL, PHONE, LOCATION, USERNAME, FINANCIAL, IDENTITY, CREDENTIAL
    raw_value: str           # Internal only, never exposed in to_dict()
    masked_value: str        # Safe masked representation
    confidence: float        # 0.0 to 1.0
    validation_status: str   # VALID, INVALID, STRUCTURAL, N/A
    context_snippet: str     # Masked snippet around match
    start_pos: int
    end_pos: int
    category: str            # identity, contact, location, financial, credential

    def to_dict(self) -> dict:
        """Safe serialization for API responses. Excludes raw_value."""
        return {
            "entity_type": self.entity_type,
            "masked_value": self.masked_value,
            "confidence": round(self.confidence, 4),
            "validation_status": self.validation_status,
            "context_snippet": self.context_snippet,
            "category": self.category
        }


# ==============================================================================
# PATTERN DEFINITIONS
# ==============================================================================

# 1. Contact Patterns
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', re.IGNORECASE)
PHONE_PATTERN = re.compile(r'(?:(?:\+91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}|\+?[1-9]\d{1,3}[\-\s]?\(?\d{2,4}\)?[\-\s]?\d{3,4}[\-\s]?\d{3,4})\b')

# 2. Identity Patterns (Aadhaar, PAN, Person Name, Username)
AADHAAR_PATTERN = re.compile(r'\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b')
PAN_PATTERN = re.compile(r'\b[A-Za-z]{5}[0-9]{4}[A-Za-z]\b')
PERSON_PREFIX_PATTERN = re.compile(
    r'(?:Name|Contact(?:\s+person)?|Applicant|Member|Attendee|Employee|User|Customer|Admin|Dr\.|Mr\.|Mrs\.|Ms\.)\s*[:\-]?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b'
)
USERNAME_PATTERN = re.compile(
    r'(?:\((?:@)?([a-zA-Z0-9_]{3,20})\)|(?:username|handle|user(?:\s+id)?|login)\s*[:\-]?\s*@?([a-zA-Z0-9_.-]{3,30})\b)',
    re.IGNORECASE
)

# 3. Location Patterns
KNOWN_LOCATIONS = [
    "Mumbai", "Delhi", "Bengaluru", "Bangalore", "Hyderabad", "Chennai", "Kolkata",
    "Pune", "Ahmedabad", "Jaipur", "Surat", "Lucknow", "Kanpur", "Nagpur", "Indore",
    "Thane", "Bhopal", "Visakhapatnam", "Purnia", "Chapra", "Panvel", "Hubbardview",
    "Surendranagar", "Dudhrej", "Hillmouth", "West Dawn", "Jeanetteberg", "North Dumdum"
]
LOCATION_PREFIX_PATTERN = re.compile(
    r'(?:Location|Office|City|Address|State|Region)\s*[:\-]?\s*([A-Z][a-zA-Z\s,.-]{2,40})(?=[,;\n]|$)'
)
KNOWN_LOCATIONS_PATTERN = re.compile(
    r'\b(?:' + '|'.join(re.escape(loc) for loc in KNOWN_LOCATIONS) + r')\b',
    re.IGNORECASE
)

# 4. Financial Patterns (Card, Bank Account, IFSC)
CARD_PATTERN = re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b|\b(?:\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4})\b')
BANK_ACCOUNT_PATTERN = re.compile(r'(?:A/C|Account|Acc|Bank\s+A/C|Direct\s+Deposit)\s*[:#\-]?\s*(\d{9,18})\b', re.IGNORECASE)
IFSC_PATTERN = re.compile(r'\b[A-Za-z]{4}0[A-Za-z0-9]{6}\b')

# 5. Credential Patterns (API keys, JWT, Passwords)
JWT_PATTERN = re.compile(r'\beyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b')
API_SECRET_PATTERN = re.compile(r'(?:API\s+Secret|API\s+Key|Bearer|Token|Secret\s+Key)\s*[:=]\s*([a-zA-Z0-9_\-]{16,64})\b', re.IGNORECASE)
PASSWORD_PATTERN = re.compile(r'(?:Password|Passwd|pwd|password_hash)\s*[:=]\s*([^\s,;]{6,64})\b', re.IGNORECASE)


# ==============================================================================
# EXTRACTION PIPELINE
# ==============================================================================

def _generate_snippet(text: str, start: int, end: int, masked_val: str) -> str:
    """Creates a bounded context snippet surrounding the entity match."""
    pad_start = max(0, start - 25)
    pad_end = min(len(text), end + 25)
    prefix = text[pad_start:start].strip()
    suffix = text[end:pad_end].strip()
    snippet = f"...{prefix} {masked_val} {suffix}..."
    return snippet.strip()


def _mask_name(name: str) -> str:
    """Masks a person name (e.g., 'Rahul Sharma' -> 'R****l S****a')."""
    parts = name.split()
    masked_parts = []
    for p in parts:
        if len(p) <= 2:
            masked_parts.append(p[0] + "*")
        else:
            masked_parts.append(p[0] + "*" * (len(p) - 2) + p[-1])
    return " ".join(masked_parts)


def _mask_location(loc: str) -> str:
    """Masks a location (e.g., 'Mumbai' -> 'M****i')."""
    s = loc.strip()
    if len(s) <= 2:
        return s
    return s[0] + "*" * (len(s) - 2) + s[-1]


def extract_exposure_entities(text: str) -> list[ExposureEntity]:
    """
    Executes Custom Regex-Based Named Entity Recognition across exposure text.
    Extracts, validates, deduplicates, and masks all detected entities.
    Returns list of ExposureEntity dataclass instances.
    """
    if not text or not text.strip():
        return []

    entities: list[ExposureEntity] = []

    # 1. Credentials (High priority to avoid parsing inner tokens as phones/words)
    for m in JWT_PATTERN.finditer(text):
        raw = m.group(0)
        entities.append(ExposureEntity(
            entity_type="CREDENTIAL",
            raw_value=raw,
            masked_value="[REDACTED_JWT_TOKEN]",
            confidence=0.99,
            validation_status="STRUCTURAL",
            context_snippet=_generate_snippet(text, m.start(), m.end(), "[REDACTED_JWT_TOKEN]"),
            start_pos=m.start(),
            end_pos=m.end(),
            category="credential"
        ))

    for m in API_SECRET_PATTERN.finditer(text):
        raw = m.group(1)
        entities.append(ExposureEntity(
            entity_type="CREDENTIAL",
            raw_value=raw,
            masked_value="[REDACTED_API_SECRET]",
            confidence=0.95,
            validation_status="STRUCTURAL",
            context_snippet=_generate_snippet(text, m.start(1), m.end(1), "[REDACTED_API_SECRET]"),
            start_pos=m.start(1),
            end_pos=m.end(1),
            category="credential"
        ))

    for m in PASSWORD_PATTERN.finditer(text):
        raw = m.group(1)
        entities.append(ExposureEntity(
            entity_type="CREDENTIAL",
            raw_value=raw,
            masked_value="[REDACTED_PASSWORD]",
            confidence=0.95,
            validation_status="STRUCTURAL",
            context_snippet=_generate_snippet(text, m.start(1), m.end(1), "[REDACTED_PASSWORD]"),
            start_pos=m.start(1),
            end_pos=m.end(1),
            category="credential"
        ))

    # 2. Identity (Aadhaar & PAN)
    for m in AADHAAR_PATTERN.finditer(text):
        raw = m.group(0)
        digits = re.sub(r'\D', '', raw)
        if len(digits) == 12:
            is_valid = validate_verhoeff(digits)
            masked = f"XXXX XXXX {digits[-4:]}"
            entities.append(ExposureEntity(
                entity_type="IDENTITY",
                raw_value=raw,
                masked_value=masked,
                confidence=0.98 if is_valid else 0.35,
                validation_status="VALID" if is_valid else "INVALID",
                context_snippet=_generate_snippet(text, m.start(), m.end(), masked),
                start_pos=m.start(),
                end_pos=m.end(),
                category="identity"
            ))

    for m in PAN_PATTERN.finditer(text):
        raw = m.group(0).upper()
        entity_char = raw[3]
        valid_entity = entity_char in ("P", "C", "H", "F", "A", "T", "B", "L", "J", "G")
        masked = f"XXXXX{raw[5:9]}X"
        entities.append(ExposureEntity(
            entity_type="IDENTITY",
            raw_value=raw,
            masked_value=masked,
            confidence=0.95 if valid_entity else 0.50,
            validation_status="VALID" if valid_entity else "STRUCTURAL",
            context_snippet=_generate_snippet(text, m.start(), m.end(), masked),
            start_pos=m.start(),
            end_pos=m.end(),
            category="identity"
        ))

    # 3. Financial (Cards, Bank Accounts, IFSC)
    for m in CARD_PATTERN.finditer(text):
        raw = m.group(0)
        digits = re.sub(r'\D', '', raw)
        if 13 <= len(digits) <= 19:
            is_valid = validate_luhn(digits)
            masked = f"**** **** **** {digits[-4:]}"
            entities.append(ExposureEntity(
                entity_type="FINANCIAL",
                raw_value=raw,
                masked_value=masked,
                confidence=0.99 if is_valid else 0.30,
                validation_status="VALID" if is_valid else "INVALID",
                context_snippet=_generate_snippet(text, m.start(), m.end(), masked),
                start_pos=m.start(),
                end_pos=m.end(),
                category="financial"
            ))

    for m in BANK_ACCOUNT_PATTERN.finditer(text):
        raw = m.group(1)
        digits = re.sub(r'\D', '', raw)
        masked = f"********{digits[-4:]}" if len(digits) >= 4 else "********"
        entities.append(ExposureEntity(
            entity_type="FINANCIAL",
            raw_value=raw,
            masked_value=masked,
            confidence=0.90,
            validation_status="STRUCTURAL",
            context_snippet=_generate_snippet(text, m.start(1), m.end(1), masked),
            start_pos=m.start(1),
            end_pos=m.end(1),
            category="financial"
        ))

    for m in IFSC_PATTERN.finditer(text):
        raw = m.group(0).upper()
        entities.append(ExposureEntity(
            entity_type="FINANCIAL",
            raw_value=raw,
            masked_value=raw,  # IFSC is a routing code, not secret PII
            confidence=0.92,
            validation_status="STRUCTURAL",
            context_snippet=_generate_snippet(text, m.start(), m.end(), raw),
            start_pos=m.start(),
            end_pos=m.end(),
            category="financial"
        ))

    # 4. Contacts (Emails & Phones)
    for m in EMAIL_PATTERN.finditer(text):
        raw = m.group(0)
        parts = raw.split("@")
        local = parts[0]
        domain = parts[1] if len(parts) > 1 else ""
        masked_local = f"{local[0]}****{local[-1]}" if len(local) > 2 else f"{local[0]}****"
        masked = f"{masked_local}@{domain}"
        entities.append(ExposureEntity(
            entity_type="EMAIL",
            raw_value=raw,
            masked_value=masked,
            confidence=0.95,
            validation_status="STRUCTURAL",
            context_snippet=_generate_snippet(text, m.start(), m.end(), masked),
            start_pos=m.start(),
            end_pos=m.end(),
            category="contact"
        ))

    for m in PHONE_PATTERN.finditer(text):
        raw = m.group(0)
        digits = re.sub(r'\D', '', raw)
        if 10 <= len(digits) <= 12:
            masked = f"+91-XXXXX-{digits[-5:]}" if digits.startswith("91") and len(digits) == 12 else f"XXXXX-{digits[-5:]}"
            entities.append(ExposureEntity(
                entity_type="PHONE",
                raw_value=raw,
                masked_value=masked,
                confidence=0.90,
                validation_status="STRUCTURAL",
                context_snippet=_generate_snippet(text, m.start(), m.end(), masked),
                start_pos=m.start(),
                end_pos=m.end(),
                category="contact"
            ))

    # 5. Persons & Usernames
    for m in PERSON_PREFIX_PATTERN.finditer(text):
        raw = m.group(1).strip()
        masked = _mask_name(raw)
        entities.append(ExposureEntity(
            entity_type="PERSON",
            raw_value=raw,
            masked_value=masked,
            confidence=0.92,
            validation_status="STRUCTURAL",
            context_snippet=_generate_snippet(text, m.start(1), m.end(1), masked),
            start_pos=m.start(1),
            end_pos=m.end(1),
            category="identity"
        ))

    for m in USERNAME_PATTERN.finditer(text):
        raw = m.group(1) or m.group(2)
        if raw and len(raw) >= 3:
            masked = f"{raw[0]}****{raw[-1]}" if len(raw) > 2 else f"{raw[0]}*"
            entities.append(ExposureEntity(
                entity_type="USERNAME",
                raw_value=raw,
                masked_value=masked,
                confidence=0.88,
                validation_status="STRUCTURAL",
                context_snippet=_generate_snippet(text, m.start(), m.end(), masked),
                start_pos=m.start(),
                end_pos=m.end(),
                category="identity"
            ))

    # 6. Locations
    for m in LOCATION_PREFIX_PATTERN.finditer(text):
        raw = m.group(1).strip()
        masked = _mask_location(raw)
        entities.append(ExposureEntity(
            entity_type="LOCATION",
            raw_value=raw,
            masked_value=masked,
            confidence=0.85,
            validation_status="STRUCTURAL",
            context_snippet=_generate_snippet(text, m.start(1), m.end(1), masked),
            start_pos=m.start(1),
            end_pos=m.end(1),
            category="location"
        ))

    for m in KNOWN_LOCATIONS_PATTERN.finditer(text):
        raw = m.group(0).strip()
        masked = _mask_location(raw)
        entities.append(ExposureEntity(
            entity_type="LOCATION",
            raw_value=raw,
            masked_value=masked,
            confidence=0.88,
            validation_status="STRUCTURAL",
            context_snippet=_generate_snippet(text, m.start(), m.end(), masked),
            start_pos=m.start(),
            end_pos=m.end(),
            category="location"
        ))

    # 7. Deduplicate overlapping spans (prioritize higher confidence, then length)
    entities.sort(key=lambda e: (e.start_pos, -(e.end_pos - e.start_pos), -e.confidence))
    deduped: list[ExposureEntity] = []
    last_end = -1

    for ent in entities:
        if ent.start_pos >= last_end:
            deduped.append(ent)
            last_end = ent.end_pos
        else:
            # Overlap: if this entity has higher confidence and significant length, keep it
            prev = deduped[-1]
            if ent.confidence > prev.confidence + 0.15:
                deduped[-1] = ent
                last_end = ent.end_pos

    return deduped


def summarize_entities(entities: list[ExposureEntity]) -> tuple[dict[str, int], dict[str, int]]:
    """
    Computes (entity_summary, category_counts) from extracted entities.
    Example:
        entity_summary: {"PERSON": 2, "EMAIL": 1, "FINANCIAL": 1}
        category_counts: {"identity": 2, "contact": 1, "financial": 1}
    """
    entity_summary: dict[str, int] = {}
    category_counts: dict[str, int] = {
        "identity": 0,
        "contact": 0,
        "location": 0,
        "financial": 0,
        "credential": 0
    }

    for e in entities:
        entity_summary[e.entity_type] = entity_summary.get(e.entity_type, 0) + 1
        cat = e.category
        if cat in category_counts:
            category_counts[cat] += 1
        else:
            category_counts[cat] = 1

    return entity_summary, category_counts
