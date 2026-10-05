import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.app import db


class PIIFinding(db.Model):
    """
    Persisted PII findings detected within scanned documents.
    Stores only masked values, confidence metrics, locations, and checksum verification status.
    NEVER stores raw sensitive plaintext (Aadhaar, PAN, Cards, Bank Accounts).
    """
    __tablename__ = "pii_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id = Column(
        UUID(as_uuid=True),
        ForeignKey("documents.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    pii_type = Column(String(50), nullable=False)           # AADHAAR, PAN, CARD, BANK_ACCOUNT, EMAIL, PHONE
    masked_value = Column(String(255), nullable=False)       # Always masked (e.g. XXXX XXXX 1234)
    confidence = Column(Float, nullable=False)              # 0.0 to 1.0
    severity = Column(String(20), nullable=False)           # LOW, MEDIUM, HIGH, CRITICAL
    checksum_valid = Column(Boolean, nullable=True)         # True/False for Aadhaar & Card; None if N/A
    detection_method = Column(String(50), nullable=True)    # regex+verhoeff, regex+luhn, regex+context, etc.
    context_snippet = Column(String(200), nullable=True)    # Surrounding text with sensitive value masked
    position_start = Column(Integer, nullable=True)         # Character offset start in extracted text
    position_end = Column(Integer, nullable=True)           # Character offset end in extracted text
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationship to parent document
    document = relationship("Document", backref=db.backref("findings", lazy="dynamic", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("ix_pii_findings_document_severity", "document_id", "severity"),
    )

    def to_dict(self):
        """Safe serialization for API responses — zero raw sensitive data."""
        return {
            "id": str(self.id),
            "document_id": str(self.document_id),
            "pii_type": self.pii_type,
            "masked_value": self.masked_value,
            "confidence": round(self.confidence, 4) if self.confidence is not None else None,
            "severity": self.severity,
            "checksum_valid": self.checksum_valid,
            "detection_method": self.detection_method,
            "context_snippet": self.context_snippet,
            "position_start": self.position_start,
            "position_end": self.position_end,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
