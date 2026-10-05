import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.app import db


class Document(db.Model):
    """
    Document record metadata entity.
    Stores metadata for processed documents without persisting original source files.
    """
    __tablename__ = "documents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    original_filename = Column(String(255), nullable=False)
    file_type = Column(String(20), nullable=False)  # pdf, png, jpg, txt
    file_size = Column(Integer, nullable=False)     # in bytes
    file_hash = Column(String(64), nullable=False, index=True)  # SHA-256 hash
    extracted_text_preview = Column(Text, nullable=True)  # Safe preview of extracted text
    extracted_text = Column(Text, nullable=True)          # Full extracted text for processing pipeline
    ocr_applied = Column(Boolean, default=False, nullable=False)
    page_count = Column(Integer, default=1, nullable=False)
    pii_count = Column(Integer, default=0, nullable=False)
    high_risk_count = Column(Integer, default=0, nullable=False)
    risk_score = Column(Float, nullable=True, default=0.0)
    risk_level = Column(String(20), nullable=True, default="LOW")
    scoring_version = Column(String(10), nullable=True, default="1.0")
    score_explanation = Column(JSON, nullable=True)
    scanned_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    user = relationship("User", backref=db.backref("documents", lazy="dynamic", cascade="all, delete-orphan"))

    def to_dict(self, include_full_text=False, include_findings=False):
        """Safe serialization for API responses."""
        data = {
            "id": str(self.id),
            "original_filename": self.original_filename,
            "file_type": self.file_type,
            "file_size": self.file_size,
            "file_hash": self.file_hash,
            "extracted_text_preview": self.extracted_text_preview,
            "ocr_applied": self.ocr_applied,
            "page_count": self.page_count,
            "pii_count": self.pii_count,
            "high_risk_count": self.high_risk_count,
            "risk_score": self.risk_score if self.risk_score is not None else 0.0,
            "risk_level": self.risk_level or "LOW",
            "scoring_version": self.scoring_version or "1.0",
            "score_explanation": self.score_explanation,
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_full_text:
            data["extracted_text"] = self.extracted_text
        if include_findings and hasattr(self, "findings"):
            data["findings"] = [f.to_dict() for f in self.findings.all()]
        return data
