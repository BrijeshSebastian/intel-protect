import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.app import db


class ExposureRecord(db.Model):
    """
    Exposure Record Entity.
    Stores analysis results for user identity exposure queries without persisting raw query text or unmasked PII.
    """
    __tablename__ = "exposure_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    query_type = Column(String(20), nullable=False)  # email, phone, username, name, combined
    query_value_hash = Column(String(64), nullable=False, index=True)  # SHA-256 (never store raw identifiers)
    total_entities = Column(Integer, default=0, nullable=False)
    sensitive_count = Column(Integer, default=0, nullable=False)
    financial_count = Column(Integer, default=0, nullable=False)
    credential_count = Column(Integer, default=0, nullable=False)
    exposure_score = Column(Float, default=0.0, nullable=False)  # Bounded 0.0 to 100.0
    exposure_level = Column(String(20), default="LOW", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    sensitivity_label = Column(String(20), default="LOW", nullable=False)  # TF-IDF + RF prediction
    sensitivity_confidence = Column(Float, default=0.0, nullable=False)
    is_anomalous = Column(Boolean, default=False, nullable=False)  # Isolation Forest result
    anomaly_score = Column(Float, default=0.0, nullable=False)  # Normalized 0.0 to 1.0
    category_scores = Column(JSON, nullable=True)  # {"identity": 80, "contact": 60, "location": 40, ...}
    entity_summary = Column(JSON, nullable=True)  # {"PERSON": 3, "EMAIL": 2, "PHONE": 1, ...}
    raw_findings = Column(JSON, nullable=True)  # List of masked entity dicts
    analyzed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    user = relationship("User", backref=db.backref("exposure_records", lazy="dynamic", cascade="all, delete-orphan"))

    def to_dict(self, include_findings=True):
        """Safe serialization for API responses. Never leaks raw PII."""
        data = {
            "id": str(self.id),
            "query_type": self.query_type,
            "query_value_hash": self.query_value_hash,
            "total_entities": self.total_entities,
            "sensitive_count": self.sensitive_count,
            "financial_count": self.financial_count,
            "credential_count": self.credential_count,
            "exposure_score": round(self.exposure_score, 1),
            "exposure_level": self.exposure_level,
            "sensitivity_label": self.sensitivity_label,
            "sensitivity_confidence": round(self.sensitivity_confidence, 4),
            "is_anomalous": self.is_anomalous,
            "anomaly_score": round(self.anomaly_score, 4),
            "category_scores": self.category_scores or {},
            "entity_summary": self.entity_summary or {},
            "analyzed_at": self.analyzed_at.isoformat() if self.analyzed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_findings and self.raw_findings:
            data["findings"] = self.raw_findings
        return data
