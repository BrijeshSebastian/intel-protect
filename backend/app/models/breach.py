"""
Breach Monitor Database Models.
Implements Breach, BreachResult, and BreachExposure entities
according to intel-protect-architecture.md.
"""
from datetime import datetime, timezone
import uuid
from sqlalchemy.dialects.postgresql import UUID, JSONB
from backend.app import db


class Breach(db.Model):
    """
    Catalog of synthetic/tracked public security breaches.
    """
    __tablename__ = "breaches"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(150), unique=True, nullable=False, index=True)
    organization = db.Column(db.String(200), nullable=False)
    breach_date = db.Column(db.Date, nullable=False)
    discovered_date = db.Column(db.Date, nullable=False)
    description = db.Column(db.Text, nullable=True)
    affected_count = db.Column(db.BigInteger, nullable=False, default=0)
    exposed_data_types = db.Column(JSONB().with_variant(db.JSON, "sqlite"), nullable=False, default=list)
    severity = db.Column(db.String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    is_synthetic = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationships
    exposures = db.relationship("BreachExposure", back_populates="breach", cascade="all, delete-orphan", lazy="dynamic")

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "name": self.name,
            "organization": self.organization,
            "breach_date": self.breach_date.isoformat() if self.breach_date else None,
            "discovered_date": self.discovered_date.isoformat() if self.discovered_date else None,
            "description": self.description,
            "affected_count": self.affected_count,
            "exposed_data_types": self.exposed_data_types or [],
            "severity": self.severity,
            "is_synthetic": self.is_synthetic,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class BreachResult(db.Model):
    """
    Result of a user's breach lookup query against the catalog.
    Stores query email hash (never plaintext email) and assessment results.
    """
    __tablename__ = "breach_results"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    query_email_hash = db.Column(db.String(64), nullable=False, index=True)
    breach_count = db.Column(db.Integer, nullable=False, default=0)
    total_exposures = db.Column(db.Integer, nullable=False, default=0)
    priority_label = db.Column(db.String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    priority_confidence = db.Column(db.Float, nullable=False, default=0.0)
    breach_risk_score = db.Column(db.Float, nullable=False, default=0.0)  # 0.0 - 100.0
    breach_risk_level = db.Column(db.String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    exposure_summary = db.Column(JSONB().with_variant(db.JSON, "sqlite"), nullable=False, default=dict)
    checked_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.Index("idx_breach_results_user_created", "user_id", created_at.desc()),
    )

    # Relationships
    user = db.relationship("User", backref=db.backref("breach_results", lazy="dynamic", cascade="all, delete-orphan"))
    exposures = db.relationship("BreachExposure", back_populates="breach_result", cascade="all, delete-orphan", lazy="joined")
    recommendations = db.relationship("Recommendation", back_populates="breach_result", cascade="all, delete-orphan", lazy="joined")

    def to_dict(self, include_breaches: bool = True) -> dict:
        result = {
            "id": str(self.id),
            "query_email_hash": self.query_email_hash,
            "breach_count": self.breach_count,
            "total_exposures": self.total_exposures,
            "priority_label": self.priority_label,
            "priority_confidence": round(self.priority_confidence, 2),
            "breach_risk_score": round(self.breach_risk_score, 1),
            "breach_risk_level": self.breach_risk_level,
            "exposure_summary": self.exposure_summary or {},
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_breaches and self.exposures:
            unique_breaches = {}
            for exp in self.exposures:
                if exp.breach and exp.breach.id not in unique_breaches:
                    unique_breaches[exp.breach.id] = exp.breach.to_dict()
            result["breaches"] = list(unique_breaches.values())
        return result


class BreachExposure(db.Model):
    """
    Granular exposed data point linking a specific breach to a search result.
    """
    __tablename__ = "breach_exposures"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    breach_id = db.Column(UUID(as_uuid=True), db.ForeignKey("breaches.id", ondelete="CASCADE"), nullable=False, index=True)
    breach_result_id = db.Column(UUID(as_uuid=True), db.ForeignKey("breach_results.id", ondelete="CASCADE"), nullable=False, index=True)
    data_type = db.Column(db.String(50), nullable=False)  # EMAIL, PASSWORD_HASH, PHONE, etc.
    severity = db.Column(db.String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.Index("idx_breach_exposures_result", "breach_result_id"),
        db.Index("idx_breach_exposures_breach", "breach_id"),
    )

    # Relationships
    breach = db.relationship("Breach", back_populates="exposures", lazy="joined")
    breach_result = db.relationship("BreachResult", back_populates="exposures")

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "breach_id": str(self.breach_id),
            "breach_result_id": str(self.breach_result_id),
            "data_type": self.data_type,
            "severity": self.severity,
            "breach_name": self.breach.name if self.breach else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
