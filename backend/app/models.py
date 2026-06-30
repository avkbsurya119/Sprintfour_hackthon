from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.database import Base


class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    status = Column(String(50), nullable=False, default="pending_review")
    created_at = Column(DateTime, server_default=func.now())


class GroundTruthSpan(Base):
    """Backend-only. NEVER expose to frontend during review."""
    __tablename__ = "ground_truth_spans"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    start_offset = Column(Integer, nullable=False)
    end_offset = Column(Integer, nullable=False)
    pii_category = Column(String(50), nullable=False)  # name | phone | email | ssn
    text_content = Column(Text, nullable=False)


class DetectorSpan(Base):
    """What the flawed detector flagged for redaction (includes FPs, misses FNs)."""
    __tablename__ = "detector_spans"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    start_offset = Column(Integer, nullable=False)
    end_offset = Column(Integer, nullable=False)
    text_content = Column(Text, nullable=False)


class RiskFlag(Base):
    """Second-pass risk scanner output: likely-missed PII the detector skipped."""
    __tablename__ = "risk_flags"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    start_offset = Column(Integer, nullable=False)
    end_offset = Column(Integer, nullable=False)
    text_content = Column(Text, nullable=False)
    pii_category = Column(String(50), nullable=False)
    pattern_source = Column(String(50), nullable=False)


class UserDecision(Base):
    """Sam's corrections."""
    __tablename__ = "user_decisions"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    span_type = Column(String(50), nullable=False)  # detector | risk_flag
    span_id = Column(Integer, nullable=False)
    decision = Column(String(50), nullable=False)  # approve | reject | redact | dismiss
    created_at = Column(DateTime, server_default=func.now())
