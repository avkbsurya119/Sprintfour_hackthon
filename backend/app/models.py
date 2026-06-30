from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON, Enum
from sqlalchemy.sql import func
from app.database import Base
import enum


class SanitizationMode(str, enum.Enum):
    """Sanitization output modes."""
    REDACT = "redact"           # Replace with black bars or [REDACTED]
    PSEUDONYMIZE = "pseudonymize"  # Replace with consistent labels (PERSON_1, etc.)


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
    """What the detectors flagged for redaction."""
    __tablename__ = "detector_spans"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    start_offset = Column(Integer, nullable=False)
    end_offset = Column(Integer, nullable=False)
    text_content = Column(Text, nullable=False)
    pii_category = Column(String(50), nullable=True)  # name, email, phone, ssn, etc.
    confidence_score = Column(Integer, nullable=True)  # 0-100
    is_manual = Column(Integer, nullable=False, default=0)  # 1 if manually added
    ensemble_sources = Column(JSON, nullable=True)
    ensemble_agreement_count = Column(Integer, nullable=True)
    ensemble_conflict_types = Column(JSON, nullable=True)


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
    confidence_score = Column(Integer, nullable=True)  # 0-100
    is_manual = Column(Integer, nullable=False, default=0)  # 1 if manually added
    ensemble_sources = Column(JSON, nullable=True)
    ensemble_agreement_count = Column(Integer, nullable=True)
    ensemble_conflict_types = Column(JSON, nullable=True)


class UserDecision(Base):
    """Sam's corrections."""
    __tablename__ = "user_decisions"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    span_type = Column(String(50), nullable=False)  # detector | risk_flag
    span_id = Column(Integer, nullable=False)
    decision = Column(String(50), nullable=False)  # approve | reject | redact | dismiss
    created_at = Column(DateTime, server_default=func.now())


class PseudonymMapping(Base):
    """Maps original PII text to consistent pseudonyms within a document."""
    __tablename__ = "pseudonym_mappings"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    original_text = Column(Text, nullable=False)        # "Marcus Whitfield"
    normalized_text = Column(Text, nullable=False)      # "marcus whitfield"
    pii_category = Column(String(50), nullable=False)   # "name"
    pseudonym = Column(String(100), nullable=False)     # "PERSON_1"
    created_at = Column(DateTime, server_default=func.now())


class SanitizedOutput(Base):
    """Stores generated sanitized document outputs."""
    __tablename__ = "sanitized_outputs"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    mode = Column(String(20), nullable=False)           # 'redact' or 'pseudonymize'
    redaction_style = Column(String(20), nullable=True) # 'bars' or 'brackets' (for redact mode)
    content = Column(Text, nullable=False)              # The sanitized text
    mapping_json = Column(JSON, nullable=True)          # Pseudonym mappings for reference
    created_at = Column(DateTime, server_default=func.now())
