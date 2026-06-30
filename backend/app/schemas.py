from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class DocumentResponse(BaseModel):
    id: int
    title: str
    content: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class DetectorSpanResponse(BaseModel):
    id: int
    start_offset: int
    end_offset: int
    text_content: str
    pii_category: Optional[str] = None
    confidence_score: Optional[int] = None
    is_manual: bool = False
    decision: Optional[str] = None
    ensemble_sources: Optional[List[str]] = None
    ensemble_agreement_count: Optional[int] = None
    ensemble_conflict_types: Optional[List[str]] = None

    class Config:
        from_attributes = True


class RiskFlagResponse(BaseModel):
    id: int
    start_offset: int
    end_offset: int
    text_content: str
    pii_category: str
    pattern_source: str
    confidence_score: Optional[int] = None
    is_manual: bool = False
    decision: Optional[str] = None
    ensemble_sources: Optional[List[str]] = None
    ensemble_agreement_count: Optional[int] = None
    ensemble_conflict_types: Optional[List[str]] = None

    class Config:
        from_attributes = True


class ReviewItemsResponse(BaseModel):
    detector_spans: List[DetectorSpanResponse]
    risk_flags: List[RiskFlagResponse]


class DecisionCreate(BaseModel):
    span_type: str  # "detector" | "risk_flag"
    span_id: int
    decision: str  # "approve" | "reject" | "redact" | "dismiss"


class DecisionResponse(BaseModel):
    id: int
    span_type: str
    span_id: int
    decision: str
    created_at: datetime

    class Config:
        from_attributes = True


class SummaryResponse(BaseModel):
    exposures_caught: int           # risk_flags redacted that were real FNs
    exposures_missed: int           # risk_flags dismissed that were real FNs
    unnecessary_redactions_fixed: int  # detector FPs that Sam rejected
    correct_redactions_kept: int       # detector TPs that Sam approved
    total_reviewed: int
    document_status: str


class UploadResponse(BaseModel):
    document_id: int
    title: str
    detector_span_count: int
    risk_flag_count: int
    file_type: str  # 'pdf' | 'docx'
    char_count: int


class DocumentListItem(BaseModel):
    id: int
    title: str
    status: str
    created_at: datetime
    is_demo: bool  # True for the seeded demo document (id == 1)

    class Config:
        from_attributes = True


# ============================================================================
# Sanitization Schemas
# ============================================================================

class SanitizeRequest(BaseModel):
    """Request to sanitize a document."""
    mode: str  # 'redact' or 'pseudonymize'
    redaction_style: Optional[str] = 'bars'  # 'bars' (████) or 'brackets' ([REDACTED])


class RedactionInfo(BaseModel):
    """Information about a single redaction."""
    original: str
    category: str
    start: int
    end: int
    replacement: str


class SanitizeResponse(BaseModel):
    """Response from sanitization."""
    document_id: int
    mode: str
    content: str  # The sanitized content
    redaction_count: int
    redactions: Optional[List[RedactionInfo]] = None  # For redact mode
    pseudonym_mapping: Optional[dict] = None  # For pseudonymize mode
    output_id: int  # ID of the saved output for later retrieval


class PseudonymMappingResponse(BaseModel):
    """Response showing pseudonym mappings for a document."""
    document_id: int
    mappings: List[dict]  # List of {original, pseudonym, category}


class SanitizedOutputResponse(BaseModel):
    """Response for retrieving a saved sanitized output."""
    id: int
    document_id: int
    mode: str
    redaction_style: Optional[str]
    content: str
    mapping: Optional[dict]
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# Manual Span Management Schemas
# ============================================================================

class ManualSpanCreate(BaseModel):
    """Request to create a manual PII detection."""
    start_offset: int
    end_offset: int
    pii_category: str
    span_type: str = 'detector'  # 'detector' or 'risk_flag'


class ManualSpanResponse(BaseModel):
    """Response after creating a manual span."""
    id: int
    span_type: str
    start_offset: int
    end_offset: int
    text_content: str
    pii_category: str
    is_manual: bool


class SpanUpdateRequest(BaseModel):
    """Request to update a span's PII category."""
    pii_category: str


class SpanDeleteResponse(BaseModel):
    """Response after deleting a span."""
    success: bool
    span_type: str
    span_id: int
