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
