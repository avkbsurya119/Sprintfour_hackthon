from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db, engine
from app.models import (
    Base, Document, DetectorSpan, RiskFlag, UserDecision,
    GroundTruthSpan, PseudonymMapping, SanitizedOutput
)
from app.schemas import (
    DocumentResponse,
    ReviewItemsResponse,
    DetectorSpanResponse,
    RiskFlagResponse,
    DecisionCreate,
    DecisionResponse,
    SummaryResponse,
    UploadResponse,
    DocumentListItem,
    SanitizeRequest,
    SanitizeResponse,
    RedactionInfo,
    PseudonymMappingResponse,
    SanitizedOutputResponse,
    ManualSpanCreate,
    ManualSpanResponse,
    SpanUpdateRequest,
    SpanDeleteResponse,
)
from app.extractor import extract_text, ExtractionError
from app.risk_scorer import find_potential_pii, PHONE_PATTERN, SSN_PATTERN, EMAIL_PATTERN, NAME_PATTERN, POSTAL_PATTERN
from app.ensemble import run_ensemble, apply_ensemble_metadata, persist_ensemble_results
from app.sanitizer import sanitize_document, DocumentSanitizer

# DEMO_DOCUMENT_ID is the seeded demo document — never deleted, never re-scanned.
# Uploaded documents get IDs > 1 and are processed via Option D confidence-tier split.
DEMO_DOCUMENT_ID = 1

# Create tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Conseal Correction Review API",
    description="API for reviewing and correcting PII redaction decisions",
    version="1.0.0"
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "ok", "service": "Conseal Correction Review API"}


@app.get("/api/documents", response_model=List[DocumentListItem])
def list_documents(db: Session = Depends(get_db)):
    """List all documents (demo + uploaded), ordered by creation time."""
    docs = db.query(Document).order_by(Document.id).all()
    return [
        DocumentListItem(
            id=doc.id,
            title=doc.title,
            status=doc.status,
            created_at=doc.created_at,
            is_demo=(doc.id == DEMO_DOCUMENT_ID),
        )
        for doc in docs
    ]


@app.post("/api/documents/upload", response_model=UploadResponse, status_code=201)
async def upload_document(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Upload a PDF or .docx document for PII review.

    Uses ensemble detection with all available detectors:
    - Regex patterns (SSN, email, phone, postal code, names)
    - Presidio Analyzer (ML-based NER)
    - spaCy NER (PERSON, ORG, GPE, etc.)
    - Rule-based patterns (URLs, usernames, ID numbers)

    All detectors run independently and results are reconciled:
    - High-confidence findings → DetectorSpan (proposed redactions)
    - Lower-confidence findings → RiskFlag (needs human review)

    Every detection includes:
    - Which detector(s) found it
    - Agreement count (1-4)
    - Confidence score (0-100)
    - Type conflicts if detectors disagree

    No ground truth is stored for uploaded documents — compute_summary
    handles this gracefully by returning zeros for GT-dependent metrics.
    """
    filename = file.filename or "uploaded_file"
    content = await file.read()

    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # --- Extract text ---
    try:
        text, file_type = extract_text(filename, content)
    except ExtractionError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # --- Create document row ---
    title = filename.rsplit('.', 1)[0]  # strip extension
    doc = Document(
        title=f"Uploaded: {title}",
        content=text,
        status="pending_review"
    )
    db.add(doc)
    db.flush()  # get doc.id

    # --- Run full ensemble detection and persist ALL results ---
    # This runs all 4 detectors (regex, presidio, spacy, rules),
    # reconciles overlapping findings, and creates database rows
    # for EVERY detection - not just regex matches.
    detector_spans_added, risk_flags_added = persist_ensemble_results(
        text=text,
        document_id=doc.id,
        db=db
    )

    db.commit()

    return UploadResponse(
        document_id=doc.id,
        title=doc.title,
        detector_span_count=len(detector_spans_added),
        risk_flag_count=len(risk_flags_added),
        file_type=file_type,
        char_count=len(text),
    )


@app.get("/api/documents/{document_id}", response_model=DocumentResponse)
def get_document(document_id: int, db: Session = Depends(get_db)):
    """Get document content and status. Does NOT expose ground truth."""
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc


@app.get("/api/documents/{document_id}/review-items", response_model=ReviewItemsResponse)
def get_review_items(document_id: int, db: Session = Depends(get_db)):
    """
    Get all detector spans and risk flags for review.
    Includes any existing user decisions.
    Does NOT expose ground truth or correctness information.
    """
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # Get detector spans with decisions
    detector_spans = db.query(DetectorSpan).filter(
        DetectorSpan.document_id == document_id
    ).all()

    # Get risk flags with decisions
    risk_flags = db.query(RiskFlag).filter(
        RiskFlag.document_id == document_id
    ).all()

    # Get all decisions for this document
    decisions = db.query(UserDecision).filter(
        UserDecision.document_id == document_id
    ).all()

    # Map decisions to spans
    decision_map = {}
    for d in decisions:
        key = (d.span_type, d.span_id)
        decision_map[key] = d.decision

    # Build response
    detector_responses = []
    for span in detector_spans:
        detector_responses.append(DetectorSpanResponse(
            id=span.id,
            start_offset=span.start_offset,
            end_offset=span.end_offset,
            text_content=span.text_content,
            pii_category=span.pii_category,
            confidence_score=span.confidence_score,
            is_manual=bool(span.is_manual) if span.is_manual is not None else False,
            decision=decision_map.get(("detector", span.id)),
            ensemble_sources=span.ensemble_sources,
            ensemble_agreement_count=span.ensemble_agreement_count,
            ensemble_conflict_types=span.ensemble_conflict_types
        ))

    risk_responses = []
    for flag in risk_flags:
        risk_responses.append(RiskFlagResponse(
            id=flag.id,
            start_offset=flag.start_offset,
            end_offset=flag.end_offset,
            text_content=flag.text_content,
            pii_category=flag.pii_category,
            pattern_source=flag.pattern_source,
            confidence_score=flag.confidence_score,
            is_manual=bool(flag.is_manual) if flag.is_manual is not None else False,
            decision=decision_map.get(("risk_flag", flag.id)),
            ensemble_sources=flag.ensemble_sources,
            ensemble_agreement_count=flag.ensemble_agreement_count,
            ensemble_conflict_types=flag.ensemble_conflict_types
        ))

    return ReviewItemsResponse(
        detector_spans=detector_responses,
        risk_flags=risk_responses
    )


@app.post("/api/documents/{document_id}/decisions", response_model=DecisionResponse)
def create_decision(
    document_id: int,
    decision_data: DecisionCreate,
    db: Session = Depends(get_db)
):
    """Record a user decision for a span."""
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # Validate span exists
    if decision_data.span_type == "detector":
        span = db.query(DetectorSpan).filter(
            DetectorSpan.id == decision_data.span_id,
            DetectorSpan.document_id == document_id
        ).first()
    elif decision_data.span_type == "risk_flag":
        span = db.query(RiskFlag).filter(
            RiskFlag.id == decision_data.span_id,
            RiskFlag.document_id == document_id
        ).first()
    else:
        raise HTTPException(status_code=400, detail="Invalid span_type")

    if not span:
        raise HTTPException(status_code=404, detail="Span not found")

    # Validate decision value
    valid_detector_decisions = {"approve", "reject"}
    valid_risk_decisions = {"redact", "dismiss"}

    if decision_data.span_type == "detector":
        if decision_data.decision not in valid_detector_decisions:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid decision for detector span. Must be one of: {valid_detector_decisions}"
            )
    else:
        if decision_data.decision not in valid_risk_decisions:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid decision for risk flag. Must be one of: {valid_risk_decisions}"
            )

    # Check if decision already exists, update if so
    existing = db.query(UserDecision).filter(
        UserDecision.document_id == document_id,
        UserDecision.span_type == decision_data.span_type,
        UserDecision.span_id == decision_data.span_id
    ).first()

    if existing:
        existing.decision = decision_data.decision
        db.commit()
        db.refresh(existing)
        return existing

    # Create new decision
    decision = UserDecision(
        document_id=document_id,
        span_type=decision_data.span_type,
        span_id=decision_data.span_id,
        decision=decision_data.decision
    )
    db.add(decision)

    # Update document status to in_progress if it was pending
    if doc.status == "pending_review":
        doc.status = "in_progress"

    db.commit()
    db.refresh(decision)
    return decision


@app.delete("/api/documents/{document_id}/decisions/{decision_id}")
def delete_decision(
    document_id: int,
    decision_id: int,
    db: Session = Depends(get_db)
):
    """Delete a user decision (for undo functionality)."""
    decision = db.query(UserDecision).filter(
        UserDecision.id == decision_id,
        UserDecision.document_id == document_id
    ).first()

    if not decision:
        raise HTTPException(status_code=404, detail="Decision not found")

    db.delete(decision)
    db.commit()
    return {"status": "deleted", "id": decision_id}


# ============================================================================
# Manual Span Management Endpoints
# ============================================================================

@app.post("/api/documents/{document_id}/spans")
def create_manual_span(
    document_id: int,
    request: ManualSpanCreate,
    db: Session = Depends(get_db)
):
    """
    Create a manual PII detection.

    Allows users to mark text as PII that was missed by automatic detection.
    """
    # Get document
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # Validate offsets
    if request.start_offset < 0 or request.end_offset > len(doc.content):
        raise HTTPException(status_code=400, detail="Invalid offsets")
    if request.start_offset >= request.end_offset:
        raise HTTPException(status_code=400, detail="start_offset must be less than end_offset")

    # Extract text content
    text_content = doc.content[request.start_offset:request.end_offset]

    # Check for overlapping spans
    existing_detector = db.query(DetectorSpan).filter(
        DetectorSpan.document_id == document_id,
        DetectorSpan.start_offset < request.end_offset,
        DetectorSpan.end_offset > request.start_offset
    ).first()

    existing_risk = db.query(RiskFlag).filter(
        RiskFlag.document_id == document_id,
        RiskFlag.start_offset < request.end_offset,
        RiskFlag.end_offset > request.start_offset
    ).first()

    if existing_detector or existing_risk:
        raise HTTPException(
            status_code=400,
            detail="Overlaps with existing detection. Edit or remove the existing one first."
        )

    # Create the span
    if request.span_type == 'risk_flag':
        span = RiskFlag(
            document_id=document_id,
            start_offset=request.start_offset,
            end_offset=request.end_offset,
            text_content=text_content,
            pii_category=request.pii_category,
            pattern_source='manual',
            confidence_score=100,
            is_manual=1,
            ensemble_sources=['manual'],
            ensemble_agreement_count=1
        )
    else:
        span = DetectorSpan(
            document_id=document_id,
            start_offset=request.start_offset,
            end_offset=request.end_offset,
            text_content=text_content,
            pii_category=request.pii_category,
            confidence_score=100,
            is_manual=1,
            ensemble_sources=['manual'],
            ensemble_agreement_count=1
        )

    db.add(span)
    db.commit()
    db.refresh(span)

    return ManualSpanResponse(
        id=span.id,
        span_type=request.span_type if request.span_type == 'risk_flag' else 'detector',
        start_offset=span.start_offset,
        end_offset=span.end_offset,
        text_content=span.text_content,
        pii_category=request.pii_category,
        is_manual=True
    )


@app.patch("/api/documents/{document_id}/spans/{span_type}/{span_id}")
def update_span_category(
    document_id: int,
    span_type: str,
    span_id: int,
    request: SpanUpdateRequest,
    db: Session = Depends(get_db)
):
    """Update the PII category of an existing span."""
    if span_type not in ['detector', 'risk_flag']:
        raise HTTPException(status_code=400, detail="Invalid span_type")

    # Find the span
    if span_type == 'detector':
        span = db.query(DetectorSpan).filter(
            DetectorSpan.id == span_id,
            DetectorSpan.document_id == document_id
        ).first()
    else:
        span = db.query(RiskFlag).filter(
            RiskFlag.id == span_id,
            RiskFlag.document_id == document_id
        ).first()

    if not span:
        raise HTTPException(status_code=404, detail="Span not found")

    # Update the category
    span.pii_category = request.pii_category
    db.commit()

    return {
        "success": True,
        "span_type": span_type,
        "span_id": span_id,
        "pii_category": request.pii_category
    }


@app.delete("/api/documents/{document_id}/spans/{span_type}/{span_id}")
def delete_span(
    document_id: int,
    span_type: str,
    span_id: int,
    db: Session = Depends(get_db)
):
    """
    Delete a span (detection).

    Only allows deletion of manual spans or spans that haven't been decided on.
    """
    if span_type not in ['detector', 'risk_flag']:
        raise HTTPException(status_code=400, detail="Invalid span_type")

    # Find the span
    if span_type == 'detector':
        span = db.query(DetectorSpan).filter(
            DetectorSpan.id == span_id,
            DetectorSpan.document_id == document_id
        ).first()
    else:
        span = db.query(RiskFlag).filter(
            RiskFlag.id == span_id,
            RiskFlag.document_id == document_id
        ).first()

    if not span:
        raise HTTPException(status_code=404, detail="Span not found")

    # Check for existing decision
    existing_decision = db.query(UserDecision).filter(
        UserDecision.document_id == document_id,
        UserDecision.span_type == span_type,
        UserDecision.span_id == span_id
    ).first()

    if existing_decision:
        # Delete the decision first
        db.delete(existing_decision)

    # Delete the span
    db.delete(span)
    db.commit()

    return SpanDeleteResponse(
        success=True,
        span_type=span_type,
        span_id=span_id
    )


@app.post("/api/documents/{document_id}/complete", response_model=SummaryResponse)
def complete_review(document_id: int, db: Session = Depends(get_db)):
    """
    Mark document review as complete and return summary.
    Validates that all items have been reviewed.
    """
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # Count items
    detector_count = db.query(DetectorSpan).filter(
        DetectorSpan.document_id == document_id
    ).count()
    risk_count = db.query(RiskFlag).filter(
        RiskFlag.document_id == document_id
    ).count()
    total_items = detector_count + risk_count

    # Count decisions
    decision_count = db.query(UserDecision).filter(
        UserDecision.document_id == document_id
    ).count()

    if decision_count < total_items:
        raise HTTPException(
            status_code=400,
            detail=f"Review incomplete: {decision_count}/{total_items} items reviewed"
        )

    # Mark complete
    doc.status = "completed"
    db.commit()

    return compute_summary(document_id, db)


@app.get("/api/documents/{document_id}/summary", response_model=SummaryResponse)
def get_summary(document_id: int, db: Session = Depends(get_db)):
    """Get the review summary. Only available after completion."""
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    if doc.status != "completed":
        raise HTTPException(
            status_code=400,
            detail="Summary not available until review is complete"
        )

    return compute_summary(document_id, db)


def compute_summary(document_id: int, db: Session) -> SummaryResponse:
    """
    Compute the risk-framed summary by comparing decisions against ground truth.

    This is the only place ground truth is used to evaluate Sam's performance.

    For uploaded documents (no ground truth rows), GT-dependent metrics
    (exposures_caught, exposures_missed, unnecessary_redactions_fixed,
    correct_redactions_kept) will be zero. total_reviewed is always accurate.
    """
    # Get ground truth spans (empty for uploaded documents — that's fine)
    ground_truth = db.query(GroundTruthSpan).filter(
        GroundTruthSpan.document_id == document_id
    ).all()
    gt_set = {(gt.start_offset, gt.end_offset) for gt in ground_truth}

    # Get all decisions
    decisions = db.query(UserDecision).filter(
        UserDecision.document_id == document_id
    ).all()

    # Get detector spans and risk flags
    detector_spans = {s.id: s for s in db.query(DetectorSpan).filter(
        DetectorSpan.document_id == document_id
    ).all()}
    risk_flags = {f.id: f for f in db.query(RiskFlag).filter(
        RiskFlag.document_id == document_id
    ).all()}

    exposures_caught = 0      # risk_flags redacted that were real FNs
    exposures_missed = 0      # risk_flags dismissed that were real FNs
    unnecessary_fixed = 0     # detector FPs that Sam rejected
    correct_kept = 0          # detector TPs that Sam approved

    for d in decisions:
        if d.span_type == "detector":
            span = detector_spans.get(d.span_id)
            if not span:
                continue
            is_true_pii = (span.start_offset, span.end_offset) in gt_set

            if d.decision == "approve":
                if is_true_pii:
                    correct_kept += 1
            elif d.decision == "reject":
                if not is_true_pii:
                    unnecessary_fixed += 1

        elif d.span_type == "risk_flag":
            flag = risk_flags.get(d.span_id)
            if not flag:
                continue
            is_true_pii = (flag.start_offset, flag.end_offset) in gt_set

            if d.decision == "redact":
                if is_true_pii:
                    exposures_caught += 1
            elif d.decision == "dismiss":
                if is_true_pii:
                    exposures_missed += 1

    doc = db.query(Document).filter(Document.id == document_id).first()

    return SummaryResponse(
        exposures_caught=exposures_caught,
        exposures_missed=exposures_missed,
        unnecessary_redactions_fixed=unnecessary_fixed,
        correct_redactions_kept=correct_kept,
        total_reviewed=len(decisions),
        document_status=doc.status if doc else "unknown"
    )


# ============================================================================
# Sanitization Endpoints
# ============================================================================

@app.post("/api/documents/{document_id}/sanitize", response_model=SanitizeResponse)
def sanitize_doc(
    document_id: int,
    request: SanitizeRequest,
    db: Session = Depends(get_db)
):
    """
    Sanitize a document using either redaction or pseudonymization.

    Requires that the review is complete (all items have decisions).

    Modes:
    - redact: Replace PII with black bars (████) or [REDACTED]
    - pseudonymize: Replace PII with consistent labels (PERSON_1, EMAIL_1, etc.)

    For pseudonymization, the same entity always gets the same label throughout
    the document, and different entities get different labels.
    """
    # Get document
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # Validate mode
    if request.mode not in ['redact', 'pseudonymize']:
        raise HTTPException(
            status_code=400,
            detail="Invalid mode. Must be 'redact' or 'pseudonymize'"
        )

    # Validate redaction style
    if request.mode == 'redact' and request.redaction_style not in ['bars', 'brackets']:
        raise HTTPException(
            status_code=400,
            detail="Invalid redaction_style. Must be 'bars' or 'brackets'"
        )

    # Perform sanitization
    try:
        sanitized_content, metadata = sanitize_document(
            document_id=document_id,
            content=doc.content,
            mode=request.mode,
            db=db,
            redaction_style=request.redaction_style or 'bars'
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sanitization failed: {str(e)}")

    # Save the sanitized output
    output = SanitizedOutput(
        document_id=document_id,
        mode=request.mode,
        redaction_style=request.redaction_style if request.mode == 'redact' else None,
        content=sanitized_content,
        mapping_json=metadata.get('mapping') if request.mode == 'pseudonymize' else None
    )
    db.add(output)
    db.commit()
    db.refresh(output)

    # Build response
    response = SanitizeResponse(
        document_id=document_id,
        mode=request.mode,
        content=sanitized_content,
        redaction_count=metadata.get('count', 0),
        output_id=output.id
    )

    if request.mode == 'redact':
        response.redactions = [
            RedactionInfo(**r) for r in metadata.get('redactions', [])
        ]
    else:
        response.pseudonym_mapping = metadata.get('mapping', {})

    return response


@app.get("/api/documents/{document_id}/sanitized-outputs", response_model=List[SanitizedOutputResponse])
def get_sanitized_outputs(
    document_id: int,
    db: Session = Depends(get_db)
):
    """Get all sanitized outputs for a document."""
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    outputs = db.query(SanitizedOutput).filter_by(
        document_id=document_id
    ).order_by(SanitizedOutput.created_at.desc()).all()

    return [
        SanitizedOutputResponse(
            id=o.id,
            document_id=o.document_id,
            mode=o.mode,
            redaction_style=o.redaction_style,
            content=o.content,
            mapping=o.mapping_json,
            created_at=o.created_at
        )
        for o in outputs
    ]


@app.get("/api/documents/{document_id}/sanitized-outputs/{output_id}", response_model=SanitizedOutputResponse)
def get_sanitized_output(
    document_id: int,
    output_id: int,
    db: Session = Depends(get_db)
):
    """Get a specific sanitized output."""
    output = db.query(SanitizedOutput).filter_by(
        id=output_id,
        document_id=document_id
    ).first()

    if not output:
        raise HTTPException(status_code=404, detail="Sanitized output not found")

    return SanitizedOutputResponse(
        id=output.id,
        document_id=output.document_id,
        mode=output.mode,
        redaction_style=output.redaction_style,
        content=output.content,
        mapping=output.mapping_json,
        created_at=output.created_at
    )


@app.get("/api/documents/{document_id}/pseudonym-mappings", response_model=PseudonymMappingResponse)
def get_pseudonym_mappings(
    document_id: int,
    db: Session = Depends(get_db)
):
    """Get all pseudonym mappings for a document."""
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    mappings = db.query(PseudonymMapping).filter_by(
        document_id=document_id
    ).all()

    return PseudonymMappingResponse(
        document_id=document_id,
        mappings=[
            {
                'original': m.original_text,
                'pseudonym': m.pseudonym,
                'category': m.pii_category
            }
            for m in mappings
        ]
    )


@app.delete("/api/documents/{document_id}/pseudonym-mappings")
def clear_pseudonym_mappings(
    document_id: int,
    db: Session = Depends(get_db)
):
    """Clear all pseudonym mappings for a document (for re-pseudonymization)."""
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    deleted = db.query(PseudonymMapping).filter_by(
        document_id=document_id
    ).delete()

    db.commit()

    return {"status": "deleted", "count": deleted}
