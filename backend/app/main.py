from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db, engine
from app.models import Base, Document, DetectorSpan, RiskFlag, UserDecision, GroundTruthSpan
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
)
from app.extractor import extract_text, ExtractionError
from app.risk_scorer import find_potential_pii, PHONE_PATTERN, SSN_PATTERN, EMAIL_PATTERN, NAME_PATTERN, POSTAL_PATTERN
from app.ensemble import run_ensemble, apply_ensemble_metadata

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

    Uses Option D confidence-tier split for detector spans vs risk flags:
    - High-confidence patterns (SSN, email, phone regex) → DetectorSpan rows
      (shown as "Proposed Redactions" — machine is confident)
    - Lower-confidence heuristics (name pattern) → RiskFlag rows
      (shown as "Potential Risk" — needs human judgment)

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

    # --- Option D: scan full text, split by confidence tier ---
    # Pass empty redacted_ranges — for uploaded docs, nothing is pre-redacted.
    # HIGH-CONFIDENCE patterns → DetectorSpan
    detector_spans_added = []
    detector_ranges = []

    for pattern, category in [
        (SSN_PATTERN, 'ssn'),
        (EMAIL_PATTERN, 'email'),
        (PHONE_PATTERN, 'phone'),
        (POSTAL_PATTERN, 'postal_code'),
    ]:
        for match in pattern.finditer(text):
            # Avoid overlapping spans (e.g. SSN pattern subset of phone pattern)
            start, end = match.start(), match.end()
            overlaps = any(
                not (end <= rs or start >= re)
                for rs, re in detector_ranges
            )
            if overlaps:
                continue
            span = DetectorSpan(
                document_id=doc.id,
                start_offset=start,
                end_offset=end,
                text_content=match.group()
            )
            db.add(span)
            detector_spans_added.append(span)
            detector_ranges.append((start, end))

    # LOWER-CONFIDENCE heuristic → RiskFlag (elevated urgency)
    risk_flags_added = []
    for match in NAME_PATTERN.finditer(text):
        start, end = match.start(), match.end()
        # Skip if already covered by a high-confidence detector span
        overlaps = any(
            not (end <= rs or start >= re)
            for rs, re in detector_ranges
        )
        if overlaps:
            continue
        flag = RiskFlag(
            document_id=doc.id,
            start_offset=start,
            end_offset=end,
            text_content=match.group(),
            pii_category='name',
            pattern_source='name_heuristic'
        )
        db.add(flag)
        risk_flags_added.append(flag)

    # ENSEMBLE PASS
    reconciled_spans = run_ensemble(text)
    apply_ensemble_metadata(detector_spans_added, reconciled_spans)
    apply_ensemble_metadata(risk_flags_added, reconciled_spans)

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
            decision=decision_map.get(("detector", span.id))
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
            decision=decision_map.get(("risk_flag", flag.id))
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
