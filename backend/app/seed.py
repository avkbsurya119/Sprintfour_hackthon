"""
Seed script: Creates the sample demand letter with ground truth PII,
deliberately flawed detector output, and runs the risk scorer.

The detector is designed to:
- Catch most PII (true positives)
- Miss 2-3 real PII items (false negatives - the dangerous ones)
- Over-redact 3-4 harmless phrases (false positives - annoying but low risk)

The risk scorer then runs on the "visible" text and flags potential misses,
including one decoy (a case reference number that looks like a phone number).
"""
from app.database import engine, SessionLocal
from app.models import Base, Document, GroundTruthSpan, DetectorSpan, RiskFlag
from app.risk_scorer import find_potential_pii


# The sample demand letter (~230 words)
DOCUMENT_CONTENT = """THOMPSON & REYNOLDS LAW OFFICES
1847 Market Street, Suite 400
San Francisco, CA 94103

Re: Demand for Payment - Case Reference 847-555-2901

Dear Mr. Marcus Whitfield,

This letter serves as formal notice that our client, Apex Financial Services,
is demanding immediate payment of the outstanding balance owed under Account
Number 4532-8891-2234-5567.

Our records indicate that despite multiple attempts to contact you at
415-867-5309 and via email at marcus.whitfield@techcorp.io, you have failed
to remit payment of $12,450.00 owed since January 15, 2024.

We have verified your identity using the Social Security Number on file
ending in 987-65-4321, and confirmed your current address at 2847 Oak Valley
Drive, San Francisco, CA 94110.

If payment is not received within thirty days of this notice, we will have no
choice but to pursue legal remedies, including but not limited to filing suit
in San Francisco Superior Court. Such action will result in additional legal
fees and court costs being added to your outstanding balance.

Please contact our office immediately at Thompson & Reynolds to arrange
payment. You may reach our collections department at 415-555-0142 or via
email at collections@thompsonreynolds.com.

Sincerely,

Elena Rodriguez
Senior Collections Attorney
Thompson & Reynolds Law Offices
elena.rodriguez@thompsonreynolds.com"""


def get_offset(text: str, substring: str, occurrence: int = 1) -> tuple[int, int]:
    """Find the start and end offset of a substring in text."""
    start = -1
    for _ in range(occurrence):
        start = text.find(substring, start + 1)
        if start == -1:
            raise ValueError(f"Substring '{substring}' not found (occurrence {occurrence})")
    return start, start + len(substring)


def seed_database():
    """Create tables and seed the demo data."""
    # Create all tables
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        # Create the document
        doc = Document(
            title="Demand for Payment - Thompson & Reynolds",
            content=DOCUMENT_CONTENT,
            status="pending_review"
        )
        db.add(doc)
        db.flush()  # Get the ID

        # === GROUND TRUTH PII (8 items) ===
        # These are the actual sensitive items that SHOULD be redacted
        ground_truth_items = [
            # Names (2)
            ("Marcus Whitfield", "name"),
            ("Elena Rodriguez", "name"),

            # Phone numbers (2)
            ("415-867-5309", "phone"),
            ("415-555-0142", "phone"),

            # Emails (3)
            ("marcus.whitfield@techcorp.io", "email"),
            ("collections@thompsonreynolds.com", "email"),
            ("elena.rodriguez@thompsonreynolds.com", "email"),

            # SSN (1)
            ("987-65-4321", "ssn"),
        ]

        for text, category in ground_truth_items:
            start, end = get_offset(DOCUMENT_CONTENT, text)
            db.add(GroundTruthSpan(
                document_id=doc.id,
                start_offset=start,
                end_offset=end,
                pii_category=category,
                text_content=text
            ))

        # === DETECTOR OUTPUT (deliberately flawed) ===
        # True positives: detector correctly catches these
        detector_catches = [
            "Marcus Whitfield",           # TP: name
            "415-555-0142",               # TP: phone
            "marcus.whitfield@techcorp.io",  # TP: email
            "collections@thompsonreynolds.com",  # TP: email
            "987-65-4321",                # TP: SSN
        ]

        # False positives: detector wrongly redacts these harmless phrases
        detector_false_positives = [
            "Apex Financial Services",     # FP: company name, not personal
            "San Francisco Superior Court",  # FP: court name, not personal
            "January 15, 2024",            # FP: date, not PII
            "$12,450.00",                  # FP: amount, not PII
        ]

        # Detector MISSES (false negatives) - these are the dangerous ones:
        # - "415-867-5309" (phone number - MISSED)
        # - "Elena Rodriguez" (name - MISSED)
        # - "elena.rodriguez@thompsonreynolds.com" (email - MISSED)

        all_detector_spans = detector_catches + detector_false_positives

        for text in all_detector_spans:
            start, end = get_offset(DOCUMENT_CONTENT, text)
            db.add(DetectorSpan(
                document_id=doc.id,
                start_offset=start,
                end_offset=end,
                text_content=text
            ))

        db.commit()

        # === RISK SCORER (second pass) ===
        # Get the detector spans to know what's already "redacted"
        detector_spans = db.query(DetectorSpan).filter_by(document_id=doc.id).all()
        redacted_ranges = [(s.start_offset, s.end_offset) for s in detector_spans]

        # Run the risk scorer on the "visible" text
        risk_findings = find_potential_pii(DOCUMENT_CONTENT, redacted_ranges)

        # Note: This will flag:
        # - "847-555-2901" (case reference number - FALSE ALARM, looks like phone)
        # - "415-867-5309" (real phone - TRUE CATCH)
        # - "Elena Rodriguez" (real name - TRUE CATCH)
        # - "elena.rodriguez@thompsonreynolds.com" (real email - TRUE CATCH)
        # - Possibly "Thompson & Reynolds" (but won't match our name heuristic)

        for finding in risk_findings:
            db.add(RiskFlag(
                document_id=doc.id,
                start_offset=finding['start_offset'],
                end_offset=finding['end_offset'],
                text_content=finding['text_content'],
                pii_category=finding['pii_category'],
                pattern_source=finding['pattern_source']
            ))

        db.commit()

        # Print summary
        print("=" * 60)
        print("SEED COMPLETE")
        print("=" * 60)
        print(f"\nDocument: {doc.title}")
        print(f"Content length: {len(DOCUMENT_CONTENT)} characters")

        gt_count = db.query(GroundTruthSpan).filter_by(document_id=doc.id).count()
        det_count = db.query(DetectorSpan).filter_by(document_id=doc.id).count()
        risk_count = db.query(RiskFlag).filter_by(document_id=doc.id).count()

        print(f"\nGround truth PII items: {gt_count}")
        print(f"Detector spans (includes FPs): {det_count}")
        print(f"Risk flags (second pass): {risk_count}")

        print("\n--- GROUND TRUTH (backend only) ---")
        for gt in db.query(GroundTruthSpan).filter_by(document_id=doc.id).all():
            print(f"  [{gt.pii_category}] '{gt.text_content}'")

        print("\n--- DETECTOR OUTPUT ---")
        print("True Positives (correct catches):")
        for text in detector_catches:
            print(f"  [OK] '{text}'")
        print("False Positives (over-redacted):")
        for text in detector_false_positives:
            print(f"  [FP] '{text}' <- harmless, shouldn't redact")
        print("False Negatives (dangerous misses):")
        print("  [FN] '415-867-5309' <- real phone, MISSED")
        print("  [FN] 'Elena Rodriguez' <- real name, MISSED")
        print("  [FN] 'elena.rodriguez@thompsonreynolds.com' <- real email, MISSED")

        print("\n--- RISK FLAGS (second pass) ---")
        for rf in db.query(RiskFlag).filter_by(document_id=doc.id).all():
            is_decoy = rf.text_content == "847-555-2901"
            marker = "DECOY - not real PII" if is_decoy else "real PII"
            print(f"  [{rf.pii_category}] '{rf.text_content}' ({rf.pattern_source}) <- {marker}")

        print("\n" + "=" * 60)

    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
