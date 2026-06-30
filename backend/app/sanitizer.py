"""
Document Sanitizer: Handles redaction and pseudonymization of PII.

Provides two sanitization modes:
1. Redaction: Replace PII with black bars (███) or [REDACTED] markers
2. Pseudonymization: Replace PII with consistent labels (PERSON_1, EMAIL_1, etc.)

Pseudonymization maintains consistency - the same entity always gets the same
replacement throughout the document.
"""

from typing import List, Dict, Tuple, Optional
from sqlalchemy.orm import Session
from app.models import PseudonymMapping, DetectorSpan, RiskFlag, UserDecision


class PseudonymGenerator:
    """
    Generates consistent pseudonyms for PII entities.

    The same original text always maps to the same pseudonym within a document.
    Different entities get different pseudonyms.
    """

    # Category to prefix mapping
    CATEGORY_PREFIXES = {
        'name': 'PERSON',
        'email': 'EMAIL',
        'phone': 'PHONE',
        'ssn': 'SSN',
        'itin': 'TAX_ID',
        'ein': 'TAX_ID',
        'tax_id': 'TAX_ID',
        'credit_card': 'CARD',
        'bank_account': 'ACCOUNT',
        'routing_number': 'ROUTING',
        'iban': 'IBAN',
        'swift': 'SWIFT',
        'organization': 'ORG',
        'location': 'LOCATION',
        'address': 'ADDRESS',
        'postal_code': 'ZIP',
        'date': 'DATE',
        'date_of_birth': 'DOB',
        'ip_address': 'IP',
        'url': 'URL',
        'username': 'USER',
        'passport': 'PASSPORT',
        'drivers_license': 'LICENSE',
        'vin': 'VIN',
        'license_plate': 'PLATE',
        'mrn': 'MRN',
        'customer_id': 'CUST',
        'employee_id': 'EMP',
        'invoice': 'INV',
        'order_number': 'ORDER',
        'account_number': 'ACCT',
        'reference_number': 'REF',
        'case_number': 'CASE',
        'policy_number': 'POLICY',
        'id_number': 'ID',
        'money': 'AMOUNT',
    }

    def __init__(self, document_id: int, db: Session):
        self.document_id = document_id
        self.db = db
        self.cache: Dict[str, str] = {}  # normalized_text -> pseudonym
        self.counters: Dict[str, int] = {}  # prefix -> next number
        self._load_existing_mappings()

    def _load_existing_mappings(self):
        """Load existing pseudonym mappings for this document."""
        existing = self.db.query(PseudonymMapping).filter_by(
            document_id=self.document_id
        ).all()

        for mapping in existing:
            key = self._make_cache_key(mapping.normalized_text, mapping.pii_category)
            self.cache[key] = mapping.pseudonym

            # Update counters based on existing mappings
            prefix = mapping.pseudonym.rsplit('_', 1)[0]
            try:
                num = int(mapping.pseudonym.rsplit('_', 1)[1])
                self.counters[prefix] = max(self.counters.get(prefix, 0), num + 1)
            except (ValueError, IndexError):
                pass

    def _normalize(self, text: str) -> str:
        """Normalize text for consistent matching."""
        return text.lower().strip()

    def _make_cache_key(self, normalized_text: str, category: str) -> str:
        """Create cache key from normalized text and category."""
        return f"{category}:{normalized_text}"

    def _get_prefix(self, category: str) -> str:
        """Get the pseudonym prefix for a PII category."""
        return self.CATEGORY_PREFIXES.get(category, 'ENTITY')

    def get_or_create_pseudonym(self, text: str, pii_category: str) -> str:
        """
        Get or create a pseudonym for the given text and category.

        Same text + category always returns the same pseudonym.
        """
        normalized = self._normalize(text)
        cache_key = self._make_cache_key(normalized, pii_category)

        # Return cached pseudonym if exists
        if cache_key in self.cache:
            return self.cache[cache_key]

        # Generate new pseudonym
        prefix = self._get_prefix(pii_category)
        counter = self.counters.get(prefix, 1)
        pseudonym = f"{prefix}_{counter}"
        self.counters[prefix] = counter + 1

        # Cache it
        self.cache[cache_key] = pseudonym

        # Persist to database
        mapping = PseudonymMapping(
            document_id=self.document_id,
            original_text=text,
            normalized_text=normalized,
            pii_category=pii_category,
            pseudonym=pseudonym
        )
        self.db.add(mapping)

        return pseudonym

    def get_mapping_dict(self) -> Dict[str, str]:
        """Get all mappings as a dictionary for export."""
        mappings = self.db.query(PseudonymMapping).filter_by(
            document_id=self.document_id
        ).all()

        return {
            m.original_text: m.pseudonym
            for m in mappings
        }


class DocumentSanitizer:
    """
    Sanitizes documents by replacing PII with redactions or pseudonyms.
    """

    def __init__(self, document_id: int, db: Session):
        self.document_id = document_id
        self.db = db

    def get_approved_spans(self) -> List[Dict]:
        """
        Get all spans that should be redacted/pseudonymized.

        This includes:
        - DetectorSpans with decision='approve' (user approved the redaction)
        - RiskFlags with decision='redact' (user chose to redact)
        """
        spans = []

        # Get decisions
        decisions = self.db.query(UserDecision).filter_by(
            document_id=self.document_id
        ).all()

        decision_map = {}
        for d in decisions:
            key = (d.span_type, d.span_id)
            decision_map[key] = d.decision

        # Get detector spans that were approved
        detector_spans = self.db.query(DetectorSpan).filter_by(
            document_id=self.document_id
        ).all()

        for span in detector_spans:
            decision = decision_map.get(('detector', span.id))
            if decision == 'approve':
                spans.append({
                    'start': span.start_offset,
                    'end': span.end_offset,
                    'text': span.text_content,
                    'category': span.pii_category or 'unknown'
                })

        # Get risk flags that were redacted
        risk_flags = self.db.query(RiskFlag).filter_by(
            document_id=self.document_id
        ).all()

        for flag in risk_flags:
            decision = decision_map.get(('risk_flag', flag.id))
            if decision == 'redact':
                spans.append({
                    'start': flag.start_offset,
                    'end': flag.end_offset,
                    'text': flag.text_content,
                    'category': flag.pii_category or 'unknown'
                })

        # Sort by start offset (reverse for replacement)
        spans.sort(key=lambda x: x['start'], reverse=True)

        return spans

    def redact(
        self,
        content: str,
        style: str = 'bars'
    ) -> Tuple[str, List[Dict]]:
        """
        Redact all approved PII from the document.

        Args:
            content: Original document content
            style: 'bars' for ████ or 'brackets' for [REDACTED]

        Returns:
            Tuple of (redacted_content, redaction_list)
        """
        spans = self.get_approved_spans()
        result = content
        redactions = []

        for span in spans:
            start = span['start']
            end = span['end']
            original = span['text']

            # Generate replacement based on style
            if style == 'bars':
                # Use Unicode full block character
                replacement = '█' * len(original)
            else:
                # Use bracketed marker
                replacement = '[REDACTED]'

            # Replace in content
            result = result[:start] + replacement + result[end:]

            redactions.append({
                'original': original,
                'category': span['category'],
                'start': start,
                'end': end,
                'replacement': replacement
            })

        return result, redactions

    def pseudonymize(self, content: str) -> Tuple[str, Dict[str, str]]:
        """
        Pseudonymize all approved PII in the document.

        Each unique entity gets a consistent pseudonym throughout.

        Args:
            content: Original document content

        Returns:
            Tuple of (pseudonymized_content, mapping_dict)
        """
        generator = PseudonymGenerator(self.document_id, self.db)
        spans = self.get_approved_spans()
        result = content

        for span in spans:
            start = span['start']
            end = span['end']
            original = span['text']
            category = span['category']

            # Get or create pseudonym
            pseudonym = generator.get_or_create_pseudonym(original, category)

            # Replace in content
            result = result[:start] + pseudonym + result[end:]

        # Commit the pseudonym mappings
        self.db.flush()

        return result, generator.get_mapping_dict()


def sanitize_document(
    document_id: int,
    content: str,
    mode: str,
    db: Session,
    redaction_style: str = 'bars'
) -> Tuple[str, Dict]:
    """
    Convenience function to sanitize a document.

    Args:
        document_id: ID of the document
        content: Original document content
        mode: 'redact' or 'pseudonymize'
        db: Database session
        redaction_style: 'bars' or 'brackets' (only for redact mode)

    Returns:
        Tuple of (sanitized_content, metadata)
        - For redact mode: metadata contains list of redactions
        - For pseudonymize mode: metadata contains mapping dictionary
    """
    sanitizer = DocumentSanitizer(document_id, db)

    if mode == 'redact':
        sanitized, redactions = sanitizer.redact(content, style=redaction_style)
        return sanitized, {'redactions': redactions, 'count': len(redactions)}
    elif mode == 'pseudonymize':
        sanitized, mapping = sanitizer.pseudonymize(content)
        return sanitized, {'mapping': mapping, 'count': len(mapping)}
    else:
        raise ValueError(f"Invalid sanitization mode: {mode}")
