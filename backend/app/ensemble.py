"""
Ensemble detection system: runs multiple detectors and reconciles their results.

This module provides:
1. Individual detector functions (enhanced_regex, presidio, spacy, context, rules)
2. Text normalization for improved detection
3. Reconciliation logic to merge overlapping detections
4. Persistence function to save ALL detections to database

Phase 2 enhancements:
- Enhanced regex with 20+ PII patterns
- Context-aware detection for embedded IDs
- Text normalization for OCR and formatting issues
"""
import re
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session

# Import new detectors
from app.detectors.enhanced_regex import EnhancedRegexDetector
from app.detectors.context_detector import ContextDetector
from app.detectors.text_normalizer import TextNormalizer

# Keep legacy patterns for backwards compatibility
from app.risk_scorer import PHONE_PATTERN, POSTAL_PATTERN, SSN_PATTERN, EMAIL_PATTERN, NAME_PATTERN

import spacy
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

# Initialize detectors
enhanced_regex = EnhancedRegexDetector()
context_detector = ContextDetector()
text_normalizer = TextNormalizer()

# Initialize Presidio with the small model
configuration = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
}
provider = NlpEngineProvider(nlp_configuration=configuration)
nlp_engine = provider.create_engine()
analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])

# Initialize spaCy
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    nlp = None

# High-confidence PII categories (go to DetectorSpan)
HIGH_CONFIDENCE_CATEGORIES = {
    'ssn', 'itin', 'ein', 'email', 'phone', 'credit_card',
    'bank_account', 'routing_number', 'passport', 'drivers_license',
    'ip_address', 'iban', 'swift', 'us_ssn', 'date_of_birth',
    'tax_id', 'vin', 'mrn'
}

# Lower-confidence categories (go to RiskFlag for human review)
REVIEW_CATEGORIES = {
    'name', 'location', 'organization', 'date', 'postal_code',
    'url', 'username', 'id_number', 'address', 'account_number',
    'customer_id', 'employee_id', 'invoice', 'order_number',
    'reference_number', 'case_number', 'policy_number', 'license_number',
    'money', 'alphanumeric_id', 'percentage', 'other'
}


def run_enhanced_regex(text: str) -> List[Dict[str, Any]]:
    """Run the enhanced regex detector with 20+ patterns."""
    return enhanced_regex.detect(text)


def run_context(text: str) -> List[Dict[str, Any]]:
    """Run the context-aware detector for embedded IDs."""
    return context_detector.detect(text)


def run_legacy_regex(text: str) -> List[Dict[str, Any]]:
    """Run the original simple regex patterns (for comparison/fallback)."""
    detections = []

    for match in SSN_PATTERN.finditer(text):
        detections.append({
            'start': match.start(),
            'end': match.end(),
            'text': match.group(),
            'type': 'ssn',
            'source': 'legacy_regex'
        })
    for match in EMAIL_PATTERN.finditer(text):
        detections.append({
            'start': match.start(),
            'end': match.end(),
            'text': match.group(),
            'type': 'email',
            'source': 'legacy_regex'
        })
    for match in PHONE_PATTERN.finditer(text):
        detections.append({
            'start': match.start(),
            'end': match.end(),
            'text': match.group(),
            'type': 'phone',
            'source': 'legacy_regex'
        })
    for match in POSTAL_PATTERN.finditer(text):
        detections.append({
            'start': match.start(),
            'end': match.end(),
            'text': match.group(),
            'type': 'postal_code',
            'source': 'legacy_regex'
        })
    for match in NAME_PATTERN.finditer(text):
        detections.append({
            'start': match.start(),
            'end': match.end(),
            'text': match.group(),
            'type': 'name',
            'source': 'legacy_regex'
        })

    return detections


def run_presidio(text: str) -> List[Dict[str, Any]]:
    """Runs Presidio Analyzer with comprehensive entity detection."""
    detections = []
    try:
        # Request all available entity types
        results = analyzer.analyze(text=text, entities=[], language='en')
        for res in results:
            t = res.entity_type.lower()
            # Map presidio types to our types
            type_mapping = {
                'person': 'name',
                'email_address': 'email',
                'phone_number': 'phone',
                'us_ssn': 'ssn',
                'credit_card': 'credit_card',
                'location': 'location',
                'date_time': 'date',
                'ip_address': 'ip_address',
                'url': 'url',
                'iban_code': 'iban',
                'us_bank_number': 'bank_account',
                'us_driver_license': 'drivers_license',
                'us_passport': 'passport',
                'us_itin': 'itin',
                'uk_nhs': 'mrn',
                'medical_license': 'license_number',
                'nrp': 'name',  # nationality/religious/political group -> name
                'organization': 'organization',
            }
            t = type_mapping.get(t, t)

            detections.append({
                'start': res.start,
                'end': res.end,
                'text': text[res.start:res.end],
                'type': t,
                'source': 'presidio',
                'presidio_score': res.score
            })
    except Exception as e:
        print(f"Presidio error: {e}")
    return detections


def run_spacy(text: str) -> List[Dict[str, Any]]:
    """Runs spaCy NER with comprehensive entity mapping."""
    detections = []
    if not nlp:
        return detections

    try:
        doc = nlp(text)
        for ent in doc.ents:
            t = ent.label_.lower()
            # Map spaCy entity types to our types
            type_mapping = {
                'person': 'name',
                'gpe': 'location',
                'loc': 'location',
                'org': 'organization',
                'date': 'date',
                'time': 'date',
                'money': 'money',
                'percent': 'percentage',
                'cardinal': None,  # Skip raw numbers
                'ordinal': None,  # Skip ordinals
                'quantity': None,  # Skip quantities
                'norp': 'name',  # nationality/religious/political -> name
                'fac': 'address',  # facility -> address
                'product': None,  # Skip products
                'event': None,  # Skip events
                'work_of_art': None,  # Skip art
                'law': None,  # Skip laws
                'language': None,  # Skip languages
            }

            mapped_type = type_mapping.get(t)
            if mapped_type is None:
                continue

            detections.append({
                'start': ent.start_char,
                'end': ent.end_char,
                'text': ent.text,
                'type': mapped_type,
                'source': 'spacy'
            })
    except Exception as e:
        print(f"spaCy error: {e}")
    return detections


def run_rules(text: str) -> List[Dict[str, Any]]:
    """Independent Rule-Based Detector for URLs, usernames, and IDs."""
    detections = []

    # URL pattern (comprehensive)
    url_pattern = re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\-._~:/?#[\]@!$&\'()*+,;=%]*'
    )
    for m in url_pattern.finditer(text):
        detections.append({
            'start': m.start(),
            'end': m.end(),
            'text': m.group(),
            'type': 'url',
            'source': 'rules'
        })

    # @mentions / Usernames
    username_pattern = re.compile(r'(?:^|(?<=[^a-zA-Z0-9-_\.]))@([A-Za-z]+[A-Za-z0-9-_]+)')
    for m in username_pattern.finditer(text):
        detections.append({
            'start': m.start(),
            'end': m.end(),
            'text': m.group(),
            'type': 'username',
            'source': 'rules'
        })

    # Alphanumeric IDs (10+ chars with both letters and digits)
    id_pattern = re.compile(r'\b[A-Z0-9]{10,20}\b')
    for m in id_pattern.finditer(text):
        if any(c.isdigit() for c in m.group()) and any(c.isalpha() for c in m.group()):
            detections.append({
                'start': m.start(),
                'end': m.end(),
                'text': m.group(),
                'type': 'id_number',
                'source': 'rules'
            })

    return detections


def reconcile_spans(all_detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Takes a flat list of all detections from all sources and merges overlapping ones.

    Returns a list of reconciled spans, each containing:
    - start, end: character offsets
    - text: the detected text
    - types: list of PII types detected (may differ across detectors)
    - sources: list of detector names that found this span
    - agreement_count: number of detectors that found this span
    - confidence_score: computed confidence (0-100)
    """
    if not all_detections:
        return []

    # Sort by start offset
    all_detections.sort(key=lambda x: x['start'])

    clusters = []
    current_cluster = [all_detections[0]]
    current_end = all_detections[0]['end']

    for det in all_detections[1:]:
        if det['start'] < current_end:
            # Overlap - add to current cluster
            current_cluster.append(det)
            current_end = max(current_end, det['end'])
        else:
            # No overlap - finalize current cluster and start new one
            clusters.append(current_cluster)
            current_cluster = [det]
            current_end = det['end']
    clusters.append(current_cluster)

    reconciled = []
    for cluster in clusters:
        start = min(d['start'] for d in cluster)
        end = max(d['end'] for d in cluster)

        # Deduplicate sources (enhanced_regex and legacy_regex count as one "regex")
        raw_sources = [d['source'] for d in cluster]
        normalized_sources = set()
        for s in raw_sources:
            if 'regex' in s:
                normalized_sources.add('regex')
            else:
                normalized_sources.add(s)
        sources = list(normalized_sources)

        # Normalize types from enhanced regex
        type_mapping = {
            'name_caps': 'name',
            'location_indian': 'location',
            'username_lax': 'username'
        }
        types = list(set(type_mapping.get(d['type'], d['type']) for d in cluster))
        agreement_count = len(sources)

        # Compute confidence score based on agreement and sources
        confidence = compute_confidence(sources, types, cluster)

        # Pick the longest text
        longest_text = max((d['text'] for d in cluster), key=len)

        # Determine primary type (prefer more specific types)
        primary_type = determine_primary_type(types)

        reconciled.append({
            'start': start,
            'end': end,
            'text': longest_text,
            'primary_type': primary_type,
            'types': types,
            'sources': sources,
            'agreement_count': agreement_count,
            'confidence_score': confidence
        })

    return reconciled


def compute_confidence(sources: List[str], types: List[str], cluster: List[Dict]) -> int:
    """
    Compute confidence score (0-100) based on:
    - Number of detectors that agree
    - Which detectors found it (ML-based vs regex)
    - Type consistency
    - Presidio's own confidence score if available
    """
    score = 0

    # Base score from agreement (now with 6 potential sources)
    agreement = len(sources)
    if agreement >= 5:
        score = 98
    elif agreement >= 4:
        score = 95
    elif agreement == 3:
        score = 85
    elif agreement == 2:
        score = 70
    else:
        score = 50

    # Bonus for ML-based detectors (presidio, spacy)
    ml_sources = {'presidio', 'spacy'}
    if ml_sources & set(sources):
        score += 5

    # Bonus for context-aware detection
    if 'context' in sources:
        score += 5

    # Penalty for type disagreement
    if len(types) > 1:
        score -= 10
    if len(types) > 2:
        score -= 5  # Additional penalty for high disagreement

    # Incorporate Presidio's confidence if available
    presidio_scores = [d.get('presidio_score', 0) for d in cluster if d.get('presidio_score')]
    if presidio_scores:
        avg_presidio = sum(presidio_scores) / len(presidio_scores)
        # Blend our score with Presidio's
        score = int(score * 0.7 + avg_presidio * 100 * 0.3)

    return max(0, min(100, score))


def determine_primary_type(types: List[str]) -> str:
    """
    Determine the primary PII type when multiple types are detected.
    Prefer more specific/sensitive types over generic ones.

    Context-specific types (from context detector) are prioritized over
    generic classifications (like drivers_license from Presidio).
    """
    # Priority order (most specific/sensitive first)
    # Note: Context-specific types are prioritized because they indicate
    # the detector found a keyword like "Invoice #" near the value
    priority = [
        # Critical identity
        'ssn', 'itin', 'ein', 'tax_id',
        # Financial
        'credit_card', 'bank_account', 'routing_number', 'iban', 'swift',
        # Medical
        'mrn', 'date_of_birth',
        # Context-specific reference numbers (before phone/email since context is more specific)
        'invoice', 'order_number', 'customer_id', 'employee_id',
        'account_number', 'reference_number', 'case_number',
        'policy_number', 'license_number',
        # Contact (after context-specific IDs)
        'phone', 'email', 'ip_address',
        # Identity documents / Vehicle
        'passport', 'drivers_license', 'vin', 'license_plate',
        # Location
        'address', 'location', 'postal_code',
        # Generic
        'url', 'username', 'id_number', 'alphanumeric_id',
        'organization', 'name', 'date', 'money'
    ]

    for t in priority:
        if t in types:
            return t

    return types[0] if types else 'unknown'


# Common false positives to filter out
FALSE_POSITIVE_FILTER = {
    # Abbreviations that get misclassified as organizations
    'ssn', 'dob', 'ein', 'tin', 'mrn', 'vin', 'pin', 'cvv', 'cvc',
    'atm', 'pos', 'aba', 'ach', 'eft', 'iban', 'bic', 'swift',
    # Common labels
    'credit card', 'bank account', 'routing number', 'account number',
    'phone number', 'email address', 'date of birth', 'social security',
    'license plate', 'order number', 'invoice number', 'customer id',
    'employee id', 'patient id', 'policy number', 'reference number',
}


def filter_false_positives(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove common false positives from detections."""
    filtered = []
    for d in detections:
        text = d['text'].strip()
        text_lower = text.lower()

        # Skip if the text is a known false positive
        if text_lower in FALSE_POSITIVE_FILTER:
            continue

        # Skip very short matches (likely fragments)
        if len(text) < 4:
            continue

        # Skip if it's just a label (ends with colon)
        if text_lower.endswith(':'):
            continue

        # Skip if organization/name is a common abbreviation
        if d['type'] in ['organization', 'name']:
            if text_lower in FALSE_POSITIVE_FILTER:
                continue
            # Also skip single short words that aren't names
            if len(text) < 5 and not any(c.isupper() for c in text[1:]):
                continue

        # Skip partial words (likely OCR artifacts)
        # But allow phone numbers starting with ( and other valid PII
        allowed_start_chars = ['(', '+', '#', '@']
        if (not text[0].isupper() and
            not text[0].isdigit() and
            text[0] not in allowed_start_chars and
            d['type'] not in ['email', 'url', 'username', 'phone']):
            continue

        filtered.append(d)

    return filtered


def run_ensemble(text: str, normalize: bool = True) -> List[Dict[str, Any]]:
    """
    Run all detectors and return reconciled spans.

    Args:
        text: The text to analyze
        normalize: Whether to apply text normalization first

    Returns:
        List of reconciled detection spans
    """
    # Optionally normalize text for better detection
    if normalize:
        processed_text = text_normalizer.normalize(text)
    else:
        processed_text = text

    # Run all detectors
    d1 = run_enhanced_regex(processed_text)  # Enhanced regex (20+ patterns)
    d2 = run_presidio(processed_text)        # Presidio ML-based
    d3 = run_spacy(processed_text)           # spaCy NER
    d4 = run_context(processed_text)         # Context-aware detection
    d5 = run_rules(processed_text)           # Rule-based patterns

    # Combine and filter all detections
    all_det = d1 + d2 + d3 + d4 + d5
    all_det = filter_false_positives(all_det)

    # Reconcile overlapping detections
    return reconcile_spans(all_det)


def persist_ensemble_results(
    text: str,
    document_id: int,
    db: Session,
    normalize: bool = True
) -> Tuple[List[Any], List[Any]]:
    """
    Run ensemble detection and persist ALL results to database.

    Args:
        text: Document text to analyze
        document_id: ID of the document in database
        db: Database session
        normalize: Whether to normalize text first

    Returns:
        Tuple of (detector_spans_added, risk_flags_added)
    """
    from app.models import DetectorSpan, RiskFlag

    reconciled_spans = run_ensemble(text, normalize=normalize)

    detector_spans_added = []
    risk_flags_added = []

    # Track ranges to avoid duplicates
    existing_ranges = set()

    for span in reconciled_spans:
        start = span['start']
        end = span['end']

        # Skip if we already have a span covering this exact range
        range_key = (start, end)
        if range_key in existing_ranges:
            continue
        existing_ranges.add(range_key)

        primary_type = span['primary_type']

        # Determine if this is high-confidence (DetectorSpan) or needs review (RiskFlag)
        is_high_confidence = (
            primary_type in HIGH_CONFIDENCE_CATEGORIES or
            span['confidence_score'] >= 80
        )

        if is_high_confidence:
            # High confidence - create DetectorSpan
            detector_span = DetectorSpan(
                document_id=document_id,
                start_offset=start,
                end_offset=end,
                text_content=span['text'],
                pii_category=primary_type,
                confidence_score=span['confidence_score'],
                is_manual=0,
                ensemble_sources=span['sources'],
                ensemble_agreement_count=span['agreement_count'],
                ensemble_conflict_types=span['types'] if len(span['types']) > 1 else None
            )
            db.add(detector_span)
            detector_spans_added.append(detector_span)
        else:
            # Lower confidence - create RiskFlag for human review
            risk_flag = RiskFlag(
                document_id=document_id,
                start_offset=start,
                end_offset=end,
                text_content=span['text'],
                pii_category=primary_type,
                pattern_source=','.join(span['sources']),
                confidence_score=span['confidence_score'],
                is_manual=0,
                ensemble_sources=span['sources'],
                ensemble_agreement_count=span['agreement_count'],
                ensemble_conflict_types=span['types'] if len(span['types']) > 1 else None
            )
            db.add(risk_flag)
            risk_flags_added.append(risk_flag)

    return detector_spans_added, risk_flags_added


# Legacy function for backwards compatibility with seed.py
def apply_ensemble_metadata(target_spans, reconciled_spans):
    """
    Legacy function: applies ensemble metadata to existing spans.

    This is kept for backwards compatibility with seed.py demo document.
    For new documents, use persist_ensemble_results() instead.
    """
    for span in target_spans:
        overlapping = [
            rs for rs in reconciled_spans
            if max(span.start_offset, rs['start']) < min(span.end_offset, rs['end'])
        ]
        if overlapping:
            rs = overlapping[0]
            span.ensemble_sources = rs['sources']
            span.ensemble_agreement_count = rs['agreement_count']
            span.ensemble_conflict_types = rs['types'] if len(rs['types']) > 1 else None
            if hasattr(span, 'confidence_score') and span.confidence_score is None:
                span.confidence_score = rs.get('confidence_score', 50)
        else:
            span.ensemble_sources = ['regex']
            span.ensemble_agreement_count = 1
            span.ensemble_conflict_types = None


# Backwards compatible alias
def run_regex(text: str) -> List[Dict[str, Any]]:
    """Alias for run_enhanced_regex for backwards compatibility."""
    return run_enhanced_regex(text)
