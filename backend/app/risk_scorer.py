"""
Second-pass risk scorer: scans text left visible by the detector
to flag likely-missed PII using pattern heuristics.

This is intentionally imperfect — it will catch some real misses
but also flag some false positives (e.g., reference numbers that
look like phone numbers). The whole point is that AI needs human
review at every layer.
"""
import re
from typing import List, Tuple, Set

# Phone: US and Indian formats (mobile/landline) without matching 16-digit accounts or SSNs
PHONE_PATTERN = re.compile(
    r'\b(?:'
    r'(?:\+?1[-.\s]*)?(?:\(\d{3}\)|\d{3})[-.\s]*\d{3}[-.\s]*\d{4}' # US formats
    r'|(?:\+?91[-.\s]*)?[6-9]\d{4}[-.\s]*\d{5}' # Indian Mobile (5-5)
    r'|(?:\+?91[-.\s]*)?[6-9]\d{2}[-.\s]*\d{3}[-.\s]*\d{4}' # Indian Mobile (3-3-4)
    r'|0\d{2,4}[-.\s]+\d{3,4}[-.\s]+\d{3,4}' # Indian Landline
    r')\b'
)

# Postal/PIN code: matches 5-digit US Zip, 6-digit PIN, and spaced 6-digit PINs
POSTAL_PATTERN = re.compile(r'\b(?:\d{5}(?:-\d{4})?|\d{6}|\d{3}\s?\d{3})\b')

# SSN: XXX-XX-XXXX format
SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')

# Email: standard email pattern
EMAIL_PATTERN = re.compile(r'\b[\w.-]+@[\w.-]+\.\w{2,}\b')

# Names: Match 2 to 4 consecutive capitalized words.
NAME_PATTERN = re.compile(r'\b(?:[A-Z][a-z]+\s+){1,3}[A-Z][a-z]+\b')


def find_potential_pii(
    text: str,
    redacted_ranges: List[Tuple[int, int]]
) -> List[dict]:
    """
    Scan text for potential PII that wasn't caught by the detector.

    Args:
        text: Full document text
        redacted_ranges: List of (start, end) tuples that detector already flagged

    Returns:
        List of dicts with keys: start_offset, end_offset, text_content,
        pii_category, pattern_source
    """
    findings = []

    def is_in_redacted_range(start: int, end: int) -> bool:
        """Check if a span overlaps with any already-redacted range."""
        for r_start, r_end in redacted_ranges:
            if not (end <= r_start or start >= r_end):
                return True
        return False

    # Check for phone numbers
    for match in PHONE_PATTERN.finditer(text):
        if not is_in_redacted_range(match.start(), match.end()):
            findings.append({
                'start_offset': match.start(),
                'end_offset': match.end(),
                'text_content': match.group(),
                'pii_category': 'phone',
                'pattern_source': 'phone_regex'
            })

    # Check for SSNs
    for match in SSN_PATTERN.finditer(text):
        if not is_in_redacted_range(match.start(), match.end()):
            findings.append({
                'start_offset': match.start(),
                'end_offset': match.end(),
                'text_content': match.group(),
                'pii_category': 'ssn',
                'pattern_source': 'ssn_regex'
            })

    # Check for emails
    for match in EMAIL_PATTERN.finditer(text):
        if not is_in_redacted_range(match.start(), match.end()):
            findings.append({
                'start_offset': match.start(),
                'end_offset': match.end(),
                'text_content': match.group(),
                'pii_category': 'email',
                'pattern_source': 'email_regex'
            })

    # Check for postal/PIN codes
    for match in POSTAL_PATTERN.finditer(text):
        if not is_in_redacted_range(match.start(), match.end()):
            findings.append({
                'start_offset': match.start(),
                'end_offset': match.end(),
                'text_content': match.group(),
                'pii_category': 'postal_code',
                'pattern_source': 'postal_regex'
            })

    # Check for names (2-4 capitalized words)
    for match in NAME_PATTERN.finditer(text):
        if not is_in_redacted_range(match.start(), match.end()):
            findings.append({
                'start_offset': match.start(),
                'end_offset': match.end(),
                'text_content': match.group(),
                'pii_category': 'name',
                'pattern_source': 'name_heuristic'
            })

    return findings
