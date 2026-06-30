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

# Phone: matches common US formats
PHONE_PATTERN = re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b')

# SSN: XXX-XX-XXXX format
SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')

# Email: standard email pattern
EMAIL_PATTERN = re.compile(r'\b[\w.-]+@[\w.-]+\.\w{2,}\b')

# Common first names for name detection heuristic
COMMON_NAMES = {
    'james', 'john', 'robert', 'michael', 'william', 'david', 'richard', 'joseph',
    'thomas', 'charles', 'mary', 'patricia', 'jennifer', 'linda', 'elizabeth',
    'barbara', 'susan', 'jessica', 'sarah', 'karen', 'margaret', 'alice', 'bob',
    'carol', 'daniel', 'edward', 'frank', 'george', 'henry', 'ivan', 'jack',
    'kevin', 'larry', 'mark', 'nancy', 'oliver', 'peter', 'quinn', 'raymond',
    'steven', 'timothy', 'victor', 'walter', 'xavier', 'zachary', 'angela',
    'catherine', 'donna', 'emily', 'fiona', 'grace', 'helen', 'irene', 'julia',
    'marcus', 'elena'  # First names from our document (not surnames)
}

# Pattern for two consecutive capitalized words (potential name)
NAME_PATTERN = re.compile(r'\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\b')


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

    # Check for names (two capitalized words where first matches common names)
    for match in NAME_PATTERN.finditer(text):
        first_name = match.group(1).lower()
        if first_name in COMMON_NAMES:
            if not is_in_redacted_range(match.start(), match.end()):
                findings.append({
                    'start_offset': match.start(),
                    'end_offset': match.end(),
                    'text_content': match.group(),
                    'pii_category': 'name',
                    'pattern_source': 'name_heuristic'
                })

    return findings
