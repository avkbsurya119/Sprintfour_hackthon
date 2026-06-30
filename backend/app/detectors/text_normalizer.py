"""
Text Normalizer: Pre-processing for improved PII detection.

Handles common issues in document text:
- OCR artifacts and errors
- Split text across lines (e.g., "john@\nemail.com")
- HTML entities
- Inconsistent whitespace
- Unicode normalization
"""

import re
import unicodedata
from typing import Tuple, List, Dict


class TextNormalizer:
    """Normalizes text for improved PII detection."""

    def __init__(self):
        # Common OCR error mappings
        self.ocr_corrections = {
            '0': 'O',  # zero to letter O (contextual)
            'l': '1',  # lowercase L to one (contextual)
            'I': '1',  # uppercase I to one (contextual)
            '|': 'I',  # pipe to I
            'rn': 'm',  # r+n often misread as m
            'vv': 'w',  # double v misread as w
        }

        # HTML entities to decode
        self.html_entities = {
            '&amp;': '&',
            '&lt;': '<',
            '&gt;': '>',
            '&quot;': '"',
            '&#39;': "'",
            '&apos;': "'",
            '&nbsp;': ' ',
            '&#x27;': "'",
            '&#x2F;': '/',
            '&ndash;': '-',
            '&mdash;': '-',
            '&hellip;': '...',
            '&copy;': '(c)',
            '&reg;': '(R)',
            '&trade;': '(TM)',
        }

    def normalize(self, text: str, preserve_offsets: bool = False) -> str | Tuple[str, List[Dict]]:
        """
        Normalize text for improved detection.

        Args:
            text: Original text
            preserve_offsets: If True, return offset mapping for translation

        Returns:
            If preserve_offsets is False: normalized text
            If preserve_offsets is True: (normalized_text, offset_map)
        """
        if preserve_offsets:
            return self._normalize_with_mapping(text)
        else:
            return self._normalize_simple(text)

    def _normalize_simple(self, text: str) -> str:
        """Simple normalization without offset tracking."""
        result = text

        # 1. Unicode normalization (NFC form)
        result = unicodedata.normalize('NFC', result)

        # 2. Decode HTML entities
        for entity, char in self.html_entities.items():
            result = result.replace(entity, char)

        # 3. Normalize whitespace
        # Replace various whitespace chars with standard space
        result = re.sub(r'[\t\r\f\v]+', ' ', result)

        # 4. Fix split emails (email split across lines)
        # Pattern: word@\nword or word@\s+word
        result = re.sub(r'(\S+@)\s*\n\s*(\S+)', r'\1\2', result)

        # 5. Fix split phone numbers (digits separated by line breaks)
        # Pattern: digits-\ndigits or digits\n-digits
        result = re.sub(r'(\d+)[-.]?\s*\n\s*[-.]?(\d+)', r'\1-\2', result)

        # 6. Fix split SSN patterns
        result = re.sub(r'(\d{3})\s*[-]?\s*\n\s*[-]?\s*(\d{2})\s*[-]?\s*\n?\s*[-]?\s*(\d{4})', r'\1-\2-\3', result)

        # 7. Normalize multiple spaces to single space (but preserve newlines)
        result = re.sub(r'[^\S\n]+', ' ', result)

        # 8. Remove zero-width characters
        result = re.sub(r'[\u200b\u200c\u200d\ufeff]', '', result)

        # 9. Normalize quotes
        result = result.replace('"', '"').replace('"', '"')
        result = result.replace(''', "'").replace(''', "'")

        # 10. Normalize dashes
        result = result.replace('–', '-').replace('—', '-')

        return result

    def _normalize_with_mapping(self, text: str) -> Tuple[str, List[Dict]]:
        """
        Normalize text while tracking offset changes.

        Returns:
            Tuple of (normalized_text, offset_map)
            offset_map is a list of dicts with:
            - original_start: start in original text
            - original_end: end in original text
            - normalized_start: start in normalized text
            - normalized_end: end in normalized text
        """
        # For now, return simple normalization with identity mapping
        # A full implementation would track each transformation
        normalized = self._normalize_simple(text)

        # Simple identity mapping (works when no length changes)
        # In a full implementation, this would track actual changes
        offset_map = [{
            'original_start': 0,
            'original_end': len(text),
            'normalized_start': 0,
            'normalized_end': len(normalized)
        }]

        return normalized, offset_map

    def fix_ocr_in_context(self, text: str, context_type: str) -> str:
        """
        Apply OCR corrections based on context.

        Args:
            text: Text to fix
            context_type: Type of data expected (e.g., 'phone', 'ssn', 'email')

        Returns:
            Corrected text
        """
        result = text

        if context_type in ['phone', 'ssn', 'credit_card', 'account']:
            # In numeric contexts, fix letter-to-digit errors
            result = result.replace('O', '0')
            result = result.replace('o', '0')
            result = result.replace('l', '1')
            result = result.replace('I', '1')
            result = result.replace('S', '5')
            result = result.replace('B', '8')

        elif context_type == 'email':
            # Fix common email OCR errors
            result = result.replace(' ', '')  # Remove accidental spaces
            result = result.replace('rnail', 'mail')  # rn -> m
            result = result.replace('corn', 'com')  # rn -> m

        return result

    def extract_potential_pii_regions(self, text: str) -> List[Dict]:
        """
        Identify regions that might contain PII for focused detection.

        Returns:
            List of dicts with:
            - start: start offset
            - end: end offset
            - text: region text
            - hint: what type of PII might be present
        """
        regions = []

        # Patterns that suggest PII follows
        indicators = [
            (r'\b(?:name|customer|client|patient|employee)[:\s]', 'name'),
            (r'\b(?:phone|tel|mobile|cell|contact)[:\s]', 'phone'),
            (r'\b(?:email|e-mail)[:\s]', 'email'),
            (r'\b(?:ssn|social security)[:\s]', 'ssn'),
            (r'\b(?:account|acct)[:\s]', 'account'),
            (r'\b(?:address|street|city)[:\s]', 'address'),
            (r'\b(?:dob|date of birth|birthday)[:\s]', 'date'),
            (r'\b(?:card|credit|debit)[:\s]', 'credit_card'),
        ]

        for pattern, hint in indicators:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                # Extract region after the indicator (up to 100 chars or end of line)
                start = match.end()
                end_of_line = text.find('\n', start)
                end = min(start + 100, end_of_line if end_of_line > 0 else len(text))

                regions.append({
                    'start': match.start(),
                    'end': end,
                    'text': text[match.start():end],
                    'hint': hint
                })

        return regions

    def rejoin_split_tokens(self, text: str) -> str:
        """
        Rejoin tokens that were incorrectly split across lines.

        Handles cases like:
        - "john.smith@exam\nple.com" -> "john.smith@example.com"
        - "555-123-\n4567" -> "555-123-4567"
        """
        result = text

        # Fix emails split at domain
        result = re.sub(
            r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]*)\s*\n\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            r'\1\2',
            result
        )

        # Fix phone numbers split across lines
        result = re.sub(
            r'(\d{3}[-.\s]?\d{3})[-.\s]?\n[-.\s]?(\d{4})',
            r'\1-\2',
            result
        )

        # Fix credit cards split across lines
        result = re.sub(
            r'(\d{4}[-.\s]?\d{4})[-.\s]?\n[-.\s]?(\d{4}[-.\s]?\d{4})',
            r'\1-\2',
            result
        )

        # Fix SSN split across lines
        result = re.sub(
            r'(\d{3})[-.\s]?\n[-.\s]?(\d{2})[-.\s]?\n?[-.\s]?(\d{4})',
            r'\1-\2-\3',
            result
        )

        return result


# Singleton instance
text_normalizer = TextNormalizer()


def normalize(text: str) -> str:
    """Convenience function to normalize text."""
    return text_normalizer.normalize(text)


def normalize_with_mapping(text: str) -> Tuple[str, List[Dict]]:
    """Normalize text and return offset mapping."""
    return text_normalizer.normalize(text, preserve_offsets=True)
