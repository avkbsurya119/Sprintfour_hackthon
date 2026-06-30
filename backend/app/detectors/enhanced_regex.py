"""
Enhanced Regex Detector: Comprehensive patterns for 20+ PII types.

This module provides extensive regex-based detection for:
- Identity documents (SSN, passport, driver's license, tax IDs)
- Financial data (credit cards, bank accounts, routing numbers)
- Contact info (phone, email, addresses)
- Digital identifiers (IP addresses, URLs, usernames)
- Reference numbers (invoice, customer ID, employee ID, MRN)
"""

import re
from typing import List, Dict, Any


class EnhancedRegexDetector:
    """Comprehensive regex-based PII detector."""

    # Common words/phrases that should NOT be flagged as PII
    BLOCKLIST = {
        # Document structure words
        'confidential', 'employee', 'record', 'information', 'details',
        'financial', 'contact', 'references', 'medical', 'vehicle',
        'summary', 'report', 'document', 'section', 'appendix',
        # Common labels
        'name', 'address', 'phone', 'email', 'date', 'number',
        'customer', 'account', 'invoice', 'order', 'reference',
        'policy', 'license', 'insurance', 'routing', 'credit',
        # Business terms
        'employee record', 'contact information', 'financial details',
        'routing number', 'credit card', 'bank account', 'social security',
        'license plate', 'order number', 'customer id', 'employee id',
    }

    def __init__(self):
        self.patterns = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile all regex patterns."""
        return {
            # ==================== IDENTITY DOCUMENTS ====================

            # US Social Security Number: XXX-XX-XXXX
            'ssn': re.compile(
                r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'
            ),

            # SSN without dashes (in context)
            'ssn_nodash': re.compile(
                r'\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}\b'
            ),

            # US Individual Taxpayer ID (ITIN): 9XX-XX-XXXX
            'itin': re.compile(
                r'\b9\d{2}-[7-9]\d-\d{4}\b'
            ),

            # US Employer ID (EIN): XX-XXXXXXX
            'ein': re.compile(
                r'\b\d{2}-\d{7}\b'
            ),

            # US Passport: 1 letter + 8 digits OR 9 digits
            'passport_us': re.compile(
                r'\b[A-Z]\d{8}\b|\b\d{9}\b'
            ),

            # UK Passport: 9 digits
            'passport_uk': re.compile(
                r'\b\d{9}\b'
            ),

            # Driver's License patterns (various US states)
            'drivers_license': re.compile(
                r'\b(?:'
                r'[A-Z]\d{7}|'           # CA, NY format
                r'[A-Z]\d{12}|'          # FL format
                r'[A-Z]{2}\d{6}|'        # Some states
                r'\d{7,9}|'              # Numeric only states
                r'[A-Z]\d{3}-\d{4}-\d{4}'  # WA format
                r')\b'
            ),

            # ==================== FINANCIAL DATA ====================

            # Credit Card Numbers (Visa, MC, Amex, Discover)
            'credit_card': re.compile(
                r'\b(?:'
                r'4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|'      # Visa
                r'5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|' # Mastercard
                r'3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}|'             # Amex
                r'6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}' # Discover
                r')\b'
            ),

            # Bank Account Number (8-17 digits)
            'bank_account': re.compile(
                r'\b\d{8,17}\b'
            ),

            # US Bank Routing Number (9 digits, ABA format)
            'routing_number': re.compile(
                r'\b(?:0[1-9]|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b'
            ),

            # IBAN (International Bank Account Number)
            'iban': re.compile(
                r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b'
            ),

            # SWIFT/BIC Code
            'swift': re.compile(
                r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b'
            ),

            # ==================== CONTACT INFORMATION ====================

            # Phone Numbers (comprehensive)
            'phone': re.compile(
                r'\b(?:'
                # US formats
                r'(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}|'
                # International with + prefix
                r'\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}|'
                # UK format
                r'(?:\+?44[-.\s]?)?(?:0|\(0\))?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}|'
                # Indian format
                r'(?:\+?91[-.\s]?)?[6-9]\d{4}[-.\s]?\d{5}'
                r')\b'
            ),

            # Email Address
            'email': re.compile(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
            ),

            # US Street Address (basic pattern)
            'address': re.compile(
                r'\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir)\.?\b',
                re.IGNORECASE
            ),

            # US ZIP Code
            'zip_code': re.compile(
                r'\b\d{5}(?:-\d{4})?\b'
            ),

            # UK Postcode
            'uk_postcode': re.compile(
                r'\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b',
                re.IGNORECASE
            ),

            # Indian PIN Code
            'pin_code': re.compile(
                r'\b[1-9]\d{5}\b'
            ),

            # ==================== DIGITAL IDENTIFIERS ====================

            # IPv4 Address
            'ipv4': re.compile(
                r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
            ),

            # IPv6 Address (simplified)
            'ipv6': re.compile(
                r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
                r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
                r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
            ),

            # MAC Address
            'mac_address': re.compile(
                r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
            ),

            # URL
            'url': re.compile(
                r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\-._~:/?#\[\]@!$&\'()*+,;=%]*'
            ),

            # Username/Handle (@mentions)
            'username': re.compile(
                r'(?:^|(?<=[^a-zA-Z0-9]))@[A-Za-z][A-Za-z0-9_]{2,30}\b'
            ),

            # ==================== REFERENCE NUMBERS ====================

            # Invoice Number
            'invoice': re.compile(
                r'\b(?:INV|Invoice|Bill)[-:#\s]*[A-Z0-9-]{4,20}\b',
                re.IGNORECASE
            ),

            # Order Number
            'order_number': re.compile(
                r'\b(?:Order|ORD|PO)[-:#\s]*[A-Z0-9-]{4,20}\b',
                re.IGNORECASE
            ),

            # Customer ID
            'customer_id': re.compile(
                r'\b(?:Customer|Client|CID|CUST)[-:#\s]*[A-Z0-9-]{4,20}\b',
                re.IGNORECASE
            ),

            # Employee ID
            'employee_id': re.compile(
                r'\b(?:Employee|EMP|EID|Staff)[-:#\s]*[A-Z0-9-]{4,15}\b',
                re.IGNORECASE
            ),

            # Medical Record Number (MRN)
            'mrn': re.compile(
                r'\b(?:MRN|Medical Record|Patient ID)[-:#\s]*[A-Z0-9-]{4,15}\b',
                re.IGNORECASE
            ),

            # Case/Reference Number
            'case_number': re.compile(
                r'\b(?:Case|Ref|Reference|File)[-:#\s]*[A-Z0-9-]{4,20}\b',
                re.IGNORECASE
            ),

            # Account Number (generic)
            'account_number': re.compile(
                r'\b(?:Account|Acct|A/C)[-:#\s]*[A-Z0-9-]{4,20}\b',
                re.IGNORECASE
            ),

            # ==================== DATES (when sensitive) ====================

            # Date of Birth patterns
            'date_of_birth': re.compile(
                r'\b(?:DOB|Date of Birth|Born|Birthday|Birth Date)[:\s]+\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b',
                re.IGNORECASE
            ),

            # General date pattern (for context matching)
            'date': re.compile(
                r'\b(?:'
                r'\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|'
                r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}'
                r')\b',
                re.IGNORECASE
            ),

            # ==================== NAMES ====================

            # Name pattern (2-4 capitalized words on same line)
            'name': re.compile(
                r'\b(?:[A-Z][a-z]+[ \t]+){1,3}[A-Z][a-z]+\b'
            ),

            # ==================== ALPHANUMERIC IDs ====================

            # Generic alphanumeric ID (10-20 chars, mixed letters and digits)
            'alphanumeric_id': re.compile(
                r'\b(?=.*[A-Z])(?=.*\d)[A-Z0-9]{10,20}\b'
            ),

            # VIN (Vehicle Identification Number)
            'vin': re.compile(
                r'\b[A-HJ-NPR-Z0-9]{17}\b'
            ),

            # License Plate (various formats - letters then numbers or mixed)
            # Uses [ \t] instead of \s to avoid matching across newlines
            'license_plate': re.compile(
                r'\b(?:'
                r'[A-Z]{1,3}[- \t]?\d{1,4}[- \t]?[A-Z0-9]{0,3}|'  # ABC-1234, AB 123
                r'\d{1,3}[- \t]?[A-Z]{1,4}[- \t]?[A-Z0-9]{0,3}'    # 123-ABC, 1 ABC 234
                r')\b'
            ),
        }

    def detect(self, text: str) -> List[Dict[str, Any]]:
        """
        Run all patterns against the text and return detections.

        Returns:
            List of detection dicts with keys:
            - start: start offset
            - end: end offset
            - text: matched text
            - type: PII category
            - source: 'enhanced_regex'
        """
        detections = []
        seen_ranges = set()  # Avoid duplicate overlapping matches

        # Define which patterns to run and in what priority
        # Higher priority patterns should match first to avoid false positives
        pattern_priority = [
            # High confidence identity docs
            ('ssn', 'ssn'),
            ('itin', 'itin'),
            ('ein', 'ein'),

            # Financial
            ('credit_card', 'credit_card'),
            ('iban', 'iban'),
            ('swift', 'swift'),
            ('routing_number', 'routing_number'),

            # Contact
            ('email', 'email'),
            ('phone', 'phone'),
            ('ipv4', 'ip_address'),
            ('ipv6', 'ip_address'),
            ('mac_address', 'mac_address'),
            ('url', 'url'),

            # Address components
            ('address', 'address'),
            ('zip_code', 'postal_code'),
            ('uk_postcode', 'postal_code'),
            ('pin_code', 'postal_code'),

            # Documents
            ('passport_us', 'passport'),
            ('drivers_license', 'drivers_license'),
            ('vin', 'vin'),
            ('license_plate', 'license_plate'),

            # Reference numbers
            ('date_of_birth', 'date_of_birth'),
            ('invoice', 'invoice'),
            ('order_number', 'order_number'),
            ('customer_id', 'customer_id'),
            ('employee_id', 'employee_id'),
            ('mrn', 'mrn'),
            ('case_number', 'case_number'),
            ('account_number', 'account_number'),

            # Generic (lower priority)
            ('username', 'username'),
            ('alphanumeric_id', 'id_number'),
            ('name', 'name'),
            ('date', 'date'),
        ]

        for pattern_name, pii_type in pattern_priority:
            pattern = self.patterns.get(pattern_name)
            if not pattern:
                continue

            for match in pattern.finditer(text):
                start, end = match.start(), match.end()

                # Skip if this range overlaps with already detected spans
                overlaps = any(
                    not (end <= s or start >= e)
                    for s, e in seen_ranges
                )
                if overlaps:
                    continue

                # Additional validation for specific types
                matched_text = match.group()
                if not self._validate_match(pattern_name, matched_text, text, start):
                    continue

                seen_ranges.add((start, end))
                detections.append({
                    'start': start,
                    'end': end,
                    'text': matched_text,
                    'type': pii_type,
                    'source': 'enhanced_regex'
                })

        return detections

    def _validate_match(self, pattern_name: str, matched_text: str, full_text: str, start: int) -> bool:
        """
        Additional validation for matches to reduce false positives.
        """
        # Check blocklist first
        if matched_text.lower() in self.BLOCKLIST:
            return False

        # Multi-word blocklist check
        matched_lower = matched_text.lower()
        for blocked in self.BLOCKLIST:
            if ' ' in blocked and blocked in matched_lower:
                return False

        # Skip very short matches (likely noise)
        if len(matched_text) < 3:
            return False

        # Credit card: Luhn check
        if pattern_name == 'credit_card':
            return self._luhn_check(matched_text)

        # Bank account: needs context keywords nearby
        if pattern_name == 'bank_account':
            context_start = max(0, start - 50)
            context = full_text[context_start:start].lower()
            keywords = ['account', 'acct', 'a/c', 'bank', 'routing', 'transfer']
            return any(kw in context for kw in keywords)

        # SSN without dashes: needs context
        if pattern_name == 'ssn_nodash':
            context_start = max(0, start - 50)
            context = full_text[context_start:start].lower()
            keywords = ['ssn', 'social security', 'social sec', 'ss#', 'ss #']
            return any(kw in context for kw in keywords)

        # Alphanumeric ID: avoid matching common words
        if pattern_name == 'alphanumeric_id':
            # Skip if it looks like a common abbreviation
            if matched_text in ['ABCDEFGHIJ', 'QWERTYUIOP']:
                return False

        # Swift codes: must be 8 or 11 characters exactly
        if pattern_name == 'swift':
            clean = matched_text.strip()
            if len(clean) not in [8, 11]:
                return False
            # Skip common English words that match the pattern
            common_words = {'EMPLOYEE', 'CUSTOMER', 'DOCUMENT', 'REFERENCE'}
            if clean.upper() in common_words:
                return False

        # License plate: must have both letters and numbers
        if pattern_name == 'license_plate':
            has_letter = any(c.isalpha() for c in matched_text)
            has_digit = any(c.isdigit() for c in matched_text)
            if not (has_letter and has_digit):
                return False
            # Skip if it looks like a phone number (too many digits)
            digits = sum(1 for c in matched_text if c.isdigit())
            if digits > 6:
                return False
            # Skip very short matches
            clean = matched_text.replace('-', '').replace(' ', '')
            if len(clean) < 5:
                return False

        # Name pattern: additional filtering
        if pattern_name == 'name':
            # Skip if it's a common phrase/label
            common_phrases = {
                'contact information', 'financial details', 'routing number',
                'credit card', 'bank account', 'social security', 'license plate',
                'date of birth', 'employee id', 'customer id', 'order number',
                'invoice number', 'reference number', 'account number',
                'patient id', 'medical record', 'insurance policy',
                'main street', 'new york', 'los angeles', 'san francisco'
            }
            if matched_lower in common_phrases:
                return False

        return True

    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        # Remove spaces and dashes
        digits = ''.join(c for c in card_number if c.isdigit())

        if len(digits) < 13 or len(digits) > 19:
            return False

        # Luhn algorithm
        total = 0
        reverse_digits = digits[::-1]

        for i, digit in enumerate(reverse_digits):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n

        return total % 10 == 0


# Singleton instance for easy import
enhanced_regex_detector = EnhancedRegexDetector()


def detect(text: str) -> List[Dict[str, Any]]:
    """Convenience function to run enhanced regex detection."""
    return enhanced_regex_detector.detect(text)
