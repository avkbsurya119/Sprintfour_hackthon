"""
Context-Aware Detector: Finds PII based on surrounding keywords.

This detector catches IDs and numbers that are embedded in sentences
and identified by context rather than format alone.

Examples:
- "Your account number is 12345678" -> detects 12345678 as account
- "Patient ID: ABC123" -> detects ABC123 as patient_id
- "Reference #98765" -> detects 98765 as reference
"""

import re
from typing import List, Dict, Any, Tuple


class ContextDetector:
    """Detects PII based on surrounding context keywords."""

    def __init__(self):
        # Define keyword patterns and their associated PII types
        # Format: (keyword_pattern, value_pattern, pii_type, max_distance)
        self.context_rules = self._build_rules()

    def _build_rules(self) -> List[Tuple[re.Pattern, re.Pattern, str, int]]:
        """Build context detection rules."""
        rules = []

        # Account/ID number patterns
        # "account number is XXXXX" or "account: XXXXX" or "account #XXXXX"
        account_keywords = re.compile(
            r'\b(?:account|acct|a/c)\s*(?:number|no\.?|num\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((account_keywords, re.compile(r'[A-Z0-9-]{4,20}', re.IGNORECASE), 'account_number', 5))

        # Customer/Client ID
        customer_keywords = re.compile(
            r'\b(?:customer|client|member)\s*(?:id|number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((customer_keywords, re.compile(r'[A-Z0-9-]{4,20}', re.IGNORECASE), 'customer_id', 5))

        # Employee/Staff ID
        employee_keywords = re.compile(
            r'\b(?:employee|staff|worker|emp)\s*(?:id|number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((employee_keywords, re.compile(r'[A-Z0-9-]{4,15}', re.IGNORECASE), 'employee_id', 5))

        # Patient/Medical Record
        patient_keywords = re.compile(
            r'\b(?:patient|medical record|mrn|health record)\s*(?:id|number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((patient_keywords, re.compile(r'[A-Z0-9-]{4,15}', re.IGNORECASE), 'mrn', 5))

        # Invoice/Bill
        invoice_keywords = re.compile(
            r'\b(?:invoice|bill|receipt)\s*(?:number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((invoice_keywords, re.compile(r'[A-Z0-9-]{4,20}', re.IGNORECASE), 'invoice', 5))

        # Order/PO
        order_keywords = re.compile(
            r'\b(?:order|purchase order|po)\s*(?:number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((order_keywords, re.compile(r'[A-Z0-9-]{4,20}', re.IGNORECASE), 'order_number', 5))

        # Reference/Case/File
        reference_keywords = re.compile(
            r'\b(?:reference|ref|case|file|ticket)\s*(?:number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((reference_keywords, re.compile(r'[A-Z0-9-]{4,20}', re.IGNORECASE), 'reference_number', 5))

        # Policy Number (insurance)
        policy_keywords = re.compile(
            r'\b(?:policy|insurance)\s*(?:number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((policy_keywords, re.compile(r'[A-Z0-9-]{6,20}', re.IGNORECASE), 'policy_number', 5))

        # License/Permit
        license_keywords = re.compile(
            r'\b(?:license|licence|permit)\s*(?:number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((license_keywords, re.compile(r'[A-Z0-9-]{4,15}', re.IGNORECASE), 'license_number', 5))

        # Passport
        passport_keywords = re.compile(
            r'\b(?:passport)\s*(?:number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((passport_keywords, re.compile(r'[A-Z0-9]{6,12}', re.IGNORECASE), 'passport', 5))

        # SSN/Social Security
        ssn_keywords = re.compile(
            r'\b(?:social security|ssn|ss#|ss #)\s*(?:number|no\.?)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((ssn_keywords, re.compile(r'\d{3}[-\s]?\d{2}[-\s]?\d{4}'), 'ssn', 5))

        # Tax ID
        tax_keywords = re.compile(
            r'\b(?:tax id|tin|taxpayer|ein|itin)\s*(?:number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((tax_keywords, re.compile(r'[\d-]{9,12}'), 'tax_id', 5))

        # Date of Birth
        dob_keywords = re.compile(
            r'\b(?:date of birth|dob|birth date|birthday|born)\s*[:\s]*',
            re.IGNORECASE
        )
        rules.append((dob_keywords, re.compile(r'\d{1,2}[-/]\d{1,2}[-/]\d{2,4}'), 'date_of_birth', 5))

        # Phone/Contact
        phone_keywords = re.compile(
            r'\b(?:phone|tel|telephone|mobile|cell|contact)\s*(?:number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((phone_keywords, re.compile(r'[\d\s\-\(\)\.+]{7,20}'), 'phone', 5))

        # Email
        email_keywords = re.compile(
            r'\b(?:email|e-mail)\s*(?:address)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((email_keywords, re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'), 'email', 5))

        # Routing Number
        routing_keywords = re.compile(
            r'\b(?:routing|aba|transit)\s*(?:number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((routing_keywords, re.compile(r'\d{9}'), 'routing_number', 5))

        # Credit Card
        cc_keywords = re.compile(
            r'\b(?:credit card|card|cc)\s*(?:number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((cc_keywords, re.compile(r'[\d\s-]{13,19}'), 'credit_card', 5))

        # Bank Account
        bank_keywords = re.compile(
            r'\b(?:bank account|checking|savings)\s*(?:number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((bank_keywords, re.compile(r'\d{8,17}'), 'bank_account', 5))

        # VIN
        vin_keywords = re.compile(
            r'\b(?:vin|vehicle identification)\s*(?:number|no\.?|#)?[:\s]*',
            re.IGNORECASE
        )
        rules.append((vin_keywords, re.compile(r'[A-HJ-NPR-Z0-9]{17}'), 'vin', 5))

        # IP Address
        ip_keywords = re.compile(
            r'\b(?:ip address|ip)\s*[:\s]*',
            re.IGNORECASE
        )
        rules.append((ip_keywords, re.compile(r'(?:\d{1,3}\.){3}\d{1,3}'), 'ip_address', 5))

        # Address patterns (street address preceded by "address" keyword)
        address_keywords = re.compile(
            r'\b(?:address|location|residence|mailing)\s*[:\s]*',
            re.IGNORECASE
        )
        # Match up to end of line or next sentence
        rules.append((address_keywords, re.compile(r'[^\n.;]{10,100}'), 'address', 0))

        return rules

    def detect(self, text: str) -> List[Dict[str, Any]]:
        """
        Find PII based on surrounding context keywords.

        Returns:
            List of detection dicts with keys:
            - start: start offset
            - end: end offset
            - text: matched text
            - type: PII category
            - source: 'context'
        """
        detections = []
        seen_ranges = set()

        for keyword_pattern, value_pattern, pii_type, max_gap in self.context_rules:
            for keyword_match in keyword_pattern.finditer(text):
                # Look for value immediately after keyword
                search_start = keyword_match.end()
                search_end = min(len(text), search_start + 100)  # Look ahead up to 100 chars
                search_text = text[search_start:search_end]

                # Find value pattern in search region
                value_match = value_pattern.search(search_text)

                if value_match:
                    # Check gap between keyword and value
                    gap = value_match.start()
                    if gap <= max_gap:
                        # Calculate absolute positions
                        abs_start = search_start + value_match.start()
                        abs_end = search_start + value_match.end()

                        # Skip if overlaps with existing detection
                        overlaps = any(
                            not (abs_end <= s or abs_start >= e)
                            for s, e in seen_ranges
                        )
                        if overlaps:
                            continue

                        # Validate the match
                        matched_text = value_match.group().strip()
                        if self._validate_value(matched_text, pii_type):
                            seen_ranges.add((abs_start, abs_end))
                            detections.append({
                                'start': abs_start,
                                'end': abs_end,
                                'text': matched_text,
                                'type': pii_type,
                                'source': 'context',
                                'context_keyword': keyword_match.group().strip()
                            })

        return detections

    # Common words that should not be treated as IDs
    SKIP_VALUES = {
        'id', 'number', 'no', 'num', '#', 'na', 'n/a', 'none', 'null',
        'record', 'information', 'details', 'data', 'field',
        'name', 'address', 'phone', 'email', 'date', 'account',
        'customer', 'employee', 'patient', 'policy', 'invoice',
        'order', 'reference', 'case', 'file', 'ticket', 'license',
        'plate', 'card', 'ssn', 'tax', 'bank', 'routing', 'credit',
    }

    def _validate_value(self, value: str, pii_type: str) -> bool:
        """Validate that the matched value is plausible for the PII type."""
        # Skip very short matches
        if len(value) < 3:
            return False

        # Skip matches that are just whitespace or punctuation
        if not any(c.isalnum() for c in value):
            return False

        # Skip common words that aren't actual values
        if value.lower().strip() in self.SKIP_VALUES:
            return False

        # Type-specific validation
        if pii_type == 'phone':
            # Must have enough digits
            digits = sum(1 for c in value if c.isdigit())
            return digits >= 7

        if pii_type == 'email':
            return '@' in value and '.' in value

        if pii_type in ['ssn', 'tax_id']:
            digits = sum(1 for c in value if c.isdigit())
            return digits >= 9

        if pii_type == 'credit_card':
            digits = sum(1 for c in value if c.isdigit())
            return 13 <= digits <= 19

        if pii_type == 'bank_account':
            digits = sum(1 for c in value if c.isdigit())
            return 8 <= digits <= 17

        if pii_type == 'routing_number':
            digits = sum(1 for c in value if c.isdigit())
            return digits == 9

        if pii_type == 'vin':
            return len(value) == 17

        if pii_type == 'address':
            # Should have some numbers and letters
            has_digit = any(c.isdigit() for c in value)
            has_alpha = any(c.isalpha() for c in value)
            return has_digit and has_alpha and len(value) >= 10

        return True


# Singleton instance
context_detector = ContextDetector()


def detect(text: str) -> List[Dict[str, Any]]:
    """Convenience function to run context detection."""
    return context_detector.detect(text)
