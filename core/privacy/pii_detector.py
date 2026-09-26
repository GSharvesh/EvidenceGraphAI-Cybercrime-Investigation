"""High-precision PII detection engine aligned with Indian DPDP Act 2023 requirements."""

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from core.logging.logger import get_logger

logger = get_logger("core.privacy.pii_detector")


class PIICategory(str, Enum):
    """Categories of Personally Identifiable Information under DPDP Act 2023."""

    AADHAAR = "AADHAAR"
    PAN = "PAN"
    PASSPORT = "PASSPORT"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    CREDIT_CARD = "CREDIT_CARD"
    PRIVATE_IP = "PRIVATE_IP"
    PERSON_NAME = "PERSON_NAME"


class PIIFinding(BaseModel):
    """Individual PII entity detected within text or raw forensic artifact."""

    category: PIICategory
    raw_text: str
    start: int
    end: int
    confidence: float = Field(ge=0.0, le=1.0)
    context: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# Verhoeff algorithm table for Aadhaar validation
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def _validate_verhoeff(number_str: str) -> bool:
    """Validates 12-digit number against Verhoeff checksum algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) != 12:
        return False
    c = 0
    for idx, item in enumerate(reversed(digits)):
        c = VERHOEFF_D[c][VERHOEFF_P[idx % 8][item]]
    return c == 0


def _validate_luhn(card_str: str) -> bool:
    """Validates payment card number against Luhn formula."""
    digits = [int(c) for c in card_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, num in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = num * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += num
    return checksum % 10 == 0


# Compiled Regular Expressions for Indian DPDP PII patterns
PATTERNS = {
    PIICategory.EMAIL: re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.IGNORECASE
    ),
    PIICategory.PAN: re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    PIICategory.AADHAAR: re.compile(r"\b[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b"),
    PIICategory.PHONE: re.compile(r"(?:\+91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}\b"),
    PIICategory.PASSPORT: re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b"),
    PIICategory.CREDIT_CARD: re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    ),
    PIICategory.PRIVATE_IP: re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    ),
}


class PIIDetector:
    """Scanner for detecting DPDP Act 2023 PII entities across text and log streams."""

    def __init__(self, include_private_ips: bool = True) -> None:
        self.include_private_ips = include_private_ips

    def detect_pii(
        self,
        text: str,
        artifact_type: str | None = None,
    ) -> list[PIIFinding]:
        """Scans input text and returns all identified PII entities.

        Args:
            text: Input string (log line, payload text, packet string).
            artifact_type: Optional forensic artifact type context.

        Returns:
            List of PIIFinding entities sorted by starting character offset.
        """
        findings: list[PIIFinding] = []
        if not text:
            return findings

        # 1. Email detection
        for match in PATTERNS[PIICategory.EMAIL].finditer(text):
            val = match.group(0)
            # Filter out sample/fake domains if needed, or include with high confidence
            findings.append(
                PIIFinding(
                    category=PIICategory.EMAIL,
                    raw_text=val,
                    start=match.start(),
                    end=match.end(),
                    confidence=0.99,
                )
            )

        # 2. PAN detection (Indian Income Tax PAN: 5 letters, 4 digits, 1 letter)
        for match in PATTERNS[PIICategory.PAN].finditer(text):
            val = match.group(0)
            findings.append(
                PIIFinding(
                    category=PIICategory.PAN,
                    raw_text=val,
                    start=match.start(),
                    end=match.end(),
                    confidence=0.98,
                    metadata={"pan_fourth_char": val[3]},
                )
            )

        # 3. Aadhaar detection (12 digits, leading digit 2-9)
        for match in PATTERNS[PIICategory.AADHAAR].finditer(text):
            val = match.group(0)
            digits_only = re.sub(r"[\s-]", "", val)
            is_verhoeff = _validate_verhoeff(digits_only)
            confidence = 1.0 if is_verhoeff else 0.85
            findings.append(
                PIIFinding(
                    category=PIICategory.AADHAAR,
                    raw_text=val,
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    metadata={"verhoeff_valid": is_verhoeff},
                )
            )

        # 4. Indian Mobile Phone Number (+91 or 10 digits starting with 6-9)
        for match in PATTERNS[PIICategory.PHONE].finditer(text):
            val = match.group(0)
            findings.append(
                PIIFinding(
                    category=PIICategory.PHONE,
                    raw_text=val,
                    start=match.start(),
                    end=match.end(),
                    confidence=0.92,
                )
            )

        # 5. Passport Number
        for match in PATTERNS[PIICategory.PASSPORT].finditer(text):
            val = match.group(0)
            findings.append(
                PIIFinding(
                    category=PIICategory.PASSPORT,
                    raw_text=val,
                    start=match.start(),
                    end=match.end(),
                    confidence=0.88,
                )
            )

        # 6. Credit / Debit Cards
        for match in PATTERNS[PIICategory.CREDIT_CARD].finditer(text):
            val = match.group(0)
            if _validate_luhn(val):
                findings.append(
                    PIIFinding(
                        category=PIICategory.CREDIT_CARD,
                        raw_text=val,
                        start=match.start(),
                        end=match.end(),
                        confidence=0.98,
                    )
                )

        # 7. Private IP Addresses (optional, e.g. RFC 1918)
        if self.include_private_ips:
            for match in PATTERNS[PIICategory.PRIVATE_IP].finditer(text):
                val = match.group(0)
                findings.append(
                    PIIFinding(
                        category=PIICategory.PRIVATE_IP,
                        raw_text=val,
                        start=match.start(),
                        end=match.end(),
                        confidence=0.95,
                    )
                )

        # Sort findings by start offset
        findings.sort(key=lambda f: f.start)

        # Deduplicate overlapping spans (keep higher confidence)
        deduped: list[PIIFinding] = []
        for f in findings:
            if not deduped:
                deduped.append(f)
                continue
            last = deduped[-1]
            if f.start < last.end:
                # Overlap
                if f.confidence > last.confidence:
                    deduped[-1] = f
            else:
                deduped.append(f)

        return deduped
