"""Privacy-preserving data anonymizer supporting MASK, PSEUDONYMIZE, and REDACT strategies."""

import hashlib
import hmac
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from core.privacy.pii_detector import PIICategory, PIIFinding


class AnonymizationMethod(str, Enum):
    """Supported data anonymization transformation methods."""

    MASK = "MASK"
    PSEUDONYMIZE = "PSEUDONYMIZE"
    REDACT = "REDACT"


class AnonymizedResult(BaseModel):
    """Structured outcome of data anonymization."""

    anonymized_text: str
    original_length: int
    anonymized_length: int
    method_used: AnonymizationMethod
    category_counts: dict[str, int] = Field(default_factory=dict)
    findings_count: int = 0
    transformations: list[dict[str, Any]] = Field(default_factory=list)


class Anonymizer:
    """Transforms raw forensic text containing PII using compliant anonymization rules."""

    def __init__(
        self,
        hmac_salt: str = "EvidenceGraphAI-DPDP-Salt-2026",
    ) -> None:
        self.hmac_salt = hmac_salt.encode("utf-8")

    def _mask_value(self, category: PIICategory, raw_text: str) -> str:
        """Masks sensitive characters while preserving format/last digits for auditability."""
        clean = raw_text.strip()
        if category == PIICategory.EMAIL:
            parts = clean.split("@")
            if len(parts) == 2:
                name, domain = parts
                masked_name = (
                    name[0]
                    + "X" * max(1, len(name) - 2)
                    + (name[-1] if len(name) > 1 else "")
                )
                return f"{masked_name}@{domain}"
            return "XXXX@XXXX.com"

        if category == PIICategory.AADHAAR:
            digits = "".join([c for c in clean if c.isdigit()])
            if len(digits) >= 12:
                return f"XXXX-XXXX-{digits[-4:]}"
            return "XXXX-XXXX-XXXX"

        if category == PIICategory.PAN:
            if len(clean) == 10:
                return f"{clean[0]}XXXXXX{clean[-3:]}"
            return "XXXXXXXXXX"

        if category == PIICategory.PHONE:
            digits = "".join([c for c in clean if c.isdigit()])
            if len(digits) >= 10:
                return f"+91-XXXXX-{digits[-4:]}"
            return "+91-XXXXXXXXXX"

        if category == PIICategory.CREDIT_CARD:
            digits = "".join([c for c in clean if c.isdigit()])
            if len(digits) >= 12:
                return f"XXXX-XXXX-XXXX-{digits[-4:]}"
            return "XXXX-XXXX-XXXX-XXXX"

        if category == PIICategory.PRIVATE_IP:
            octets = clean.split(".")
            if len(octets) == 4:
                return f"{octets[0]}.{octets[1]}.X.X"
            return "10.X.X.X"

        # Default fallback masking
        if len(clean) <= 4:
            return "X" * len(clean)
        return clean[:1] + "X" * (len(clean) - 2) + clean[-1:]

    def _pseudonymize_value(self, category: PIICategory, raw_text: str) -> str:
        """Generates deterministic pseudo-identifier token using HMAC-SHA256."""
        h = hmac.new(
            self.hmac_salt, raw_text.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:12]
        return f"PSEUDO_{category.value}_{h}"

    def _redact_value(self, category: PIICategory, raw_text: str) -> str:
        """Replaces PII entirely with a structured redaction tag."""
        return f"[REDACTED_{category.value}]"

    def transform_finding(
        self,
        finding: PIIFinding,
        method: AnonymizationMethod,
    ) -> str:
        """Transforms a single PII finding according to the specified method."""
        if method == AnonymizationMethod.MASK:
            return self._mask_value(finding.category, finding.raw_text)
        if method == AnonymizationMethod.PSEUDONYMIZE:
            return self._pseudonymize_value(finding.category, finding.raw_text)
        if method == AnonymizationMethod.REDACT:
            return self._redact_value(finding.category, finding.raw_text)
        return self._mask_value(finding.category, finding.raw_text)

    def anonymize(
        self,
        text: str,
        findings: list[PIIFinding],
        method: AnonymizationMethod = AnonymizationMethod.MASK,
    ) -> AnonymizedResult:
        """Anonymizes input text by applying transformations to identified PII entities.

        Args:
            text: Original raw text.
            findings: List of PII findings.
            method: Selected transformation method (MASK, PSEUDONYMIZE, REDACT).

        Returns:
            AnonymizedResult with transformed text and transformation audit trail.
        """
        if not findings or not text:
            return AnonymizedResult(
                anonymized_text=text,
                original_length=len(text),
                anonymized_length=len(text),
                method_used=method,
                category_counts={},
                findings_count=0,
                transformations=[],
            )

        # Sort findings from end to beginning so string replacements don't shift index offsets
        sorted_findings = sorted(findings, key=lambda f: f.start, reverse=True)
        transformed_chars = list(text)

        category_counts: dict[str, int] = {}
        transformations: list[dict[str, Any]] = []

        for f in sorted_findings:
            replacement = self.transform_finding(f, method)
            cat_name = f.category.value
            category_counts[cat_name] = category_counts.get(cat_name, 0) + 1

            transformations.append(
                {
                    "category": cat_name,
                    "start": f.start,
                    "end": f.end,
                    "original_snippet": (
                        f.raw_text[:2] + "..." if len(f.raw_text) > 4 else "***"
                    ),
                    "replacement": replacement,
                }
            )

            # Splice in replacement
            transformed_chars[f.start : f.end] = list(replacement)

        anonymized_str = "".join(transformed_chars)

        return AnonymizedResult(
            anonymized_text=anonymized_str,
            original_length=len(text),
            anonymized_length=len(anonymized_str),
            method_used=method,
            category_counts=category_counts,
            findings_count=len(findings),
            transformations=transformations[::-1],
        )
