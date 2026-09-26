"""Unit tests for PII Anonymizer transformation engine."""

from core.privacy.anonymizer import AnonymizationMethod, Anonymizer
from core.privacy.pii_detector import PIICategory, PIIFinding


def test_anonymize_mask_method() -> None:
    """Verifies MASK method preserves partial format/tail digits."""
    from core.privacy.pii_detector import PIIDetector

    detector = PIIDetector()
    anonymizer = Anonymizer()
    text = "User email is test.user@example.com and Aadhaar is 2345 6789 0123"
    findings = detector.detect_pii(text)

    result = anonymizer.anonymize(text, findings, method=AnonymizationMethod.MASK)
    assert "@example.com" in result.anonymized_text
    assert "XXXX-XXXX-0123" in result.anonymized_text
    assert "2345 6789 0123" not in result.anonymized_text
    assert result.category_counts[PIICategory.EMAIL.value] == 1
    assert result.category_counts[PIICategory.AADHAAR.value] == 1


def test_anonymize_pseudonymize_method() -> None:
    """Verifies PSEUDONYMIZE produces deterministic HMAC tokens."""
    anonymizer = Anonymizer()
    text = "Account owned by PAN: ABCDE1234F"
    findings = [
        PIIFinding(
            category=PIICategory.PAN,
            raw_text="ABCDE1234F",
            start=22,
            end=32,
            confidence=1.0,
        )
    ]

    res1 = anonymizer.anonymize(text, findings, method=AnonymizationMethod.PSEUDONYMIZE)
    res2 = anonymizer.anonymize(text, findings, method=AnonymizationMethod.PSEUDONYMIZE)

    assert res1.anonymized_text == res2.anonymized_text
    assert "PSEUDO_PAN_" in res1.anonymized_text
    assert "ABCDE1234F" not in res1.anonymized_text


def test_anonymize_redact_method() -> None:
    """Verifies REDACT replaces entities with clean category labels."""
    from core.privacy.pii_detector import PIIDetector

    detector = PIIDetector()
    anonymizer = Anonymizer()
    text = "Call +91 9876543210 immediately"
    findings = detector.detect_pii(text)

    result = anonymizer.anonymize(text, findings, method=AnonymizationMethod.REDACT)
    assert "[REDACTED_PHONE]" in result.anonymized_text
    assert result.findings_count >= 1
