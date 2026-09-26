"""Unit tests for PII Anonymizer transformation engine."""

from core.privacy.anonymizer import AnonymizationMethod, Anonymizer
from core.privacy.pii_detector import PIICategory, PIIDetector, PIIFinding


def test_anonymize_mask_method() -> None:
    """Verifies MASK method preserves partial format/tail digits."""
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
    detector = PIIDetector()
    anonymizer = Anonymizer()
    text = "Call +91 9876543210 immediately"
    findings = detector.detect_pii(text)

    result = anonymizer.anonymize(text, findings, method=AnonymizationMethod.REDACT)
    assert "[REDACTED_PHONE]" in result.anonymized_text
    assert result.findings_count >= 1


def test_anonymize_credit_card_and_ip_and_passport() -> None:
    """Verifies masking across credit card, private IP, and passport categories."""
    anonymizer = Anonymizer()
    text = "Card 4532-7589-2341-9823 IP 192.168.1.50 Passport A1234567 Name Alice Smith"
    findings = [
        PIIFinding(
            category=PIICategory.CREDIT_CARD,
            raw_text="4532-7589-2341-9823",
            start=5,
            end=24,
            confidence=1.0,
        ),
        PIIFinding(
            category=PIICategory.PRIVATE_IP,
            raw_text="192.168.1.50",
            start=28,
            end=40,
            confidence=1.0,
        ),
        PIIFinding(
            category=PIICategory.PASSPORT,
            raw_text="A1234567",
            start=50,
            end=58,
            confidence=1.0,
        ),
        PIIFinding(
            category=PIICategory.PERSON_NAME,
            raw_text="Alice Smith",
            start=64,
            end=75,
            confidence=1.0,
        ),
    ]

    masked = anonymizer.anonymize(text, findings, method=AnonymizationMethod.MASK)
    assert "XXXX-XXXX-XXXX-9823" in masked.anonymized_text
    assert "192.168.X.X" in masked.anonymized_text
    assert "AXXXXXX7" in masked.anonymized_text
    assert "AXXXXXXXXXh" in masked.anonymized_text


def test_anonymize_empty_inputs() -> None:
    """Verifies handling empty text and empty findings."""
    anonymizer = Anonymizer()
    res1 = anonymizer.anonymize("", [])
    assert res1.anonymized_text == ""
    assert res1.findings_count == 0

    res2 = anonymizer.anonymize("Some plain text", [])
    assert res2.anonymized_text == "Some plain text"
    assert res2.findings_count == 0
