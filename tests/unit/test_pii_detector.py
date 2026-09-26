"""Unit tests for DPDP Act 2023 PII detection engine."""

from core.privacy.pii_detector import PIICategory, PIIDetector


def test_detect_email() -> None:
    """Verifies email address detection."""
    detector = PIIDetector()
    text = "Contact the investigator at security.officer@domain.gov.in regarding the incident."
    findings = detector.detect_pii(text)
    assert len(findings) == 1
    assert findings[0].category == PIICategory.EMAIL
    assert findings[0].raw_text == "security.officer@domain.gov.in"


def test_detect_pan() -> None:
    """Verifies Indian Income Tax PAN detection."""
    detector = PIIDetector()
    text = "Taxpayer identifier recorded as ABCDE1234F in system logs."
    findings = detector.detect_pii(text)
    assert len(findings) == 1
    assert findings[0].category == PIICategory.PAN
    assert findings[0].raw_text == "ABCDE1234F"


def test_detect_aadhaar() -> None:
    """Verifies Indian Aadhaar 12-digit UID detection."""
    detector = PIIDetector()
    text = "Citizen UID: 3456 7890 1234 verified successfully."
    findings = detector.detect_pii(text)
    assert len(findings) == 1
    assert findings[0].category == PIICategory.AADHAAR
    assert "3456 7890 1234" in findings[0].raw_text


def test_detect_phone() -> None:
    """Verifies Indian mobile phone numbers."""
    detector = PIIDetector()
    text = "Call back on +91 9876543210 or alternate 8765432109 immediately."
    findings = detector.detect_pii(text)
    assert len(findings) == 2
    assert all(f.category == PIICategory.PHONE for f in findings)


def test_detect_credit_card() -> None:
    """Verifies payment card detection with Luhn check."""
    detector = PIIDetector()
    # 4111111111111111 passes Luhn
    text = "Transaction billed to card 4111111111111111 auth=OK"
    findings = detector.detect_pii(text)
    assert len(findings) == 1
    assert findings[0].category == PIICategory.CREDIT_CARD


def test_detect_private_ip() -> None:
    """Verifies RFC1918 private IP detection."""
    detector = PIIDetector(include_private_ips=True)
    text = "Host 192.168.1.50 communicated with internal gateway 10.0.0.1"
    findings = detector.detect_pii(text)
    assert len(findings) == 2
    assert all(f.category == PIICategory.PRIVATE_IP for f in findings)


def test_detect_multiple_pii_entities() -> None:
    """Verifies multi-entity extraction in complex log line."""
    detector = PIIDetector()
    text = "User rajesh.kumar@bank.in (PAN: ABCDE5678Z, Phone: +91-9876501234) authenticated from 10.20.30.40"
    findings = detector.detect_pii(text)
    categories = {f.category for f in findings}
    assert PIICategory.EMAIL in categories
    assert PIICategory.PAN in categories
    assert PIICategory.PHONE in categories
    assert PIICategory.PRIVATE_IP in categories
